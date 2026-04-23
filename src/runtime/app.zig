const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const mode = @import("mode.zig");
const edge = @import("../root.zig");

const config_types = edge.config_types;
const zonfig = edge.zonfig;
const server_mod = edge.server;
const runtime_metrics_mod = @import("runtime_metrics.zig");
const proxy_module = edge.proxy_module;
const passthrough_mod = edge.passthrough_module;
const datadog_mod = edge.datadog_module;
const otlp_mod = edge.otlp_module;
const prometheus_mod = edge.prometheus_module;
const health_mod = edge.health_module;
const policy = edge.policy;

const ProxyConfig = config_types.ProxyConfig;

const o11y = @import("o11y");
const EventBus = o11y.EventBus;
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PassthroughModule = passthrough_mod.PassthroughModule;
const DatadogModule = datadog_mod.DatadogModule;
const DatadogConfig = datadog_mod.DatadogConfig;
const OtlpModule = otlp_mod.OtlpModule;
const OtlpConfig = otlp_mod.OtlpConfig;
const PrometheusModule = prometheus_mod.PrometheusModule;
const PrometheusConfig = prometheus_mod.PrometheusConfig;
const HealthModule = health_mod.HealthModule;
const RuntimeMetrics = runtime_metrics_mod.RuntimeMetrics;

pub const std_options: std.Options = .{
    .log_level = .warn,
    .logFn = StdLogAdapter.logFn,
};

const ServerStarting = struct {};
const ConfigurationLoaded = struct { path: []const u8 };
const ConfigLoadError = struct { err: []const u8 };
const ListenAddressConfigured = struct {
    address: []const u8,
    port: u16,
};
const UpstreamConfigured = struct { url: []const u8 };
const LogsUpstreamConfigured = struct { url: []const u8 };
const MetricsUpstreamConfigured = struct { url: []const u8 };
const ServiceConfigured = struct {
    namespace: []const u8,
    name: []const u8,
    instance_id: []const u8,
    version: []const u8,
};
const ConfigValidationError = struct { field: []const u8, value: []const u8 };
const ServerReady = struct {};
const ServerStopped = struct {};
const ShutdownSignalReceived = struct { signal: []const u8, count: u32 };
const ShutdownForceExit = struct { signal: []const u8, count: u32 };
const ShutdownHint = struct { pid: c_int };
const SignalHandlingNotSupported = struct { platform: []const u8 };

const RouteBundle = enum {
    datadog_logs,
    datadog_metrics,
    otlp,
    prometheus,
};

const edge_bundles = [_]RouteBundle{ .datadog_logs, .datadog_metrics, .otlp, .prometheus };
const datadog_bundles = [_]RouteBundle{ .datadog_logs, .datadog_metrics };
const otlp_bundles = [_]RouteBundle{.otlp};
const prometheus_bundles = [_]RouteBundle{.prometheus};

const SignalWaiterContext = struct {
    bus: *EventBus,
    server: *ProxyServer,
    signal_count: *std.atomic.Value(u32),
    stopping: *std.atomic.Value(bool),
    shutdown_waiter: *std.atomic.Value(bool),
    signal_set: std.posix.sigset_t,
};

const SignalWaiterHandle = struct {
    thread: std.Thread,
    previous_mask: std.posix.sigset_t,
};

fn supportedStagesFor(distribution: mode.Distribution) []const policy.proto.policy.PolicyStage {
    return switch (distribution) {
        .edge => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
            .POLICY_STAGE_TRACE_SAMPLING,
        },
        .datadog => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
        },
        .otlp => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
            .POLICY_STAGE_TRACE_SAMPLING,
        },
        .prometheus => &.{.POLICY_STAGE_METRIC_FILTER},
    };
}

fn bundlesFor(distribution: mode.Distribution) []const RouteBundle {
    return switch (distribution) {
        .edge => &edge_bundles,
        .datadog => &datadog_bundles,
        .otlp => &otlp_bundles,
        .prometheus => &prometheus_bundles,
    };
}

fn distributionLabel(distribution: mode.Distribution) runtime_metrics_mod.DistributionLabel {
    return switch (distribution) {
        .edge => .edge,
        .datadog => .datadog,
        .otlp => .otlp,
        .prometheus => .prometheus,
    };
}

fn containsTemplatePlaceholder(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "${") != null;
}

fn installSignalWaiter(
    bus: *EventBus,
    server: *ProxyServer,
    signal_count: *std.atomic.Value(u32),
    stopping: *std.atomic.Value(bool),
    shutdown_waiter: *std.atomic.Value(bool),
) anyerror!SignalWaiterHandle {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        bus.warn(SignalHandlingNotSupported{ .platform = @tagName(builtin.os.tag) });
        return error.UnsupportedPlatform;
    }

    var signal_set = std.posix.sigemptyset();
    std.posix.sigaddset(&signal_set, std.posix.SIG.INT);
    std.posix.sigaddset(&signal_set, std.posix.SIG.TERM);
    std.posix.sigaddset(&signal_set, std.posix.SIG.USR1);

    var previous_mask = std.posix.sigemptyset();
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &signal_set, &previous_mask);

    const waiter = try std.Thread.spawn(.{}, signalWaiterThread, .{SignalWaiterContext{
        .bus = bus,
        .server = server,
        .signal_count = signal_count,
        .stopping = stopping,
        .shutdown_waiter = shutdown_waiter,
        .signal_set = signal_set,
    }});

    return .{
        .thread = waiter,
        .previous_mask = previous_mask,
    };
}

fn signalWaiterThread(ctx: SignalWaiterContext) void {
    while (true) {
        var sig: c_int = 0;
        if (std.c.sigwait(@constCast(&ctx.signal_set), &sig) != 0) continue;
        if (sig == std.posix.SIG.USR1 and ctx.shutdown_waiter.load(.acquire)) return;

        const signal_name = if (sig == std.posix.SIG.INT) "SIGINT" else "SIGTERM";
        const count = ctx.signal_count.fetchAdd(1, .acq_rel) + 1;

        if (count == 1) {
            ctx.bus.info(ShutdownSignalReceived{ .signal = signal_name, .count = count });
            if (!ctx.stopping.swap(true, .acq_rel)) {
                ctx.server.stop();
            }
            continue;
        }

        ctx.bus.info(ShutdownForceExit{ .signal = signal_name, .count = count });
        std.posix.exit(1);
    }
}

pub fn run(distribution: mode.Distribution) !void {
    const allocator = std.heap.smp_allocator;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next();
    const config_path = args.next() orelse distribution.defaultConfigPath();

    bus.info(ServerStarting{});
    bus.info(ConfigurationLoaded{ .path = config_path });

    const config = zonfig.load(ProxyConfig, allocator, .{
        .json_path = config_path,
        .env_prefix = "TERO",
    }) catch |err| {
        bus.err(ConfigLoadError{ .err = @errorName(err) });
        return err;
    };
    defer zonfig.deinit(ProxyConfig, allocator, config);

    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "edge-{d}-{d}", .{
        std.time.milliTimestamp(),
        std.Thread.getCurrentId(),
    });
    const instance_id_copy = try allocator.dupe(u8, instance_id);
    defer allocator.free(instance_id_copy);

    const service_metadata = policy.ServiceMetadata{
        .name = config.service.name,
        .namespace = config.service.namespace,
        .version = config.service.version,
        .instance_id = instance_id_copy,
        .supported_stages = supportedStagesFor(distribution),
    };

    var addr_buf: [64]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&addr_buf, "{}.{}.{}.{}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
    });

    bus.info(ListenAddressConfigured{ .address = addr_str, .port = config.listen_port });
    bus.info(UpstreamConfigured{ .url = config.upstream_url });
    if (config.logs_url) |logs_url| bus.info(LogsUpstreamConfigured{ .url = logs_url });
    if (config.metrics_url) |metrics_url| bus.info(MetricsUpstreamConfigured{ .url = metrics_url });
    bus.info(ServiceConfigured{
        .namespace = service_metadata.namespace,
        .name = service_metadata.name,
        .instance_id = service_metadata.instance_id,
        .version = service_metadata.version,
    });

    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    if (containsTemplatePlaceholder(config.upstream_url)) {
        bus.err(ConfigValidationError{
            .field = "upstream_url",
            .value = config.upstream_url,
        });
        return error.InvalidConfig;
    }
    if (config.logs_url) |logs_url| {
        if (containsTemplatePlaceholder(logs_url)) {
            bus.err(ConfigValidationError{
                .field = "logs_url",
                .value = logs_url,
            });
            return error.InvalidConfig;
        }
    }
    if (config.metrics_url) |metrics_url| {
        if (containsTemplatePlaceholder(metrics_url)) {
            bus.err(ConfigValidationError{
                .field = "metrics_url",
                .value = metrics_url,
            });
            return error.InvalidConfig;
        }
    }

    var runtime_metrics = try RuntimeMetrics.init(allocator, distributionLabel(distribution));
    defer runtime_metrics.deinit();
    runtime_metrics.setBuildInfo(build_options.version, build_options.commit);

    var loader = try policy.Loader.init(
        allocator,
        bus,
        &registry,
        config.policy_providers,
        service_metadata,
    );
    defer loader.deinit();

    try loader.startAsync();

    var datadog_config = DatadogConfig{
        .registry = &registry,
        .bus = bus,
        .metrics = &runtime_metrics,
    };
    var otlp_config = OtlpConfig{
        .registry = &registry,
        .bus = bus,
        .metrics = &runtime_metrics,
    };
    var prometheus_config = PrometheusConfig{
        .registry = &registry,
        .bus = bus,
        .metrics = &runtime_metrics,
        .max_input_bytes_per_scrape = config.prometheus.max_input_bytes_per_scrape,
        .max_output_bytes_per_scrape = config.prometheus.max_output_bytes_per_scrape,
    };

    const logs_upstream = config.logs_url orelse config.upstream_url;
    const metrics_upstream = config.metrics_url orelse config.upstream_url;

    var health_module = HealthModule{};
    var datadog_logs_module = DatadogModule{};
    var datadog_metrics_module = DatadogModule{};
    var otlp_module = OtlpModule{};
    var prometheus_module = PrometheusModule{};
    var passthrough_module = PassthroughModule{};

    var module_registrations = std.ArrayListUnmanaged(ModuleRegistration){};
    defer module_registrations.deinit(allocator);

    try module_registrations.append(allocator, .{
        .module = .{ .health = &health_module },
        .route_kind = .health,
        .routes = &health_mod.routes,
        .upstream_url = config.upstream_url,
        .max_request_body = 0,
        .max_response_body = 0,
        .module_data = null,
    });

    for (bundlesFor(distribution)) |bundle| {
        switch (bundle) {
            .datadog_logs => try module_registrations.append(allocator, .{
                .module = .{ .datadog = &datadog_logs_module },
                .route_kind = .datadog_logs,
                .routes = &datadog_mod.logs_routes,
                .upstream_url = logs_upstream,
                .max_request_body = config.max_body_size,
                .max_response_body = config.max_body_size,
                .module_data = @ptrCast(&datadog_config),
            }),
            .datadog_metrics => try module_registrations.append(allocator, .{
                .module = .{ .datadog = &datadog_metrics_module },
                .route_kind = .datadog_metrics,
                .routes = &datadog_mod.metrics_routes,
                .upstream_url = metrics_upstream,
                .max_request_body = config.max_body_size,
                .max_response_body = config.max_body_size,
                .module_data = @ptrCast(&datadog_config),
            }),
            .otlp => try module_registrations.append(allocator, .{
                .module = .{ .otlp = &otlp_module },
                .route_kind = .otlp_logs,
                .routes = &otlp_mod.routes,
                .upstream_url = config.upstream_url,
                .max_request_body = config.max_body_size,
                .max_response_body = config.max_body_size,
                .module_data = @ptrCast(&otlp_config),
            }),
            .prometheus => try module_registrations.append(allocator, .{
                .module = .{ .prometheus = &prometheus_module },
                .route_kind = .prometheus_metrics,
                .routes = &prometheus_mod.default_routes,
                .upstream_url = metrics_upstream,
                .max_request_body = 1024,
                .max_response_body = config.max_body_size,
                .module_data = @ptrCast(&prometheus_config),
            }),
        }
    }

    try module_registrations.append(allocator, .{
        .module = .{ .passthrough = &passthrough_module },
        .route_kind = .passthrough,
        .routes = &passthrough_mod.default_routes,
        .upstream_url = config.upstream_url,
        .max_request_body = config.max_body_size,
        .max_response_body = config.max_body_size,
        .module_data = null,
    });

    var proxy = try ProxyServer.init(
        allocator,
        bus,
        &runtime_metrics,
        config.listen_address,
        config.listen_port,
        config.max_upstream_retries,
        config.max_body_size,
        module_registrations.items,
    );
    defer proxy.deinit();

    var signal_count = std.atomic.Value(u32).init(0);
    var stopping = std.atomic.Value(bool).init(false);
    var shutdown_waiter = std.atomic.Value(bool).init(false);

    var signal_waiter: ?SignalWaiterHandle = null;
    if (installSignalWaiter(bus, &proxy, &signal_count, &stopping, &shutdown_waiter)) |waiter| {
        signal_waiter = waiter;
    } else |err| switch (err) {
        error.UnsupportedPlatform => {},
        else => return err,
    }

    bus.info(ServerReady{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        bus.info(ShutdownHint{ .pid = std.c.getpid() });
    }

    proxy.listen() catch |err| {
        if (stopping.load(.acquire)) {
            // Listener was interrupted by shutdown and may report socket-close errors.
        } else {
            return err;
        }
    };

    if (signal_waiter) |waiter| {
        shutdown_waiter.store(true, .release);
        std.posix.kill(std.c.getpid(), std.posix.SIG.USR1) catch {};
        waiter.thread.join();
        std.posix.sigprocmask(std.posix.SIG.SETMASK, &waiter.previous_mask, null);
    }

    bus.info(ServerStopped{});
}
