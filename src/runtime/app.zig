//! Composition root for the proxy distributions (PLAN.md §10).
//!
//! Juicy main hands us io/gpa/environ; everything below is wired here and
//! NOWHERE else: Io selection, limits, upstreams, services, router,
//! lifecycle, HTTP frontend. Shutdown is structured — the signal
//! watcher calls Lifecycle.requestShutdown and Lifecycle.shutdown cancels
//! the accept loop and every connection task together.
const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

const mode = @import("mode.zig");
const distro = @import("distro.zig");
const runtime_metrics_mod = @import("runtime_metrics.zig");
const config_types = @import("../config/types.zig");
const zonfig = @import("../zonfig/root.zig");
const limits_mod = @import("../core/limits.zig");
const io_select = @import("../core/io_select.zig");
const lifecycle_mod = @import("../core/lifecycle.zig");
const service_mod = @import("../service/service.zig");
const router_mod = @import("../service/router.zig");
const upstream_mod = @import("../frontend/upstream.zig");
const exec_mod = @import("../frontend/exec.zig");
const frontend_select = @import("../frontend/select.zig");

const policy = @import("policy_zig");
const o11y = @import("o11y");
const EventBus = o11y.EventBus;
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const ProxyConfig = config_types.ProxyConfig;
const RuntimeMetrics = runtime_metrics_mod.RuntimeMetrics;

const log = std.log.scoped(.app);

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = StdLogAdapter.logFn,
};

// Named event payloads: the type name is the telemetry event name.
const ServerStarting = struct {};
const ConfigurationLoaded = struct { path: []const u8 };
const ConfigLoadError = struct { err: []const u8 };
const ListenAddressConfigured = struct { address: []const u8, port: u16 };
const UpstreamConfigured = struct { url: []const u8 };
const LogsUpstreamConfigured = struct { url: []const u8 };
const MetricsUpstreamConfigured = struct { url: []const u8 };
const ServiceConfigured = struct {
    namespace: []const u8,
    name: []const u8,
    instance_id: []const u8,
    version: []const u8,
};
const ServerReady = struct {};
const DataPlaneBudget = struct {
    max_connections: usize,
    per_conn_bytes: usize,
    steady_state_bytes: usize,
};
const ShutdownHint = struct { pid: c_int };
const ServerStopped = struct {};
const ShutdownSignalReceived = struct { signal: []const u8, count: u32 };
const ShutdownForceExit = struct { signal: []const u8, count: u32 };
const SignalHandlingNotSupported = struct { platform: []const u8 };

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

fn distributionLabel(distribution: mode.Distribution) runtime_metrics_mod.DistributionLabel {
    return switch (distribution) {
        .edge => .edge,
        .datadog => .datadog,
        .otlp => .otlp,
        .prometheus => .prometheus,
    };
}

// =============================================================================
// Signal handling: sigwait thread; first INT/TERM requests structured
// shutdown, second force-exits. USR1 wakes the waiter for clean teardown.
// Ported from the pre-rewrite app.zig.
// =============================================================================

const SignalWaiterContext = struct {
    bus: *EventBus,
    io: std.Io,
    lifecycle: *lifecycle_mod.Lifecycle,
    signal_count: *std.atomic.Value(u32),
    shutdown_waiter: *std.atomic.Value(bool),
    signal_set: std.posix.sigset_t,
};

const SignalWaiterHandle = struct {
    thread: std.Thread,
    previous_mask: std.posix.sigset_t,
};

fn installSignalWaiter(
    bus: *EventBus,
    io: std.Io,
    lifecycle: *lifecycle_mod.Lifecycle,
    signal_count: *std.atomic.Value(u32),
    shutdown_waiter: *std.atomic.Value(bool),
) anyerror!SignalWaiterHandle {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
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
        .io = io,
        .lifecycle = lifecycle,
        .signal_count = signal_count,
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
        if (sig == @intFromEnum(std.posix.SIG.USR1) and ctx.shutdown_waiter.load(.acquire)) return;

        const signal_name = if (sig == @intFromEnum(std.posix.SIG.INT)) "SIGINT" else "SIGTERM";
        const count = ctx.signal_count.fetchAdd(1, .acq_rel) + 1;

        if (count == 1) {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.info(ShutdownSignalReceived{ .signal = signal_name, .count = count });
            ctx.lifecycle.requestShutdown(ctx.io);
            continue;
        }

        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.info(ShutdownForceExit{ .signal = signal_name, .count = count });
        std.process.exit(1);
    }
}

fn handleSegfault(sig: std.posix.SIG, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) void {
    _ = sig;
    _ = ctx_ptr;

    std.debug.print("\n=== SEGFAULT ===\n", .{});

    const fault_addr: usize = switch (builtin.os.tag) {
        .macos => @intFromPtr(info.addr),
        .linux => @intFromPtr(info.fields.sigfault.addr),
        else => 0,
    };
    std.debug.print("Faulting address: 0x{x}\n", .{fault_addr});
    std.debug.print("Signal code: {d}\n", .{info.code});
    std.debug.print("Stack trace:\n", .{});
    std.debug.dumpCurrentStackTrace(.{ .first_address = @returnAddress() });

    std.process.abort();
}

fn installSegfaultHandler() void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return;

    const segv_act: std.posix.Sigaction = .{
        .handler = .{ .sigaction = handleSegfault },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.SIGINFO,
    };
    std.posix.sigaction(std.posix.SIG.SEGV, &segv_act, null);
}

// =============================================================================
// Engine: the assembled data plane. Heap-allocated so the internal pointers
// (SharedCtx -> router/upstreams/...) stay stable. Shared by app.run and the
// Lambda extension main. Frontend-specific state (the stdio conn slab and
// arena pool) is owned by the frontend server, not the Engine.
// =============================================================================

pub const EngineOptions = struct {
    listen_address: [4]u8,
    listen_port: u16,
    max_body_size: u32,
    upstream_url: []const u8,
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,
    service_options: distro.ServiceOptions = .{},
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    limits: limits_mod.Limits,
    upstreams: upstream_mod.UpstreamManager,
    services_buf: [8]service_mod.Service,
    services_len: usize,
    router: router_mod.Router,
    lifecycle: lifecycle_mod.Lifecycle,
    shared_ctx: exec_mod.SharedCtx,
    server: frontend_select.Server,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        environ_map: *const std.process.Environ.Map,
        bus: *EventBus,
        registry: *policy.Registry,
        metrics: ?*RuntimeMetrics,
        kinds: []const distro.ServiceKind,
        options: EngineOptions,
    ) !*Engine {
        const self = try allocator.create(Engine);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.io = io;
        self.limits = .resolve(options.max_body_size, environ_map);
        self.limits.logStartup();

        self.upstreams = upstream_mod.UpstreamManager.init(io, allocator, self.limits.max_connections);
        errdefer self.upstreams.deinit();
        const max_body = options.max_body_size;
        const upstream_ids: exec_mod.UpstreamIds = .{
            .default = try self.upstreams.createUpstream(options.upstream_url, 2048, max_body, max_body),
            .logs = try self.upstreams.createUpstream(
                options.logs_url orelse options.upstream_url,
                2048,
                max_body,
                max_body,
            ),
            .metrics = try self.upstreams.createUpstream(
                options.metrics_url orelse options.upstream_url,
                2048,
                max_body,
                max_body,
            ),
        };

        std.debug.assert(kinds.len <= self.services_buf.len);
        for (kinds, 0..) |kind, i| {
            self.services_buf[i] = distro.buildService(kind, options.service_options);
        }
        self.services_len = kinds.len;

        var route_sets_buf: [8]router_mod.RouteSet = undefined;
        for (self.services_buf[0..self.services_len], 0..) |*svc, i| {
            route_sets_buf[i] = .{
                .service = @enumFromInt(@as(u16, @intCast(i))),
                .routes = svc.routes(),
            };
        }
        self.router = try .init(allocator, route_sets_buf[0..self.services_len]);
        errdefer self.router.deinit();

        self.lifecycle = .init;
        self.shared_ctx = .{
            .io = io,
            .gpa = allocator,
            .router = &self.router,
            .services = self.services_buf[0..self.services_len],
            .upstreams = &self.upstreams,
            .upstream_ids = upstream_ids,
            .registry = registry,
            .bus = bus,
            .metrics = metrics,
            .limits = self.limits,
        };

        self.server = try .init(
            &self.shared_ctx,
            &self.lifecycle,
            options.listen_address,
            options.listen_port,
        );
        return self;
    }

    /// Spawns the accept loop. Pair with `stop` then `destroy`.
    pub fn start(self: *Engine) !void {
        try self.lifecycle.spawn(self.io, frontend_select.Server.run, .{&self.server});
    }

    pub fn requestShutdown(self: *Engine) void {
        self.lifecycle.requestShutdown(self.io);
    }

    /// Blocks until requestShutdown is called (from a signal thread or the
    /// Lambda event loop).
    pub fn awaitShutdown(self: *Engine) void {
        self.lifecycle.awaitShutdown(self.io) catch |err| switch (err) {
            error.Canceled => {},
        };
    }

    /// Cancels the accept loop and all connection tasks and waits for them.
    /// stopAccepting first: the httpz frontend blocks in its own event loop,
    /// which Io cancellation can't interrupt (stdio's is a no-op).
    pub fn stop(self: *Engine) void {
        self.server.stopAccepting();
        self.lifecycle.shutdown(self.io);
    }

    pub fn destroy(self: *Engine) void {
        const allocator = self.allocator;
        self.server.deinit();
        self.router.deinit();
        self.upstreams.deinit();
        allocator.destroy(self);
    }
};

pub fn serviceKindsFor(distribution: mode.Distribution) []const distro.ServiceKind {
    return switch (distribution) {
        inline else => |d| comptime distro.servicesFor(d),
    };
}

// =============================================================================
// run
// =============================================================================

fn raiseOpenFileLimit() void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return;
    // A proxy holding max_connections inbound sockets + 3 upstream pools of the
    // same size can easily consume 1000+ FDs. The OS default soft limit (256 on
    // older macOS, 1024 on many Linux systems) is far too low. Raise to the hard
    // limit, or to a known-sufficient value, whichever is smaller.
    const want: std.posix.rlim_t = 65536;
    const current = std.posix.getrlimit(.NOFILE) catch return;
    if (current.cur >= want) return;
    const new: std.posix.rlimit = .{
        .cur = if (current.max == std.posix.RLIM.INFINITY) want else @min(want, current.max),
        .max = current.max,
    };
    std.posix.setrlimit(.NOFILE, new) catch |err|
        log.warn("could not raise RLIMIT_NOFILE to {d}: {s}", .{ want, @errorName(err) });
}

pub fn run(init: std.process.Init, distribution: mode.Distribution) !void {
    raiseOpenFileLimit();
    const allocator = init.gpa;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init(init.io);
    const bus = stdio_bus.eventBus();

    bus.setLevel(Level.parseFromEnv(init.environ_map, "TERO_LOG_LEVEL", .info));

    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    var args = init.minimal.args.iterate();
    _ = args.skip();
    const config_path = args.next() orelse distribution.defaultConfigPath();

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ServerStarting{});
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ConfigurationLoaded{ .path = config_path });

    // The selected Io backend; everything below uses io, never init.io.
    var io_runtime = try io_select.IoRuntime.fromEnv(init.io, init.environ_map);
    defer io_runtime.deinit();
    const io = io_runtime.io();

    const config = zonfig.load(ProxyConfig, allocator, io, .{
        .json_path = config_path,
        .env_prefix = "TERO",
        .environ = init.environ_map,
    }) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.err(ConfigLoadError{ .err = @errorName(err) });
        return err;
    };
    defer zonfig.deinit(ProxyConfig, allocator, config);

    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "edge-{d}-{d}", .{
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
        std.Thread.getCurrentId(),
    });
    const instance_id_copy = try allocator.dupe(u8, instance_id);
    defer allocator.free(instance_id_copy);

    const service_metadata: policy.ServiceMetadata = .{
        .name = config.service.name,
        .namespace = config.service.namespace,
        .version = config.service.version,
        .instance_id = instance_id_copy,
        .supported_stages = supportedStagesFor(distribution),
    };

    logStartupConfig(bus, config, service_metadata);

    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    var runtime_metrics = try RuntimeMetrics.init(allocator, io, distributionLabel(distribution));
    defer runtime_metrics.deinit();
    runtime_metrics.setBuildInfo(build_options.version, build_options.commit);

    var loader = try policy.Loader.init(allocator, io, bus, &registry, config.policy_providers, service_metadata);
    defer loader.deinit();
    try loader.startAsync(io);
    installSegfaultHandler();

    const kinds = serviceKindsFor(distribution);
    const engine = try Engine.create(allocator, io, init.environ_map, bus, &registry, &runtime_metrics, kinds, .{
        .listen_address = config.listen_address,
        .listen_port = config.listen_port,
        .max_body_size = config.max_body_size,
        .upstream_url = config.upstream_url,
        .logs_url = config.logs_url,
        .metrics_url = config.metrics_url,
        .service_options = .{
            .prometheus_max_input_bytes = config.prometheus.max_input_bytes_per_scrape,
            .prometheus_max_output_bytes = config.prometheus.max_output_bytes_per_scrape,
        },
    });
    defer engine.destroy();

    var signal_count = std.atomic.Value(u32).init(0);
    var shutdown_waiter = std.atomic.Value(bool).init(false);
    var signal_waiter: ?SignalWaiterHandle = null;
    if (installSignalWaiter(bus, io, &engine.lifecycle, &signal_count, &shutdown_waiter)) |waiter| {
        signal_waiter = waiter;
    } else |err| switch (err) {
        error.UnsupportedPlatform => {},
        else => return err,
    }

    try engine.start();

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(DataPlaneBudget{
        .max_connections = engine.limits.max_connections,
        .per_conn_bytes = engine.limits.perConnBytes(),
        .steady_state_bytes = engine.limits.steadyStateBytes(),
    });
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ServerReady{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.info(ShutdownHint{ .pid = std.c.getpid() });
    }

    engine.awaitShutdown();
    engine.stop();

    if (signal_waiter) |waiter| {
        shutdown_waiter.store(true, .release);
        std.posix.kill(std.c.getpid(), std.posix.SIG.USR1) catch |err|
            log.warn("failed to send shutdown signal: {}", .{err});
        waiter.thread.join();
        std.posix.sigprocmask(std.posix.SIG.SETMASK, &waiter.previous_mask, null);
    }

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ServerStopped{});
}

fn logStartupConfig(bus: *EventBus, config: *const ProxyConfig, service_metadata: policy.ServiceMetadata) void {
    var addr_buf: [64]u8 = undefined;
    const addr_str = std.fmt.bufPrint(&addr_buf, "{d}.{d}.{d}.{d}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
    }) catch "?";

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ListenAddressConfigured{ .address = addr_str, .port = config.listen_port });
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(UpstreamConfigured{ .url = config.upstream_url });
    if (config.logs_url) |logs_url| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.info(LogsUpstreamConfigured{ .url = logs_url });
    }
    if (config.metrics_url) |metrics_url| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.info(MetricsUpstreamConfigured{ .url = metrics_url });
    }
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ServiceConfigured{
        .namespace = service_metadata.namespace,
        .name = service_metadata.name,
        .instance_id = service_metadata.instance_id,
        .version = service_metadata.version,
    });
}
