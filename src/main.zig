//! Full Distribution Entry Point
//!
//! A full edge proxy distribution supporting both Datadog and OTLP ingestion with filtering.
//! Handles /api/v2/logs, /api/v2/series, /v1/logs, and /v1/metrics with policy-based filtering,
//! passes all other requests through.
//!
//! Features:
//! - Policy-based log filtering (DROP/KEEP actions)
//! - Fail-open behavior (errors pass logs through unchanged)
//! - Thread-safe, stateless request processing
//! - Lock-free policy updates via atomic snapshots
//! - Graceful shutdown with signal handling

const std = @import("std");
const builtin = @import("builtin");

const edge = @import("root.zig");
const config_parser = edge.config_parser;
const server_mod = edge.server;
const proxy_module = edge.proxy_module;
const passthrough_mod = edge.passthrough_module;
const datadog_mod = edge.datadog_module;
const otlp_mod = edge.otlp_module;
const prometheus_mod = edge.prometheus_module;
const health_mod = edge.health_module;
const policy = edge.policy;

const o11y = @import("observability/root.zig");
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

/// Route std.log through our EventBus adapter
pub const std_options: std.Options = .{
    .log_level = .debug, // Allow all levels through, EventBus will filter
    .logFn = StdLogAdapter.logFn,
};

// =============================================================================
// Observability Events
// =============================================================================

const ShutdownSignalReceived = struct {};
const SignalHandlersInstalled = struct {};
const SignalHandlingNotSupported = struct { platform: []const u8 };

const ServerStarting = struct {};
const ConfigurationLoaded = struct { path: []const u8 };
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

const ServerReady = struct {};
const ShutdownHint = struct { pid: c_int };
const ServerStopped = struct {};
const ServerError = struct { message: anyerror };

// =============================================================================
// Global state for signal handlers
// =============================================================================

var server_instance: ?*ProxyServer = null;
var global_event_bus: ?*EventBus = null;

fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_event_bus) |bus| {
        bus.info(ShutdownSignalReceived{});
    }

    // Stop the server - this unblocks the main thread
    // Provider cleanup happens in the defer blocks of main()
    if (server_instance) |server| {
        server_instance = null;
        server.server.stop();
    }
}

fn handleSegfault(sig: c_int, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) noreturn {
    _ = sig;
    _ = ctx_ptr;

    std.debug.print("\n=== SEGFAULT ===\n", .{});

    // Get faulting address - field layout differs between Linux and macOS
    const fault_addr: usize = switch (builtin.os.tag) {
        .macos => @intFromPtr(info.addr),
        .linux => @intFromPtr(info.fields.sigfault.addr),
        else => 0,
    };
    std.debug.print("Faulting address: 0x{x}\n", .{fault_addr});
    std.debug.print("Signal code: {d}\n", .{info.code});
    std.debug.print("Stack trace:\n", .{});
    std.debug.dumpCurrentStackTrace(@returnAddress());

    std.posix.abort();
}

fn installShutdownHandlers(bus: *EventBus) void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        bus.warn(SignalHandlingNotSupported{ .platform = @tagName(builtin.os.tag) });
        return;
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // Install SIGSEGV handler to capture crash info
    const segv_act = std.posix.Sigaction{
        .handler = .{ .sigaction = handleSegfault },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.SIGINFO,
    };
    std.posix.sigaction(std.posix.SIG.SEGV, &segv_act, null);

    bus.debug(SignalHandlersInstalled{});
}

// =============================================================================
// Main entry point
// =============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize observability with log level from environment
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    // Parse TERO_LOG_LEVEL env var (defaults to info)
    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    // Initialize std.log adapter to route through EventBus
    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    // Set global event bus for signal handler
    global_event_bus = bus;
    defer global_event_bus = null;

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name
    const config_path = args.next() orelse "config.json";

    bus.info(ServerStarting{});
    bus.info(ConfigurationLoaded{ .path = config_path });

    // Parse configuration
    const config = try config_parser.parseConfigFile(allocator, config_path);
    defer {
        allocator.free(config.upstream_url);
        if (config.logs_url) |logs_url| allocator.free(logs_url);
        if (config.metrics_url) |metrics_url| allocator.free(metrics_url);
        allocator.free(config.workspace_id);
        for (config.policy_providers) |provider_config| {
            allocator.free(provider_config.id);
            if (provider_config.path) |path| allocator.free(path);
            if (provider_config.url) |url| allocator.free(url);
            for (provider_config.headers) |header| {
                allocator.free(header.name);
                allocator.free(header.value);
            }
            if (provider_config.headers.len > 0) {
                allocator.free(provider_config.headers);
            }
        }
        allocator.free(config.policy_providers);
        allocator.destroy(config);
    }

    // Generate service instance ID (UUID-like identifier for this instance's lifetime)
    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "edge-{d}-{d}", .{
        std.time.milliTimestamp(),
        std.Thread.getCurrentId(),
    });
    const instance_id_copy = try allocator.dupe(u8, instance_id);
    defer allocator.free(instance_id_copy);

    // Set the instance_id in service metadata
    config.service.instance_id = instance_id_copy;

    // Format listen address for logging
    var addr_buf: [64]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&addr_buf, "{}.{}.{}.{}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
    });

    bus.info(ListenAddressConfigured{ .address = addr_str, .port = config.listen_port });
    bus.info(UpstreamConfigured{ .url = config.upstream_url });
    if (config.logs_url) |logs_url| {
        bus.info(LogsUpstreamConfigured{ .url = logs_url });
    }
    if (config.metrics_url) |metrics_url| {
        bus.info(MetricsUpstreamConfigured{ .url = metrics_url });
    }
    bus.info(ServiceConfigured{
        .namespace = config.service.namespace,
        .name = config.service.name,
        .instance_id = config.service.instance_id,
        .version = config.service.version,
    });

    // Create centralized policy registry
    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    // Create async policy loader
    var loader = try policy.Loader.init(
        allocator,
        bus,
        &registry,
        config.policy_providers,
        config.workspace_id,
        config.service,
    );
    defer loader.deinit();

    // Start loading policies asynchronously (non-blocking)
    // Server can start accepting requests immediately while policies load in background
    try loader.startAsync();

    // Note: We don't wait for initial load - requests will be processed with
    // whatever policies are available. The registry handles this gracefully.

    // Install signal handlers
    installShutdownHandlers(bus);

    // Use GPA for server allocator - it's thread-safe.
    // For memory limits, use OS-level limits (ulimit, cgroups) instead.
    const server_allocator = allocator;

    // Create Datadog module configuration
    var datadog_config = DatadogConfig{
        .registry = &registry,
        .bus = bus,
    };

    // Create OTLP module configuration
    var otlp_config = OtlpConfig{
        .registry = &registry,
        .bus = bus,
    };

    // Create Prometheus module configuration
    var prometheus_config = PrometheusConfig{
        .registry = &registry,
        .bus = bus,
        .max_bytes_per_scrape = config.prometheus.max_bytes_per_scrape,
    };

    // Determine upstream URLs (use specific URLs if configured, otherwise fall back to upstream_url)
    const logs_upstream = config.logs_url orelse config.upstream_url;
    const metrics_upstream = config.metrics_url orelse config.upstream_url;

    // Create modules
    var health_module = HealthModule{};
    var datadog_logs_module = DatadogModule{};
    var datadog_metrics_module = DatadogModule{};
    var otlp_module = OtlpModule{};
    var prometheus_module = PrometheusModule{};
    var passthrough_module = PassthroughModule{};

    // Register modules (order matters - first match wins)
    const module_registrations = [_]ModuleRegistration{
        // Health module - reserved /_health endpoint (responds immediately, no upstream)
        .{
            .module = health_module.asProxyModule(),
            .routes = &health_mod.routes,
            .upstream_url = config.upstream_url,
            .max_request_body = 0,
            .max_response_body = 0,
            .module_data = null,
        },
        // Datadog logs module - handles /api/v2/logs with filtering
        .{
            .module = datadog_logs_module.asProxyModule(),
            .routes = &datadog_mod.logs_routes,
            .upstream_url = logs_upstream,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&datadog_config),
        },
        // Datadog metrics module - handles /api/v2/series with filtering
        .{
            .module = datadog_metrics_module.asProxyModule(),
            .routes = &datadog_mod.metrics_routes,
            .upstream_url = metrics_upstream,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&datadog_config),
        },
        // OTLP module - handles /v1/logs and /v1/metrics with filtering
        .{
            .module = otlp_module.asProxyModule(),
            .routes = &otlp_mod.routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&otlp_config),
        },
        // Prometheus module - handles /metrics with filtering
        .{
            .module = prometheus_module.asProxyModule(),
            .routes = &prometheus_mod.default_routes,
            .upstream_url = metrics_upstream,
            .max_request_body = 1024, // Small - GET requests only
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&prometheus_config),
        },
        // Passthrough module - handles all other requests
        .{
            .module = passthrough_module.asProxyModule(),
            .routes = &passthrough_mod.default_routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = null,
        },
    };

    // Create proxy server with modules
    var proxy = try ProxyServer.init(
        server_allocator,
        bus,
        config.listen_address,
        config.listen_port,
        config.max_upstream_retries,
        config.max_body_size,
        &module_registrations,
    );
    defer proxy.deinit();

    // Set global server instance for signal handler
    server_instance = &proxy;
    defer server_instance = null;

    bus.info(ServerReady{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        bus.info(ShutdownHint{ .pid = std.c.getpid() });
    }

    // Start listening (blocks until server.stop() is called)
    proxy.listen() catch |err| {
        bus.err(ServerError{ .message = err });
    };

    bus.info(ServerStopped{});
}
