//! Prometheus Distribution Entry Point
//!
//! A minimal edge proxy distribution for Prometheus remote write ingestion.
//! Currently passes all requests through unchanged to the upstream.

const std = @import("std");
const builtin = @import("builtin");

const edge = @import("root.zig");
const config_parser = edge.config_parser;
const server_mod = edge.server;
const proxy_module = edge.proxy_module;
const prometheus_mod = edge.prometheus_module;
const passthrough_mod = edge.passthrough_module;

const o11y = @import("observability/root.zig");
const EventBus = o11y.EventBus;
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PrometheusModule = prometheus_mod.PrometheusModule;
const PassthroughModule = passthrough_mod.PassthroughModule;

/// Route std.log through our EventBus adapter
pub const std_options: std.Options = .{
    .log_level = .debug,
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
    std.process.exit(0);
}

fn handleSegfault(sig: c_int, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) noreturn {
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

    // Initialize observability
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    global_event_bus = bus;
    defer global_event_bus = null;

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name
    const config_path = args.next() orelse "config-prometheus.json";

    bus.info(ServerStarting{});
    bus.info(ConfigurationLoaded{ .path = config_path });

    // Parse configuration
    const config = try config_parser.parseConfigFile(allocator, config_path);
    defer {
        allocator.free(config.upstream_url);
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

    // Install signal handlers
    installShutdownHandlers(bus);

    // Create modules
    var prometheus_module = PrometheusModule{};
    var passthrough_module = PassthroughModule{};

    // Register modules - prometheus for /metrics, passthrough for everything else
    const module_registrations = [_]ModuleRegistration{
        // Prometheus module for /metrics endpoint with response interception
        .{
            .module = prometheus_module.asProxyModule(),
            .routes = &prometheus_mod.routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = null,
            .response_intercept_fn = prometheus_mod.prometheusInterceptCallback,
            .create_intercept_context_fn = prometheus_mod.createInterceptContext,
            .destroy_intercept_context_fn = prometheus_mod.destroyInterceptContext,
        },
        // Passthrough module for all other routes
        .{
            .module = passthrough_module.asProxyModule(),
            .routes = &passthrough_mod.default_routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = null,
        },
    };

    // Create proxy server
    var proxy = try ProxyServer.init(
        std.heap.page_allocator,
        bus,
        config.listen_address,
        config.listen_port,
        config.max_upstream_retries,
        config.max_body_size,
        &module_registrations,
    );
    defer proxy.deinit();

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
