const std = @import("std");
const builtin = @import("builtin");
const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const config_watcher = @import("config/watcher.zig");
const config_http_client = @import("config/http_client.zig");
const httpz_server = @import("proxy/httpz_server.zig");
const filter_mod = @import("core/filter.zig");
const policy_registry_mod = @import("core/policy_registry.zig");

/// Global server instance for signal handler
var server_instance: ?*httpz_server.HttpzProxyServer = null;

/// Signal handler for graceful shutdown
fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    std.log.info("Shutdown signal received, stopping server...", .{});
    if (server_instance) |server| {
        server_instance = null;
        server.server.stop();
    }
}

/// Install SIGINT and SIGTERM handlers
fn installShutdownHandlers() void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        std.log.warn("Signal handling not supported on this platform", .{});
        return;
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    std.log.debug("Installed signal handlers for SIGINT and SIGTERM", .{});
}

/// Check if config source is an HTTP(S) URL
fn isHttpUrl(source: []const u8) bool {
    return std.mem.startsWith(u8, source, "http://") or
        std.mem.startsWith(u8, source, "https://");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name

    const config_source = args.next() orelse "config.json";

    std.log.info("Tero Edge HTTP Proxy starting...", .{});
    std.log.info("Configuration source: {s}", .{config_source});

    // Create centralized policy registry
    var policy_registry = policy_registry_mod.PolicyRegistry.init(allocator);
    defer policy_registry.deinit();

    // Determine if we're using HTTP or file-based config
    const use_http = isHttpUrl(config_source);

    // Pointer to config that will be used by the server
    var config_ptr: *std.atomic.Value(*const config_types.ProxyConfig) = undefined;

    // Initialize file config manager (always active for non-policy config)
    var file_config_manager = try config_watcher.ConfigManager.init(
        allocator,
        &policy_registry,
        if (use_http) "config.json" else config_source,
    );
    defer file_config_manager.deinit();
    config_ptr = &file_config_manager.current;

    // Optionally initialize HTTP client for policy overlays
    var http_config_client: ?config_http_client.HttpConfigClient = null;
    defer if (http_config_client) |*client| client.deinit();

    if (use_http) {
        std.log.info("Using HTTP config client for policies (polling every 60s)", .{});
        http_config_client = try config_http_client.HttpConfigClient.init(
            allocator,
            &policy_registry,
            config_source,
            60, // Poll every 60 seconds
        );
    } else {
        std.log.info("Using file-based config watcher", .{});
    }

    const initial_config = config_ptr.load(.acquire);
    std.log.info("Listen address: {}.{}.{}.{}:{}", .{
        initial_config.listen_address[0],
        initial_config.listen_address[1],
        initial_config.listen_address[2],
        initial_config.listen_address[3],
        initial_config.listen_port,
    });
    std.log.info("Upstream URL: {s}", .{initial_config.upstream_url});
    std.log.info("Policy count: {}", .{policy_registry.getPolicyCount()});

    // Create filter evaluator with reference to registry
    var filter_evaluator = filter_mod.FilterEvaluator.init(&policy_registry);
    defer filter_evaluator.deinit();

    // Install signal handlers
    installShutdownHandlers();

    // Install config-specific handlers and start watching/polling
    config_watcher.installSignalHandler(&file_config_manager) catch |err| {
        std.log.warn("Failed to install config reload handler: {}", .{err});
    };
    try file_config_manager.startWatching();

    if (http_config_client) |*client| {
        try client.startPolling();
    }

    // Create httpz proxy server
    var proxy = try httpz_server.HttpzProxyServer.init(
        allocator,
        config_ptr,
        &filter_evaluator,
    );
    defer proxy.deinit();

    // Set global server instance for signal handler
    server_instance = &proxy;
    defer server_instance = null;

    std.log.info("Proxy ready. Waiting for connections...", .{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.log.info("To shutdown: kill -s INT {d}", .{std.c.getpid()});
    }

    // Start listening (blocks until server.stop() is called)
    try proxy.listen();

    std.log.info("Server stopped gracefully.", .{});
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
