const std = @import("std");
const builtin = @import("builtin");
const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const config_watcher = @import("config/watcher.zig");
const httpz_server = @import("proxy/httpz_server.zig");

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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name

    const config_path = args.next() orelse "config.txt";

    std.log.info("Tero Edge HTTP Proxy starting...", .{});
    std.log.info("Configuration file: {s}", .{config_path});

    // Load configuration
    var config_manager = try config_watcher.ConfigManager.init(allocator, config_path);
    defer config_manager.deinit();

    const initial_config = config_manager.get();
    std.log.info("Listen address: {}.{}.{}.{}:{}", .{
        initial_config.listen_address[0],
        initial_config.listen_address[1],
        initial_config.listen_address[2],
        initial_config.listen_address[3],
        initial_config.listen_port,
    });
    std.log.info("Upstream URL: {s}", .{initial_config.upstream_url});
    std.log.info("HTTP/1.1: {s}", .{if (initial_config.enable_http1) "enabled" else "disabled"});
    std.log.info("HTTP/2: {s}", .{if (initial_config.enable_http2) "enabled" else "disabled"});

    // Install signal handlers
    installShutdownHandlers();

    config_watcher.installSignalHandler(&config_manager) catch |err| {
        std.log.warn("Failed to install config reload handler: {}", .{err});
    };

    // Start config file watcher
    try config_manager.startWatching();

    // Create httpz proxy server
    var proxy = try httpz_server.HttpzProxyServer.init(
        allocator,
        &config_manager.current,
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
