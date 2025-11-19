const std = @import("std");
const builtin = @import("builtin");
const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const config_watcher = @import("config/watcher.zig");
const tcp = @import("network/tcp.zig");
const thread_pool = @import("proxy/thread_pool.zig");

/// Global shutdown flag - set by signal handler
var shutdown = std.atomic.Value(bool).init(false);

/// Signal handler for graceful shutdown
fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    shutdown.store(true, .release);
    std.log.info("Shutdown signal received, initiating graceful shutdown...", .{});
}

/// Install SIGINT and SIGTERM handlers
fn installShutdownHandlers() void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        return; // Signal handling not supported on this platform
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
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
    std.log.info("Upstream address: {}.{}.{}.{}:{}", .{
        initial_config.upstream_address[0],
        initial_config.upstream_address[1],
        initial_config.upstream_address[2],
        initial_config.upstream_address[3],
        initial_config.upstream_port,
    });
    std.log.info("Thread pool size: {}", .{initial_config.thread_pool_size});
    std.log.info("HTTP/1.1: {s}", .{if (initial_config.enable_http1) "enabled" else "disabled"});
    std.log.info("HTTP/2: {s}", .{if (initial_config.enable_http2) "enabled" else "disabled"});

    // Install signal handlers
    installShutdownHandlers();

    config_watcher.installSignalHandler(&config_manager) catch |err| {
        std.log.warn("Failed to install config reload handler: {}", .{err});
    };

    // Start config file watcher
    try config_manager.startWatching();

    // Create TCP listener
    var listener = try tcp.TcpListener.init(
        initial_config.listen_address,
        initial_config.listen_port,
    );
    defer listener.deinit();

    std.log.info("Listening on {}.{}.{}.{}:{}", .{
        initial_config.listen_address[0],
        initial_config.listen_address[1],
        initial_config.listen_address[2],
        initial_config.listen_address[3],
        initial_config.listen_port,
    });

    // Create thread pool
    const pool = try thread_pool.ThreadPool.init(
        allocator,
        &config_manager.current,
        initial_config.thread_pool_size,
    );
    defer pool.deinit(allocator);

    std.log.info("Proxy ready. Waiting for connections...", .{});

    std.log.info("Main: entering accept loop", .{});
    var loop_iterations: usize = 0;
    // Main accept loop with graceful shutdown support
    while (!shutdown.load(.acquire)) {
        loop_iterations += 1;
        if (loop_iterations % 10 == 0) {
            std.log.info("Main: accept loop iteration {}", .{loop_iterations});
        }
        // Accept client connection with timeout to allow checking shutdown flag
        const client = listener.acceptTimeout(1000) catch |err| {
            std.log.err("Accept failed: {}", .{err});
            continue;
        };

        // Timeout - no connection, check shutdown flag
        if (client == null) continue;

        const current_config = config_manager.get();

        // Connect to upstream
        var upstream = tcp.TcpConnection.connect(
            current_config.upstream_address,
            current_config.upstream_port,
        ) catch |err| {
            std.log.err("Failed to connect to upstream: {}", .{err});
            var mutable_client = client.?;
            mutable_client.close();
            continue;
        };

        // Submit to thread pool
        pool.submit(.{
            .client = client.?.fd,
            .upstream = upstream.fd,
        }) catch |err| {
            std.log.err("Failed to submit connection to pool: {}", .{err});
            var mutable_client = client.?;
            mutable_client.close();
            upstream.close();
            continue;
        };
    }

    std.log.info("Shutting down gracefully...", .{});
    std.log.info("Proxy stopped.", .{});
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
