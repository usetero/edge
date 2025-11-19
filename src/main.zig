const std = @import("std");
const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const config_watcher = @import("config/watcher.zig");
const tcp = @import("network/tcp.zig");
const thread_pool = @import("proxy/thread_pool.zig");

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

    // Install signal handler for hot-reload
    config_watcher.installSignalHandler(&config_manager) catch |err| {
        std.log.warn("Failed to install signal handler: {}", .{err});
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
    var pool = try thread_pool.ThreadPool.init(
        allocator,
        &config_manager.current,
        initial_config.thread_pool_size,
    );
    defer pool.deinit();

    std.log.info("Proxy ready. Waiting for connections...", .{});

    // Main accept loop
    while (true) {
        // Accept client connection
        const client = listener.accept() catch |err| {
            std.log.err("Accept failed: {}", .{err});
            continue;
        };

        const current_config = config_manager.get();

        // Connect to upstream
        var upstream = tcp.TcpConnection.connect(
            current_config.upstream_address,
            current_config.upstream_port,
        ) catch |err| {
            std.log.err("Failed to connect to upstream: {}", .{err});
            var mutable_client = client;
            mutable_client.close();
            continue;
        };

        // Submit to thread pool
        pool.submit(.{
            .client = client.fd,
            .upstream = upstream.fd,
        }) catch |err| {
            std.log.err("Failed to submit connection to pool: {}", .{err});
            var mutable_client = client;
            mutable_client.close();
            upstream.close();
            continue;
        };
    }
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
