const std = @import("std");
const config_types = @import("../config/types.zig");
const tcp = @import("../network/tcp.zig");
const protocol = @import("../network/protocol.zig");
const http1 = @import("../network/http1.zig");
const inspector = @import("inspector.zig");

pub fn handleConnection(
    allocator: std.mem.Allocator,
    client_fd: std.posix.socket_t,
    upstream_fd: std.posix.socket_t,
    config: *const config_types.ProxyConfig,
) !void {
    defer std.posix.close(client_fd);
    defer std.posix.close(upstream_fd);

    // Per-connection arena for temporary allocations
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const arena_alloc = arena.allocator();

    // Read initial data from client to detect protocol
    var read_buffer: [16384]u8 = undefined;
    const initial_n = try std.posix.read(client_fd, &read_buffer);
    if (initial_n == 0) return; // Client closed connection

    const detected_protocol = protocol.detect(read_buffer[0..initial_n]);

    // Check if protocol is enabled
    switch (detected_protocol) {
        .http1 => {
            if (!config.enable_http1) {
                std.log.warn("HTTP/1.1 is disabled in config", .{});
                return error.Http1Disabled;
            }
            try handleHttp1(
                arena_alloc,
                client_fd,
                upstream_fd,
                read_buffer[0..initial_n],
                config,
            );
        },
        .http2 => {
            if (!config.enable_http2) {
                std.log.warn("HTTP/2 is disabled in config", .{});
                return error.Http2Disabled;
            }
            // For now, just forward HTTP/2 without parsing
            try forwardRaw(client_fd, upstream_fd, read_buffer[0..initial_n]);
            std.log.info("HTTP/2 connection forwarded (inspection not yet implemented)", .{});
        },
        .unknown => {
            std.log.warn("Unknown protocol detected", .{});
            return error.UnknownProtocol;
        },
    }
}

fn handleHttp1(
    allocator: std.mem.Allocator,
    client_fd: std.posix.socket_t,
    upstream_fd: std.posix.socket_t,
    initial_data: []const u8,
    config: *const config_types.ProxyConfig,
) !void {
    const start_time = std.time.milliTimestamp();

    // Parse request
    var parser = http1.Parser.init(allocator);

    // We need to read the full request (headers + body)
    var request_buffer = std.ArrayList(u8){};
    defer request_buffer.deinit(allocator);

    try request_buffer.appendSlice(allocator, initial_data);

    // Try to parse what we have - keep reading until we get a valid request
    var req = while (true) {
        if (parser.parseRequest(request_buffer.items)) |parsed_req| {
            break parsed_req;
        } else |err| {
            if (err == error.InvalidRequest) {
                // Need more data
                var temp_buf: [4096]u8 = undefined;
                const n = std.posix.read(client_fd, &temp_buf) catch return err;
                if (n == 0) return error.UnexpectedEndOfStream;
                try request_buffer.appendSlice(allocator, temp_buf[0..n]);
            } else {
                return err;
            }
        }
    };
    defer allocator.free(req.headers);

    // Check if we need to read the body based on Content-Length
    if (req.getContentLength()) |content_length| {
        const expected_total = request_buffer.items.len - req.body.len + content_length;

        while (request_buffer.items.len < expected_total) {
            var temp_buf: [4096]u8 = undefined;
            const n = try std.posix.read(client_fd, &temp_buf);
            if (n == 0) break;
            try request_buffer.appendSlice(allocator, temp_buf[0..n]);
        }

        // Re-parse with full body
        allocator.free(req.headers);
        req = try parser.parseRequest(request_buffer.items);
    }

    // Inspect and log request
    inspector.inspectRequest(req, config, allocator) catch |err| {
        std.log.warn("Failed to inspect request: {}", .{err});
    };

    // Forward request to upstream
    _ = try std.posix.send(upstream_fd, request_buffer.items, 0);

    // Read response from upstream
    var response_buffer = std.ArrayList(u8){};
    defer response_buffer.deinit(allocator);

    var temp_buf: [4096]u8 = undefined;
    while (true) {
        const n = std.posix.read(upstream_fd, &temp_buf) catch |err| {
            if (err == error.ConnectionResetByPeer) break;
            return err;
        };
        if (n == 0) break;
        try response_buffer.appendSlice(allocator, temp_buf[0..n]);

        // Try to parse response
        var resp = parser.parseResponse(response_buffer.items) catch |err| {
            if (err == error.InvalidResponse) continue; // Need more data
            return err;
        };

        // Check if we have the full response
        if (resp.getContentLength()) |content_length| {
            const expected_total = response_buffer.items.len - resp.body.len + content_length;
            if (response_buffer.items.len >= expected_total) {
                allocator.free(resp.headers);
                break;
            }
            allocator.free(resp.headers);
        } else if (resp.isChunked()) {
            // For chunked encoding, look for last chunk marker
            if (std.mem.indexOf(u8, response_buffer.items, "\r\n0\r\n\r\n") != null or
                std.mem.indexOf(u8, response_buffer.items, "\n0\n\n") != null)
            {
                allocator.free(resp.headers);
                break;
            }
            allocator.free(resp.headers);
        } else {
            // No content-length and not chunked, read until connection close
            allocator.free(resp.headers);
            continue;
        }
    }

    // Parse final response
    const resp = try parser.parseResponse(response_buffer.items);
    defer allocator.free(resp.headers);

    const end_time = std.time.milliTimestamp();
    const duration_ms: u64 = @intCast(end_time - start_time);

    // Inspect and log response
    inspector.inspectResponse(resp, config, allocator, duration_ms) catch |err| {
        std.log.warn("Failed to inspect response: {}", .{err});
    };

    // Forward response to client
    _ = try std.posix.send(client_fd, response_buffer.items, 0);
}

fn forwardRaw(
    client_fd: std.posix.socket_t,
    upstream_fd: std.posix.socket_t,
    initial_data: []const u8,
) !void {
    // Forward initial data
    _ = try std.posix.send(upstream_fd, initial_data, 0);

    // Create two threads: client->upstream and upstream->client
    const ForwardContext = struct {
        from: std.posix.socket_t,
        to: std.posix.socket_t,
    };

    const forwardLoop = struct {
        fn run(ctx: ForwardContext) void {
            var buf: [8192]u8 = undefined;
            while (true) {
                const n = std.posix.read(ctx.from, &buf) catch break;
                if (n == 0) break;
                _ = std.posix.send(ctx.to, buf[0..n], 0) catch break;
            }
        }
    }.run;

    const t1 = try std.Thread.spawn(.{}, forwardLoop, .{ForwardContext{
        .from = client_fd,
        .to = upstream_fd,
    }});
    const t2 = try std.Thread.spawn(.{}, forwardLoop, .{ForwardContext{
        .from = upstream_fd,
        .to = client_fd,
    }});

    t1.join();
    t2.join();
}
