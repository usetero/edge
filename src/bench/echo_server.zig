const std = @import("std");
const httpz = @import("httpz");

/// Minimal echo server for benchmarking.
/// Responds to all requests with HTTP 202 Accepted.
const ServerContext = struct {
    requests_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn handle(self: *ServerContext, _: *httpz.Request, res: *httpz.Response) void {
        _ = self.requests_received.fetchAdd(1, .monotonic);
        res.status = 202;
        res.body = "{}";
    }
};

var server_instance: ?*httpz.Server(*ServerContext) = null;

fn handleSigint(_: c_int) callconv(.c) void {
    if (server_instance) |s| {
        s.stop();
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const port: u16 = if (args.len > 1)
        try std.fmt.parseInt(u16, args[1], 10)
    else
        9999;

    var ctx = ServerContext{};
    var server = try httpz.Server(*ServerContext).init(allocator, .{
        .port = port,
        .address = "127.0.0.1",
        .request = .{
            .max_body_size = 5194304,
        },
    }, &ctx);
    defer server.deinit();

    server_instance = &server;
    defer server_instance = null;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleSigint },
        .mask = std.mem.zeroes(std.posix.sigset_t),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    try server.listen();

    std.debug.print("\nShutting down. Received {d} requests.\n", .{ctx.requests_received.load(.monotonic)});
}
