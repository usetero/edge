const std = @import("std");
const httpz = @import("httpz");

const ServerContext = struct {
    requests_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn handle(self: *ServerContext, _: *httpz.Request, res: *httpz.Response) void {
        _ = self.requests_received.fetchAdd(1, .monotonic);
        res.status = 202;
        res.body = "{}";
    }
};

var server_instance: ?*httpz.Server(*ServerContext) = null;
var request_counter: ?*std.atomic.Value(u64) = null;

fn shutdown(_: c_int) callconv(.c) void {
    if (request_counter) |counter| {
        std.debug.print("\nReceived {d} requests.\n", .{counter.load(.monotonic)});
    }
    std.process.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const port: u16 = if (args.len > 1)
        try std.fmt.parseInt(u16, args[1], 10)
    else
        9999;

    var ctx = ServerContext{};
    request_counter = &ctx.requests_received;

    std.posix.sigaction(std.posix.SIG.INT, &.{
        .handler = .{ .handler = shutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    }, null);

    var server = try httpz.Server(*ServerContext).init(allocator, .{
        .port = port,
        .address = "127.0.0.1",
        .request = .{
            .max_body_size = 5194304,
        },
    }, &ctx);
    server_instance = &server;

    std.debug.print("Echo server listening on http://127.0.0.1:{d}\n", .{port});
    std.debug.print("Press Ctrl+C to stop\n", .{});

    try server.listen();
}
