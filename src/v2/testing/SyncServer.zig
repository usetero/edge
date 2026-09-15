//! Loopback-only policy sync fixture with bounded captures and cancellable accept.
const Self = @This();

const std = @import("std");

listener: std.Io.net.Server,
exchanges: []Exchange,
served: std.atomic.Value(usize) = .init(0),
task: ?std.Io.Future(anyerror!void) = null,

pub const Exchange = struct {
    response: []const u8 = "{}",
    status: std.http.Status = .ok,
    request_body: []u8 = &.{},
};

/// The fixture and exchanges must keep their addresses until deinit joins the task.
pub fn init(self: *Self, allocator: std.mem.Allocator, io: std.Io, exchanges: []Exchange) !void {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    self.* = .{ .listener = try address.listen(io, .{}), .exchanges = exchanges };
    errdefer self.listener.deinit(io);
    self.task = try io.concurrent(serve, .{ self, allocator, io });
}

pub fn deinit(self: *Self, allocator: std.mem.Allocator, io: std.Io) void {
    defer self.* = undefined;
    if (self.task) |*task| task.cancel(io) catch |err| switch (err) {
        error.Canceled => {},
        else => std.log.err("v2 sync fixture exited early: {t}", .{err}),
    };
    self.listener.deinit(io);
    for (self.exchanges) |exchange| allocator.free(exchange.request_body);
}

pub fn url(self: *const Self, buffer: []u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "http://127.0.0.1:{d}/sync", .{self.listener.socket.address.getPort()});
}

/// A completed response publishes the capture before the testing thread reads it.
pub fn waitFor(self: *Self, io: std.Io, count: usize) !void {
    for (0..5000) |_| {
        if (self.served.load(.acquire) >= count) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestSyncTimeout;
}

fn serve(self: *Self, allocator: std.mem.Allocator, io: std.Io) anyerror!void {
    while (true) {
        const stream = try self.listener.accept(io);
        defer stream.close(io);
        try self.respond(allocator, io, stream);
    }
}

fn respond(self: *Self, allocator: std.mem.Allocator, io: std.Io, stream: std.Io.net.Stream) !void {
    var receive_buffer: [16 * 1024]u8 = undefined;
    var send_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &receive_buffer);
    var writer = stream.writer(io, &send_buffer);
    var server: std.http.Server = .init(&reader.interface, &writer.interface);
    var request = try server.receiveHead();
    const index = self.served.load(.monotonic);
    if (index >= self.exchanges.len) {
        // Extra syncs get a real error response instead of hanging a broken close test.
        try request.respond("{}", .{ .status = .internal_server_error, .keep_alive = false });
    } else {
        var body_buffer: [8192]u8 = undefined;
        const body = try request.readerExpectContinue(&body_buffer);
        const exchange = &self.exchanges[index];
        exchange.request_body = try body.allocRemaining(allocator, .limited(1 << 20));
        try request.respond(exchange.response, .{ .status = exchange.status, .keep_alive = false });
    }
    _ = self.served.fetchAdd(1, .release);
}
