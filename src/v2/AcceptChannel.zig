//! Fixed accepted-socket handoff. Successful enqueue transfers the sole close duty.
const Self = @This();

const std = @import("std");
const Connections = @import("Connections.zig");
const Native = @import("os/Poller.zig");

storage: []std.posix.fd_t,
queue: std.Io.Queue(std.posix.fd_t),

pub const Limits = struct { capacity: u32, ceiling_bytes: u64 = std.math.maxInt(u64) };
pub const Offer = enum { accepted, full, closed };
pub const Drain = struct {
    adopted: u32 = 0,
    rejected: u32 = 0,
    last_error: ?anyerror = null,
    budget_exhausted: bool = false,
};

/// Keep the channel stable after the first queue operation. Only the bounded
/// descriptor array is allocated; kernel socket buffers have a separate budget.
pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
    if (try requiredBytes(limits) > limits.ceiling_bytes) return error.MemoryBudgetExceeded;
    const storage = try allocator.alloc(std.posix.fd_t, limits.capacity);
    return .{ .storage = storage, .queue = .init(storage) };
}

/// Join producers/consumers first. Pending descriptors are owned by this queue,
/// so teardown closes them even if the receiving reactor never adopted them.
pub fn deinit(self: *Self, allocator: std.mem.Allocator, io: std.Io) void {
    self.close(io);
    while (self.receive(io)) |fd| Native.closeFd(fd);
    allocator.free(self.storage);
    self.* = undefined;
}

pub fn requiredBytes(limits: Limits) !u64 {
    if (limits.capacity == 0) return error.InvalidCapacity;
    return std.math.add(u64, @sizeOf(Self), try std.math.mul(u64, limits.capacity, @sizeOf(std.posix.fd_t)));
}

/// Transfers ownership ONLY on accepted. Full/closed leave fd with the caller,
/// allowing the acceptor to try another target without a duplicate close.
/// Publish before waking the reactor. Wake failure cannot undo this transfer.
pub fn offer(self: *Self, io: std.Io, fd: std.posix.fd_t) Offer {
    std.debug.assert(fd >= 0);
    const count = self.queue.putUncancelable(io, &.{fd}, 0) catch return .closed;
    return if (count == 1) .accepted else .full;
}

/// Transfers the queued descriptor to the receiver. Never waits for an item;
/// closed queues still return their buffered descriptors before null.
pub fn receive(self: *Self, io: std.Io) ?std.posix.fd_t {
    var buffer: [1]std.posix.fd_t = undefined;
    const count = self.queue.getUncancelable(io, &buffer, 0) catch return null;
    return if (count == 1) buffer[0] else null;
}

/// Reactor-only. Connections.adopt consumes fd on both success and error. Failed
/// adoption therefore needs no second close. At the budget, schedule another
/// immediate reactor turn rather than waiting for a previously coalesced wake.
pub fn drain(self: *Self, io: std.Io, connections: *Connections, budget: u16) Drain {
    std.debug.assert(budget > 0);
    var result: Drain = .{};
    for (0..budget) |_| {
        const fd = self.receive(io) orelse return result;
        _ = connections.adopt(fd) catch |err| {
            result.rejected += 1;
            result.last_error = err;
            continue;
        };
        result.adopted += 1;
    }
    result.budget_exhausted = true;
    return result;
}

/// Thread-safe admission barrier. A concurrent successful offer remains queued
/// and must still be drained or closed; close does not revoke transferred fds.
pub fn close(self: *Self, io: std.Io) void {
    self.queue.close(io);
}

const testing = std.testing;

test "v2 accept handoff keeps rejected descriptors with their caller" {
    var channel: Self = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator, testing.io);
    const first = try testSocket();
    try testing.expectEqual(Offer.accepted, channel.offer(testing.io, first));
    const second = try testSocket();
    defer Native.closeFd(second);
    try testing.expectEqual(Offer.full, channel.offer(testing.io, second));
    try testing.expect(std.c.fcntl(second, std.c.F.GETFD) >= 0);
    channel.close(testing.io);
    try testing.expectEqual(Offer.closed, channel.offer(testing.io, second));
    const received = channel.receive(testing.io).?;
    try testing.expectEqual(first, received);
    Native.closeFd(received);
    try testing.expect(channel.receive(testing.io) == null);
}

fn testSocket() !std.posix.fd_t {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(testing.io, .{});
    defer server.deinit(testing.io);
    const peer = try server.socket.address.connect(testing.io, .{ .mode = .stream });
    defer peer.close(testing.io);
    return (try server.accept(testing.io)).socket.handle;
}

test "v2 handoff bounded drain closes sockets rejected by a full reactor" {
    const RequestTable = @import("RequestTable.zig");
    const WorkChannel = @import("WorkChannel.zig");
    var connections: Connections = try .init(testing.allocator, .{ .sockets = 1, .head_bytes = 64, .events = 2 });
    defer connections.deinit(testing.allocator);
    var requests: RequestTable = try .init(testing.allocator, .{
        .requests = 1,
        .head_bytes = 64,
        .body_bytes = 64,
        .response_bytes = 64,
    });
    defer requests.deinit(testing.allocator);
    var work: WorkChannel = try .init(testing.allocator, .{ .capacity = 1 });
    defer work.deinit(testing.allocator);
    defer work.close(testing.io);
    defer connections.closeAll(&requests, &work);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 2 });
    defer channel.deinit(testing.allocator, testing.io);
    const first = try testSocket();
    const second = try testSocket();
    try testing.expectEqual(Offer.accepted, channel.offer(testing.io, first));
    try testing.expectEqual(Offer.accepted, channel.offer(testing.io, second));
    const a = channel.drain(testing.io, &connections, 1);
    try testing.expectEqual(@as(u32, 1), a.adopted);
    try testing.expect(a.budget_exhausted);
    const b = channel.drain(testing.io, &connections, 2);
    try testing.expectEqual(@as(u32, 1), b.rejected);
    try testing.expectEqual(error.NoCapacity, b.last_error.?);
    try testing.expect(!b.budget_exhausted);
    try testing.expectEqual(@as(c_int, -1), std.c.fcntl(second, std.c.F.GETFD));
    try testing.expect(std.c.fcntl(first, std.c.F.GETFD) >= 0);
}

test "v2 handoff teardown closes queued descriptors and allocation failure unwinds" {
    try testing.checkAllAllocationFailures(testing.allocator, allocationLifecycle, .{});
    const bytes = try requiredBytes(.{ .capacity = 2 });
    try testing.expectError(error.MemoryBudgetExceeded, Self.init(testing.allocator, .{
        .capacity = 2,
        .ceiling_bytes = bytes - 1,
    }));
    try testing.expectError(error.InvalidCapacity, requiredBytes(.{ .capacity = 0 }));
}

fn allocationLifecycle(allocator: std.mem.Allocator) !void {
    const bytes = try requiredBytes(.{ .capacity = 2 });
    var descriptors: [2]std.posix.fd_t = undefined;
    {
        var channel: Self = try .init(allocator, .{ .capacity = 2, .ceiling_bytes = bytes });
        defer channel.deinit(allocator, testing.io);
        try testing.expectEqual(bytes, @sizeOf(Self) + channel.storage.len * @sizeOf(std.posix.fd_t));
        for (&descriptors) |*fd| {
            fd.* = try testSocket();
            if (channel.offer(testing.io, fd.*) != .accepted) {
                Native.closeFd(fd.*);
                return error.UnexpectedOffer;
            }
        }
    }
    // No concurrent descriptor creation between teardown and the EBADF checks.
    for (descriptors) |fd| try testing.expectEqual(@as(c_int, -1), std.c.fcntl(fd, std.c.F.GETFD));
}
