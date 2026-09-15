//! Reactor-owned socket registrations and generation-safe kernel events.
const Self = @This();

const std = @import("std");
const builtin = @import("builtin");

const Native = @import("os/Poller.zig");

native: Native,
slots: []Slot,
raw_events: []Native.RawEvent,
events: []Event,
free_head: u32,
live: u32 = 0,

const NONE = std.math.maxInt(u32);
pub const Token = u64;
pub const Interest = Native.Interest;
pub const Event = Native.Event;
pub const Limits = struct {
    sockets: u32,
    events: u32,
    ceiling_bytes: u64 = std.math.maxInt(u64),
};
const Slot = struct {
    token: Token,
    fd: std.posix.fd_t = -1,
    next: u32,
    interest: Interest = .{},
};

/// Native kernel allocations are separate from these exact allocator reservations.
/// The instance may move before use; event spans are borrowed until the next wait.
pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
    if (try requiredBytes(limits) > limits.ceiling_bytes) return error.MemoryBudgetExceeded;
    const slots = try allocator.alloc(Slot, limits.sockets);
    errdefer allocator.free(slots);
    const raw_events = try allocator.alloc(Native.RawEvent, limits.events);
    errdefer allocator.free(raw_events);
    const events = try allocator.alloc(Event, limits.events);
    errdefer allocator.free(events);
    for (slots, 0..) |*slot, index| slot.* = .{
        .token = index + 1,
        .next = if (index + 1 < slots.len) @intCast(index + 1) else NONE,
    };
    return .{
        .native = try .init(),
        .slots = slots,
        .raw_events = raw_events,
        .events = events,
        .free_head = 0,
    };
}

/// Stop/join wake producers first. The reactor is the sole socket closer,
/// including shutdown with sockets still registered.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    for (self.slots) |slot| if (slot.fd >= 0) Native.closeFd(slot.fd);
    self.native.deinit();
    allocator.free(self.events);
    allocator.free(self.raw_events);
    allocator.free(self.slots);
    self.* = undefined;
}

pub fn requiredBytes(limits: Limits) !u64 {
    if (limits.sockets == 0 or limits.sockets == NONE or limits.events == 0 or
        limits.events > std.math.maxInt(c_int)) return error.InvalidCapacity;
    const slots = try std.math.mul(u64, limits.sockets, @sizeOf(Slot));
    const events = try std.math.mul(u64, limits.events, @sizeOf(Native.RawEvent) + @sizeOf(Event));
    return std.math.add(u64, @sizeOf(Self), try std.math.add(u64, slots, events));
}

/// ALWAYS consumes fd, including failure/exhaustion. Do not close or duplicate it
/// after this call. Borrow it only on the reactor, through resolve/descriptor.
pub fn adopt(self: *Self, fd: std.posix.fd_t, interest: Interest) !Token {
    errdefer Native.closeFd(fd);
    if (self.free_head == NONE) return error.NoCapacity;
    const slot = &self.slots[self.free_head];
    std.debug.assert(slot.fd == -1);
    try Native.prepare(fd);
    try self.native.set(fd, slot.token, .{}, interest);
    self.free_head = slot.next;
    slot.fd = fd;
    slot.next = NONE;
    slot.interest = interest;
    self.live += 1;
    return slot.token;
}

/// Failure consumes the registration and closes its socket. This also unwinds
/// partial native changes; the caller must detach associated request ownership.
pub fn setInterest(self: *Self, token: Token, interest: Interest) !void {
    const slot = self.lookup(token) orelse return error.StaleRegistration;
    if (slot.interest.read == interest.read and slot.interest.write == interest.write) return;
    self.native.set(slot.fd, token, slot.interest, interest) catch |err| {
        try self.close(token);
        return err;
    };
    slot.interest = interest;
}

/// Invalidate before reuse. Closing removes both kqueue filters / epoll watches;
/// already-returned batches still carry the old token and fail resolve.
pub fn close(self: *Self, token: Token) !void {
    const slot = self.lookup(token) orelse return error.StaleRegistration;
    Native.closeFd(slot.fd);
    slot.fd = -1;
    slot.interest = .{};
    std.debug.assert(self.live > 0);
    self.live -= 1;
    // Congruence identifies a slot; exact equality identifies its incarnation.
    // No request handle is squeezed into kernel udata and no counter wraps.
    slot.token = std.math.add(u64, token, self.slots.len) catch return;
    slot.next = self.free_head;
    self.free_head = @intCast((token - 1) % self.slots.len);
}

/// Resolve immediately before dispatch, even for events from the same batch.
/// Token zero is a wake hint and never identifies a socket. EOF may accompany
/// readable bytes; the caller must drain those bytes before treating it as EOF.
pub fn resolve(self: *Self, event: Event) ?std.posix.fd_t {
    return self.descriptor(event.token);
}

pub fn descriptor(self: *Self, token: Token) ?std.posix.fd_t {
    return (self.lookup(token) orelse return null).fd;
}

/// Index for parallel reactor metadata arrays of the same fixed capacity.
/// The index is not an identity: retain/validate the full token on every access.
pub fn slotIndex(self: *Self, token: Token) ?u32 {
    _ = self.lookup(token) orelse return null;
    return @intCast((token - 1) % self.slots.len);
}

/// A bounded batch may contain stale events; callers must use resolve. If a
/// completion/ready-work budget runs out, poll with an immediate deadline next
/// turn instead of sleeping for a wake that was already consumed.
pub fn wait(self: *Self, io: std.Io, deadline: std.Io.Timestamp) ![]const Event {
    const count = try self.native.wait(io, self.raw_events, deadline);
    for (self.raw_events[0..count], self.events[0..count]) |raw, *event| {
        event.* = try self.native.decode(raw);
    }
    return self.events[0..count];
}

/// Worker-safe until producers join. Publish completion before calling this.
/// A wake error does not undo publication; reactor waits must have finite deadlines.
pub fn wake(self: *const Self) !void {
    try self.native.wake();
}

fn lookup(self: *Self, token: Token) ?*Slot {
    if (token == 0) return null;
    const slot = &self.slots[(token - 1) % self.slots.len];
    if (slot.token != token or slot.fd < 0) return null;
    return slot;
}

const testing = std.testing;

test "v2 readiness rejects stale batches after slot reuse and retires before token wrap" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 4 });
    defer poller.deinit(testing.allocator);
    const first = try socketPair();
    defer first[1].close(testing.io);
    const old = try poller.adopt(first[0].handle, .{ .read = true });
    const stale: Event = .{ .token = old, .readable = true };
    try testing.expect(poller.resolve(stale) != null);
    try poller.close(old);
    const second = try socketPair();
    defer second[1].close(testing.io);
    const current = try poller.adopt(second[0].handle, .{ .read = true });
    try testing.expect(current != old);
    try testing.expect(poller.resolve(stale) == null);
    try testing.expectError(error.StaleRegistration, poller.close(old));
    try testing.expectEqual(second[0].handle, poller.resolve(.{ .token = current }).?);
    poller.slots[0].token = std.math.maxInt(u64);
    try poller.close(std.math.maxInt(u64));
    const third = try socketPair();
    defer third[1].close(testing.io);
    try testing.expectError(error.NoCapacity, poller.adopt(third[0].handle, .{}));
}

test "v2 readiness preserves readable bytes with half close and suppresses disabled writes" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 4 });
    defer poller.deinit(testing.allocator);
    const pair = try socketPair();
    defer pair[1].close(testing.io);
    const token = try poller.adopt(pair[0].handle, .{ .read = true });
    try testing.expectEqual(@as(isize, 4), std.c.write(pair[1].handle, "data", 4));
    const peer: std.Io.net.Stream = .{ .socket = pair[1] };
    try peer.shutdown(testing.io, .send);
    var readable = false;
    var ended = false;
    for (try poller.wait(testing.io, deadlineIn(1000))) |event| {
        if (event.token != token) continue;
        readable = readable or event.readable;
        ended = ended or event.read_closed;
        try testing.expect(!event.writable);
    }
    try testing.expect(readable);
    try testing.expect(ended);
    var bytes: [4]u8 = undefined;
    try testing.expectEqual(@as(isize, 4), std.c.read(pair[0].handle, &bytes, bytes.len));
    try testing.expectEqualStrings("data", &bytes);
    try poller.setInterest(token, .{ .write = true });
    var writable = false;
    for (try poller.wait(testing.io, deadlineIn(1000))) |event| {
        if (event.token == token) writable = writable or event.writable;
    }
    try testing.expect(writable);
    try poller.setInterest(token, .{});
    try testing.expectEqual(@as(usize, 0), (try poller.wait(testing.io, deadlineIn(0))).len);
    try poller.close(token);
}

test "v2 readiness coalesces wake hints without losing a later wake" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 1 });
    defer poller.deinit(testing.allocator);
    if (comptime builtin.os.tag == .linux) {
        // Force EAGAIN on subsequent wake writes: the saturated counter itself
        // is already a wake, not a lost completion or a worker failure.
        const saturated: u64 = std.math.maxInt(u64) - 1;
        try testing.expectEqual(@as(isize, 8), std.c.write(
            poller.native.wake_fd,
            std.mem.asBytes(&saturated),
            @sizeOf(u64),
        ));
    }
    for (0..1000) |_| try poller.wake();
    const events = try poller.wait(testing.io, deadlineIn(1000));
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqual(@as(u64, 0), events[0].token);
    try testing.expectEqual(@as(usize, 0), (try poller.wait(testing.io, deadlineIn(0))).len);
    try poller.wake();
    try testing.expectEqual(@as(usize, 1), (try poller.wait(testing.io, deadlineIn(1000))).len);
}

fn socketPair() ![2]std.Io.net.Socket {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(testing.io, .{});
    defer listener.deinit(testing.io);
    const client = try listener.socket.address.connect(testing.io, .{ .mode = .stream });
    errdefer client.close(testing.io);
    const server = try listener.accept(testing.io);
    return .{ server.socket, client.socket };
}

fn deadlineIn(ms: u16) std.Io.Timestamp {
    return std.Io.Timestamp.now(testing.io, .awake).addDuration(.fromMilliseconds(ms));
}

test "v2 readiness fake event batches resolve each incarnation independently" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 2, .events = 1 });
    defer poller.deinit(testing.allocator);
    const pair = try socketPair();
    defer pair[1].close(testing.io);
    const old = try poller.adopt(pair[0].handle, .{});
    // Scripted kernel output: close on the first event, then dispatch a stale
    // second event from that same batch after another socket takes its slot.
    const batch = [_]Event{
        .{ .token = old, .read_closed = true },
        .{ .token = old, .writable = true },
        .{ .token = 0 },
        .{ .token = std.math.maxInt(u64), .failed = true },
    };
    try testing.expect(poller.resolve(batch[0]) != null);
    try poller.close(old);
    const next_pair = try socketPair();
    defer next_pair[1].close(testing.io);
    const next = try poller.adopt(next_pair[0].handle, .{});
    for (batch[1..]) |event| try testing.expect(poller.resolve(event) == null);
    try testing.expect(poller.descriptor(next) != null);
    try testing.expectError(error.StaleRegistration, poller.setInterest(old, .{ .read = true }));
    try testing.expectEqual(@as(u32, 1), poller.live);
    try poller.close(next);
}

test "v2 readiness consumes exhausted sockets and preserves descriptor flags" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 1 });
    defer poller.deinit(testing.allocator);
    const pair = try socketPair();
    defer pair[1].close(testing.io);
    const token = try poller.adopt(pair[0].handle, .{});
    const fd_flags = std.c.fcntl(pair[0].handle, std.c.F.GETFD);
    try testing.expect(fd_flags & std.c.FD_CLOEXEC != 0);
    const status = std.c.fcntl(pair[0].handle, std.c.F.GETFL);
    const nonblock: u32 = @bitCast(@as(std.c.O, .{ .NONBLOCK = true }));
    try testing.expect(@as(u32, @intCast(status)) & nonblock != 0);
    const rejected = try socketPair();
    defer rejected[1].close(testing.io);
    try testing.expectError(error.NoCapacity, poller.adopt(rejected[0].handle, .{}));
    try testing.expectEqual(@as(c_int, -1), std.c.fcntl(rejected[0].handle, std.c.F.GETFD));
    try testing.expectEqual(std.posix.E.BADF, std.posix.errno(-1));
    try poller.close(token);
    try testing.expectError(error.DescriptorFlagsFailed, poller.adopt(-1, .{}));
    try testing.expectEqual(@as(u32, 0), poller.live);
}

test "v2 readiness startup budget is exact and allocation failures unwind" {
    const limits: Limits = .{ .sockets = 3, .events = 7 };
    const bytes = try requiredBytes(limits);
    try testing.expectError(error.MemoryBudgetExceeded, Self.init(testing.allocator, .{
        .sockets = limits.sockets,
        .events = limits.events,
        .ceiling_bytes = bytes - 1,
    }));
    try testing.expectError(error.InvalidCapacity, requiredBytes(.{ .sockets = 1, .events = 0 }));
    try testing.checkAllAllocationFailures(testing.allocator, allocationLifecycle, .{bytes});
}

fn allocationLifecycle(allocator: std.mem.Allocator, bytes: u64) !void {
    var poller: Self = try .init(allocator, .{ .sockets = 3, .events = 7, .ceiling_bytes = bytes });
    defer poller.deinit(allocator);
    try testing.expectEqual(bytes, @sizeOf(Self) + poller.slots.len * @sizeOf(Slot) +
        poller.events.len * @sizeOf(Event) + poller.raw_events.len * @sizeOf(Native.RawEvent));
    const pair = try socketPair();
    defer pair[1].close(testing.io);
    _ = try poller.adopt(pair[0].handle, .{ .read = true });
    // deinit closes the live socket; callers do not need an allocation to unwind.
}

const Waker = struct {
    poller: *Self,
    started: std.Io.Event = .unset,

    fn run(self: *Waker, io: std.Io) !void {
        self.started.set(io);
        try io.sleep(.fromMilliseconds(30), .awake);
        try self.poller.wake();
    }
};

test "v2 readiness a producer interrupts a waiting reactor and idle deadline expires" {
    const io = testing.io;
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 1 });
    defer poller.deinit(testing.allocator);
    var waker: Waker = .{ .poller = &poller };
    var task = try io.concurrent(Waker.run, .{ &waker, io });
    defer task.cancel(io) catch {};
    try waker.started.wait(io);
    const started: std.Io.Timestamp = .now(io, .awake);
    const events = try poller.wait(io, deadlineIn(2000));
    try testing.expectEqual(@as(usize, 1), events.len);
    try testing.expectEqual(@as(Token, 0), events[0].token);
    try testing.expect(started.durationTo(.now(io, .awake)).toMilliseconds() < 1500);
    try task.await(io);
    const idle_started: std.Io.Timestamp = .now(io, .awake);
    try testing.expectEqual(@as(usize, 0), (try poller.wait(io, deadlineIn(20))).len);
    try testing.expect(idle_started.durationTo(.now(io, .awake)).toMilliseconds() >= 20);
}

test "v2 readiness registration failures retain no socket or admission ownership" {
    var poller: Self = try .init(testing.allocator, .{ .sockets = 1, .events = 1 });
    defer poller.deinit(testing.allocator);
    const native_fd = poller.native.fd;
    defer poller.native.fd = native_fd;
    const pair = try socketPair();
    defer pair[1].close(testing.io);
    poller.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, poller.adopt(pair[0].handle, .{ .read = true }));
    try testing.expectEqual(@as(c_int, -1), std.c.fcntl(pair[0].handle, std.c.F.GETFD));
    try testing.expectEqual(@as(u32, 0), poller.live);
    poller.native.fd = native_fd;
    const second = try socketPair();
    defer second[1].close(testing.io);
    const token = try poller.adopt(second[0].handle, .{ .read = true });
    poller.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, poller.setInterest(token, .{ .write = true }));
    try testing.expectEqual(@as(c_int, -1), std.c.fcntl(second[0].handle, std.c.F.GETFD));
    try testing.expect(poller.descriptor(token) == null);
    try testing.expectEqual(@as(u32, 0), poller.live);
}
