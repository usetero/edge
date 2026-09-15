//! Reactor-owned connections and FIFO admission to request/completion capacity.
//! One instance belongs to one reactor, RequestTable and WorkChannel. Use the
//! embedded Readiness for wait/resolve/wake only; this module owns registration
//! mutations and socket close so metadata and leases cannot diverge.
const Self = @This();

const std = @import("std");
const Readiness = @import("Readiness.zig");
const RequestTable = @import("RequestTable.zig");
const WorkChannel = @import("WorkChannel.zig");

readiness: Readiness,
slots: []Slot,
heads: []u8,
head_bytes: u32,
wait_head: u32 = NONE,
wait_tail: u32 = NONE,
waiting: u32 = 0,

const NONE = std.math.maxInt(u32);
pub const Limits = struct {
    sockets: u32,
    head_bytes: u32,
    events: u32,
    ceiling_bytes: u64 = std.math.maxInt(u64),
};
pub const Admission = struct { connection: Readiness.Token, request: RequestTable.Id };
pub const State = enum { free, reading_head, waiting_credit, reading_body, processing, responding };
const Slot = struct {
    token: Readiness.Token = 0,
    request_id: ?RequestTable.Id = null,
    previous: u32 = NONE,
    next: u32 = NONE,
    state: State = .free,
};

/// Connection heads are separate from request backing bytes: idle/waiting
/// clients cannot consume a body or worker credit. Later methods allocate no
/// application storage.
pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
    if (try requiredBytes(limits) > limits.ceiling_bytes) return error.MemoryBudgetExceeded;
    const slots = try allocator.alloc(Slot, limits.sockets);
    errdefer allocator.free(slots);
    @memset(slots, .{});
    const heads_len = try std.math.mul(usize, limits.sockets, limits.head_bytes);
    const heads = try allocator.alloc(u8, heads_len);
    errdefer allocator.free(heads);
    return .{
        .readiness = try .init(allocator, .{ .sockets = limits.sockets, .events = limits.events }),
        .slots = slots,
        .heads = heads,
        .head_bytes = limits.head_bytes,
    };
}

/// Close all clients, drain work/completions, and join wake producers first.
/// A detached worker still requires this instance to resolve its completion.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    std.debug.assert(self.readiness.live == 0);
    std.debug.assert(self.waiting == 0);
    for (self.slots) |slot| std.debug.assert(slot.state == .free);
    self.readiness.deinit(allocator);
    allocator.free(self.heads);
    allocator.free(self.slots);
    self.* = undefined;
}

/// Includes the embedded poller once, its arrays, metadata and connection heads.
/// Request/queue/stack budgets and native kernel allocations remain separate.
pub fn requiredBytes(limits: Limits) !u64 {
    if (limits.head_bytes == 0) return error.InvalidCapacity;
    const readiness_bytes = try Readiness.requiredBytes(.{ .sockets = limits.sockets, .events = limits.events });
    const slot_bytes = try std.math.mul(u64, limits.sockets, @sizeOf(Slot) + @as(u64, limits.head_bytes));
    return std.math.add(u64, try std.math.add(u64, readiness_bytes, slot_bytes), @sizeOf(Self) - @sizeOf(Readiness));
}

/// ALWAYS consumes fd, including failure. Readiness remains its sole closer.
pub fn adopt(self: *Self, fd: std.posix.fd_t) !Readiness.Token {
    const token = try self.readiness.adopt(fd, .{ .read = true });
    const slot = &self.slots[self.readiness.slotIndex(token).?];
    std.debug.assert(slot.state == .free);
    slot.* = .{ .token = token, .state = .reading_head };
    return token;
}

/// Reactor-only capacity, initially undefined. The framer must track initialized
/// lengths and preserve unread/pipelined bytes; workers borrow RequestTable spans.
pub fn head(self: *Self, token: Readiness.Token) ![]u8 {
    _ = try self.lookup(token);
    const start = self.slotIndex(token) * self.head_bytes;
    return self.heads[start .. start + self.head_bytes];
}

/// Revalidate the token immediately before dispatching a batched readiness event.
/// A still-live socket may have changed phase since the kernel produced its event.
pub fn state(self: *Self, token: Readiness.Token) !State {
    return (try self.lookup(token)).state;
}

pub fn request(self: *Self, token: Readiness.Token) !RequestTable.Id {
    return (try self.lookup(token)).request_id orelse error.NoRequest;
}

/// All parsed requests join the tail, including keep-alive requests. Disable
/// readiness while credit-starved; timers/disconnect handling may remove any waiter.
/// A native failure closes the connection before it joins the queue.
pub fn enqueue(self: *Self, token: Readiness.Token) !void {
    const slot = try self.lookup(token);
    if (slot.state != .reading_head) return error.InvalidTransition;
    self.readiness.setInterest(token, .{}) catch |err| {
        slot.* = .{};
        return err;
    };
    const index: u32 = @intCast(self.slotIndex(token));
    slot.previous = self.wait_tail;
    if (self.wait_tail != NONE) self.slots[self.wait_tail].next = index else self.wait_head = index;
    self.wait_tail = index;
    slot.state = .waiting_credit;
    self.waiting += 1;
}

/// One grant per call. The caller limits grants per turn and retries on returned
/// credits/storage, not on every unrelated socket event. Exhaustion leaves FIFO
/// order untouched; no client reads a body without both reservations.
pub fn admitNext(self: *Self, table: *RequestTable, channel: *WorkChannel) !?Admission {
    if (self.wait_head == NONE) return null;
    if (!try channel.canReserve()) return null;
    const request_id = table.acquire() orelse return null;
    const reserved = channel.reserve(table, request_id) catch |err| {
        table.disconnect(request_id) catch unreachable;
        return err;
    };
    std.debug.assert(reserved); // Only this reactor changes channel admission.
    const slot = &self.slots[self.wait_head];
    const token = slot.token;
    table.bindConnection(request_id, token) catch unreachable;
    self.unlink(slot);
    slot.state = .reading_body;
    slot.request_id = request_id;
    self.readiness.setInterest(token, .{ .read = true }) catch |err| {
        self.close(table, channel, token) catch unreachable;
        return err;
    };
    return .{ .connection = token, .request = request_id };
}

/// Disable socket events before publication so native failure cannot make the
/// caller mistake a queued job for unsubmitted work. Validation failure retains
/// the reservation; the caller can fix input or close the connection.
pub fn dispatch(
    self: *Self,
    io: std.Io,
    table: *RequestTable,
    channel: *WorkChannel,
    token: Readiness.Token,
    input: WorkChannel.Input,
) !void {
    const slot = try self.lookup(token);
    if (slot.state != .reading_body) return error.InvalidTransition;
    try self.setInterest(table, channel, token, .{});
    channel.submit(io, table, slot.request_id.?, input) catch |err| {
        try self.setInterest(table, channel, token, .{ .read = true });
        return err;
    };
    slot.state = .processing;
}

/// Consume exactly once, before touching response storage. A detached completion
/// returns null and may recycle its request bytes. A connected response remains
/// pinned until finishResponse/close. No native operation can fail after ack.
pub fn complete(
    self: *Self,
    table: *RequestTable,
    channel: *WorkChannel,
    completion: WorkChannel.Completion,
) !?Readiness.Token {
    const token = try table.connectionToken(completion.request);
    if (token == 0) return error.UnboundRequest;
    const slot = self.lookup(token) catch null;
    if (slot) |live| {
        if (live.state != .processing) return error.InvalidTransition;
        const expected = live.request_id.?;
        if (expected.index != completion.request.index or expected.generation != completion.request.generation) {
            return error.WrongRequest;
        }
    }
    try channel.acknowledge(table, completion);
    if (slot) |live| {
        live.state = .responding;
        return token;
    }
    return null;
}

/// Arm writes after response/error framing is ready. If the OS rejects interest,
/// close returns the already-acknowledged response storage exactly once.
pub fn responseReady(self: *Self, table: *RequestTable, channel: *WorkChannel, token: Readiness.Token) !void {
    const slot = try self.lookup(token);
    if (slot.state != .responding) return error.InvalidTransition;
    try self.setInterest(table, channel, token, .{ .write = true });
}

/// Release the response before reading the next head. Existing connection bytes
/// are preserved for the framer; a following parsed request must enqueue again.
pub fn finishResponse(self: *Self, table: *RequestTable, channel: *WorkChannel, token: Readiness.Token) !void {
    const slot = try self.lookup(token);
    if (slot.state != .responding) return error.InvalidTransition;
    try table.finishResponse(slot.request_id.?);
    slot.request_id = null;
    slot.state = .reading_head;
    try self.setInterest(table, channel, token, .{ .read = true });
}

/// Remove waiters immediately. Return unpublished credit on body-read disconnect;
/// published jobs keep their lease until completion, independent of socket reuse.
pub fn close(self: *Self, table: *RequestTable, channel: *WorkChannel, token: Readiness.Token) !void {
    const slot = try self.lookup(token);
    if (slot.state == .waiting_credit) self.unlink(slot);
    if (slot.request_id) |id| {
        table.disconnect(id) catch unreachable;
        if (slot.state == .reading_body) channel.cancelReservation(table, id) catch unreachable;
    }
    if (self.readiness.descriptor(token) != null) self.readiness.close(token) catch unreachable;
    slot.* = .{};
}

/// Shutdown detaches clients but does not cancel/drain worker ownership. Call
/// complete for every published job and join producers before deinit.
pub fn closeAll(self: *Self, table: *RequestTable, channel: *WorkChannel) void {
    for (self.slots) |slot| {
        if (slot.state != .free) self.close(table, channel, slot.token) catch unreachable;
    }
}

fn setInterest(
    self: *Self,
    table: *RequestTable,
    channel: *WorkChannel,
    token: Readiness.Token,
    interest: Readiness.Interest,
) !void {
    self.readiness.setInterest(token, interest) catch |err| {
        self.close(table, channel, token) catch unreachable;
        return err;
    };
}

fn lookup(self: *Self, token: Readiness.Token) !*Slot {
    if (token == 0) return error.StaleConnection;
    const slot = &self.slots[self.slotIndex(token)];
    if (slot.token != token or slot.state == .free) return error.StaleConnection;
    return slot;
}

fn slotIndex(self: *const Self, token: Readiness.Token) usize {
    return @intCast((token - 1) % self.slots.len);
}

fn unlink(self: *Self, slot: *Slot) void {
    std.debug.assert(slot.state == .waiting_credit);
    std.debug.assert(self.waiting > 0);
    if (slot.previous == NONE) self.wait_head = slot.next else self.slots[slot.previous].next = slot.next;
    if (slot.next == NONE) self.wait_tail = slot.previous else self.slots[slot.next].previous = slot.previous;
    slot.previous = NONE;
    slot.next = NONE;
    self.waiting -= 1;
}

const testing = std.testing;

test "v2 admission is FIFO across middle disconnect and keep alive reentry" {
    var fixture = try Fixture.init(testing.allocator, 4, 1, 1);
    defer fixture.deinit(testing.allocator);
    const first = try fixture.connect();
    const middle = try fixture.connect();
    const last = try fixture.connect();
    try fixture.connections.enqueue(first);
    try fixture.connections.enqueue(middle);
    try fixture.connections.enqueue(last);
    try testing.expectError(error.InvalidTransition, fixture.connections.enqueue(first));
    try fixture.disconnect(middle);
    const admitted = (try fixture.admit()).?;
    try testing.expectEqual(first, admitted.connection);
    try testing.expect(try fixture.admit() == null);
    try testing.expectEqual(@as(u32, 1), fixture.connections.waiting);
    try fixture.dispatch(first);
    const job = (try fixture.channel.take(testing.io)).?;
    fixture.channel.publish(testing.io, job, .{ .response = 0 });
    const completion = fixture.channel.receive(testing.io).?;
    try testing.expectEqual(first, (try fixture.complete(completion)).?);
    // A returned channel credit alone cannot release a live response's storage.
    try testing.expect(try fixture.admit() == null);
    try fixture.connections.finishResponse(&fixture.requests, &fixture.channel, first);
    try fixture.connections.enqueue(first);
    try testing.expectEqual(last, (try fixture.admit()).?.connection);
    try fixture.disconnect(last);
    try testing.expectEqual(first, (try fixture.admit()).?.connection);
    try fixture.disconnect(first);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
}

test "v2 disconnected work cannot deliver its completion to a reused connection" {
    var fixture = try Fixture.init(testing.allocator, 1, 2, 2);
    defer fixture.deinit(testing.allocator);
    const first = try fixture.connect();
    try fixture.connections.enqueue(first);
    const old_request = (try fixture.admit()).?.request;
    try fixture.dispatch(first);
    const job = (try fixture.channel.take(testing.io)).?;
    try fixture.disconnect(first);
    const current = try fixture.connect();
    try fixture.connections.enqueue(current);
    const new_request = (try fixture.admit()).?.request;
    try testing.expect(current != first);
    try testing.expect(old_request.index != new_request.index);
    @memcpy(job.response[0..2], "ok");
    fixture.channel.publish(testing.io, job, .{ .response = 2 });
    const completion = fixture.channel.receive(testing.io).?;
    try testing.expect(try fixture.complete(completion) == null);
    try testing.expectEqual(new_request, try fixture.connections.request(current));
    try testing.expectEqual(State.reading_body, try fixture.connections.state(current));
    try testing.expectEqual(@as(u32, 1), fixture.channel.outstanding);
    try testing.expectError(error.StaleRequest, fixture.complete(completion));
    try fixture.disconnect(current);
}

const Fixture = struct {
    connections: Self,
    requests: RequestTable,
    channel: WorkChannel,

    fn init(allocator: std.mem.Allocator, sockets: u32, requests: u32, jobs: u32) !Fixture {
        var connections: Self = try .init(allocator, .{ .sockets = sockets, .head_bytes = 64, .events = 8 });
        errdefer connections.deinit(allocator);
        var table: RequestTable = try .init(allocator, .{
            .requests = requests,
            .head_bytes = 64,
            .body_bytes = 64,
            .response_bytes = 64,
        });
        errdefer table.deinit(allocator);
        return .{
            .connections = connections,
            .requests = table,
            .channel = try .init(allocator, .{ .capacity = jobs }),
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.connections.closeAll(&self.requests, &self.channel);
        self.connections.deinit(allocator);
        self.channel.close(testing.io);
        self.channel.deinit(allocator);
        self.requests.deinit(allocator);
        self.* = undefined;
    }

    fn connect(self: *Fixture) !Readiness.Token {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        var listener = try address.listen(testing.io, .{});
        defer listener.deinit(testing.io);
        const peer = try listener.socket.address.connect(testing.io, .{ .mode = .stream });
        defer peer.close(testing.io);
        const stream = try listener.accept(testing.io);
        return self.connections.adopt(stream.socket.handle);
    }

    fn admit(self: *Fixture) !?Admission {
        return self.connections.admitNext(&self.requests, &self.channel);
    }

    fn dispatch(self: *Fixture, token: Readiness.Token) !void {
        try self.connections.dispatch(testing.io, &self.requests, &self.channel, token, .{
            .head_len = 0,
            .body_len = 0,
            .deadline = .now(testing.io, .awake),
        });
    }

    fn complete(self: *Fixture, completion: WorkChannel.Completion) !?Readiness.Token {
        return self.connections.complete(&self.requests, &self.channel, completion);
    }

    fn disconnect(self: *Fixture, token: Readiness.Token) !void {
        try self.connections.close(&self.requests, &self.channel, token);
    }
};

test "v2 channel exhaustion leaves waiting clients without request storage" {
    var fixture = try Fixture.init(testing.allocator, 3, 3, 1);
    defer fixture.deinit(testing.allocator);
    const first = try fixture.connect();
    const second = try fixture.connect();
    const third = try fixture.connect();
    for ([_]Readiness.Token{ first, second, third }) |token| try fixture.connections.enqueue(token);
    try testing.expectEqual(first, (try fixture.admit()).?.connection);
    for (0..100) |_| try testing.expect(try fixture.admit() == null);
    try testing.expectEqual(@as(u32, 1), fixture.requests.live);
    try testing.expectEqual(@as(u32, 2), fixture.connections.waiting);
    try testing.expectError(error.NoRequest, fixture.connections.request(second));
    try fixture.disconnect(first);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
    try testing.expectEqual(second, (try fixture.admit()).?.connection);
    fixture.channel.close(testing.io);
    try testing.expectError(error.Closed, fixture.admit());
    try testing.expectEqual(@as(u32, 1), fixture.connections.waiting);
    try fixture.disconnect(second);
    try fixture.disconnect(third);
}

test "v2 connection shutdown returns reservations but waits for published work" {
    var fixture = try Fixture.init(testing.allocator, 5, 3, 3);
    defer fixture.deinit(testing.allocator);
    _ = try fixture.connect(); // Idle head owns no request.
    const reserved = try fixture.connect();
    const running = try fixture.connect();
    const responding = try fixture.connect();
    const waiting = try fixture.connect();
    for ([_]Readiness.Token{ reserved, running, responding, waiting }) |token| {
        try fixture.connections.enqueue(token);
    }
    for (0..3) |_| try testing.expect(try fixture.admit() != null);
    try fixture.dispatch(running);
    const running_job = (try fixture.channel.take(testing.io)).?;
    try fixture.dispatch(responding);
    const response_job = (try fixture.channel.take(testing.io)).?;
    fixture.channel.publish(testing.io, response_job, .{ .response = 0 });
    try testing.expectEqual(responding, (try fixture.complete(fixture.channel.receive(testing.io).?)).?);
    try fixture.connections.responseReady(&fixture.requests, &fixture.channel, responding);
    fixture.connections.closeAll(&fixture.requests, &fixture.channel);
    try testing.expectEqual(@as(u32, 0), fixture.connections.readiness.live);
    try testing.expectEqual(@as(u32, 0), fixture.connections.waiting);
    try testing.expectEqual(@as(u32, 1), fixture.requests.live);
    try testing.expectEqual(@as(u32, 1), fixture.channel.outstanding);
    fixture.channel.publish(testing.io, running_job, .{ .failed = error.Canceled });
    try testing.expect(try fixture.complete(fixture.channel.receive(testing.io).?) == null);
    try testing.expectEqual(@as(u32, 0), fixture.requests.live);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
    try testing.expectError(error.StaleConnection, fixture.disconnect(running));
}

test "v2 admission and response interest failures release exactly their own ownership" {
    var fixture = try Fixture.init(testing.allocator, 2, 1, 1);
    defer fixture.deinit(testing.allocator);
    const native_fd = fixture.connections.readiness.native.fd;
    defer fixture.connections.readiness.native.fd = native_fd;
    const first = try fixture.connect();
    const second = try fixture.connect();
    try fixture.connections.enqueue(first);
    try fixture.connections.enqueue(second);
    fixture.connections.readiness.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, fixture.admit());
    try testing.expectEqual(@as(u32, 0), fixture.requests.live);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
    try testing.expectEqual(@as(u32, 1), fixture.connections.waiting);
    try testing.expectError(error.StaleConnection, fixture.connections.head(first));
    fixture.connections.readiness.native.fd = native_fd;
    try testing.expectEqual(second, (try fixture.admit()).?.connection);
    try fixture.dispatch(second);
    const job = (try fixture.channel.take(testing.io)).?;
    fixture.channel.publish(testing.io, job, .{ .response = 0 });
    const completion = fixture.channel.receive(testing.io).?;
    try testing.expectEqual(second, (try fixture.complete(completion)).?);
    try testing.expectError(error.InvalidTransition, fixture.complete(completion));
    fixture.connections.readiness.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, fixture.connections.responseReady(
        &fixture.requests,
        &fixture.channel,
        second,
    ));
    try testing.expectEqual(@as(u32, 0), fixture.requests.live);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
    try testing.expectEqual(@as(u32, 0), fixture.connections.readiness.live);
}

test "v2 dispatch failures cannot leave an ambiguously published job" {
    var fixture = try Fixture.init(testing.allocator, 1, 1, 1);
    defer fixture.deinit(testing.allocator);
    const token = try fixture.connect();
    try fixture.connections.enqueue(token);
    _ = (try fixture.admit()).?;
    try testing.expectError(error.InvalidInputLength, fixture.connections.dispatch(
        testing.io,
        &fixture.requests,
        &fixture.channel,
        token,
        .{ .head_len = 65, .body_len = 0, .deadline = .now(testing.io, .awake) },
    ));
    try testing.expectEqual(@as(u32, 1), fixture.channel.outstanding);
    const native_fd = fixture.connections.readiness.native.fd;
    defer fixture.connections.readiness.native.fd = native_fd;
    fixture.connections.readiness.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, fixture.dispatch(token));
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
    try testing.expectEqual(@as(u32, 0), fixture.requests.live);
    fixture.channel.close(testing.io);
    try testing.expect(try fixture.channel.take(testing.io) == null);
}

test "v2 connection heads survive request turnover and are not worker storage" {
    var fixture = try Fixture.init(testing.allocator, 1, 1, 1);
    defer fixture.deinit(testing.allocator);
    const token = try fixture.connect();
    const buffer = try fixture.connections.head(token);
    @memcpy(buffer[0..4], "next");
    try fixture.connections.enqueue(token);
    const admission = (try fixture.admit()).?;
    const spans = try fixture.requests.buffers(admission.request);
    @memcpy(spans.head[0..4], "head");
    try fixture.dispatch(token);
    const job = (try fixture.channel.take(testing.io)).?;
    fixture.channel.publish(testing.io, job, .{ .response = 0 });
    _ = try fixture.complete(fixture.channel.receive(testing.io).?);
    try fixture.connections.finishResponse(&fixture.requests, &fixture.channel, token);
    try testing.expectEqualStrings("next", (try fixture.connections.head(token))[0..4]);
    try testing.expectError(error.NoRequest, fixture.connections.request(token));
    try testing.expectError(error.InvalidTransition, fixture.connections.finishResponse(
        &fixture.requests,
        &fixture.channel,
        token,
    ));
}

test "v2 connection startup budget is exact and partial allocations unwind" {
    const limits: Limits = .{ .sockets = 3, .head_bytes = 64, .events = 8 };
    const bytes = try requiredBytes(limits);
    try testing.expectError(error.MemoryBudgetExceeded, Self.init(testing.allocator, .{
        .sockets = limits.sockets,
        .head_bytes = limits.head_bytes,
        .events = limits.events,
        .ceiling_bytes = bytes - 1,
    }));
    try testing.expectError(error.InvalidCapacity, requiredBytes(.{ .sockets = 1, .head_bytes = 0, .events = 1 }));
    try testing.expectError(error.Overflow, requiredBytes(.{
        .sockets = std.math.maxInt(u32) - 1,
        .head_bytes = std.math.maxInt(u32),
        .events = 1,
    }));
    try testing.checkAllAllocationFailures(testing.allocator, allocationLifecycle, .{bytes});
}

fn allocationLifecycle(allocator: std.mem.Allocator, bytes: u64) !void {
    var connections: Self = try .init(allocator, .{
        .sockets = 3,
        .head_bytes = 64,
        .events = 8,
        .ceiling_bytes = bytes,
    });
    defer connections.deinit(allocator);
    const readiness_bytes = try Readiness.requiredBytes(.{ .sockets = 3, .events = 8 });
    const actual = @sizeOf(Self) - @sizeOf(Readiness) + readiness_bytes +
        connections.slots.len * @sizeOf(Slot) + connections.heads.len;
    try testing.expectEqual(bytes, actual);
}

test "v2 head and keep alive interest failures close without request credit" {
    var fixture = try Fixture.init(testing.allocator, 1, 1, 1);
    defer fixture.deinit(testing.allocator);
    const native_fd = fixture.connections.readiness.native.fd;
    defer fixture.connections.readiness.native.fd = native_fd;
    const first = try fixture.connect();
    fixture.connections.readiness.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, fixture.connections.enqueue(first));
    try testing.expectEqual(@as(u32, 0), fixture.connections.waiting);
    try testing.expectEqual(@as(u32, 0), fixture.connections.readiness.live);
    fixture.connections.readiness.native.fd = native_fd;
    const second = try fixture.connect();
    try fixture.connections.enqueue(second);
    _ = (try fixture.admit()).?;
    try fixture.dispatch(second);
    const job = (try fixture.channel.take(testing.io)).?;
    fixture.channel.publish(testing.io, job, .{ .response = 0 });
    _ = try fixture.complete(fixture.channel.receive(testing.io).?);
    fixture.connections.readiness.native.fd = -1;
    try testing.expectError(error.RegistrationFailed, fixture.connections.finishResponse(
        &fixture.requests,
        &fixture.channel,
        second,
    ));
    try testing.expectEqual(@as(u32, 0), fixture.connections.readiness.live);
    try testing.expectEqual(@as(u32, 0), fixture.requests.live);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
}

test "v2 connection lifecycle needs no application allocation after startup" {
    var failing: testing.FailingAllocator = .init(testing.allocator, .{});
    const allocator = failing.allocator();
    var fixture = try Fixture.init(allocator, 2, 1, 1);
    defer fixture.deinit(allocator);
    const allocations = failing.alloc_index;
    failing.fail_index = allocations;
    const first = try fixture.connect();
    const second = try fixture.connect();
    try fixture.connections.enqueue(first);
    try fixture.connections.enqueue(second);
    _ = (try fixture.admit()).?;
    try fixture.dispatch(first);
    const job = (try fixture.channel.take(testing.io)).?;
    try fixture.disconnect(first);
    fixture.channel.publish(testing.io, job, .{ .failed = error.Canceled });
    try testing.expect(try fixture.complete(fixture.channel.receive(testing.io).?) == null);
    try testing.expectEqual(second, (try fixture.admit()).?.connection);
    try fixture.disconnect(second);
    try testing.expectEqual(allocations, failing.alloc_index);
    try testing.expect(!failing.has_induced_failure);
}
