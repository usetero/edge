//! Bounded reactor-to-worker handoff with a completion slot reserved before body admission.
const Self = @This();

const std = @import("std");
const RequestTable = @import("RequestTable.zig");
const Readiness = @import("Readiness.zig");
const Response = @import("Response.zig");

jobs: []Job,
completions: []Completion,
work: std.Io.Queue(Job),
done: std.Io.Queue(Completion),
outstanding: u32 = 0,
closed: bool = false,

pub const Limits = struct {
    capacity: u32,
    ceiling_bytes: u64 = std.math.maxInt(u64),
};

pub const Input = struct { head_len: u32, body_len: u32, trailer_len: u32 = 0, deadline: std.Io.Timestamp };

/// Immutable input and exclusive response storage, pinned until acknowledgement.
/// A worker must publish exactly one completion for every job it takes.
pub const Job = struct {
    request: RequestTable.Id,
    head: []const u8,
    body: []const u8,
    trailers: []const u8,
    response: []u8,
    response_head: []u8,
    response_tail: []u8,
    deadline: std.Io.Timestamp,

    /// Receive directly into body; prepare all metadata here before completion.
    pub fn responseBuffers(self: Job) Response.Buffers {
        return .{ .head = self.response_head, .body = self.response, .tail = self.response_tail };
    }
};

pub const Outcome = union(enum) { response: u32, framed_response: Response.Lengths, file_response: @import("FileResponse.zig").Complete, failed: anyerror };
pub const Completion = struct { request: RequestTable.Id, outcome: Outcome };

/// One channel belongs to one reactor and request table. Only take/publish may
/// run on workers. Keep its address stable from the first queue operation onward.
pub fn init(allocator: std.mem.Allocator, limits: Limits) !Self {
    if (try requiredBytes(limits) > limits.ceiling_bytes) return error.MemoryBudgetExceeded;
    const jobs = try allocator.alloc(Job, limits.capacity);
    errdefer allocator.free(jobs);
    const completions = try allocator.alloc(Completion, limits.capacity);
    return .{
        .jobs = jobs,
        .completions = completions,
        .work = .init(jobs),
        .done = .init(completions),
    };
}

/// Close, drain/acknowledge all work and join every worker before teardown.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    std.debug.assert(self.outstanding == 0);
    allocator.free(self.completions);
    allocator.free(self.jobs);
    self.* = undefined;
}

/// Includes the queue objects and their actual element layouts, not allocator overhead.
pub fn requiredBytes(limits: Limits) !u64 {
    if (limits.capacity == 0) return error.InvalidCapacity;
    const elements = try std.math.mul(u64, limits.capacity, @sizeOf(Job) + @sizeOf(Completion));
    return std.math.add(u64, @sizeOf(Self), elements);
}

/// Reactor-only: reserve before admitting the body. False means apply backpressure;
/// it leaves request state unchanged. Every live credit covers a future completion.
pub fn reserve(self: *Self, table: *RequestTable, request: RequestTable.Id) !bool {
    if (!try self.canReserve()) return false;
    try table.reserve(request);
    self.outstanding += 1;
    return true;
}

/// Reactor-only capacity observation. Check before acquiring request storage to
/// avoid churning request generations while the completion channel is saturated.
pub fn canReserve(self: *const Self) !bool {
    if (self.closed) return error.Closed;
    return self.outstanding < self.jobs.len;
}

/// Reactor-only: return an unpublished credit on disconnect, timeout or shutdown.
pub fn cancelReservation(self: *Self, table: *RequestTable, request: RequestTable.Id) !void {
    try table.cancelReservation(request);
    std.debug.assert(self.outstanding > 0);
    self.outstanding -= 1;
}

/// Reactor-only: publish initialized spans. Validation failure leaves admission
/// reserved so the caller can correct input or cancel it without losing credit.
pub fn submit(self: *Self, io: std.Io, table: *RequestTable, request: RequestTable.Id, sizes: Input) !void {
    if (self.closed) return error.Closed;
    const spans = try table.ingressBuffers(request);
    if (sizes.head_len > spans.head.len or sizes.body_len > spans.body.len or
        sizes.trailer_len > spans.trailers.len) return error.InvalidInputLength;
    try table.dispatch(request);
    const job: Job = .{
        .request = request,
        .head = spans.head[0..sizes.head_len],
        .body = spans.body[0..sizes.body_len],
        .trailers = spans.trailers[0..sizes.trailer_len],
        .response = spans.response,
        .response_head = spans.response_head,
        .response_tail = spans.response_tail,
        .deadline = sizes.deadline,
    };
    // Capacity is reserved and only this reactor closes work. Publication must
    // not introduce cancellation after the request has transferred ownership.
    const count = self.work.putUncancelable(io, &.{job}, 0) catch unreachable;
    std.debug.assert(count == 1);
}

/// Worker-only: sleep on an empty queue. Closing drains buffered jobs before null.
pub fn take(self: *Self, io: std.Io) !?Job {
    return self.work.getOne(io) catch |err| switch (err) {
        error.Closed => null,
        error.Canceled => return error.Canceled,
    };
}

/// Worker-only: publish even on cancellation. No completion can wait for capacity:
/// reservations include queued jobs, executing jobs and unacknowledged completions.
/// This is not a lock-free guarantee; std.Io.Queue takes a short internal lock.
/// The readiness driver must wake its reactor after this publication returns.
pub fn publish(self: *Self, io: std.Io, job: Job, outcome: Outcome) void {
    if (outcome == .response) std.debug.assert(outcome.response <= job.response.len);
    if (outcome == .framed_response) {
        _ = Response.init(job.responseBuffers(), outcome.framed_response) catch unreachable;
    }
    const completion: Completion = .{ .request = job.request, .outcome = outcome };
    const count = self.done.putUncancelable(io, &.{completion}, 0) catch unreachable;
    std.debug.assert(count == 1);
}

/// Reactor-only: polling preserves the credit and request storage until acknowledgement.
pub fn receive(self: *Self, io: std.Io) ?Completion {
    var result: [1]Completion = undefined;
    const count = self.done.getUncancelable(io, &result, 0) catch unreachable;
    return if (count == 0) null else result[0];
}

/// Consume all completion references before calling. Connected clients retain
/// their response storage; detached requests can recycle immediately afterward.
pub fn acknowledge(self: *Self, table: *RequestTable, completion: Completion) !void {
    try table.complete(completion.request);
    try table.consumeCompletion(completion.request);
    std.debug.assert(self.outstanding > 0);
    self.outstanding -= 1;
}

/// Reactor-only: stop admission and wake waiting workers. Completion publication
/// stays open until all jobs have returned and their workers have been joined.
pub fn close(self: *Self, io: std.Io) void {
    if (self.closed) return;
    self.closed = true;
    self.work.close(io);
}

const testing = std.testing;
const input: Input = .{ .head_len = 4, .body_len = 4, .deadline = .{ .nanoseconds = 1000 } };

test "v2 work channel holds credit until completion acknowledgement" {
    const io = testing.io;
    var table = try testTable(3);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 2 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    const first = table.acquire().?;
    const second = table.acquire().?;
    const waiting = table.acquire().?;
    try testing.expect(try channel.reserve(&table, first));
    try testing.expectError(error.InvalidTransition, channel.reserve(&table, first));
    try testing.expect(try channel.reserve(&table, second));
    try testing.expect(!try channel.reserve(&table, waiting));
    try channel.submit(io, &table, first, input);
    try channel.submit(io, &table, second, input);
    const a = (try channel.take(io)).?;
    const b = (try channel.take(io)).?;
    try testing.expectEqual(first, a.request);
    try testing.expectEqual(second, b.request);
    // Both workers can finish while the reactor is stalled, including reverse order.
    channel.publish(io, b, .{ .response = 0 });
    channel.publish(io, a, .{ .failed = error.Canceled });
    const done = channel.receive(io).?;
    try testing.expectEqual(second, done.request);
    try testing.expect(!try channel.reserve(&table, waiting));
    try channel.acknowledge(&table, done);
    try testing.expect(try channel.reserve(&table, waiting));
    try testing.expectError(error.InvalidTransition, channel.acknowledge(&table, done));
    try channel.cancelReservation(&table, waiting);
    const failed = channel.receive(io).?;
    try testing.expectEqual(error.Canceled, failed.outcome.failed);
    try channel.acknowledge(&table, failed);
    try testing.expect(channel.receive(io) == null);
    try table.finishResponse(first);
    try table.finishResponse(second);
    try table.disconnect(waiting);
    try testing.expectEqual(@as(u32, 0), channel.outstanding);
}

test "v2 work channel keeps detached request spans until acknowledgement" {
    const io = testing.io;
    var table = try testTable(1);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    const id = table.acquire().?;
    try testing.expect(try channel.reserve(&table, id));
    const spans = try table.buffers(id);
    @memcpy(spans.head[0..4], "head");
    @memcpy(spans.body[0..4], "body");
    try channel.submit(io, &table, id, input);
    try testing.expectError(error.InvalidTransition, channel.cancelReservation(&table, id));
    try table.disconnect(id);
    const job = (try channel.take(io)).?;
    try testing.expectEqualStrings("head", job.head);
    try testing.expectEqualStrings("body", job.body);
    try testing.expectEqual(input.deadline, job.deadline);
    @memcpy(job.response[0..2], "ok");
    channel.publish(io, job, .{ .response = 2 });
    try testing.expect(table.acquire() == null);
    const done = channel.receive(io).?;
    try testing.expect(table.acquire() == null);
    try testing.expectEqualStrings("ok", job.response[0..done.outcome.response]);
    try channel.acknowledge(&table, done);
    const next = table.acquire().?;
    try testing.expect(next.generation != id.generation);
    try table.disconnect(next);
}

test "v2 work channel cancels admission before a worker owns the request" {
    const io = testing.io;
    var table = try testTable(1);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    const id = table.acquire().?;
    try testing.expect(try channel.reserve(&table, id));
    try testing.expectError(error.InvalidInputLength, channel.submit(io, &table, id, .{
        .head_len = 4096,
        .body_len = 0,
        .deadline = input.deadline,
    }));
    try testing.expectError(error.InvalidInputLength, channel.submit(io, &table, id, .{
        .head_len = 0,
        .body_len = 0,
        .trailer_len = 1,
        .deadline = input.deadline,
    }));
    _ = try table.ingressBuffers(id);
    try table.disconnect(id);
    try testing.expectEqual(@as(u32, 1), table.live);
    try channel.cancelReservation(&table, id);
    try testing.expectEqual(@as(u32, 0), table.live);
    try testing.expectError(error.StaleRequest, channel.cancelReservation(&table, id));
    try testing.expectEqual(@as(u32, 0), channel.outstanding);
}

test "v2 work channel close drains queued work and preserves completions" {
    const io = testing.io;
    var table = try testTable(2);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 2 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    const queued = table.acquire().?;
    const reserved = table.acquire().?;
    try testing.expect(try channel.reserve(&table, queued));
    try testing.expect(try channel.reserve(&table, reserved));
    try channel.submit(io, &table, queued, input);
    channel.close(io);
    channel.close(io);
    try testing.expectError(error.Closed, channel.reserve(&table, reserved));
    try testing.expectError(error.Closed, channel.submit(io, &table, reserved, input));
    try channel.cancelReservation(&table, reserved);
    try table.disconnect(reserved);
    const job = (try channel.take(io)).?;
    try testing.expect(try channel.take(io) == null);
    channel.publish(io, job, .{ .failed = error.Canceled });
    try channel.acknowledge(&table, channel.receive(io).?);
    try table.disconnect(queued);
}

test "v2 work channel startup is bounded and releases partial allocations" {
    const limits: Limits = .{ .capacity = 2 };
    try testing.expectError(error.MemoryBudgetExceeded, Self.init(testing.allocator, .{
        .capacity = 2,
        .ceiling_bytes = (try requiredBytes(limits)) - 1,
    }));
    try testing.expectError(error.InvalidCapacity, Self.init(testing.allocator, .{ .capacity = 0 }));
    try testing.checkAllAllocationFailures(testing.allocator, testAllocation, .{});
}

test "v2 work channel close wakes a worker waiting on an empty queue" {
    const io = testing.io;
    var channel: Self = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    var entered: std.Io.Event = .unset;
    var task = try io.concurrent(waitForWork, .{ &channel, io, &entered });
    defer _ = task.cancel(io) catch |err| switch (err) {
        error.Canceled => {},
        else => unreachable,
    };
    try entered.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    channel.close(io);
    try testing.expect(try task.await(io) == null);
}

test "v2 work channel cancellation publishes before worker ownership ends" {
    const io = testing.io;
    var table = try testTable(1);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    const id = table.acquire().?;
    try testing.expect(try channel.reserve(&table, id));
    try channel.submit(io, &table, id, input);
    var acquired: std.Io.Event = .unset;
    var task = try io.concurrent(holdUntilCanceled, .{ &channel, io, &acquired });
    defer task.cancel(io);
    try acquired.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
    try table.disconnect(id);
    task.cancel(io);
    const done = channel.receive(io).?;
    try testing.expectEqual(error.Canceled, done.outcome.failed);
    try testing.expectEqual(@as(u32, 1), table.live);
    try channel.acknowledge(&table, done);
    try testing.expectEqual(@as(u32, 0), table.live);
}

fn waitForWork(channel: *Self, io: std.Io, entered: *std.Io.Event) !?Job {
    entered.set(io);
    return channel.take(io);
}

fn holdUntilCanceled(channel: *Self, io: std.Io, acquired: *std.Io.Event) void {
    const job = (channel.take(io) catch unreachable).?;
    acquired.set(io);
    var never: std.Io.Event = .unset;
    never.wait(io) catch |err| {
        channel.publish(io, job, .{ .failed = err });
        return;
    };
    unreachable;
}

fn testTable(count: u32) !RequestTable {
    return .init(testing.allocator, .{ .requests = count, .head_bytes = 16, .body_bytes = 16, .response_bytes = 16 });
}

fn testAllocation(allocator: std.mem.Allocator) !void {
    const limits: Limits = .{ .capacity = 2 };
    var channel: Self = try .init(allocator, .{ .capacity = 2, .ceiling_bytes = try requiredBytes(limits) });
    defer channel.deinit(allocator);
    const actual = @sizeOf(Self) + channel.jobs.len * @sizeOf(Job) + channel.completions.len * @sizeOf(Completion);
    try testing.expectEqual(try requiredBytes(limits), actual);
    channel.close(testing.io);
}

const WakeWorker = struct {
    channel: *Self,
    poller: *Readiness,

    fn run(self: *WakeWorker, io: std.Io) !void {
        while (try self.channel.take(io)) |job| {
            @memcpy(job.response[0..2], "ok");
            self.channel.publish(io, job, .{ .response = 2 });
            try self.poller.wake();
        }
    }
};

test "v2 completion publication precedes coalesced wake and bounded drains keep ownership" {
    const io = testing.io;
    var table = try testTable(4);
    defer table.deinit(testing.allocator);
    var channel: Self = try .init(testing.allocator, .{ .capacity = 4 });
    defer channel.deinit(testing.allocator);
    defer channel.close(io);
    var poller: Readiness = try .init(testing.allocator, .{ .sockets = 1, .events = 1 });
    defer poller.deinit(testing.allocator);
    for (0..4) |_| {
        const id = table.acquire().?;
        try testing.expect(try channel.reserve(&table, id));
        const spans = try table.buffers(id);
        @memcpy(spans.head[0..4], "head");
        @memcpy(spans.body[0..4], "body");
        try channel.submit(io, &table, id, input);
        try table.disconnect(id);
    }
    channel.close(io);
    var worker: WakeWorker = .{ .channel = &channel, .poller = &poller };
    var task = try io.concurrent(WakeWorker.run, .{ &worker, io });
    defer task.cancel(io) catch {};
    try task.await(io);
    // Four publications may yield just one wake. Drain only two per reactor turn.
    const deadline = std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(1000));
    try testing.expectEqual(@as(usize, 1), (try poller.wait(io, deadline)).len);
    for (0..2) |_| {
        const completion = channel.receive(io).?;
        const spans = try table.buffers(completion.request);
        try testing.expectEqualStrings("ok", spans.response[0..completion.outcome.response]);
        try channel.acknowledge(&table, completion);
    }
    try testing.expectEqual(@as(u32, 2), channel.outstanding);
    try testing.expectEqual(@as(u32, 2), table.live);
    // Exhausting a completion budget schedules another turn without sleeping.
    // Waiting for a second wake here would strand the two remaining leases.
    _ = try poller.wait(io, .now(io, .awake));
    for (0..2) |_| try channel.acknowledge(&table, channel.receive(io).?);
    try testing.expect(channel.receive(io) == null);
    try testing.expectEqual(@as(u32, 0), channel.outstanding);
    try testing.expectEqual(@as(u32, 0), table.live);
    try task.await(io);
}
