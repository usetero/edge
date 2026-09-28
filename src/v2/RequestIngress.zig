//! Reactor-local bridge from validated wire bytes to a reserved request slot.
//! It owns no allocation and never publishes a worker job by itself.
const Self = @This();

const std = @import("std");
const BodyFramer = @import("BodyFramer.zig");
const RequestHead = @import("RequestHead.zig");
const RequestTable = @import("RequestTable.zig");
const WorkChannel = @import("WorkChannel.zig");

table: *RequestTable,
request: RequestTable.Id,
head: RequestHead,
head_fields: []RequestHead.Field,
framer: BodyFramer,

pub const Limits = struct { head: RequestHead.Limits, body: BodyFramer.Limits };
pub const Storage = struct {
    head_fields: []RequestHead.Field,
    line: []u8,
    trailer_fields: []RequestHead.Field,
};

/// Reactor-only. `request` must have a live RequestTable/WorkChannel reservation.
/// Scratch spans must remain live and disjoint from wire input and request storage.
/// Copy before parsing so every head span belongs to the request slot,
/// rather than a reusable connection buffer. Do not dispatch on construction.
pub fn init(
    table: *RequestTable,
    request: RequestTable.Id,
    wire_head: []const u8,
    storage: Storage,
    ingress_limits: Limits,
) !Self {
    const buffers = try table.ingressBuffers(request);
    if (wire_head.len > buffers.head.len) return error.HeadTooLarge;
    if (ingress_limits.body.body_bytes > buffers.body.len) return error.StorageTooSmall;
    @memcpy(buffers.head[0..wire_head.len], wire_head);
    const head = try RequestHead.parse(buffers.head[0..wire_head.len], storage.head_fields, ingress_limits.head);
    const framer = try BodyFramer.init(head.framing, .{
        .line = storage.line,
        .trailers = buffers.trailers,
        .fields = storage.trailer_fields,
    }, ingress_limits.body);
    return .{ .table = table, .request = request, .head = head, .head_fields = storage.head_fields, .framer = framer };
}

/// Reactor-only. Consume entity/framing bytes while the reservation remains live.
/// On output backpressure or completion, the returned count identifies the suffix
/// still owned by the connection framer.
pub fn feed(self: *Self, wire_body: []const u8) !BodyFramer.Result {
    const buffers = try self.table.ingressBuffers(self.request);
    const start: usize = @intCast(self.framer.body_len);
    return self.framer.feed(wire_body, buffers.body[start..]);
}

/// Worker input is unavailable until every body/framing byte validated. The
/// caller passes this to Connections.dispatch, which performs the only publish.
pub fn input(self: *const Self, deadline: std.Io.Timestamp) !WorkChannel.Input {
    _ = try self.table.ingressBuffers(self.request);
    if (self.framer.state != .done) return error.IncompleteBody;
    return .{
        .head_len = self.head.head_len,
        .body_len = std.math.cast(u32, self.framer.body_len) orelse return error.BodyTooLarge,
        .trailer_len = self.framer.trailer_len,
        .deadline = deadline,
    };
}

/// This cannot write; the connection owner records a one-time send after real
/// reservation/deadline checks. Before a body read, pass false for body_received.
pub fn continueAction(self: *const Self, body_received: bool) !RequestHead.ContinueAction {
    _ = try self.table.ingressBuffers(self.request);
    if (self.framer.state == .failed) return error.InvalidState;
    return self.head.continueAction(true, body_received);
}

/// Reactor-only view before publication. Workers receive request-owned raw bytes
/// through their job; they must not retain ingress or its scratch descriptors.
pub fn trailers(self: *const Self) !BodyFramer.Trailers {
    _ = try self.table.ingressBuffers(self.request);
    if (self.framer.state != .done) return error.IncompleteBody;
    return self.framer.trailers();
}

const testing = std.testing;
const HEAD = "POST /v1/logs HTTP/1.1\r\nHost: edge\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n";
const BODY = "3\r\nabc\r\n0\r\nX-End: one\r\n\r\n";
const NEXT = "GET /next HTTP/1.1\r\nHost: edge\r\n\r\n";

const Fixture = struct {
    table: RequestTable,
    channel: WorkChannel,
    fields: [16]RequestHead.Field = undefined,
    trailer_fields: [8]RequestHead.Field = undefined,
    line: [128]u8 = undefined,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var table: RequestTable = try .init(allocator, .{
            .requests = 1,
            .head_bytes = 256,
            .body_bytes = 64,
            .trailer_bytes = 256,
            .response_bytes = 32,
        });
        errdefer table.deinit(allocator);
        return .{
            .table = table,
            .channel = try .init(allocator, .{ .capacity = 1 }),
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.channel.close(testing.io);
        self.channel.deinit(allocator);
        self.table.deinit(allocator);
        self.* = undefined;
    }

    fn reserve(self: *Fixture) !RequestTable.Id {
        const request = self.table.acquire() orelse return error.NoRequestCapacity;
        errdefer self.table.disconnect(request) catch unreachable;
        if (!try self.channel.reserve(&self.table, request)) return error.NoChannelCapacity;
        return request;
    }

    fn storage(self: *Fixture) Storage {
        return .{
            .head_fields = &self.fields,
            .line = &self.line,
            .trailer_fields = &self.trailer_fields,
        };
    }
};

fn limits() Limits {
    return .{ .head = .{ .head_bytes = 256 }, .body = .{ .body_bytes = 64 } };
}

test "v2 ingress reserves then copies a complete chunked request for a worker" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    var ingress = try Self.init(&fixture.table, request, HEAD, fixture.storage(), limits());
    try testing.expectEqual(.send_continue, try ingress.continueAction(false));
    const wire = BODY ++ NEXT;
    const result = try ingress.feed(wire);
    try testing.expectEqual(.done, result.status);
    try testing.expectEqual(BODY.len, result.consumed);
    try testing.expectEqualStrings(NEXT, wire[result.consumed..]);
    const work_input = try ingress.input(.{ .nanoseconds = 1000 });
    try testing.expectEqualStrings("X-End: one\r\n\r\n", (try ingress.trailers()).bytes);
    try fixture.channel.submit(testing.io, &fixture.table, request, work_input);
    const job = (try fixture.channel.take(testing.io)).?;
    try testing.expectEqualStrings(HEAD, job.head);
    try testing.expectEqualStrings("abc", job.body);
    fixture.channel.publish(testing.io, job, .{ .failed = error.Canceled });
    try fixture.channel.acknowledge(&fixture.table, fixture.channel.receive(testing.io).?);
    try fixture.table.disconnect(request);
}

test "v2 ingress rejects publish before framing completes and fences malformed body" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    var ingress = try Self.init(&fixture.table, request, HEAD, fixture.storage(), limits());
    _ = try ingress.feed("3\r\nab");
    try testing.expectError(error.IncompleteBody, ingress.input(.{ .nanoseconds = 1 }));
    try testing.expectError(error.IncompleteBody, ingress.trailers());
    try testing.expectError(error.UnexpectedEndOfStream, ingress.framer.finish());
    try testing.expectError(error.InvalidState, ingress.feed(BODY));
    try testing.expectError(error.InvalidState, ingress.continueAction(false));
    try fixture.table.disconnect(request);
    try fixture.channel.cancelReservation(&fixture.table, request);
    try testing.expectEqual(@as(u32, 0), fixture.table.live);
}

test "v2 ingress head copy survives reuse of a source buffer" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    var wire: [HEAD.len]u8 = undefined;
    @memcpy(&wire, HEAD);
    var ingress = try Self.init(&fixture.table, request, &wire, fixture.storage(), limits());
    @memset(&wire, 'x');
    _ = try ingress.feed(BODY);
    const work_input = try ingress.input(.{ .nanoseconds = 1 });
    const buffers = try fixture.table.buffers(request);
    try testing.expectEqualStrings(HEAD, buffers.head[0..work_input.head_len]);
    try testing.expectEqualStrings("abc", buffers.body[0..work_input.body_len]);
    try fixture.table.disconnect(request);
    try fixture.channel.cancelReservation(&fixture.table, request);
}

test "v2 ingress no-body requests have no body read or Continue" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    const head = "GET /_health HTTP/1.1\r\nHost: edge\r\n\r\n";
    var ingress = try Self.init(&fixture.table, request, head, fixture.storage(), limits());
    try testing.expectEqual(.none, try ingress.continueAction(false));
    const result = try ingress.feed(NEXT);
    try testing.expectEqual(.done, result.status);
    try testing.expectEqual(0, result.consumed);
    const work_input = try ingress.input(.{ .nanoseconds = 1 });
    try testing.expectEqual(0, work_input.body_len);
    try fixture.table.disconnect(request);
    try fixture.channel.cancelReservation(&fixture.table, request);
}

test "v2 ingress enforces backing capacity before body reads and releases reservation" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    const too_large: Limits = .{
        .head = .{ .head_bytes = 256 },
        .body = .{ .body_bytes = 65 },
    };
    try testing.expectError(
        error.StorageTooSmall,
        Self.init(&fixture.table, request, HEAD, fixture.storage(), too_large),
    );
    try fixture.table.disconnect(request);
    try fixture.channel.cancelReservation(&fixture.table, request);
    try testing.expectEqual(@as(u32, 0), fixture.channel.outstanding);
}

test "v2 ingress rejects an unreserved slot before modifying its head" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = fixture.table.acquire().?;
    defer fixture.table.disconnect(request) catch unreachable;
    const buffers = try fixture.table.buffers(request);
    @memset(buffers.head, 'x');
    try testing.expectError(error.InvalidTransition, Self.init(
        &fixture.table,
        request,
        HEAD,
        fixture.storage(),
        limits(),
    ));
    for (buffers.head) |byte| try testing.expectEqual(@as(u8, 'x'), byte);
}

test "v2 ingress cannot mutate a dispatched worker request" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    var ingress = try Self.init(&fixture.table, request, HEAD, fixture.storage(), limits());
    _ = try ingress.feed(BODY);
    try fixture.channel.submit(testing.io, &fixture.table, request, try ingress.input(.{ .nanoseconds = 1 }));
    const job = (try fixture.channel.take(testing.io)).?;
    defer {
        fixture.channel.publish(testing.io, job, .{ .failed = error.Canceled });
        fixture.channel.acknowledge(&fixture.table, fixture.channel.receive(testing.io).?) catch unreachable;
        fixture.table.disconnect(request) catch unreachable;
    }
    try testing.expectError(error.InvalidTransition, ingress.feed(BODY));
    try testing.expectError(error.InvalidTransition, ingress.input(.{ .nanoseconds = 1 }));
    try testing.expectError(error.InvalidTransition, ingress.continueAction(false));
    try testing.expectError(error.InvalidTransition, ingress.trailers());
    try testing.expectError(error.InvalidTransition, Self.init(
        &fixture.table,
        request,
        NEXT,
        fixture.storage(),
        limits(),
    ));
    try testing.expectEqualStrings(HEAD, job.head);
    try testing.expectEqualStrings("abc", job.body);
}

test "v2 ingress rejects canceled detached and stale reservations" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    for ([_]bool{ false, true }) |detach_first| {
        const request = try fixture.reserve();
        var ingress = try Self.init(&fixture.table, request, HEAD, fixture.storage(), limits());
        _ = try ingress.feed(BODY);
        if (detach_first) {
            try fixture.table.disconnect(request);
        } else {
            try fixture.channel.cancelReservation(&fixture.table, request);
        }
        try testing.expectError(error.InvalidTransition, ingress.feed(BODY));
        try testing.expectError(error.InvalidTransition, ingress.input(.{ .nanoseconds = 1 }));
        try testing.expectError(error.InvalidTransition, ingress.continueAction(false));
        try testing.expectError(error.InvalidTransition, ingress.trailers());
        if (detach_first) {
            try fixture.channel.cancelReservation(&fixture.table, request);
        } else {
            try fixture.table.disconnect(request);
        }
        const reused = try fixture.reserve();
        try testing.expectEqual(request.index, reused.index);
        try testing.expectError(error.StaleRequest, ingress.feed(BODY));
        try testing.expectError(error.StaleRequest, ingress.input(.{ .nanoseconds = 1 }));
        try testing.expectError(error.StaleRequest, ingress.continueAction(false));
        try testing.expectError(error.StaleRequest, ingress.trailers());
        try fixture.table.disconnect(reused);
        try fixture.channel.cancelReservation(&fixture.table, reused);
    }
}

test "v2 ingress fixture unwinds every startup allocation failure" {
    try testing.checkAllAllocationFailures(testing.allocator, testAllocation, .{});
}

fn testAllocation(allocator: std.mem.Allocator) !void {
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
}

test "v2 ingress fixture returns an acquired slot if reservation fails" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    fixture.channel.close(testing.io);
    try testing.expectError(error.Closed, fixture.reserve());
    // Clean up even on regression so the assertion reports the lost slot.
    const live = fixture.table.live;
    if (live != 0) try fixture.table.disconnect(.{ .index = 0, .generation = 1 });
    try testing.expectEqual(@as(u32, 0), live);
}

test "v2 ingress trailers survive scratch reuse and disconnect until acknowledgement" {
    var fixture = try Fixture.init(testing.allocator);
    defer fixture.deinit(testing.allocator);
    const request = try fixture.reserve();
    var ingress = try Self.init(&fixture.table, request, HEAD, fixture.storage(), limits());
    _ = try ingress.feed("3\r\nabc\r\n0\r\nX-End: one\r\nx-end: two\r\n\r\n");
    try fixture.channel.submit(testing.io, &fixture.table, request, try ingress.input(.{ .nanoseconds = 1 }));
    try fixture.table.disconnect(request);
    const job = (try fixture.channel.take(testing.io)).?;
    defer {
        fixture.channel.publish(testing.io, job, .{ .failed = error.Canceled });
        fixture.channel.acknowledge(&fixture.table, fixture.channel.receive(testing.io).?) catch unreachable;
    }
    ingress = undefined;
    @memset(&fixture.line, 'x');
    @memset(&fixture.fields, .{ .name = .{ .start = 0, .len = 0 }, .value = .{ .start = 0, .len = 0 } });
    @memset(&fixture.trailer_fields, fixture.fields[0]);
    try testing.expect(fixture.table.acquire() == null);
    try testing.expectEqualStrings(HEAD, job.head);
    try testing.expectEqualStrings("abc", job.body);
    try testing.expectEqualStrings("X-End: one\r\nx-end: two\r\n\r\n", job.trailers);
}

test "v2 ingress trailer capacity includes the final CRLF and cannot spill into response" {
    for ([_]u32{ 1, 2, 3 }) |trailer_bytes| {
        var table: RequestTable = try .init(testing.allocator, .{
            .requests = 1,
            .head_bytes = 256,
            .body_bytes = 64,
            .trailer_bytes = trailer_bytes,
            .response_bytes = 8,
        });
        defer table.deinit(testing.allocator);
        const request = table.acquire().?;
        try table.reserve(request);
        defer {
            table.disconnect(request) catch unreachable;
            table.cancelReservation(request) catch unreachable;
        }
        var fields: [16]RequestHead.Field = undefined;
        var line: [128]u8 = undefined;
        var trailer_fields: [8]RequestHead.Field = undefined;
        const storage: Storage = .{ .head_fields = &fields, .line = &line, .trailer_fields = &trailer_fields };
        const buffers = try table.ingressBuffers(request);
        @memset(buffers.response, 'r');
        if (trailer_bytes == 1) {
            try testing.expectError(error.InvalidCapacity, Self.init(&table, request, HEAD, storage, limits()));
        } else {
            var ingress = try Self.init(&table, request, HEAD, storage, limits());
            if (trailer_bytes == 2) {
                try testing.expectEqual(.done, (try ingress.feed("0\r\n\r\n")).status);
                try testing.expectEqualStrings("\r\n", (try ingress.trailers()).bytes);
            } else {
                try testing.expectError(error.TrailersTooLarge, ingress.feed("0\r\nX: y\r\n\r\n"));
                try testing.expectError(error.IncompleteBody, ingress.input(.{ .nanoseconds = 1 }));
            }
        }
        for (buffers.response) |byte| try testing.expectEqual(@as(u8, 'r'), byte);
    }
}
