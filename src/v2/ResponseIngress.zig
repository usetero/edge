//! Bounded buffered upstream reception. Incomplete data never becomes a response.
const Self = @This();

const std = @import("std");
const BodyFramer = @import("BodyFramer.zig");
const HeadScanner = @import("HeadScanner.zig");
const RequestHead = @import("RequestHead.zig");
const ResponseHead = @import("ResponseHead.zig");
const http_field = @import("http_field.zig");

storage: Storage,
limits: Limits,
method: ResponseHead.Method,
scanner: HeadScanner,
state: enum { head, informational, body, done, failed } = .head,
head: ResponseHead = undefined,
framer: ?BodyFramer = null,
body_len: usize = 0,
head_bytes_total: u32 = 0,
informational_count: u16 = 0,
reusable: bool = true,

pub const Storage = struct {
    head: []u8,
    body: []u8,
    fields: []http_field.Field,
    line: []u8,
    trailers: []u8,
    trailer_fields: []http_field.Field,
};
pub const Limits = struct {
    head_bytes: u32 = 16 * 1024,
    total_head_bytes: u32 = 64 * 1024,
    informational_heads: u16 = 8,
    body_bytes: u32,
    body_metadata_bytes: u32 = 64 * 1024,
};
pub const Result = struct { consumed: usize, status: enum { need_input, informational, done } };
pub const End = enum { clean_eof, transport_failure };
pub const HeadView = struct { bytes: []const u8, fields: []const http_field.Field, metadata: ResponseHead };
pub const Message = struct {
    changed: bool = false,
    external_body_len: ?u64 = null,
    head: HeadView,
    body: []const u8,
    trailers: BodyFramer.Trailers,
    /// A framing precondition, not pool authorization. The owner must also check
    /// request completion, deadlines, transport health and unexpected read-ahead.
    reusable: bool,
};

/// Stores must remain live and mutually disjoint, including descriptor scratch.
/// Input to feed must not overlap them. Keep any containing owner at a stable address.
pub fn init(storage: Storage, method: ResponseHead.Method, limits: Limits) !Self {
    if (limits.total_head_bytes == 0 or storage.fields.len > std.math.maxInt(u16)) return error.InvalidCapacity;
    if (limits.head_bytes > storage.head.len or limits.body_bytes > storage.body.len) return error.StorageTooSmall;
    return .{ .storage = storage, .method = method, .limits = limits, .scanner = try .init(limits.head_bytes) };
}

/// Feed only unread bytes once. An informational event ends this call immediately;
/// consume/copy its view before the next feed, which reuses the bounded head store.
pub fn feed(self: *Self, bytes: []const u8) !Result {
    if (self.state == .failed) return error.InvalidState;
    errdefer self.fail();
    if (self.state == .informational) {
        self.scanner.reset();
        self.state = .head;
    }
    var consumed: usize = 0;
    if (self.state == .head) {
        consumed = try self.readHead(bytes);
        switch (self.state) {
            .head => return .{ .consumed = consumed, .status = .need_input },
            .informational => return .{ .consumed = consumed, .status = .informational },
            .body, .done => {},
            .failed => unreachable,
        }
    }
    if (self.state == .body) consumed += try self.readBody(bytes[consumed..]);
    return .{ .consumed = consumed, .status = if (self.state == .done) .done else .need_input };
}

/// Only the transport owner can establish clean EOF: timeout/cancellation, TLS
/// truncation, reset and watchdog shutdown must be reported as transport_failure.
pub fn finish(self: *Self, end: End) !void {
    if (self.state == .failed) return error.InvalidState;
    errdefer self.fail();
    self.reusable = false;
    if (end == .transport_failure) return error.TransportFailure;
    switch (self.state) {
        .head, .informational => return error.UnexpectedEndOfStream,
        .body => {
            if (self.framer) |*framer| try framer.finish();
            self.state = .done;
        },
        .done => {},
        .failed => unreachable,
    }
}

/// A borrowed 1xx event; never forward it without downstream header rewriting.
pub fn informational(self: *const Self) !HeadView {
    if (self.state == .failed) return error.InvalidState;
    if (self.state != .informational) return error.NoInformationalResponse;
    return self.headView();
}

/// Only a completely framed final response can cross the worker commit boundary.
/// Views remain borrowed; this component neither extends nor releases a queue lease.
pub fn message(self: *const Self) !Message {
    if (self.state == .failed) return error.InvalidState;
    if (self.state != .done) return error.IncompleteResponse;
    return .{
        .head = self.headView(),
        .body = self.storage.body[0..self.body_len],
        .trailers = if (self.framer) |*framer| framer.trailers() else .{ .bytes = "", .fields = &.{} },
        .reusable = self.reusable,
    };
}

fn readHead(self: *Self, bytes: []const u8) !usize {
    const available = self.limits.total_head_bytes - self.head_bytes_total;
    if (available == 0) return error.ResponseMetadataTooLarge;
    const start = self.scanner.length;
    const result = try self.scanner.feed(bytes[0..@min(bytes.len, available)]);
    @memcpy(self.storage.head[start..][0..result.consumed], bytes[0..result.consumed]);
    self.head_bytes_total += result.consumed;
    const length = result.head_len orelse {
        if (self.head_bytes_total == self.limits.total_head_bytes) return error.ResponseMetadataTooLarge;
        return result.consumed;
    };
    self.head = try ResponseHead.parse(
        self.storage.head[0..length],
        self.storage.fields,
        self.method,
        .{ .head_bytes = self.limits.head_bytes },
    );
    // A later final head cannot undo an interim Connection: close declaration.
    self.reusable = self.reusable and self.head.keep_alive;
    if (self.head.status < 200) {
        if (self.informational_count == self.limits.informational_heads) return error.TooManyInformationalResponses;
        self.informational_count += 1;
        self.state = .informational;
    } else try self.startBody();
    return result.consumed;
}

fn startBody(self: *Self) !void {
    self.state = .body;
    // 205 has ordinary HTTP framing but is forbidden from carrying content.
    const body_limit = if (self.head.status == 205) 0 else self.limits.body_bytes;
    const framing: RequestHead.Framing = switch (self.head.framing) {
        .none => .none,
        .content_length => |length| .{ .content_length = length },
        .chunked => .chunked,
        .close_delimited => return,
    };
    self.framer = try .init(framing, .{
        .line = self.storage.line,
        .trailers = self.storage.trailers,
        .fields = self.storage.trailer_fields,
    }, .{ .body_bytes = body_limit, .metadata_bytes = self.limits.body_metadata_bytes });
    if (self.framer.?.state == .done) self.state = .done;
}

fn readBody(self: *Self, bytes: []const u8) !usize {
    if (self.framer) |*framer| {
        const result = try framer.feed(bytes, self.storage.body[self.body_len..self.limits.body_bytes]);
        // Storage was reserved for the complete declared maximum at init.
        std.debug.assert(result.status != .output_full);
        self.body_len += result.written;
        if (result.status == .done) self.state = .done;
        return result.consumed;
    }
    std.debug.assert(self.head.framing == .close_delimited);
    const body_limit = if (self.head.status == 205) 0 else self.limits.body_bytes;
    if (bytes.len > body_limit - self.body_len) return error.BodyTooLarge;
    @memcpy(self.storage.body[self.body_len..][0..bytes.len], bytes);
    self.body_len += bytes.len;
    return bytes.len;
}

fn headView(self: *const Self) HeadView {
    return .{
        .bytes = self.storage.head[0..self.head.head_len],
        .fields = self.storage.fields[0..self.head.header_count],
        .metadata = self.head,
    };
}

fn fail(self: *Self) void {
    self.state = .failed;
    self.reusable = false;
}

const testing = std.testing;
const INFO = "HTTP/1.1 103 Early Hints\r\nLink: </style>\r\n\r\n";
const HEAD = "HTTP/1.1 200 OK\r\nContent-Encoding: alien\r\nTransfer-Encoding: chunked\r\n\r\n";
const BODY = "3\r\na\x00b\r\n2\r\n\xffz\r\n0\r\nX-End: one\r\nx-end: two\r\n\r\n";
const NEXT = "HTTP/1.1 204 Empty\r\n\r\n";

const Fixture = struct {
    head: [256]u8 = undefined,
    body: [64]u8 = undefined,
    fields: [16]http_field.Field = undefined,
    line: [64]u8 = undefined,
    trailers: [128]u8 = undefined,
    trailer_fields: [8]http_field.Field = undefined,

    fn storage(self: *Fixture) Storage {
        return .{
            .head = &self.head,
            .body = &self.body,
            .fields = &self.fields,
            .line = &self.line,
            .trailers = &self.trailers,
            .trailer_fields = &self.trailer_fields,
        };
    }
};

fn testLimits() Limits {
    return .{ .head_bytes = 256, .body_bytes = 64 };
}

fn consume(ingress: *Self, bytes: []const u8) !usize {
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const result = try ingress.feed(bytes[cursor..]);
        cursor += result.consumed;
        if (result.status == .informational) {
            const view = try ingress.informational();
            try testing.expectEqualStrings(INFO, view.bytes);
            try testing.expectEqual(103, view.metadata.status);
        }
        if (result.status == .done) break;
        try testing.expect(result.consumed != 0);
    }
    return cursor;
}

test "v2 response ingress preserves informational events and trailers across every split" {
    const wire = INFO ++ HEAD ++ BODY ++ NEXT;
    const response_len = INFO.len + HEAD.len + BODY.len;
    for (0..wire.len + 1) |split| {
        var fixture: Fixture = .{};
        var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
        try testing.expectError(error.IncompleteResponse, ingress.message());
        const first = try consume(&ingress, wire[0..split]);
        const second = if (first == split) try consume(&ingress, wire[split..]) else 0;
        try testing.expectEqual(response_len, first + second);
        const received = try ingress.message();
        try testing.expectEqualStrings(HEAD, received.head.bytes);
        try testing.expectEqualStrings("a\x00b\xffz", received.body);
        try testing.expectEqualStrings("X-End: one\r\nx-end: two\r\n\r\n", received.trailers.bytes);
        try testing.expect(received.reusable);
        try testing.expectEqual(@as(u16, 1), ingress.informational_count);
        try testing.expectEqual(0, (try ingress.feed(NEXT)).consumed);
    }
}

test "v2 response ingress waits for clean EOF on close delimited bodies" {
    var fixture: Fixture = .{};
    var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    _ = try ingress.feed("HTTP/1.1 200 OK\r\n\r\nabc");
    try testing.expectError(error.IncompleteResponse, ingress.message());
    try ingress.finish(.clean_eof);
    try testing.expectEqualStrings("abc", (try ingress.message()).body);
    try testing.expect(!(try ingress.message()).reusable);
    ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    _ = try ingress.feed("HTTP/1.1 200 OK\r\n\r\nabc");
    try testing.expectError(error.TransportFailure, ingress.finish(.transport_failure));
    try testing.expectError(error.InvalidState, ingress.message());
    try testing.expectError(error.InvalidState, ingress.finish(.clean_eof));
    try testing.expectError(error.InvalidState, ingress.feed("more"));
}

test "v2 response ingress rejects every truncated final response and fences malformed framing" {
    const wire = HEAD ++ BODY;
    for (0..wire.len) |prefix| {
        var fixture: Fixture = .{};
        var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
        _ = try ingress.feed(wire[0..prefix]);
        try testing.expectError(error.UnexpectedEndOfStream, ingress.finish(.clean_eof));
        try testing.expectError(error.InvalidState, ingress.message());
    }
    var fixture: Fixture = .{};
    var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    try testing.expectError(error.InvalidChunkTerminator, ingress.feed(HEAD ++ "3\r\nabcX"));
    try testing.expectError(error.InvalidState, ingress.feed(BODY));
    try testing.expectError(error.InvalidState, ingress.message());
}

test "v2 response ingress ignores HEAD representation length and preserves following bytes" {
    var fixture: Fixture = .{};
    var ingress = try Self.init(fixture.storage(), .head, testLimits());
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n";
    try testing.expectEqual(head.len, (try ingress.feed(head ++ NEXT)).consumed);
    try testing.expectEqualStrings("", (try ingress.message()).body);
    try testing.expectEqual(99999999, (try ingress.message()).head.metadata.content_length.?);
}

test "v2 response ingress bounds informational count and aggregate head work" {
    var fixture: Fixture = .{};
    var budget = testLimits();
    budget.informational_heads = 1;
    var ingress = try Self.init(fixture.storage(), .ordinary, budget);
    const result = try ingress.feed(INFO ++ INFO);
    try testing.expectEqual(INFO.len, result.consumed);
    try testing.expectEqual(.informational, result.status);
    try testing.expectEqualStrings(INFO, (try ingress.informational()).bytes);
    try testing.expectError(error.TooManyInformationalResponses, ingress.feed(INFO));
    try testing.expectError(error.InvalidState, ingress.message());
    budget = testLimits();
    budget.total_head_bytes = INFO.len + NEXT.len;
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    _ = try ingress.feed(INFO);
    try testing.expectEqual(.done, (try ingress.feed(NEXT)).status);
    budget.total_head_bytes -= 1;
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    _ = try ingress.feed(INFO);
    try testing.expectError(error.ResponseMetadataTooLarge, ingress.feed(NEXT));
}

test "v2 response ingress caps fixed chunked and close delimited entities" {
    var fixture: Fixture = .{};
    var budget = testLimits();
    budget.body_bytes = 3;
    const valid = [_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
        HEAD ++ "3\r\nabc\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\n\r\nabc",
    };
    for (valid) |wire| {
        var ingress = try Self.init(fixture.storage(), .ordinary, budget);
        _ = try ingress.feed(wire);
        try ingress.finish(.clean_eof);
        try testing.expectEqualStrings("abc", (try ingress.message()).body);
        try testing.expect(!(try ingress.message()).reusable);
    }
    const invalid = [_][]const u8{
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n",
        HEAD ++ "4\r\n",
        "HTTP/1.1 200 OK\r\n\r\nabcd",
    };
    for (invalid) |wire| {
        var ingress = try Self.init(fixture.storage(), .ordinary, budget);
        try testing.expectError(error.BodyTooLarge, ingress.feed(wire));
        try testing.expectError(error.InvalidState, ingress.message());
    }
    budget.body_bytes = 65;
    try testing.expectError(error.StorageTooSmall, Self.init(fixture.storage(), .ordinary, budget));
}

test "v2 response ingress bounds 205 content without skipping its framing" {
    var fixture: Fixture = .{};
    const cases = [_][]const u8{
        "HTTP/1.1 205 Reset\r\nContent-Length: 0\r\n\r\n",
        "HTTP/1.1 205 Reset\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 205 Reset\r\n\r\n",
    };
    for (cases) |wire| {
        var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
        for (wire, 0..) |_, offset| _ = try ingress.feed(wire[offset..][0..1]);
        try ingress.finish(.clean_eof);
        try testing.expectEqualStrings("", (try ingress.message()).body);
    }
    for ([_][]const u8{
        "HTTP/1.1 205 Reset\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        "HTTP/1.1 205 Reset\r\n\r\nx",
    }) |wire| {
        var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
        try testing.expectError(error.BodyTooLarge, ingress.feed(wire));
        try testing.expectError(error.InvalidState, ingress.message());
    }
}

test "v2 response ingress keeps interim close sticky and rejects interim only EOF" {
    var fixture: Fixture = .{};
    var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    const interim = "HTTP/1.1 100 Continue\r\nConnection: close\r\n\r\n";
    try testing.expectEqual(.informational, (try ingress.feed(interim ++ NEXT)).status);
    try testing.expectEqual(100, (try ingress.informational()).metadata.status);
    try testing.expectError(error.IncompleteResponse, ingress.message());
    try testing.expectEqual(.done, (try ingress.feed(NEXT)).status);
    try testing.expect(!(try ingress.message()).reusable);
    try testing.expectError(error.NoInformationalResponse, ingress.informational());
    ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    _ = try ingress.feed(INFO);
    try testing.expectError(error.UnexpectedEndOfStream, ingress.finish(.clean_eof));
    try testing.expectError(error.InvalidState, ingress.informational());
    var budget = testLimits();
    budget.informational_heads = 0;
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    try testing.expectEqual(.done, (try ingress.feed(NEXT)).status);
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    try testing.expectError(error.TooManyInformationalResponses, ingress.feed(INFO));
}

test "v2 response ingress fixed length detects EOF and copies bytes independently of read buffers" {
    const head = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n";
    const wire = head ++ "abc";
    for (0..wire.len) |prefix| {
        var fixture: Fixture = .{};
        var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
        _ = try ingress.feed(wire[0..prefix]);
        try testing.expectError(error.UnexpectedEndOfStream, ingress.finish(.clean_eof));
    }
    var fixture: Fixture = .{};
    var ingress = try Self.init(fixture.storage(), .ordinary, testLimits());
    var source: [wire.len]u8 = undefined;
    @memcpy(&source, wire);
    for (source, 0..) |_, offset| _ = try ingress.feed(source[offset..][0..1]);
    @memset(&source, 'x');
    try testing.expectEqualStrings(head, (try ingress.message()).head.bytes);
    try testing.expectEqualStrings("abc", (try ingress.message()).body);
    try testing.expect((try ingress.message()).reusable);
}

test "v2 response ingress enforces head field trailer and framing metadata capacities" {
    var fixture: Fixture = .{};
    var budget = testLimits();
    budget.head_bytes = NEXT.len;
    var storage = fixture.storage();
    storage.head = storage.head[0..NEXT.len];
    var ingress = try Self.init(storage, .ordinary, budget);
    try testing.expectEqual(.done, (try ingress.feed(NEXT)).status);
    budget.head_bytes -= 1;
    ingress = try Self.init(storage, .ordinary, budget);
    try testing.expectError(error.HeadTooLarge, ingress.feed(NEXT));
    storage = fixture.storage();
    storage.fields = storage.fields[0..1];
    ingress = try Self.init(storage, .ordinary, testLimits());
    try testing.expectError(error.TooManyHeaders, ingress.feed(HEAD));
    storage = fixture.storage();
    storage.trailers = storage.trailers[0..2];
    ingress = try Self.init(storage, .ordinary, testLimits());
    try testing.expectEqual(.done, (try ingress.feed(HEAD ++ "0\r\n\r\n")).status);
    ingress = try Self.init(storage, .ordinary, testLimits());
    try testing.expectError(error.TrailersTooLarge, ingress.feed(HEAD ++ "0\r\nX: y\r\n\r\n"));
    budget = testLimits();
    budget.body_metadata_bytes = 5;
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    try testing.expectEqual(.done, (try ingress.feed(HEAD ++ "0\r\n\r\n")).status);
    ingress = try Self.init(fixture.storage(), .ordinary, budget);
    try testing.expectError(error.MetadataTooLarge, ingress.feed(HEAD ++ "0;x\r\n\r\n"));
}
