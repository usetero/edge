//! Bounded request-body transfer framing. Outputs are provisional until done;
//! malformed framing is a transport failure, never a reason to forward a prefix.
const Self = @This();

const std = @import("std");
const RequestHead = @import("RequestHead.zig");
const http_field = @import("http_field.zig");
const HeadScanner = @import("HeadScanner.zig");

line: []u8,
trailer_bytes: []u8,
trailer_fields: []RequestHead.Field,
limits: Limits,
state: State,
remaining: u64 = 0,
body_len: u64 = 0,
metadata_used: u32 = 0,
line_len: u32 = 0,
trailer_len: u32 = 0,
trailer_start: u32 = 0,
trailer_count: u16 = 0,

pub const Limits = struct { body_bytes: u64, metadata_bytes: u32 = 64 * 1024 };
pub const Storage = struct { line: []u8, trailers: []u8, fields: []RequestHead.Field };
pub const State = enum { fixed, chunk_line, chunk_data, data_cr, data_lf, trailer_line, done, failed };
pub const Status = enum { need_input, output_full, done };
pub const Result = struct { consumed: usize, written: usize, status: Status };
pub const Trailers = struct { bytes: []const u8, fields: []const RequestHead.Field };

/// Storage is borrowed for the entire message and must be mutually disjoint.
/// Construct in its final owner: do not move an owner containing these buffers.
pub fn init(framing: RequestHead.Framing, storage: Storage, limits: Limits) !Self {
    if (storage.line.len > std.math.maxInt(u32) or storage.trailers.len > std.math.maxInt(u32) or
        storage.fields.len > std.math.maxInt(u16)) return error.InvalidCapacity;
    var self: Self = .{
        .line = storage.line,
        .trailer_bytes = storage.trailers,
        .trailer_fields = storage.fields,
        .limits = limits,
        .state = .done,
    };
    switch (framing) {
        .none => {},
        .content_length => |length| {
            if (length > limits.body_bytes) return error.BodyTooLarge;
            self.remaining = length;
            if (length > 0) self.state = .fixed;
        },
        .chunked => {
            // Even an empty chunked body needs a size line and final empty line.
            if (storage.line.len < 3 or storage.trailers.len < 2 or
                limits.metadata_bytes < 5) return error.InvalidCapacity;
            self.state = .chunk_line;
        },
    }
    return self;
}

/// Input/output must not overlap each other or borrowed metadata storage. Input
/// is never mutated. Feed only the unconsumed suffix on retry. Bound input.len at
/// the reactor turn boundary; work is linear in supplied bytes, with no IO.
pub fn feed(self: *Self, input: []const u8, output: []u8) !Result {
    if (self.state == .failed) return error.InvalidState;
    errdefer self.state = .failed;
    var consumed: usize = 0;
    var written: usize = 0;
    while (true) {
        if (self.state == .done) return .{ .consumed = consumed, .written = written, .status = .done };
        if (consumed == input.len) return .{ .consumed = consumed, .written = written, .status = .need_input };
        switch (self.state) {
            .fixed, .chunk_data => {
                if (written == output.len) return .{ .consumed = consumed, .written = written, .status = .output_full };
                const count: usize = @intCast(@min(input.len - consumed, output.len - written, self.remaining));
                @memcpy(output[written..][0..count], input[consumed..][0..count]);
                consumed += count;
                written += count;
                self.remaining -= count;
                self.body_len += count;
                if (self.remaining == 0) self.state = if (self.state == .fixed) .done else .data_cr;
            },
            .chunk_line, .data_cr, .data_lf, .trailer_line => {
                if (self.metadata_used == self.limits.metadata_bytes) return error.MetadataTooLarge;
                self.metadata_used += 1;
                try self.metadataByte(input[consumed]);
                consumed += 1;
            },
            .done, .failed => unreachable,
        }
    }
}

/// Call on transport EOF. Success means a complete body, including all trailers.
pub fn finish(self: *Self) !void {
    if (self.state == .failed) return error.InvalidState;
    if (self.state == .done) return;
    self.state = .failed;
    return error.UnexpectedEndOfStream;
}

/// Only completed messages expose trailers for later semantic checks/rewriting.
/// These fields are never merged into the original head by the framer.
pub fn trailers(self: *const Self) Trailers {
    std.debug.assert(self.state == .done);
    return .{ .bytes = self.trailer_bytes[0..self.trailer_len], .fields = self.trailer_fields[0..self.trailer_count] };
}

fn metadataByte(self: *Self, byte: u8) !void {
    switch (self.state) {
        .chunk_line => {
            if (!try appendLine(self.line, &self.line_len, 0, byte)) return;
            const size = try chunkSize(self.line[0 .. self.line_len - 2]);
            if (size > self.limits.body_bytes - self.body_len) return error.BodyTooLarge;
            self.line_len = 0;
            self.remaining = size;
            self.state = if (size == 0) .trailer_line else .chunk_data;
        },
        .data_cr => {
            if (byte != '\r') return error.InvalidChunkTerminator;
            self.state = .data_lf;
        },
        .data_lf => {
            if (byte != '\n') return error.InvalidChunkTerminator;
            self.state = .chunk_line;
        },
        .trailer_line => try self.trailerByte(byte),
        else => unreachable,
    }
}

fn trailerByte(self: *Self, byte: u8) !void {
    if (self.trailer_len == self.trailer_bytes.len) return error.TrailersTooLarge;
    if (!try appendLine(self.trailer_bytes, &self.trailer_len, self.trailer_start, byte)) return;
    const length = self.trailer_len - self.trailer_start - 2;
    if (length == 0) {
        self.state = .done;
        return;
    }
    if (self.trailer_count == self.trailer_fields.len) return error.TooManyTrailers;
    const field = try http_field.parse(self.trailer_bytes, .{ .start = self.trailer_start, .len = length });
    if (http_field.forbiddenTrailer(field.name.slice(self.trailer_bytes))) return error.ForbiddenTrailer;
    self.trailer_fields[self.trailer_count] = field;
    self.trailer_count += 1;
    self.trailer_start = self.trailer_len;
}

fn appendLine(buffer: []u8, length: *u32, start: u32, byte: u8) !bool {
    if (length.* == buffer.len) return error.LineTooLarge;
    const count = length.* - start;
    if (count > 0 and buffer[length.* - 1] == '\r' and byte != '\n') return error.InvalidLineEnding;
    if (byte == '\n' and (count == 0 or buffer[length.* - 1] != '\r')) return error.InvalidLineEnding;
    buffer[length.*] = byte;
    length.* += 1;
    return byte == '\n';
}

fn chunkSize(line: []const u8) !u64 {
    var cursor: usize = 0;
    var value: u64 = 0;
    while (cursor < line.len and std.ascii.isHex(line[cursor])) : (cursor += 1) {
        const byte = line[cursor];
        const digit: u64 = if (byte <= '9') byte - '0' else (byte | 0x20) - 'a' + 10;
        const scaled = @mulWithOverflow(value, 16);
        const added = @addWithOverflow(scaled[0], digit);
        if (scaled[1] != 0 or added[1] != 0) return error.InvalidChunkLine;
        value = added[0];
    }
    if (cursor == 0) return error.InvalidChunkLine;
    try extensions(line, cursor);
    return value;
}

fn extensions(line: []const u8, start: usize) !void {
    var cursor = start;
    while (cursor < line.len) {
        skipWhitespace(line, &cursor);
        if (cursor == line.len or line[cursor] != ';') return error.InvalidChunkLine;
        cursor += 1;
        skipWhitespace(line, &cursor);
        try token(line, &cursor);
        const name_end = cursor;
        skipWhitespace(line, &cursor);
        if (cursor < line.len and line[cursor] == '=') {
            cursor += 1;
            skipWhitespace(line, &cursor);
            if (cursor < line.len and line[cursor] == '"') {
                try quoted(line, &cursor);
            } else {
                try token(line, &cursor);
            }
        } else {
            // BWS belongs to a following semicolon or equals, not a bare suffix.
            cursor = name_end;
        }
    }
}

fn skipWhitespace(bytes: []const u8, cursor: *usize) void {
    while (cursor.* < bytes.len and (bytes[cursor.*] == ' ' or bytes[cursor.*] == '\t')) cursor.* += 1;
}

fn token(bytes: []const u8, cursor: *usize) !void {
    const start = cursor.*;
    while (cursor.* < bytes.len and http_field.validToken(bytes[cursor.*..][0..1])) cursor.* += 1;
    if (cursor.* == start) return error.InvalidChunkLine;
}

fn quoted(bytes: []const u8, cursor: *usize) !void {
    cursor.* += 1;
    while (cursor.* < bytes.len) {
        const byte = bytes[cursor.*];
        cursor.* += 1;
        if (byte == '"') return;
        if (byte == '\\') {
            if (cursor.* == bytes.len) return error.InvalidChunkLine;
            const escaped = bytes[cursor.*];
            if ((escaped < 0x20 and escaped != '\t') or escaped == 0x7f) return error.InvalidChunkLine;
            cursor.* += 1;
        } else if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidChunkLine;
    }
    return error.InvalidChunkLine;
}

const testing = std.testing;
const NEXT = "GET /next HTTP/1.1\r\nHost: edge\r\n\r\n";
const CHUNKED = "3;tag=one\r\na\x00b\r\n2;tag=\"x\\\"y\"\r\n\xffz\r\n0\r\nX-End: one\r\nx-end: two\r\n\r\n";

const Fixture = struct {
    line: [128]u8 = undefined,
    bytes: [256]u8 = undefined,
    fields: [8]RequestHead.Field = undefined,
    body: [128]u8 = undefined,
    framer: Self = undefined,

    fn init(self: *Fixture, framing: RequestHead.Framing, limits: Limits) !void {
        const storage: Storage = .{ .line = &self.line, .trailers = &self.bytes, .fields = &self.fields };
        self.framer = try .init(framing, storage, limits);
    }
};

test "v2 body framing preserves entity bytes trailers and read ahead at every split" {
    const wire = CHUNKED ++ NEXT;
    for (0..wire.len + 1) |split| {
        var fixture: Fixture = .{};
        try fixture.init(.chunked, .{ .body_bytes = 5 });
        const first = try fixture.framer.feed(wire[0..split], &fixture.body);
        var consumed = first.consumed;
        var written = first.written;
        if (first.status != .done) {
            const second = try fixture.framer.feed(wire[split..], fixture.body[written..]);
            try testing.expectEqual(.done, second.status);
            consumed += second.consumed;
            written += second.written;
        }
        try testing.expectEqual(CHUNKED.len, consumed);
        try testing.expectEqualStrings("a\x00b\xffz", fixture.body[0..written]);
        try testing.expectEqualStrings(NEXT, wire[consumed..]);
        try fixture.framer.finish();
        const view = fixture.framer.trailers();
        try testing.expectEqual(2, view.fields.len);
        try testing.expectEqualStrings("X-End: one\r\nx-end: two\r\n\r\n", view.bytes);
        try testing.expectEqualStrings("x-end", view.fields[1].name.slice(view.bytes));
        try testing.expectEqualStrings("two", view.fields[1].value.slice(view.bytes));
    }
}

test "v2 body framing fixed length and empty bodies never consume the next request" {
    const empty_cases: [2]RequestHead.Framing = .{ .none, .{ .content_length = 0 } };
    inline for (empty_cases) |framing| {
        const storage: Storage = .{ .line = &.{}, .trailers = &.{}, .fields = &.{} };
        var framer: Self = try .init(framing, storage, .{ .body_bytes = 0 });
        const result = try framer.feed(NEXT, &.{});
        try testing.expectEqual(.done, result.status);
        try testing.expectEqual(0, result.consumed);
        try framer.finish();
    }
    const wire = "abcde" ++ NEXT;
    for (0..wire.len + 1) |split| {
        var fixture: Fixture = .{};
        try fixture.init(.{ .content_length = 5 }, .{ .body_bytes = 5 });
        const first = try fixture.framer.feed(wire[0..split], &fixture.body);
        var consumed = first.consumed;
        var written = first.written;
        if (first.status != .done) {
            const second = try fixture.framer.feed(wire[split..], fixture.body[written..]);
            try testing.expectEqual(.done, second.status);
            consumed += second.consumed;
            written += second.written;
        }
        try testing.expectEqual(5, consumed);
        try testing.expectEqualStrings("abcde", fixture.body[0..written]);
    }
}

test "v2 body framing output backpressure never discards unconsumed body bytes" {
    var fixture: Fixture = .{};
    try fixture.init(.chunked, .{ .body_bytes = 5 });
    const blocked = try fixture.framer.feed(CHUNKED, &.{});
    try testing.expectEqual(.output_full, blocked.status);
    try testing.expectEqual(0, blocked.written);
    var consumed = blocked.consumed;
    var written: usize = 0;
    while (fixture.framer.state != .done) {
        const result = try fixture.framer.feed(CHUNKED[consumed..], fixture.body[written..][0..1]);
        try testing.expect(result.consumed > 0);
        consumed += result.consumed;
        written += result.written;
    }
    try testing.expectEqual(CHUNKED.len, consumed);
    try testing.expectEqualStrings("a\x00b\xffz", fixture.body[0..written]);
    const done = try fixture.framer.feed(NEXT, &.{});
    try testing.expectEqual(0, done.consumed);
    try testing.expectEqual(.done, done.status);
}

test "v2 body framing survives one byte input and empty feed calls" {
    var fixture: Fixture = .{};
    try fixture.init(.chunked, .{ .body_bytes = 5 });
    var written: usize = 0;
    for (CHUNKED, 0..) |_, index| {
        const empty = try fixture.framer.feed("", fixture.body[written..]);
        try testing.expectEqual(.need_input, empty.status);
        const result = try fixture.framer.feed(CHUNKED[index..][0..1], fixture.body[written..]);
        try testing.expectEqual(1, result.consumed);
        written += result.written;
    }
    try fixture.framer.finish();
    try testing.expectEqualStrings("a\x00b\xffz", fixture.body[0..written]);
}

test "v2 body framing detects every truncated chunked prefix and fences errors" {
    for (0..CHUNKED.len) |end| {
        var fixture: Fixture = .{};
        try fixture.init(.chunked, .{ .body_bytes = 5 });
        _ = try fixture.framer.feed(CHUNKED[0..end], &fixture.body);
        try testing.expectError(error.UnexpectedEndOfStream, fixture.framer.finish());
        try testing.expectError(error.InvalidState, fixture.framer.feed(CHUNKED[end..], &fixture.body));
    }
    var fixture: Fixture = .{};
    try fixture.init(.{ .content_length = 5 }, .{ .body_bytes = 5 });
    _ = try fixture.framer.feed("abc", &fixture.body);
    try testing.expectError(error.UnexpectedEndOfStream, fixture.framer.finish());
}

test "v2 body framing validates chunk extensions and checked hexadecimal lengths" {
    const good = "000a \t; flag ; key = \"a;=\\\"\\\\z\";empty=\"\"\r\n0123456789\r\n0;last=yes\r\n\r\n";
    var fixture: Fixture = .{};
    try fixture.init(.chunked, .{ .body_bytes = 10 });
    const result = try fixture.framer.feed(good, &fixture.body);
    try testing.expectEqual(.done, result.status);
    try testing.expectEqualStrings("0123456789", fixture.body[0..result.written]);
    const invalid = .{
        "",   "-1",   "+1",   "0x1",     "1_0",        "g",            " 1", "1 ", "10000000000000000",
        "1;", "1;=v", "1;a=", "1;a=\"x", "1;a=\"x\"z", "1;a=\"\x00\"",
    };
    inline for (invalid) |line| {
        try fixture.init(.chunked, .{ .body_bytes = std.math.maxInt(u64) });
        try testing.expectError(error.InvalidChunkLine, fixture.framer.feed(line ++ "\r\n", &fixture.body));
        try testing.expectError(error.InvalidState, fixture.framer.finish());
    }
}

test "v2 body framing enforces body and cumulative metadata budgets" {
    var fixture: Fixture = .{};
    try testing.expectError(error.BodyTooLarge, fixture.init(.{ .content_length = 6 }, .{ .body_bytes = 5 }));
    try fixture.init(.chunked, .{ .body_bytes = 4 });
    try testing.expectError(error.BodyTooLarge, fixture.framer.feed(CHUNKED, &fixture.body));
    try fixture.init(.chunked, .{ .body_bytes = 0, .metadata_bytes = 5 });
    try testing.expectEqual(.done, (try fixture.framer.feed("0\r\n\r\n" ++ NEXT, &.{})).status);
    try fixture.init(.chunked, .{ .body_bytes = 1, .metadata_bytes = 5 });
    try testing.expectError(error.MetadataTooLarge, fixture.framer.feed("1\r\nx\r\n0\r\n\r\n", &fixture.body));
    try testing.expect(@sizeOf(Self) <= 256);
}

test "v2 body framing rejects malformed CRLF and trailer field syntax" {
    const invalid = .{
        "1\nx\r\n0\r\n\r\n",    "1\rX",               "1\r\nxX",            "1\r\nx\rX",
        "0\r\nX: v\n\n",        "0\r\nX : v\r\n\r\n", "0\r\n X: v\r\n\r\n", "0\r\nX: a\x7fb\r\n\r\n",
        "0\r\nX: a\rb\r\n\r\n",
    };
    inline for (invalid) |wire| {
        var fixture: Fixture = .{};
        try fixture.init(.chunked, .{ .body_bytes = 5 });
        if (fixture.framer.feed(wire, &fixture.body)) |_| return error.MalformedBodyAccepted else |_| {}
        try testing.expectEqual(.failed, fixture.framer.state);
    }
}

test "v2 body framing refuses critical trailers without merging them into headers" {
    const critical = .{
        "Content-Length", "transfer-encoding", "Host",         "Connection",    "Trailer", "TE",
        "Upgrade",        "Content-Encoding",  "Content-Type", "Authorization", "Expect",
    };
    inline for (critical) |name| {
        var fixture: Fixture = .{};
        try fixture.init(.chunked, .{ .body_bytes = 0 });
        try testing.expectError(
            error.ForbiddenTrailer,
            fixture.framer.feed("0\r\n" ++ name ++ ": x\r\n\r\n", &fixture.body),
        );
    }
}

test "v2 body framing exact line trailer and descriptor capacities" {
    var fixture: Fixture = .{};
    const storage: Storage = .{
        .line = fixture.line[0..3],
        .trailers = fixture.bytes[0..8],
        .fields = fixture.fields[0..1],
    };
    fixture.framer = try .init(.chunked, storage, .{ .body_bytes = 0, .metadata_bytes = 11 });
    try testing.expectEqual(.done, (try fixture.framer.feed("0\r\nX: a\r\n\r\n", &.{})).status);
    try testing.expectEqual(11, fixture.framer.metadata_used);
    var copied: [8]u8 = undefined;
    @memcpy(&copied, fixture.framer.trailers().bytes);
    try testing.expectEqualStrings("a", fixture.framer.trailers().fields[0].value.slice(&copied));

    fixture.framer = try .init(.chunked, storage, .{ .body_bytes = 0 });
    try testing.expectError(error.LineTooLarge, fixture.framer.feed("00\r\n\r\n", &.{}));
    var smaller = storage;
    smaller.trailers = fixture.bytes[0..7];
    fixture.framer = try .init(.chunked, smaller, .{ .body_bytes = 0 });
    try testing.expectError(error.TrailersTooLarge, fixture.framer.feed("0\r\nX: a\r\n\r\n", &.{}));
    smaller = storage;
    smaller.trailers = &fixture.bytes;
    fixture.framer = try .init(.chunked, smaller, .{ .body_bytes = 0 });
    try testing.expectError(error.TooManyTrailers, fixture.framer.feed("0\r\nX: a\r\nX: b\r\n\r\n", &.{}));
    smaller.fields = &.{};
    fixture.framer = try .init(.chunked, smaller, .{ .body_bytes = 0 });
    try testing.expectEqual(.done, (try fixture.framer.feed("0\r\n\r\n", &.{})).status);

    try testing.expectError(
        error.InvalidCapacity,
        Self.init(.chunked, storage, .{ .body_bytes = 0, .metadata_bytes = 4 }),
    );
    smaller.line = fixture.line[0..2];
    try testing.expectError(error.InvalidCapacity, Self.init(.chunked, smaller, .{ .body_bytes = 0 }));
    smaller.line = storage.line;
    smaller.trailers = fixture.bytes[0..1];
    try testing.expectError(error.InvalidCapacity, Self.init(.chunked, smaller, .{ .body_bytes = 0 }));
}

test "v2 body framing small independent input and output windows make progress" {
    for (1..18) |input_size| {
        for (1..8) |output_size| {
            var fixture: Fixture = .{};
            try fixture.init(.chunked, .{ .body_bytes = 5 });
            var consumed: usize = 0;
            var written: usize = 0;
            while (fixture.framer.state != .done) {
                const end = @min(consumed + input_size, CHUNKED.len);
                const result = try fixture.framer.feed(CHUNKED[consumed..end], fixture.body[written..][0..output_size]);
                try testing.expect(result.consumed > 0);
                consumed += result.consumed;
                written += result.written;
            }
            try testing.expectEqual(CHUNKED.len, consumed);
            try testing.expectEqualStrings("a\x00b\xffz", fixture.body[0..written]);
        }
    }
    var fixture: Fixture = .{};
    try fixture.init(.{ .content_length = 5 }, .{ .body_bytes = 5 });
    try testing.expectEqual(.output_full, (try fixture.framer.feed("abcde", &.{})).status);
    try testing.expectEqual(0, fixture.framer.body_len);
    try testing.expectEqual(.done, (try fixture.framer.feed("abcde", fixture.body[0..5])).status);
}

test "v2 body framing accepts u64 chunk length without allocating it" {
    var fixture: Fixture = .{};
    try fixture.init(.chunked, .{ .body_bytes = std.math.maxInt(u64) });
    const result = try fixture.framer.feed("ffffffffffffffff\r\n", &.{});
    try testing.expectEqual(.need_input, result.status);
    try testing.expectEqual(std.math.maxInt(u64), fixture.framer.remaining);
    try testing.expectEqual(0, fixture.framer.body_len);
    try testing.expectError(error.UnexpectedEndOfStream, fixture.framer.finish());
}

test "v2 complete request framing composes across every wire split" {
    const head_wire = "POST /v1/logs HTTP/1.1\r\nHost: edge\r\n" ++
        "Transfer-Encoding: chunked\r\nContent-Encoding: future\r\n\r\n";
    const wire = head_wire ++ CHUNKED ++ NEXT;
    for (0..wire.len + 1) |split| {
        var scanner: HeadScanner = try .init(256);
        var head_bytes: [256]u8 = undefined;
        var fields: [8]RequestHead.Field = undefined;
        var fixture: Fixture = .{};
        var head_done = false;
        var consumed: usize = 0;
        var written: usize = 0;
        for ([_][]const u8{ wire[0..split], wire[split..] }) |part| {
            var offset: usize = 0;
            if (!head_done) {
                const start = scanner.length;
                const result = try scanner.feed(part);
                @memcpy(head_bytes[start..][0..result.consumed], part[0..result.consumed]);
                offset = result.consumed;
                if (result.head_len) |len| {
                    const head = try RequestHead.parse(head_bytes[0..len], &fields, .{});
                    try fixture.init(head.framing, .{ .body_bytes = 5 });
                    head_done = true;
                }
            }
            if (head_done) {
                const result = try fixture.framer.feed(part[offset..], fixture.body[written..]);
                offset += result.consumed;
                written += result.written;
            }
            consumed += offset;
        }
        try testing.expect(head_done);
        try fixture.framer.finish();
        try testing.expectEqualStrings("a\x00b\xffz", fixture.body[0..written]);
        try testing.expectEqualStrings(NEXT, wire[consumed..]);
        try testing.expectEqualStrings("future", fields[2].value.slice(&head_bytes));
    }
}
