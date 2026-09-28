//! Bounded incremental head boundary detection; validation must precede admission.
//! Borrow fresh bytes from connection storage. Never consume body/read-ahead bytes.
const Self = @This();

const std = @import("std");

parser: std.http.HeadParser = .{},
length: u32 = 0,
limit: u32,

pub const Result = struct {
    consumed: u32,
    head_len: ?u32,
};

/// Includes the terminating empty line in the head-byte limit.
pub fn init(limit: u32) !Self {
    if (limit == 0) return error.InvalidCapacity;
    return .{ .limit = limit };
}

/// Feed only newly received bytes, once. A boundary is not proof of valid HTTP;
/// std also recognizes LF-only delimiters. Keep all head bytes for validation.
pub fn feed(self: *Self, bytes: []const u8) !Result {
    if (self.parser.state == .finished or self.length == self.limit) return error.InvalidTransition;
    const available = @min(bytes.len, self.limit - self.length);
    const consumed: u32 = @intCast(self.parser.feed(bytes[0..available]));
    self.length += consumed;
    if (self.parser.state == .finished) return .{ .consumed = consumed, .head_len = self.length };
    if (self.length == self.limit) return error.HeadTooLarge;
    return .{ .consumed = consumed, .head_len = null };
}

/// Start another head with the same cap. This does not release borrowed storage.
pub fn reset(self: *Self) void {
    self.parser = .{};
    self.length = 0;
}

const HEAD = "POST /v1/logs?x=1 HTTP/1.1\r\nHost: edge\r\nContent-Length: 3\r\n\r\n";
const TAIL = "abcGET /next HTTP/1.1\r\nHost: edge\r\n\r\n";

test "v2 head scanner preserves body and next request at every split" {
    const wire = HEAD ++ TAIL;
    for (0..wire.len + 1) |split| {
        var scanner: Self = try .init(HEAD.len);
        const first = try scanner.feed(wire[0..split]);
        try std.testing.expectEqual(@min(split, HEAD.len), first.consumed);
        if (split < HEAD.len) {
            try std.testing.expectEqual(null, first.head_len);
            const second = try scanner.feed(wire[split..]);
            try std.testing.expectEqual(HEAD.len - split, second.consumed);
            try std.testing.expectEqual(HEAD.len, second.head_len.?);
            try std.testing.expectEqualStrings(TAIL, wire[split + second.consumed ..]);
        } else {
            try std.testing.expectEqual(HEAD.len, first.head_len.?);
            try std.testing.expectEqualStrings(TAIL, wire[first.consumed..]);
        }
    }
}

test "v2 head scanner advances one byte at a time without rescanning" {
    var scanner: Self = try .init(HEAD.len);
    for (HEAD, 0..) |_, index| {
        const empty = try scanner.feed("");
        try std.testing.expectEqual(0, empty.consumed);
        try std.testing.expectEqual(null, empty.head_len);
        const result = try scanner.feed(HEAD[index..][0..1]);
        try std.testing.expectEqual(1, result.consumed);
        if (index + 1 == HEAD.len) {
            try std.testing.expectEqual(HEAD.len, result.head_len.?);
        } else {
            try std.testing.expectEqual(null, result.head_len);
        }
    }
}

test "v2 head scanner enforces capacity on unterminated and oversized heads" {
    try std.testing.expectError(error.InvalidCapacity, Self.init(0));
    var scanner: Self = try .init(HEAD.len - 1);
    try std.testing.expectError(error.HeadTooLarge, scanner.feed(HEAD ++ TAIL));
    scanner.reset();
    _ = try scanner.feed(HEAD[0 .. HEAD.len - 2]);
    try std.testing.expectError(error.HeadTooLarge, scanner.feed(HEAD[HEAD.len - 2 ..]));
    var tiny: Self = try .init(4);
    try std.testing.expectError(error.HeadTooLarge, tiny.feed("GET "));
}

test "v2 head scanner requires reset after completion or capacity failure" {
    var scanner: Self = try .init(HEAD.len);
    _ = try scanner.feed(HEAD);
    try std.testing.expectError(error.InvalidTransition, scanner.feed(TAIL));
    scanner.reset();
    const again = try scanner.feed(HEAD ++ TAIL);
    try std.testing.expectEqual(HEAD.len, again.head_len.?);
    var tiny: Self = try .init(1);
    try std.testing.expectError(error.HeadTooLarge, tiny.feed("G"));
    try std.testing.expectError(error.InvalidTransition, tiny.feed(""));
}

test "v2 head scanner delimiter recognition does not validate HTTP syntax" {
    var scanner: Self = try .init(64);
    const malformed = "x\n\n";
    const result = try scanner.feed(malformed);
    try std.testing.expectEqual(malformed.len, result.head_len.?);
    try std.testing.expectEqual(malformed.len, result.consumed);
    // The later head validator must reject this; scanner completion cannot grant
    // queue/body credit, emit Continue, or authorize forwarding by itself.
}

test "v2 head scanner finds CRLF boundaries at different vector alignments" {
    const prefix = "GET / HTTP/1.1\r\nX-Padding: ";
    var wire: [256]u8 = undefined;
    @memcpy(wire[0..prefix.len], prefix);
    for (0..129) |padding| {
        const end = prefix.len + padding;
        @memset(wire[prefix.len..end], 'x');
        @memcpy(wire[end..][0..4], "\r\n\r\n");
        @memcpy(wire[end + 4 ..][0..TAIL.len], TAIL);
        const head_len = end + 4;
        const wire_len = head_len + TAIL.len;
        for (0..head_len + 1) |split| {
            var scanner: Self = try .init(wire.len);
            const first = try scanner.feed(wire[0..split]);
            if (first.head_len) |length| {
                try std.testing.expectEqual(head_len, length);
            } else {
                const second = try scanner.feed(wire[split..wire_len]);
                try std.testing.expectEqual(head_len, second.head_len.?);
                try std.testing.expectEqualStrings(TAIL, wire[split + second.consumed .. wire_len]);
            }
        }
    }
}
