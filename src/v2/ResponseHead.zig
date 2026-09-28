//! Strict upstream response metadata with offsets into one bounded complete head.
const Self = @This();

const std = @import("std");
const http_field = @import("http_field.zig");

head_len: u32,
version: std.http.Version,
status: u16,
reason: http_field.Span,
header_count: u16,
content_length: ?u64 = null,
framing: Framing,
keep_alive: bool,

pub const Framing = union(enum) { none, content_length: u64, chunked, close_delimited };
pub const Limits = struct { head_bytes: u32 = 16 * 1024 };
pub const Method = enum { ordinary, head, connect };

/// `bytes` must contain exactly one head. Descriptors borrow only offsets; this
/// never decodes content or grants permission to publish an incomplete body.
pub fn parse(bytes: []const u8, fields: []http_field.Field, method: Method, limits: Limits) !Self {
    if (limits.head_bytes == 0 or fields.len > std.math.maxInt(u16)) return error.InvalidCapacity;
    if (bytes.len > limits.head_bytes) return error.HeadTooLarge;
    var cursor: usize = 0;
    const line = try http_field.nextLine(bytes, &cursor);
    var head = try statusLine(bytes, line);
    var chunked = false;
    var close = false;
    while (true) {
        const field_line = try http_field.nextLine(bytes, &cursor);
        if (field_line.len == 0) {
            if (cursor != bytes.len) return error.TrailingData;
            break;
        }
        if (head.header_count == fields.len) return error.TooManyHeaders;
        const field = try http_field.parse(bytes, field_line);
        const name = field.name.slice(bytes);
        const value = field.value.slice(bytes);
        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            if (head.content_length != null) return error.DuplicateContentLength;
            head.content_length = try http_field.contentLength(value);
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (chunked) return error.DuplicateTransferEncoding;
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.InvalidTransferEncoding;
            chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            const field_close = try http_field.connectionClose(value);
            close = close or field_close;
        }
        fields[head.header_count] = field;
        head.header_count += 1;
    }
    head.framing = try bodyFraming(head, method, chunked);
    head.keep_alive = head.version == .@"HTTP/1.1" and !close and head.framing != .close_delimited;
    head.head_len = @intCast(bytes.len);
    return head;
}

fn statusLine(bytes: []const u8, line: http_field.Span) !Self {
    const raw = line.slice(bytes);
    if (raw.len < 13 or raw[8] != ' ' or raw[12] != ' ') return error.InvalidStatusLine;
    const version = std.meta.stringToEnum(std.http.Version, raw[0..8]) orelse return error.UnsupportedVersion;
    var status: u16 = 0;
    for (raw[9..12]) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidStatusLine;
        status = status * 10 + byte - '0';
    }
    if (status < 100 or status > 599) return error.InvalidStatusLine;
    for (raw[13..]) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return error.InvalidStatusLine;
    }
    return .{
        .head_len = 0,
        .version = version,
        .status = status,
        .reason = .{ .start = line.start + 13, .len = line.len - 13 },
        .header_count = 0,
        .framing = .none,
        .keep_alive = false,
    };
}

fn bodyFraming(head: Self, method: Method, chunked: bool) !Framing {
    if (head.status == 101) return error.UnsupportedUpgrade;
    if (method == .connect and head.status >= 200 and head.status < 300) return error.UnsupportedTunnel;
    if (chunked and head.content_length != null) return error.AmbiguousFraming;
    if (chunked and head.version == .@"HTTP/1.0") return error.InvalidTransferEncoding;
    if (head.status < 200 or head.status == 204) {
        if (chunked or head.content_length != null) return error.ForbiddenFraming;
        return .none;
    }
    if (head.status == 205 and (head.content_length orelse 0) != 0) return error.ForbiddenBody;
    if (method == .head or head.status == 304) return .none;
    if (chunked) return .chunked;
    if (head.content_length) |length| return .{ .content_length = length };
    return .close_delimited;
}

const testing = std.testing;

test "v2 response head preserves unknown status reason and opaque repeated metadata" {
    const bytes = "HTTP/1.1 299 Custom\t\xff\r\nContent-Length: 3\r\nContent-Encoding: alien\r\n" ++
        "Set-Cookie: a=1\r\nset-cookie: b=2\r\n\r\n";
    var fields: [8]http_field.Field = undefined;
    const head = try Self.parse(bytes, &fields, .ordinary, .{});
    try testing.expectEqual(299, head.status);
    try testing.expectEqualStrings("Custom\t\xff", head.reason.slice(bytes));
    const framing: Framing = .{ .content_length = 3 };
    try testing.expectEqualDeep(framing, head.framing);
    try testing.expect(head.keep_alive);
    try testing.expectEqual(4, head.header_count);
    var copied: [bytes.len]u8 = undefined;
    @memcpy(&copied, bytes);
    try testing.expectEqualStrings("alien", fields[1].value.slice(&copied));
    try testing.expectEqualStrings("Set-Cookie", fields[2].name.slice(&copied));
    try testing.expectEqualStrings("b=2", fields[3].value.slice(&copied));
}

test "v2 response head distinguishes declared representation length from absent bodies" {
    var fields: [8]http_field.Field = undefined;
    const cases = [_]struct { wire: []const u8, method: Method, length: ?u64 }{
        .{ .wire = "HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n", .method = .head, .length = 999999 },
        .{ .wire = "HTTP/1.1 304 Not Modified\r\nContent-Length: 99\r\n\r\n", .method = .ordinary, .length = 99 },
        .{ .wire = "HTTP/1.1 204 No Content\r\n\r\n", .method = .ordinary, .length = null },
        .{ .wire = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n", .method = .ordinary, .length = null },
        .{ .wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", .method = .head, .length = null },
    };
    for (cases) |case| {
        const head = try Self.parse(case.wire, &fields, case.method, .{});
        try testing.expectEqual(.none, head.framing);
        try testing.expectEqual(case.length, head.content_length);
    }
}

test "v2 response head rejects ambiguous lengths forbidden bodies and tunnel switches" {
    var fields: [8]http_field.Field = undefined;
    const cases = [_]struct { wire: []const u8, failure: anyerror }{
        .{
            .wire = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\n",
            .failure = error.DuplicateContentLength,
        },
        .{ .wire = "HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\n\r\n", .failure = error.InvalidContentLength },
        .{
            .wire = "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\n",
            .failure = error.InvalidContentLength,
        },
        .{
            .wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
            .failure = error.AmbiguousFraming,
        },
        .{
            .wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            .failure = error.InvalidTransferEncoding,
        },
        .{ .wire = "HTTP/1.1 204 Empty\r\nContent-Length: 0\r\n\r\n", .failure = error.ForbiddenFraming },
        .{ .wire = "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n", .failure = error.ForbiddenFraming },
        .{ .wire = "HTTP/1.1 205 Reset\r\nContent-Length: 1\r\n\r\n", .failure = error.ForbiddenBody },
        .{ .wire = "HTTP/1.1 101 Switching Protocols\r\n\r\n", .failure = error.UnsupportedUpgrade },
    };
    for (cases) |case| try testing.expectError(case.failure, Self.parse(case.wire, &fields, .ordinary, .{}));
    try testing.expectError(error.UnsupportedTunnel, Self.parse(
        "HTTP/1.1 200 Connected\r\n\r\n",
        &fields,
        .connect,
        .{},
    ));
    const failed_connect = try Self.parse("HTTP/1.1 407 Auth\r\nContent-Length: 0\r\n\r\n", &fields, .connect, .{});
    const framing: Framing = .{ .content_length = 0 };
    try testing.expectEqualDeep(framing, failed_connect.framing);
}

test "v2 response head validates status reason field syntax and exact boundaries" {
    var fields: [8]http_field.Field = undefined;
    for ([_][]const u8{
        "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 200OK\r\n\r\n",
        "HTTP/1.1 099 Bad\r\n\r\n",
        "HTTP/1.1 600 Bad\r\n\r\n",
        "HTTP/1.1 2x0 Bad\r\n\r\n",
        "HTTP/1.1 200 Bad\x00\r\n\r\n",
        "HTTP/1.1 200 OK\n\n",
        "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nBad : x\r\n\r\n",
        "HTTP/1.1 200 OK\r\nX: \x7f\r\n\r\n",
    }) |wire| {
        if (Self.parse(wire, &fields, .ordinary, .{})) |_| return error.InvalidResponseAccepted else |_| {}
    }
    const empty_reason = "HTTP/1.1 200 \r\n\r\n";
    _ = try Self.parse(empty_reason, fields[0..0], .ordinary, .{ .head_bytes = empty_reason.len });
    try testing.expectError(error.HeadTooLarge, Self.parse(
        empty_reason,
        &fields,
        .ordinary,
        .{ .head_bytes = empty_reason.len - 1 },
    ));
    try testing.expectError(error.TrailingData, Self.parse(empty_reason ++ "extra", &fields, .ordinary, .{}));
    try testing.expectError(error.TooManyHeaders, Self.parse(
        "HTTP/1.1 200 OK\r\nX: y\r\n\r\n",
        fields[0..0],
        .ordinary,
        .{},
    ));
}

test "v2 response head permits reuse only for persistent self delimited messages" {
    var fields: [8]http_field.Field = undefined;
    const cases = [_]struct { wire: []const u8, framing: Framing, persistent: bool }{
        .{ .wire = "HTTP/1.1 200 OK\r\n\r\n", .framing = .close_delimited, .persistent = false },
        .{
            .wire = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            .framing = .{ .content_length = 0 },
            .persistent = false,
        },
        .{
            .wire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: x, close\r\nConnection: keep-alive\r\n\r\n",
            .framing = .{ .content_length = 0 },
            .persistent = false,
        },
        .{ .wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", .framing = .chunked, .persistent = true },
    };
    for (cases) |case| {
        const head = try Self.parse(case.wire, &fields, .ordinary, .{});
        try testing.expectEqualDeep(case.framing, head.framing);
        try testing.expectEqual(case.persistent, head.keep_alive);
    }
}

test "v2 response head validates framing and Connection fields even after close" {
    var fields: [8]http_field.Field = undefined;
    try testing.expectError(error.DuplicateTransferEncoding, Self.parse(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
        &fields,
        .ordinary,
        .{},
    ));
    try testing.expectError(error.InvalidTransferEncoding, Self.parse(
        "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        &fields,
        .ordinary,
        .{},
    ));
    try testing.expectError(error.InvalidConnection, Self.parse(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nConnection: bad token\r\n\r\n",
        &fields,
        .ordinary,
        .{},
    ));
    try testing.expectError(error.InvalidConnection, Self.parse(
        "HTTP/1.1 200 OK\r\nConnection: close, bad token\r\n\r\n",
        &fields,
        .ordinary,
        .{},
    ));
    try testing.expectError(error.AmbiguousFraming, Self.parse(
        "HTTP/1.1 304 No Body\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        &fields,
        .ordinary,
        .{},
    ));
}

test "v2 response head reason syntax accepts only HTAB space visible and obs text" {
    var fields: [1]http_field.Field = undefined;
    const prefix = "HTTP/1.1 200 ";
    var bytes: [prefix.len + 5]u8 = undefined;
    @memcpy(bytes[0..prefix.len], prefix);
    @memcpy(bytes[prefix.len + 1 ..], "\r\n\r\n");
    for (0..256) |value| {
        bytes[prefix.len] = @intCast(value);
        if (value == '\t' or (value >= 0x20 and value != 0x7f)) {
            const head = try Self.parse(&bytes, &fields, .ordinary, .{});
            try testing.expectEqual(@as(u8, @intCast(value)), head.reason.slice(&bytes)[0]);
        } else if (Self.parse(&bytes, &fields, .ordinary, .{})) |_| {
            return error.InvalidReasonAccepted;
        } else |_| {}
    }
    try testing.expect(@sizeOf(Self) <= 128);
}
