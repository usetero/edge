//! Validate one complete request head before admission. All metadata uses offsets
//! into caller-owned bytes, so copying a head does not invalidate its descriptors.
const Self = @This();

const std = @import("std");
const HeadScanner = @import("HeadScanner.zig");
const http_field = @import("http_field.zig");

head_len: u32,
method: Span,
target: Span,
path_query: Span,
authority: ?Span = null,
host: ?Span = null,
header_count: u16 = 0,
version: std.http.Version,
target_form: TargetForm,
framing: Framing = .none,
expectation: Expectation = .none,
keep_alive: bool = false,

pub const Span = http_field.Span;
pub const Field = http_field.Field;
pub const Limits = struct { head_bytes: u32 = 16 * 1024 };
pub const TargetForm = enum { origin, absolute, authority, asterisk };
pub const Framing = union(enum) { none, content_length: u64, chunked };
pub const Expectation = enum { none, continue_100, unsupported };
pub const ContinueAction = enum { none, wait_for_admission, send_continue, reject_expectation };

/// Pass exactly the head, including its final CRLF; body/read-ahead is excluded.
/// Field capacity bounds header count. On error, discard partially written fields.
/// This operation neither mutates input nor reserves body/queue capacity.
pub fn parse(bytes: []const u8, fields: []Field, limits: Limits) !Self {
    if (limits.head_bytes == 0 or fields.len > std.math.maxInt(u16)) return error.InvalidCapacity;
    if (bytes.len > limits.head_bytes) return error.HeadTooLarge;
    var cursor: usize = 0;
    const request_line = try http_field.nextLine(bytes, &cursor);
    var state: ParseState = .{ .head = try requestLine(bytes, request_line) };
    while (true) {
        const line = try http_field.nextLine(bytes, &cursor);
        if (line.len == 0) {
            if (cursor != bytes.len) return error.TrailingData;
            break;
        }
        if (state.head.header_count == fields.len) return error.TooManyHeaders;
        const field = try http_field.parse(bytes, line);
        try state.consume(field, bytes);
        fields[state.head.header_count] = field;
        state.head.header_count += 1;
    }
    if (state.head.version == .@"HTTP/1.1" and state.head.host == null) return error.MissingHost;
    if (state.chunked and state.content_length != null) return error.AmbiguousFraming;
    if (state.chunked and state.head.version == .@"HTTP/1.0") return error.InvalidTransferEncoding;
    state.head.framing = if (state.chunked)
        .chunked
    else if (state.content_length) |len|
        .{ .content_length = len }
    else
        .none;
    // Edge is a proxy: HTTP/1.0 keep-alive is unsafe across intermediaries.
    state.head.keep_alive = state.head.version == .@"HTTP/1.1" and !state.close;
    state.head.head_len = @intCast(bytes.len);
    return state.head;
}

/// This decision performs no IO. The serving owner supplies actual reservation
/// state and tracks whether Continue was already sent before acting on it.
pub fn continueAction(self: Self, admitted: bool, body_received: bool) ContinueAction {
    if (self.expectation == .unsupported) return .reject_expectation;
    if (self.expectation == .none or self.version == .@"HTTP/1.0" or body_received) return .none;
    const has_body = switch (self.framing) {
        .none => false,
        .content_length => |len| len > 0,
        .chunked => true,
    };
    if (!has_body) return .none;
    return if (admitted) .send_continue else .wait_for_admission;
}

const ParseState = struct {
    head: Self,
    content_length: ?u64 = null,
    chunked: bool = false,
    close: bool = false,

    fn consume(self: *ParseState, field: Field, bytes: []const u8) !void {
        const name = field.name.slice(bytes);
        const value = field.value.slice(bytes);
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            if (self.head.host != null) return error.DuplicateHost;
            validateAuthority(value, false) catch return error.InvalidHost;
            self.head.host = field.value;
        } else if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            // Reject even identical repetitions; do not normalize ambiguous input.
            if (self.content_length != null) return error.DuplicateContentLength;
            self.content_length = try http_field.contentLength(value);
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (self.chunked) return error.DuplicateTransferEncoding;
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.InvalidTransferEncoding;
            self.chunked = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            const close = try http_field.connectionClose(value);
            self.close = self.close or close;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            self.consumeExpect(value);
        }
    }

    fn consumeExpect(self: *ParseState, value: []const u8) void {
        if (self.head.expectation == .unsupported) return;
        var tokens = std.mem.splitScalar(u8, value, ',');
        var found = false;
        while (tokens.next()) |part| {
            const token = std.mem.trim(u8, part, " \t");
            if (token.len == 0) continue;
            if (!std.ascii.eqlIgnoreCase(token, "100-continue")) {
                self.head.expectation = .unsupported;
                return;
            }
            found = true;
        }
        self.head.expectation = if (found) .continue_100 else .unsupported;
    }
};

fn requestLine(bytes: []const u8, line: Span) !Self {
    const raw = line.slice(bytes);
    const first = std.mem.findScalar(u8, raw, ' ') orelse return error.InvalidRequestLine;
    if (!http_field.validToken(raw[0..first])) return error.InvalidRequestLine;
    const remainder = raw[first + 1 ..];
    const second = std.mem.findScalar(u8, remainder, ' ') orelse return error.InvalidRequestLine;
    if (second == 0 or std.mem.findScalar(u8, remainder[second + 1 ..], ' ') != null) return error.InvalidRequestLine;
    const version = remainder[second + 1 ..];
    const target: Span = .{ .start = @intCast(line.start + first + 1), .len = @intCast(second) };
    var head: Self = .{
        .head_len = 0,
        .method = .{ .start = line.start, .len = @intCast(first) },
        .target = target,
        .path_query = target,
        .target_form = .origin,
        .version = std.meta.stringToEnum(std.http.Version, version) orelse return error.UnsupportedVersion,
    };
    try parseTarget(&head, bytes);
    return head;
}

fn parseTarget(head: *Self, bytes: []const u8) !void {
    const target = head.target.slice(bytes);
    const method = head.method.slice(bytes);
    if (std.mem.eql(u8, method, "CONNECT")) {
        validateAuthority(target, true) catch return error.InvalidTarget;
        head.target_form = .authority;
        head.authority = head.target;
        head.path_query = .{ .start = head.target.start + head.target.len, .len = 0 };
    } else if (std.mem.eql(u8, target, "*")) {
        if (!std.mem.eql(u8, method, "OPTIONS")) return error.InvalidTarget;
        head.target_form = .asterisk;
    } else if (target[0] == '/') {
        try validateComponent(target, true);
    } else {
        const scheme_end = std.mem.find(u8, target, "://") orelse return error.InvalidTarget;
        if (!std.ascii.eqlIgnoreCase(target[0..scheme_end], "http") and
            !std.ascii.eqlIgnoreCase(target[0..scheme_end], "https")) return error.InvalidTarget;
        const start = scheme_end + 3;
        const length = std.mem.findAny(u8, target[start..], "/?") orelse target.len - start;
        validateAuthority(target[start..][0..length], false) catch return error.InvalidTarget;
        try validateComponent(target[start + length ..], true);
        head.target_form = .absolute;
        head.authority = .{ .start = @intCast(head.target.start + start), .len = @intCast(length) };
        head.path_query = .{
            .start = @intCast(head.target.start + start + length),
            .len = @intCast(target.len - start - length),
        };
    }
}

/// Reuse the inbound syntax rules before interpolating a configured upstream Host.
/// This validates syntax only; destination selection and port policy belong to routing.
pub fn validateAuthority(value: []const u8, require_port: bool) !void {
    if (value.len == 0) return error.InvalidAuthority;
    const end = if (value[0] == '[') blk: {
        const bracket = std.mem.findScalar(u8, value, ']') orelse return error.InvalidAuthority;
        try validateIpLiteral(value[1..bracket]);
        break :blk bracket + 1;
    } else blk: {
        const colon = std.mem.findScalar(u8, value, ':') orelse value.len;
        if (colon == 0) return error.InvalidAuthority;
        try validateComponent(value[0..colon], false);
        break :blk colon;
    };
    if (end == value.len) {
        if (require_port) return error.InvalidAuthority;
        return;
    }
    if (value[end] != ':') return error.InvalidAuthority;
    const port = value[end + 1 ..];
    if (require_port and port.len == 0) return error.InvalidAuthority;
    // Only syntax is needed here. The configured upstream, never this field,
    // chooses the actual network destination. CONNECT is a planning non-goal.
    for (port) |byte| if (byte < '0' or byte > '9') return error.InvalidAuthority;
}

/// Validate an already constructed upstream target without decoding path/query bytes.
pub fn validateOriginTarget(target: []const u8, method: []const u8) !void {
    if (std.mem.eql(u8, target, "*") and std.mem.eql(u8, method, "OPTIONS")) return;
    if (target.len == 0 or target[0] != '/') return error.InvalidTarget;
    try validateComponent(target, true);
}

fn validateIpLiteral(value: []const u8) !void {
    if (value.len == 0) return error.InvalidAuthority;
    if (value[0] != 'v' and value[0] != 'V') {
        _ = std.Io.net.Ip6Address.parse(value, 0) catch return error.InvalidAuthority;
        return;
    }
    const dot = std.mem.findScalar(u8, value, '.') orelse return error.InvalidAuthority;
    if (dot == 1 or dot + 1 == value.len) return error.InvalidAuthority;
    for (value[1..dot]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidAuthority;
    for (value[dot + 1 ..]) |byte| {
        if (!uriPlain(byte) and byte != ':') return error.InvalidAuthority;
    }
}

fn validateComponent(value: []const u8, path_query: bool) !void {
    var index: usize = 0;
    while (index < value.len) : (index += 1) {
        const byte = value[index];
        if (uriPlain(byte)) continue;
        if (path_query and (byte == '/' or byte == '?' or byte == ':' or byte == '@')) continue;
        if (byte == '%' and value.len - index >= 3 and
            std.ascii.isHex(value[index + 1]) and std.ascii.isHex(value[index + 2]))
        {
            index += 2;
            continue;
        }
        return error.InvalidTarget;
    }
}

fn uriPlain(byte: u8) bool {
    if (std.ascii.isAlphanumeric(byte)) return true;
    return switch (byte) {
        '-', '.', '_', '~', '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => true,
        else => false,
    };
}

const testing = std.testing;
const BASE = "POST /v1/logs?x=%2f&x=2 HTTP/1.1\r\nHost: edge\r\n";

test "v2 request head preserves relocated offsets repeated fields and opaque encoding" {
    const raw = BASE ++ "Content-Length: 0003\r\nContent-Encoding: future, br\r\nX-Tag: a\r\nx-tag:\tb \t\r\n\r\n";
    var fields: [64]Field = undefined;
    const head = try parse(raw, &fields, .{});
    try testing.expectEqual(5, head.header_count);
    try testing.expectEqual(raw.len, head.head_len);
    try testing.expectEqual(3, head.framing.content_length);
    try testing.expect(head.keep_alive);
    var copy: [raw.len]u8 = undefined;
    @memcpy(&copy, raw);
    try testing.expectEqualStrings("POST", head.method.slice(&copy));
    try testing.expectEqualStrings("/v1/logs?x=%2f&x=2", head.path_query.slice(&copy));
    try testing.expectEqualStrings("edge", head.host.?.slice(&copy));
    try testing.expectEqualStrings("future, br", fields[2].value.slice(&copy));
    try testing.expectEqualStrings("X-Tag", fields[3].name.slice(&copy));
    try testing.expectEqualStrings("b", fields[4].value.slice(&copy));
    try testing.expectEqualStrings(raw, &copy);
}

test "v2 request head rejects duplicate or ambiguous message framing" {
    const cases = [_]struct { fields: []const u8, err: anyerror }{
        .{ .fields = "Content-Length: 3\r\nContent-Length: 3\r\n", .err = error.DuplicateContentLength },
        .{ .fields = "Content-Length: 3\r\ncontent-length: 4\r\n", .err = error.DuplicateContentLength },
        .{
            .fields = "Transfer-Encoding: chunked\r\ntransfer-encoding: chunked\r\n",
            .err = error.DuplicateTransferEncoding,
        },
        .{ .fields = "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n", .err = error.AmbiguousFraming },
        .{ .fields = "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n", .err = error.AmbiguousFraming },
        .{ .fields = "Host: edge\r\n", .err = error.DuplicateHost },
    };
    inline for (cases) |case| {
        var fields: [64]Field = undefined;
        try testing.expectError(case.err, parse(BASE ++ case.fields ++ "\r\n", &fields, .{}));
    }
}

test "v2 request head Content-Length is strict decimal and checked u64" {
    inline for (.{ "", "+1", "-1", "1_0", "0x10", "1 0", "1, 1", "18446744073709551616" }) |value| {
        var fields: [64]Field = undefined;
        try testing.expectError(
            error.InvalidContentLength,
            parse(BASE ++ "Content-Length: " ++ value ++ "\r\n\r\n", &fields, .{}),
        );
    }
    var fields: [64]Field = undefined;
    const head = try parse(BASE ++ "Content-Length: 18446744073709551615\r\n\r\n", &fields, .{});
    try testing.expectEqual(std.math.maxInt(u64), head.framing.content_length);
}

test "v2 request head supports only a single chunked transfer coding" {
    var fields: [64]Field = undefined;
    const head = try parse(BASE ++ "Transfer-Encoding: ChUnKeD\r\n\r\n", &fields, .{});
    try testing.expectEqual(.chunked, head.framing);
    const invalid = .{
        "",              "gzip",          "identity",        "chunked, chunked",
        "gzip, chunked", "chunked, gzip", "chunked;foo=bar",
    };
    inline for (invalid) |value| {
        try testing.expectError(
            error.InvalidTransferEncoding,
            parse(BASE ++ "Transfer-Encoding: " ++ value ++ "\r\n\r\n", &fields, .{}),
        );
    }
    try testing.expectError(
        error.InvalidTransferEncoding,
        parse("POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", &fields, .{}),
    );
}

test "v2 request head rejects malformed request lines and fields" {
    const cases = [_]struct { raw: []const u8, err: anyerror }{
        .{ .raw = "\r\n", .err = error.InvalidRequestLine },
        .{ .raw = "GET  / HTTP/1.1\r\nHost: edge\r\n\r\n", .err = error.InvalidRequestLine },
        .{ .raw = "G(ET / HTTP/1.1\r\nHost: edge\r\n\r\n", .err = error.InvalidRequestLine },
        .{ .raw = "GET\t/ HTTP/1.1\r\nHost: edge\r\n\r\n", .err = error.InvalidRequestLine },
        .{ .raw = "GET / HTTP/2.0\r\nHost: edge\r\n\r\n", .err = error.UnsupportedVersion },
        .{ .raw = "GET / HTTP/1.1\nHost: edge\n\n", .err = error.InvalidLineEnding },
        .{ .raw = BASE ++ "X: a\rb\r\n\r\n", .err = error.InvalidLineEnding },
        .{ .raw = BASE ++ "X : a\r\n\r\n", .err = error.InvalidFieldName },
        .{ .raw = BASE ++ "X\r\n\r\n", .err = error.InvalidFieldName },
        .{ .raw = BASE ++ ": a\r\n\r\n", .err = error.InvalidFieldName },
        .{ .raw = BASE ++ " X: a\r\n\r\n", .err = error.InvalidFieldName },
        .{ .raw = BASE ++ "X: a\r\n\tb\r\n\r\n", .err = error.InvalidFieldName },
        .{ .raw = BASE ++ "X: a\x00b\r\n\r\n", .err = error.InvalidFieldValue },
        .{ .raw = BASE ++ "X: a\x7fb\r\n\r\n", .err = error.InvalidFieldValue },
        .{ .raw = "GET / HTTP/1.1\r\n\r\n", .err = error.MissingHost },
    };
    var fields: [64]Field = undefined;
    for (cases) |case| try testing.expectError(case.err, parse(case.raw, &fields, .{}));
    _ = try parse(BASE ++ "X: \t\x80\xff\t \r\n\r\n", &fields, .{});
}

test "v2 request head validates Host authority syntax without DNS" {
    var fields: [64]Field = undefined;
    inline for (.{ "edge", "edge:8080", "edge:", "127.0.0.1", "[::1]:443", "[v1.a:b]", "my_edge.local" }) |value| {
        _ = try parse("GET / HTTP/1.1\r\nHost: " ++ value ++ "\r\n\r\n", &fields, .{});
    }
    const invalid = .{
        "",         "a b",    "a\tb", "a/b",       "user@edge", "a\\b",
        "edge:abc", "[nope]", "::1",  "[::1]junk", "edge%zz",
    };
    inline for (invalid) |value| {
        try testing.expectError(
            error.InvalidHost,
            parse("GET / HTTP/1.1\r\nHost: " ++ value ++ "\r\n\r\n", &fields, .{}),
        );
    }
}

test "v2 request head recognizes target forms without decoding query bytes" {
    const cases = [_]struct { line: []const u8, form: TargetForm, path: []const u8 }{
        .{ .line = "CUSTOM /raw%2Fpath?a=%00&a=2 HTTP/1.1", .form = .origin, .path = "/raw%2Fpath?a=%00&a=2" },
        .{ .line = "GET http://example.com/a?b=%2f HTTP/1.1", .form = .absolute, .path = "/a?b=%2f" },
        .{ .line = "GET HTTPS://[::1]:443?x=1 HTTP/1.1", .form = .absolute, .path = "?x=1" },
        .{ .line = "GET http://example.com HTTP/1.1", .form = .absolute, .path = "" },
        .{ .line = "OPTIONS * HTTP/1.1", .form = .asterisk, .path = "*" },
        .{ .line = "CONNECT example.com:443 HTTP/1.1", .form = .authority, .path = "" },
    };
    inline for (cases) |case| {
        const raw = case.line ++ "\r\nHost: configured-edge\r\n\r\n";
        var fields: [64]Field = undefined;
        const head = try parse(raw, &fields, .{});
        try testing.expectEqual(case.form, head.target_form);
        try testing.expectEqualStrings(case.path, head.path_query.slice(raw));
        if (case.form == .absolute or case.form == .authority) try testing.expect(head.authority != null);
    }
    const invalid = .{
        "GET relative",     "GET /a#b",     "GET /a%xx",     "GET /a\\b",
        "GET *",            "OPTIONS /a\t", "GET http:///a", "GET http://a@b/",
        "GET ftp://edge/a", "CONNECT edge", "CONNECT /a",
    };
    inline for (invalid) |line| {
        var fields: [64]Field = undefined;
        try testing.expectError(error.InvalidTarget, parse(line ++ " HTTP/1.1\r\nHost: edge\r\n\r\n", &fields, .{}));
    }
}

test "v2 request head Connection close dominates lists and HTTP 1.0 is nonpersistent" {
    var fields: [64]Field = undefined;
    const head = try parse(BASE ++ "Connection: Keep-Alive, X-A\r\nConnection: , CLOSE,,\r\n\r\n", &fields, .{});
    try testing.expect(!head.keep_alive);
    const old = try parse("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", &fields, .{});
    try testing.expect(!old.keep_alive);
    const unknown = try parse(BASE ++ "Connection: X-A\r\n\r\n", &fields, .{});
    try testing.expect(unknown.keep_alive);
    try testing.expectError(error.InvalidConnection, parse(BASE ++ "Connection: \"close\"\r\n\r\n", &fields, .{}));
}

test "v2 request head Continue waits for admission and ignores bodyless requests" {
    var fields: [64]Field = undefined;
    const head = try parse(BASE ++ "Content-Length: 3\r\nExpect: 100-Continue\r\n\r\n", &fields, .{});
    try testing.expectEqual(.wait_for_admission, head.continueAction(false, false));
    try testing.expectEqual(.send_continue, head.continueAction(true, false));
    try testing.expectEqual(.none, head.continueAction(true, true));
    inline for (.{ "", "Content-Length: 0\r\n" }) |body| {
        const empty = try parse(BASE ++ body ++ "Expect: 100-continue\r\n\r\n", &fields, .{});
        try testing.expectEqual(.none, empty.continueAction(false, false));
    }
    const chunked_raw = BASE ++ "Transfer-Encoding: chunked\r\nExpect: 100-continue, 100-continue\r\n\r\n";
    const chunked = try parse(chunked_raw, &fields, .{});
    try testing.expectEqual(.send_continue, chunked.continueAction(true, false));
    const old = try parse("POST / HTTP/1.0\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n", &fields, .{});
    try testing.expectEqual(.none, old.continueAction(true, false));
    inline for (.{ "magic", "100-continue;foo=bar", "", "100-continue, magic" }) |value| {
        const rejected = try parse(BASE ++ "Expect: " ++ value ++ "\r\nExpect: 100-continue\r\n\r\n", &fields, .{});
        try testing.expectEqual(.reject_expectation, rejected.continueAction(false, false));
    }
}

test "v2 request head exact byte and descriptor limits do not truncate" {
    var fields: [64]Field = undefined;
    const raw = "GET / HTTP/1.1\r\nHost: edge\r\n" ++ "X: v\r\n" ** 63 ++ "\r\n";
    const head = try parse(raw, &fields, .{ .head_bytes = raw.len });
    try testing.expectEqual(64, head.header_count);
    try testing.expectError(error.TooManyHeaders, parse(raw, fields[0..63], .{}));
    try testing.expectError(error.HeadTooLarge, parse(raw, &fields, .{ .head_bytes = raw.len - 1 }));
    try testing.expectError(error.InvalidCapacity, parse(raw, &fields, .{ .head_bytes = 0 }));
    _ = try parse("GET / HTTP/1.0\r\n\r\n", &.{}, .{});
    const prefix = "GET / HTTP/1.1\r\nHost: edge\r\nX: ";
    const large = prefix ++ "a" ** (16384 - prefix.len - 4) ++ "\r\n\r\n";
    _ = try parse(large, &fields, .{});
    try testing.expectError(error.HeadTooLarge, parse(large ++ "x", &fields, .{}));
    try testing.expect(@sizeOf(Self) <= 128);
    try testing.expect(@sizeOf(Field) * fields.len <= 1024);
}

test "v2 request head rejects truncation and extra bytes after the head" {
    const raw = BASE ++ "Content-Length: 3\r\n\r\n";
    var fields: [64]Field = undefined;
    for (0..raw.len) |end| try testing.expectError(error.IncompleteHead, parse(raw[0..end], &fields, .{}));
    try testing.expectError(error.TrailingData, parse(raw ++ "abc", &fields, .{}));
    try testing.expectError(error.TrailingData, parse(raw ++ "GET / HTTP/1.0\r\n\r\n", &fields, .{}));
}

test "v2 request head rejects every forbidden value byte but retains obs text" {
    const prefix = BASE ++ "X: a";
    var wire: [prefix.len + 6]u8 = undefined;
    @memcpy(wire[0..prefix.len], prefix);
    @memcpy(wire[prefix.len + 1 ..], "b\r\n\r\n");
    var fields: [64]Field = undefined;
    for (0..256) |value| {
        wire[prefix.len] = @intCast(value);
        const allowed = value == 9 or (value >= 32 and value != 127);
        if (parse(&wire, &fields, .{})) |head| {
            try testing.expect(allowed);
            try testing.expectEqual(3, fields[head.header_count - 1].value.len);
        } else |_| {
            try testing.expect(!allowed);
        }
    }
}

test "v2 request head framing follows fields independently of method and encoding" {
    var fields: [64]Field = undefined;
    inline for (.{ "GET", "HEAD", "POST", "CUSTOM" }) |method| {
        const raw = method ++ " / HTTP/1.1\r\nHost: edge\r\nContent-Encoding: future\r\nContent-Encoding: br\r\n";
        const body = try parse(raw ++ "Content-Length: 3\r\n\r\n", &fields, .{});
        try testing.expectEqual(3, body.framing.content_length);
        try testing.expectEqual(4, body.header_count);
        const empty = try parse(raw ++ "\r\n", &fields, .{});
        try testing.expectEqual(.none, empty.framing);
        try testing.expectEqual(3, empty.header_count);
    }
}

test "v2 request head scanner validation and relocation compose at every split" {
    const raw = BASE ++ "Content-Length: 3\r\n\r\n";
    const wire = raw ++ "abcGET / HTTP/1.0\r\n\r\n";
    for (0..wire.len + 1) |split| {
        var scanner: HeadScanner = try .init(16384);
        var storage: [16384]u8 = undefined;
        const first = try scanner.feed(wire[0..split]);
        @memcpy(storage[0..first.consumed], wire[0..first.consumed]);
        if (first.head_len == null) {
            const second = try scanner.feed(wire[split..]);
            @memcpy(storage[first.consumed..][0..second.consumed], wire[split..][0..second.consumed]);
        }
        var fields: [64]Field = undefined;
        const head = try parse(storage[0..scanner.length], &fields, .{});
        try testing.expectEqual(raw.len, head.head_len);
        try testing.expectEqual(3, head.framing.content_length);
        try testing.expectEqualStrings("abcGET / HTTP/1.0\r\n\r\n", wire[head.head_len..]);
    }
}
