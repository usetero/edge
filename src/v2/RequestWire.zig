//! Prepare a complete raw request before upstream commitment, borrowing its body.
const Self = @This();

const std = @import("std");
const BodyFramer = @import("BodyFramer.zig");
const HeadScanner = @import("HeadScanner.zig");
const RequestHead = @import("RequestHead.zig");
const RequestIngress = @import("RequestIngress.zig");
const RequestTable = @import("RequestTable.zig");
const WorkChannel = @import("WorkChannel.zig");
const http_field = @import("http_field.zig");

parts: [3][]const u8,
part: u8 = 0,
offset: usize = 0,

pub const Input = struct {
    head: []const u8,
    body: []const u8,
    trailers: []const u8 = "",
    /// Set only for a fully validated replacement encoded with the original codec.
    /// Validates ingress framing against retained original bytes, not the candidate.
    source_body_len: ?usize = null,
};
pub const Destination = struct { authority: []const u8, target: ?[]const u8 = null };
pub const Storage = struct {
    head: []u8,
    tail: []u8,
    fields: []RequestHead.Field,
    trailer_fields: []RequestHead.Field,
};
pub const Limits = struct {
    input_head_bytes: u32 = 16 * 1024,
    input_trailer_bytes: u32 = 16 * 1024,
    output_head_bytes: u32 = 16 * 1024,
    output_fields: u16 = 64,
};

/// Input must be the complete original entity from successful ingress framing.
/// Stores must be mutually disjoint and disjoint from input/destination bytes.
/// Only the body and generated head/tail buffers must survive until sending ends;
/// descriptor scratch and other inputs can be reused after successful preparation.
/// No output is publishable on error; discard partially written scratch.
pub fn init(input: Input, destination: Destination, storage: Storage, limits: Limits) !Self {
    if (input.trailers.len > limits.input_trailer_bytes) return error.TrailersTooLarge;
    const head = try RequestHead.parse(input.head, storage.fields, .{ .head_bytes = limits.input_head_bytes });
    if (head.target_form == .authority) return error.UnsupportedTarget;
    if (head.expectation == .unsupported) return error.UnsupportedExpectation;
    try RequestHead.validateAuthority(destination.authority, false);
    const fields = storage.fields[0..head.header_count];
    const trailers = try prepareTrailers(input, head.framing, fields, storage.trailer_fields);
    const head_len = writeHead(input, head, fields, trailers, destination, storage.head, limits) catch |err| {
        return if (err == error.WriteFailed) error.HeadTooLarge else err;
    };
    var prefix_len = head_len;
    if (head.framing == .chunked and input.body.len > 0) {
        const chunk = std.fmt.bufPrint(storage.head[head_len..], "{x}\r\n", .{input.body.len}) catch
            return error.OutputTooSmall;
        prefix_len += chunk.len;
    }
    const tail_len = writeTail(input, head.framing, trailers, storage.tail) catch return error.TailTooLarge;
    return .{ .parts = .{ storage.head[0..prefix_len], input.body, storage.tail[0..tail_len] } };
}

/// Borrow the next contiguous span. A socket writer can limit this slice
/// to its turn budget, then advance only by bytes actually accepted by the OS.
pub fn pending(self: *Self) []const u8 {
    while (self.part < self.parts.len and self.offset == self.parts[self.part].len) {
        self.part += 1;
        self.offset = 0;
    }
    return if (self.part == self.parts.len) "" else self.parts[self.part][self.offset..];
}

/// Failed/blocked writes advance zero bytes. This cursor does not authorize retry.
pub fn advance(self: *Self, count: usize) !void {
    if (count > self.pending().len) return error.InvalidWriteLength;
    self.offset += count;
}

fn prepareTrailers(
    input: Input,
    framing: RequestHead.Framing,
    fields: []const RequestHead.Field,
    output: []RequestHead.Field,
) ![]const RequestHead.Field {
    switch (framing) {
        .none => if ((input.source_body_len orelse input.body.len) != 0) return error.InvalidBodyLength,
        .content_length => |length| if (length != (input.source_body_len orelse input.body.len)) {
            return error.InvalidBodyLength;
        },
        .chunked => return parseTrailers(input, fields, output),
    }
    if (input.trailers.len != 0) return error.UnexpectedTrailers;
    return output[0..0];
}

fn parseTrailers(
    input: Input,
    fields: []const RequestHead.Field,
    output: []RequestHead.Field,
) ![]const RequestHead.Field {
    if (input.trailers.len > std.math.maxInt(u32)) return error.TrailersTooLarge;
    var cursor: usize = 0;
    var count: usize = 0;
    var seen: usize = 0;
    while (true) {
        const start = cursor;
        const length = std.mem.findScalar(u8, input.trailers[start..], '\n') orelse return error.IncompleteTrailers;
        if (length == 0 or input.trailers[start + length - 1] != '\r') return error.InvalidLineEnding;
        cursor += length + 1;
        if (length == 1) {
            if (cursor != input.trailers.len) return error.TrailingData;
            return output[0..count];
        }
        // Count discarded fields as well so nominations cannot evade work limits.
        if (seen == output.len) return error.TooManyTrailers;
        seen += 1;
        const field = try http_field.parse(input.trailers, .{ .start = @intCast(start), .len = @intCast(length - 1) });
        const name = field.name.slice(input.trailers);
        if (http_field.forbiddenTrailer(name)) return error.ForbiddenTrailer;
        if (http_field.nominated(name, input.head, fields)) continue;
        if (input.source_body_len != null and http_field.representationField(name)) continue;
        output[count] = field;
        count += 1;
    }
}

fn writeHead(
    input: Input,
    head: RequestHead,
    fields: []const RequestHead.Field,
    trailers: []const RequestHead.Field,
    destination: Destination,
    buffer: []u8,
    limits: Limits,
) !usize {
    var builder: HeadBuilder = .{
        .writer = .fixed(buffer[0..@min(buffer.len, limits.output_head_bytes)]),
        .limit = limits.output_fields,
    };
    const writer = &builder.writer;
    const method = head.method.slice(input.head);
    try writer.print("{s} ", .{method});
    try writeTarget(writer, head, input.head, destination.target);
    try writer.writeAll(" HTTP/1.1\r\n");
    try builder.field("Host", destination.authority);
    for (fields) |field| {
        const name = field.name.slice(input.head);
        if (transportField(name) or http_field.nominated(name, input.head, fields)) continue;
        if (input.source_body_len != null and http_field.representationField(name)) continue;
        try builder.field(name, field.value.slice(input.head));
    }
    try builder.field("Via", if (head.version == .@"HTTP/1.1") "1.1 tero-edge" else "1.0 tero-edge");
    switch (head.framing) {
        .none => {},
        .content_length => {
            try builder.begin("Content-Length");
            try writer.print("{d}\r\n", .{input.body.len});
        },
        .chunked => {
            try builder.field("Transfer-Encoding", "chunked");
            if (trailers.len > 0) {
                try builder.begin("Trailer");
                for (trailers, 0..) |field, index| {
                    if (index > 0) try writer.writeAll(", ");
                    try writer.writeAll(field.name.slice(input.trailers));
                }
                try writer.writeAll("\r\n");
            }
        },
    }
    try writer.writeAll("\r\n");
    return writer.buffered().len;
}

fn writeTarget(writer: *std.Io.Writer, head: RequestHead, bytes: []const u8, override: ?[]const u8) !void {
    if (override) |target| {
        try RequestHead.validateOriginTarget(target, head.method.slice(bytes));
        return writer.writeAll(target);
    }
    const target = head.path_query.slice(bytes);
    if (head.target_form == .absolute and target.len == 0 and std.mem.eql(u8, head.method.slice(bytes), "OPTIONS")) {
        return writer.writeAll("*");
    }
    if (target.len == 0 or target[0] == '?') try writer.writeAll("/");
    try writer.writeAll(target);
}

fn writeTail(input: Input, framing: RequestHead.Framing, fields: []const RequestHead.Field, buffer: []u8) !usize {
    if (framing != .chunked) return 0;
    var writer: std.Io.Writer = .fixed(buffer);
    if (input.body.len > 0) try writer.writeAll("\r\n");
    try writer.writeAll("0\r\n");
    for (fields) |field| {
        try writer.print("{s}: {s}\r\n", .{ field.name.slice(input.trailers), field.value.slice(input.trailers) });
    }
    try writer.writeAll("\r\n");
    return writer.buffered().len;
}

fn transportField(name: []const u8) bool {
    const names = [_][]const u8{
        "host", "content-length", "transfer-encoding", "connection", "keep-alive",          "proxy-connection",
        "te",   "trailer",        "upgrade",           "expect",     "proxy-authorization", "proxy-authenticate",
    };
    for (names) |field| if (std.ascii.eqlIgnoreCase(name, field)) return true;
    return false;
}

const HeadBuilder = struct {
    writer: std.Io.Writer,
    limit: u16,
    count: u16 = 0,

    fn field(self: *HeadBuilder, name: []const u8, value: []const u8) !void {
        try self.begin(name);
        try self.writer.print("{s}\r\n", .{value});
    }

    fn begin(self: *HeadBuilder, name: []const u8) !void {
        if (self.count == self.limit) return error.TooManyHeaders;
        self.count += 1;
        try self.writer.print("{s}: ", .{name});
    }
};

const testing = std.testing;
const Fixture = struct {
    head: [4096]u8 = undefined,
    tail: [512]u8 = undefined,
    fields: [64]RequestHead.Field = undefined,
    trailer_fields: [16]RequestHead.Field = undefined,

    fn storage(self: *Fixture) Storage {
        return .{
            .head = &self.head,
            .tail = &self.tail,
            .fields = &self.fields,
            .trailer_fields = &self.trailer_fields,
        };
    }
};

test "v2 raw wire rebuilds authority and framing while retaining repeated opaque metadata" {
    var fixture: Fixture = .{};
    const body = "a\x00\xff";
    const head = "POST /v1/logs?q=%2f+ HTTP/1.1\r\nHost: inbound\r\nContent-Length: 3\r\n" ++
        "Content-Encoding: alien\r\nX-Tag: one\r\nx-tag: two\r\nAuthorization: Bearer secret\r\n" ++
        "Expect: 100-continue\r\n\r\n";
    const wire = try Self.init(
        .{ .head = head, .body = body },
        .{ .authority = "upstream:443" },
        fixture.storage(),
        .{},
    );
    try testing.expectEqualStrings("POST /v1/logs?q=%2f+ HTTP/1.1\r\nHost: upstream:443\r\n" ++
        "Content-Encoding: alien\r\nX-Tag: one\r\nx-tag: two\r\nAuthorization: Bearer secret\r\n" ++
        "Via: 1.1 tero-edge\r\nContent-Length: 3\r\n\r\n", wire.parts[0]);
    try testing.expectEqual(@intFromPtr(body.ptr), @intFromPtr(wire.parts[1].ptr));
    try testing.expectEqualStrings(body, wire.parts[1]);
    try testing.expectEqualStrings("", wire.parts[2]);
}

test "v2 raw wire filters all Connection nominations in heads and trailers" {
    var fixture: Fixture = .{};
    const head = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\n" ++
        "X-Drop: before\r\nConnection: X-Drop, keep-alive\r\nConnection: , X-End,\r\n" ++
        "Keep-Alive: timeout=1\r\nTE: trailers\r\nUpgrade: websocket\r\nProxy-Authorization: secret\r\n" ++
        "Trailer: X-End, X-Keep\r\nX-Stay: ok\r\n\r\n";
    const wire = try Self.init(.{
        .head = head,
        .body = "abc",
        .trailers = "X-End: drop\r\nX-Keep: one\r\nx-keep: two\r\n\r\n",
    }, .{ .authority = "up" }, fixture.storage(), .{});
    try testing.expectEqualStrings("POST / HTTP/1.1\r\nHost: up\r\nX-Stay: ok\r\n" ++
        "Via: 1.1 tero-edge\r\nTransfer-Encoding: chunked\r\nTrailer: X-Keep, x-keep\r\n\r\n3\r\n", wire.parts[0]);
    try testing.expectEqualStrings("abc", wire.parts[1]);
    try testing.expectEqualStrings("\r\n0\r\nX-Keep: one\r\nx-keep: two\r\n\r\n", wire.parts[2]);
}

test "v2 raw wire handles empty chunked messages without terminating before trailers" {
    var fixture: Fixture = .{};
    const wire = try Self.init(.{
        .head = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\n\r\n",
        .body = "",
        .trailers = "X-End: yes\r\n\r\n",
    }, .{ .authority = "up" }, fixture.storage(), .{});
    try testing.expectEqualStrings("POST / HTTP/1.1\r\nHost: up\r\nVia: 1.1 tero-edge\r\n" ++
        "Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n", wire.parts[0]);
    try testing.expectEqualStrings("0\r\nX-End: yes\r\n\r\n", wire.parts[2]);
}

test "v2 raw wire preserves target bytes and refuses CONNECT or unsupported expectations" {
    var fixture: Fixture = .{};
    const cases = [_]struct { target: []const u8, expected: []const u8 }{
        .{ .target = "https://inbound?q=%2F", .expected = "/?q=%2F" },
        .{ .target = "http://inbound", .expected = "/" },
        .{ .target = "/a%2fb?x=1&x=2", .expected = "/a%2fb?x=1&x=2" },
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const head = try std.fmt.bufPrint(&buffer, "GET {s} HTTP/1.0\r\n\r\n", .{case.target});
        const wire = try Self.init(.{ .head = head, .body = "" }, .{ .authority = "up" }, fixture.storage(), .{});
        var expected: [256]u8 = undefined;
        const rendered = try std.fmt.bufPrint(
            &expected,
            "GET {s} HTTP/1.1\r\nHost: up\r\nVia: 1.0 tero-edge\r\n\r\n",
            .{case.expected},
        );
        try testing.expectEqualStrings(rendered, wire.parts[0]);
    }
    try testing.expectError(error.UnsupportedTarget, Self.init(.{
        .head = "CONNECT host:443 HTTP/1.1\r\nHost: host\r\n\r\n",
        .body = "",
    }, .{ .authority = "up" }, fixture.storage(), .{}));
    try testing.expectError(error.UnsupportedExpectation, Self.init(.{
        .head = "POST / HTTP/1.1\r\nHost: e\r\nExpect: magic\r\nContent-Length: 0\r\n\r\n",
        .body = "",
    }, .{ .authority = "up" }, fixture.storage(), .{}));
}

test "v2 raw wire rejects incomplete originals and critical trailers before publication" {
    var fixture: Fixture = .{};
    const fixed = "POST / HTTP/1.1\r\nHost: e\r\nContent-Length: 3\r\n\r\n";
    try testing.expectError(error.InvalidBodyLength, Self.init(
        .{ .head = fixed, .body = "ab" },
        .{ .authority = "up" },
        fixture.storage(),
        .{},
    ));
    const chunked = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\n\r\n";
    try testing.expectError(error.IncompleteTrailers, Self.init(
        .{ .head = chunked, .body = "", .trailers = "X: y\r\n" },
        .{ .authority = "up" },
        fixture.storage(),
        .{},
    ));
    try testing.expectError(error.ForbiddenTrailer, Self.init(.{
        .head = chunked,
        .body = "abc",
        .trailers = "Content-Length: 9\r\n\r\n",
    }, .{ .authority = "up" }, fixture.storage(), .{}));
}

test "v2 raw wire validates selected destinations and preserves OPTIONS targets" {
    var fixture: Fixture = .{};
    const input: Input = .{ .head = "OPTIONS http://e HTTP/1.1\r\nHost: e\r\n\r\n", .body = "" };
    const wire = try Self.init(input, .{ .authority = "[::1]:4318" }, fixture.storage(), .{});
    try testing.expect(std.mem.startsWith(u8, wire.parts[0], "OPTIONS * HTTP/1.1\r\nHost: [::1]:4318\r\n"));
    const rerouted = try Self.init(input, .{ .authority = "up", .target = "/base?q=%2f" }, fixture.storage(), .{});
    try testing.expect(std.mem.startsWith(u8, rerouted.parts[0], "OPTIONS /base?q=%2f HTTP/1.1\r\n"));
    for ([_][]const u8{ "", "up\r\nX-Evil: yes", "user@up", "up/path" }) |authority| {
        if (Self.init(input, .{ .authority = authority }, fixture.storage(), .{})) |_| {
            return error.InvalidAuthorityAccepted;
        } else |_| {}
    }
    for ([_][]const u8{ "", "/bad path", "/bad\r\nX: y", "http://evil/", "/bad%xx", "/bad#fragment" }) |target| {
        try testing.expectError(error.InvalidTarget, Self.init(
            input,
            .{ .authority = "up", .target = target },
            fixture.storage(),
            .{},
        ));
    }
}

test "v2 raw wire bounds trailer input including discarded fields and rejects malformed tails" {
    var fixture: Fixture = .{};
    const head = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\nConnection: X\r\n\r\n";
    const input: Input = .{ .head = head, .body = "", .trailers = "X: y\r\n\r\n" };
    try testing.expectError(error.TrailersTooLarge, Self.init(
        input,
        .{ .authority = "up" },
        fixture.storage(),
        .{ .input_trailer_bytes = input.trailers.len - 1 },
    ));
    _ = try Self.init(input, .{ .authority = "up" }, fixture.storage(), .{ .input_trailer_bytes = input.trailers.len });
    var storage = fixture.storage();
    storage.trailer_fields = storage.trailer_fields[0..0];
    try testing.expectError(error.TooManyTrailers, Self.init(input, .{ .authority = "up" }, storage, .{}));
    const cases = [_]struct { trailer: []const u8, failure: anyerror }{
        .{ .trailer = "", .failure = error.IncompleteTrailers },
        .{ .trailer = "X: y\n\r\n", .failure = error.InvalidLineEnding },
        .{ .trailer = "X: y\rZ\r\n\r\n", .failure = error.InvalidFieldValue },
        .{ .trailer = " folded: y\r\n\r\n", .failure = error.InvalidFieldName },
        .{ .trailer = "\r\nextra", .failure = error.TrailingData },
    };
    for (cases) |case| try testing.expectError(case.failure, Self.init(.{
        .head = head,
        .body = "",
        .trailers = case.trailer,
    }, .{ .authority = "up" }, fixture.storage(), .{}));
    try testing.expectError(error.UnexpectedTrailers, Self.init(.{
        .head = "GET / HTTP/1.1\r\nHost: e\r\n\r\n",
        .body = "",
        .trailers = "\r\n",
    }, .{ .authority = "up" }, fixture.storage(), .{}));
}

test "v2 raw wire includes generated fields in the 64 header limit" {
    var fixture: Fixture = .{};
    var input_buffer: [4096]u8 = undefined;
    for ([_]usize{ 61, 62 }) |count| {
        var writer: std.Io.Writer = .fixed(&input_buffer);
        try writer.writeAll("POST / HTTP/1.1\r\nHost: e\r\nContent-Length: 0\r\n");
        for (0..count) |_| try writer.writeAll("X: y\r\n");
        try writer.writeAll("\r\n");
        const input: Input = .{ .head = writer.buffered(), .body = "" };
        if (count == 62) {
            try testing.expectError(error.TooManyHeaders, Self.init(
                input,
                .{ .authority = "up" },
                fixture.storage(),
                .{},
            ));
        } else {
            const wire = try Self.init(input, .{ .authority = "up" }, fixture.storage(), .{});
            const head = try RequestHead.parse(wire.parts[0], &fixture.fields, .{});
            try testing.expectEqual(@as(u16, 64), head.header_count);
        }
    }
}

test "v2 raw wire exact head tail and chunk prefix capacities never truncate" {
    var fixture: Fixture = .{};
    const input: Input = .{
        .head = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\n\r\n",
        .body = "abc",
        .trailers = "\r\n",
    };
    const wire = try Self.init(input, .{ .authority = "up" }, fixture.storage(), .{});
    const prefix_len = wire.parts[0].len;
    const head_len: u32 = @intCast(prefix_len - "3\r\n".len);
    const tail_len = wire.parts[2].len;
    var storage = fixture.storage();
    storage.head = storage.head[0..prefix_len];
    storage.tail = storage.tail[0..tail_len];
    _ = try Self.init(input, .{ .authority = "up" }, storage, .{ .output_head_bytes = head_len });
    try testing.expectError(error.HeadTooLarge, Self.init(
        input,
        .{ .authority = "up" },
        storage,
        .{ .output_head_bytes = head_len - 1 },
    ));
    storage.head = storage.head[0 .. prefix_len - 1];
    try testing.expectError(error.OutputTooSmall, Self.init(input, .{ .authority = "up" }, storage, .{}));
    storage.head = &fixture.head;
    storage.tail = storage.tail[0 .. tail_len - 1];
    try testing.expectError(error.TailTooLarge, Self.init(input, .{ .authority = "up" }, storage, .{}));
}

test "v2 raw wire enforces 16 KiB after generated metadata" {
    var fixture: Fixture = .{};
    var source: [16 * 1024]u8 = undefined;
    var output: [16 * 1024]u8 = undefined;
    const input_prefix = "GET / HTTP/1.1\r\nHost: e\r\nX: ";
    const output_overhead = "GET / HTTP/1.1\r\nHost: up\r\nX: \r\nVia: 1.1 tero-edge\r\n\r\n".len;
    const value_len = output.len - output_overhead;
    for (0..2) |extra| {
        var writer: std.Io.Writer = .fixed(&source);
        try writer.writeAll(input_prefix);
        for (0..value_len + extra) |_| try writer.writeAll("v");
        try writer.writeAll("\r\n\r\n");
        var storage = fixture.storage();
        storage.head = &output;
        const input: Input = .{ .head = writer.buffered(), .body = "" };
        if (extra == 0) {
            const wire = try Self.init(input, .{ .authority = "up" }, storage, .{});
            try testing.expectEqual(output.len, wire.parts[0].len);
        } else try testing.expectError(error.HeadTooLarge, Self.init(input, .{ .authority = "up" }, storage, .{}));
    }
}

test "v2 raw wire cursor preserves every byte across short and blocked writes" {
    const input: Input = .{
        .head = "POST / HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\n\r\n",
        .body = "a\x00\xff",
        .trailers = "X-End: yes\r\n\r\n",
    };
    for (1..32) |window| {
        var fixture: Fixture = .{};
        var wire = try Self.init(input, .{ .authority = "up" }, fixture.storage(), .{});
        const start = wire.pending();
        try wire.advance(0);
        try testing.expectEqualStrings(start, wire.pending());
        try testing.expectError(error.InvalidWriteLength, wire.advance(start.len + 1));
        var output: [8192]u8 = undefined;
        const bytes = try collect(&wire, &output, window);
        try testing.expectEqualStrings("POST / HTTP/1.1\r\nHost: up\r\nVia: 1.1 tero-edge\r\n" ++
            "Transfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n3\r\na\x00\xff\r\n0\r\nX-End: yes\r\n\r\n", bytes);
        try testing.expectEqualStrings("", wire.pending());
        try wire.advance(0);
        try testing.expectError(error.InvalidWriteLength, wire.advance(1));
    }
}

fn collect(wire: *Self, output: []u8, window: usize) ![]const u8 {
    var writer: std.Io.Writer = .fixed(output);
    while (wire.pending().len > 0) {
        const bytes = wire.pending();
        const count = @min(window, bytes.len);
        try writer.writeAll(bytes[0..count]);
        try wire.advance(count);
    }
    return writer.buffered();
}

test "v2 raw wire composes admitted detached jobs into a parseable upstream message" {
    var table: RequestTable = try .init(testing.allocator, .{
        .requests = 1,
        .head_bytes = 256,
        .body_bytes = 64,
        .trailer_bytes = 256,
        .response_bytes = 16,
    });
    defer table.deinit(testing.allocator);
    var channel: WorkChannel = try .init(testing.allocator, .{ .capacity = 1 });
    defer channel.deinit(testing.allocator);
    defer channel.close(testing.io);
    const request = table.acquire().?;
    try testing.expect(try channel.reserve(&table, request));
    var fixture: Fixture = .{};
    var line: [64]u8 = undefined;
    const head = "POST /logs HTTP/1.1\r\nHost: e\r\nTransfer-Encoding: chunked\r\nConnection: X-Drop\r\n\r\n";
    var ingress = try RequestIngress.init(&table, request, head, .{
        .head_fields = &fixture.fields,
        .line = &line,
        .trailer_fields = &fixture.trailer_fields,
    }, .{ .head = .{}, .body = .{ .body_bytes = 64 } });
    const body = "3;ext=discard\r\na\x00b\r\n2\r\n\xffz\r\n0\r\nX-End: one\r\nx-end: two\r\nX-Drop: no\r\n\r\n";
    _ = try ingress.feed(body);
    try channel.submit(testing.io, &table, request, try ingress.input(.{ .nanoseconds = 1 }));
    try table.disconnect(request);
    const job = (try channel.take(testing.io)).?;
    defer {
        channel.publish(testing.io, job, .{ .failed = error.Canceled });
        channel.acknowledge(&table, channel.receive(testing.io).?) catch unreachable;
    }
    var wire = try Self.init(
        .{ .head = job.head, .body = job.body, .trailers = job.trailers },
        .{ .authority = "up" },
        fixture.storage(),
        .{},
    );
    try testing.expectEqual(@intFromPtr(job.body.ptr), @intFromPtr(wire.parts[1].ptr));
    @memset(&fixture.fields, std.mem.zeroes(RequestHead.Field));
    @memset(&fixture.trailer_fields, std.mem.zeroes(RequestHead.Field));
    try testing.expect(table.acquire() == null);
    var output: [8192]u8 = undefined;
    try checkRoundTrip(try collect(&wire, &output, 1));
    try testing.expectEqualStrings("a\x00b\xffz", job.body);
    try testing.expectEqualStrings("X-End: one\r\nx-end: two\r\nX-Drop: no\r\n\r\n", job.trailers);
}

fn checkRoundTrip(bytes: []const u8) !void {
    var scanner: HeadScanner = try .init(4096);
    const result = try scanner.feed(bytes);
    const head_len = result.head_len.?;
    var fields: [64]RequestHead.Field = undefined;
    const head = try RequestHead.parse(bytes[0..head_len], &fields, .{});
    try testing.expectEqualStrings("/logs", head.target.slice(bytes));
    try testing.expectEqualStrings("up", head.host.?.slice(bytes));
    var line: [64]u8 = undefined;
    var trailers: [256]u8 = undefined;
    var body: [64]u8 = undefined;
    var framer = try BodyFramer.init(head.framing, .{
        .line = &line,
        .trailers = &trailers,
        .fields = &fields,
    }, .{ .body_bytes = 64 });
    const framed = try framer.feed(bytes[head_len..], &body);
    try testing.expectEqual(.done, framed.status);
    try testing.expectEqual(bytes.len - head_len, framed.consumed);
    try testing.expectEqualStrings("a\x00b\xffz", body[0..framed.written]);
    try testing.expectEqualStrings("X-End: one\r\nx-end: two\r\n\r\n", framer.trailers().bytes);
}

test "v2 changed request regenerates length and removes stale representation digests" {
    var head_buffer: [1024]u8 = undefined;
    var tail_buffer: [256]u8 = undefined;
    var fields: [16]RequestHead.Field = undefined;
    var trailers: [8]RequestHead.Field = undefined;
    const wire = try Self.init(.{
        .head = "POST / HTTP/1.1\r\nHost: old\r\nContent-Length: 1\r\nDigest: old\r\n" ++
            "ETag: old\r\nContent-Encoding: gzip\r\n\r\n",
        .body = "expanded",
        .source_body_len = 1,
    }, .{ .authority = "new" }, .{
        .head = &head_buffer,
        .tail = &tail_buffer,
        .fields = &fields,
        .trailer_fields = &trailers,
    }, .{});
    try testing.expectEqualStrings("POST / HTTP/1.1\r\nHost: new\r\nContent-Encoding: gzip\r\n" ++
        "Via: 1.1 tero-edge\r\nContent-Length: 8\r\n\r\n", wire.parts[0]);
}
