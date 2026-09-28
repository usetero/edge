//! Prepare raw final responses in pinned request storage before publishing completion.

const std = @import("std");
const Response = @import("Response.zig");
const ResponseHead = @import("ResponseHead.zig");
const ResponseIngress = @import("ResponseIngress.zig");
const RequestTable = @import("RequestTable.zig");
const WorkChannel = @import("WorkChannel.zig");
const http_field = @import("http_field.zig");

pub const Client = struct { version: std.http.Version = .@"HTTP/1.1", keep_alive: bool = true, changed: bool = false };
pub const Limits = struct { head_bytes: u32 = 16 * 1024, fields: u16 = 64 };

/// Only complete original entities are supported. Receive the body directly into
/// buffers.body; all other input/scratch and output spans must be disjoint. On
/// error discard generated metadata; it is never a publishable response prefix.
pub fn prepare(
    ingress: *const ResponseIngress,
    buffers: Response.Buffers,
    client: Client,
    limits: Limits,
) !Response.Lengths {
    var message = try ingress.message();
    message.changed = client.changed;
    if (message.body.len > buffers.body.len or
        (message.body.len > 0 and message.body.ptr != buffers.body.ptr)) return error.WrongBodyStorage;
    const chunked = hasTrailers(message);
    if (chunked and client.version == .@"HTTP/1.0") return error.TrailersUnsupported;
    const close = client.version == .@"HTTP/1.0" or !client.keep_alive;
    var head_len = writeHead(message, buffers.head, client, limits, chunked, close) catch |err| {
        return if (err == error.WriteFailed) error.HeadTooLarge else err;
    };
    if (chunked and message.body.len > 0) {
        const line = std.fmt.bufPrint(buffers.head[head_len..], "{x}\r\n", .{message.body.len}) catch
            return error.OutputTooSmall;
        head_len += line.len;
    }
    const tail_len = if (chunked) writeTail(message, buffers.tail) catch return error.TailTooLarge else 0;
    return .{
        .head = std.math.cast(u32, head_len) orelse return error.ResponseTooLarge,
        .body = @intCast(message.body.len),
        .tail = std.math.cast(u32, tail_len) orelse return error.ResponseTooLarge,
        .close = close,
    };
}

/// Frame an already validated external entity; its file owner supplies the body
/// between these head and tail spans. This path always closes the client socket.
pub fn prepareFile(message: ResponseIngress.Message, buffers: Response.Buffers, client: Client) !Response.Lengths {
    const length = message.external_body_len orelse return error.MissingExternalLength;
    const chunked = hasTrailers(message);
    if (chunked and client.version == .@"HTTP/1.0") return error.TrailersUnsupported;
    var head_len = try writeHead(message, buffers.head, client, .{}, chunked, true);
    if (chunked and length > 0) {
        const prefix = try std.fmt.bufPrint(buffers.head[head_len..], "{x}\r\n", .{length});
        head_len += prefix.len;
    }
    const tail_len = if (chunked) try writeTail(message, buffers.tail) else 0;
    return .{ .head = @intCast(head_len), .body = 0, .tail = @intCast(tail_len), .close = true };
}

fn hasTrailers(message: ResponseIngress.Message) bool {
    for (message.trailers.fields) |field| {
        if (!dropTrailer(field, message)) return true;
    }
    return false;
}

fn dropTrailer(field: http_field.Field, message: ResponseIngress.Message) bool {
    const name = field.name.slice(message.trailers.bytes);
    return http_field.nominated(name, message.head.bytes, message.head.fields) or
        (message.changed and http_field.representationField(name));
}

fn writeHead(
    message: ResponseIngress.Message,
    buffer: []u8,
    client: Client,
    limits: Limits,
    chunked: bool,
    close: bool,
) !usize {
    var builder: HeadBuilder = .{
        .writer = .fixed(buffer[0..@min(buffer.len, limits.head_bytes)]),
        .limit = limits.fields,
    };
    const writer = &builder.writer;
    const head = message.head.metadata;
    try writer.print("{t} {d} {s}\r\n", .{ client.version, head.status, head.reason.slice(message.head.bytes) });
    for (message.head.fields) |field| {
        const name = field.name.slice(message.head.bytes);
        if (transportField(name) or http_field.nominated(name, message.head.bytes, message.head.fields)) continue;
        if (client.changed and http_field.representationField(name)) continue;
        try builder.field(name, field.value.slice(message.head.bytes));
    }
    try builder.field("Via", if (head.version == .@"HTTP/1.1") "1.1 tero-edge" else "1.0 tero-edge");
    if (chunked) {
        try builder.field("Transfer-Encoding", "chunked");
        try builder.begin("Trailer");
        var first = true;
        for (message.trailers.fields) |field| {
            if (dropTrailer(field, message)) continue;
            if (!first) try writer.writeAll(", ");
            try writer.writeAll(field.name.slice(message.trailers.bytes));
            first = false;
        }
        try writer.writeAll("\r\n");
    } else {
        // HEAD/304 lengths describe the representation, not the empty wire body.
        const length: ?u64 = if (head.framing == .none) head.content_length else (message.external_body_len orelse message.body.len);
        if (length) |value| {
            try builder.begin("Content-Length");
            try writer.print("{d}\r\n", .{value});
        }
    }
    if (close) try builder.field("Connection", "close");
    try writer.writeAll("\r\n");
    return writer.buffered().len;
}

fn writeTail(message: ResponseIngress.Message, buffer: []u8) !usize {
    var writer: std.Io.Writer = .fixed(buffer);
    if ((message.external_body_len orelse message.body.len) > 0) try writer.writeAll("\r\n");
    try writer.writeAll("0\r\n");
    for (message.trailers.fields) |field| {
        if (dropTrailer(field, message)) continue;
        try writer.print("{s}: {s}\r\n", .{
            field.name.slice(message.trailers.bytes), field.value.slice(message.trailers.bytes),
        });
    }
    try writer.writeAll("\r\n");
    return writer.buffered().len;
}

/// Shared with informational rewriting so transport metadata has one filter.
pub fn transportField(name: []const u8) bool {
    const names = [_][]const u8{
        "content-length", "transfer-encoding", "connection", "keep-alive",         "proxy-connection",
        "te",             "trailer",           "upgrade",    "proxy-authenticate", "proxy-authorization",
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
    upstream_head: [1024]u8 = undefined,
    body: [128]u8 = undefined,
    line: [128]u8 = undefined,
    trailers: [512]u8 = undefined,
    fields: [64]http_field.Field = undefined,
    trailer_fields: [16]http_field.Field = undefined,
    head: [2048]u8 = undefined,
    tail: [1024]u8 = undefined,

    fn receiver(self: *Fixture, method: ResponseHead.Method) !ResponseIngress {
        return self.receiverIn(method, &self.body);
    }

    fn receiverIn(self: *Fixture, method: ResponseHead.Method, body: []u8) !ResponseIngress {
        return .init(.{
            .head = &self.upstream_head,
            .body = body,
            .line = &self.line,
            .trailers = &self.trailers,
            .fields = &self.fields,
            .trailer_fields = &self.trailer_fields,
        }, method, .{ .head_bytes = 1024, .body_bytes = @intCast(body.len) });
    }

    fn buffers(self: *Fixture) Response.Buffers {
        return .{ .head = &self.head, .body = &self.body, .tail = &self.tail };
    }
};

test "v2 response wire retains status cookies opaque encoding and authentication" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 299 Custom\r\nContent-Length: 3\r\nContent-Encoding: alien\r\n" ++
        "Set-Cookie: a=1\r\nset-cookie: b=2\r\nWWW-Authenticate: Bearer\r\nConnection: close\r\n\r\na\x00b");
    const lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    const response = try Response.init(fixture.buffers(), lengths);
    try testing.expectEqualStrings("HTTP/1.1 299 Custom\r\nContent-Encoding: alien\r\n" ++
        "Set-Cookie: a=1\r\nset-cookie: b=2\r\nWWW-Authenticate: Bearer\r\n" ++
        "Via: 1.1 tero-edge\r\nContent-Length: 3\r\n\r\n", response.parts[0]);
    try testing.expectEqualStrings("a\x00b", response.parts[1]);
    try testing.expectEqual(@intFromPtr(&fixture.body), @intFromPtr(response.parts[1].ptr));
    try testing.expect(!response.close);
}

test "v2 response wire filters connection metadata and regenerates ordered trailers" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Drop: before\r\n" ++
        "Connection: X-Drop\r\nConnection: X-End\r\nTrailer: X-End, X-Keep\r\n\r\n" ++
        "3\r\nabc\r\n0\r\nX-End: drop\r\nX-Keep: one\r\nx-keep: two\r\n\r\n");
    const lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    const response = try Response.init(fixture.buffers(), lengths);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nVia: 1.1 tero-edge\r\n" ++
        "Transfer-Encoding: chunked\r\nTrailer: X-Keep, x-keep\r\n\r\n3\r\n", response.parts[0]);
    try testing.expectEqualStrings("\r\n0\r\nX-Keep: one\r\nx-keep: two\r\n\r\n", response.parts[2]);
}

test "v2 response wire preserves HEAD and 304 metadata length and omits 204 framing" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.head);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n");
    var lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nVia: 1.1 tero-edge\r\n" ++
        "Content-Length: 99999\r\n\r\n", fixture.head[0..lengths.head]);
    try testing.expectEqual(0, lengths.body);
    ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 304 Not Modified\r\nContent-Length: 888\r\n\r\n");
    lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    try testing.expectEqualStrings("HTTP/1.1 304 Not Modified\r\nVia: 1.1 tero-edge\r\n" ++
        "Content-Length: 888\r\n\r\n", fixture.head[0..lengths.head]);
    ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 204 Empty\r\n\r\n");
    lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    try testing.expectEqualStrings("HTTP/1.1 204 Empty\r\nVia: 1.1 tero-edge\r\n\r\n", fixture.head[0..lengths.head]);
}

test "v2 response wire requires complete body in destination storage" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nab");
    try testing.expectError(error.IncompleteResponse, prepare(&ingress, fixture.buffers(), .{}, .{}));
    _ = try ingress.feed("c");
    var other: [128]u8 = undefined;
    var buffers = fixture.buffers();
    buffers.body = &other;
    try testing.expectError(error.WrongBodyStorage, prepare(&ingress, buffers, .{}, .{}));
}

test "v2 response wire closes HTTP 1.0 and refuses silently lost trailers" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\n\r\nabc");
    try ingress.finish(.clean_eof);
    const client: Client = .{ .version = .@"HTTP/1.0" };
    const lengths = try prepare(&ingress, fixture.buffers(), client, .{});
    try testing.expect(lengths.close);
    try testing.expectEqualStrings("HTTP/1.0 200 OK\r\nVia: 1.1 tero-edge\r\n" ++
        "Content-Length: 3\r\nConnection: close\r\n\r\n", fixture.head[0..lengths.head]);
    ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-End: yes\r\n\r\n");
    try testing.expectError(error.TrailersUnsupported, prepare(&ingress, fixture.buffers(), client, .{}));
}

test "v2 response wire completion retains all spans after forwarder scratch reuse" {
    for ([_]bool{ false, true }) |detached| {
        var table: RequestTable = try .init(testing.allocator, .{
            .requests = 1,
            .head_bytes = 64,
            .body_bytes = 0,
            .response_bytes = 128,
            .response_head_bytes = 1024,
            .response_tail_bytes = 256,
        });
        defer table.deinit(testing.allocator);
        var channel: WorkChannel = try .init(testing.allocator, .{ .capacity = 1 });
        defer channel.deinit(testing.allocator);
        defer channel.close(testing.io);
        const request = table.acquire().?;
        try testing.expect(try channel.reserve(&table, request));
        try channel.submit(testing.io, &table, request, .{
            .head_len = 0,
            .body_len = 0,
            .deadline = .{ .nanoseconds = 1 },
        });
        const job = (try channel.take(testing.io)).?;
        var fixture: Fixture = .{};
        var ingress = try fixture.receiverIn(.ordinary, job.response);
        _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: a=1\r\n\r\n" ++
            "3\r\na\x00b\r\n0\r\nX-End: yes\r\n\r\n");
        const lengths = try prepare(&ingress, job.responseBuffers(), .{ .keep_alive = false }, .{});
        try testing.expectError(error.InvalidTransition, table.responseView(request, lengths));
        if (detached) try table.disconnect(request);
        channel.publish(testing.io, job, .{ .framed_response = lengths });
        @memset(&fixture.upstream_head, 'x');
        @memset(&fixture.trailers, 'x');
        ingress = undefined;
        const completion = channel.receive(testing.io).?;
        try testing.expect(table.acquire() == null);
        try testing.expectError(error.InvalidTransition, table.responseView(request, lengths));
        try channel.acknowledge(&table, completion);
        if (detached) {
            try testing.expectError(error.StaleRequest, table.responseView(request, lengths));
        } else {
            try testing.expect(table.acquire() == null);
            var invalid = completion.outcome.framed_response;
            invalid.head = table.capacity.response_head_bytes + 1;
            try testing.expectError(error.InvalidResponseLength, table.responseView(request, invalid));
            var response = try table.responseView(request, completion.outcome.framed_response);
            try testing.expect(response.close);
            var output: [2048]u8 = undefined;
            const wire = try collect(&response, &output, 1);
            try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nVia: 1.1 tero-edge\r\n" ++
                "Transfer-Encoding: chunked\r\nTrailer: X-End\r\nConnection: close\r\n\r\n" ++
                "3\r\na\x00b\r\n0\r\nX-End: yes\r\n\r\n", wire);
            // A fresh downstream receiver must see the same binary body/trailers.
            var downstream = try fixture.receiver(.ordinary);
            const received = try downstream.feed(wire);
            try testing.expectEqual(wire.len, received.consumed);
            const message = try downstream.message();
            try testing.expectEqualStrings("a\x00b", message.body);
            try testing.expectEqualStrings("X-End: yes\r\n\r\n", message.trailers.bytes);
            try table.finishResponse(request);
        }
        const reused = table.acquire().?;
        try testing.expect(reused.generation != request.generation);
        try testing.expectError(error.StaleRequest, table.responseView(request, lengths));
        try table.disconnect(reused);
    }
}

fn collect(response: *Response, output: []u8, window: usize) ![]const u8 {
    var writer: std.Io.Writer = .fixed(output);
    while (response.pending().len > 0) {
        const bytes = response.pending();
        const count = @min(window, bytes.len);
        try writer.writeAll(bytes[0..count]);
        try response.advance(count);
    }
    return writer.buffered();
}

test "v2 response wire empty chunk trailers and filtered trailer sets frame correctly" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-End: yes\r\n\r\n");
    const lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    try testing.expectEqualStrings("0\r\nX-End: yes\r\n\r\n", fixture.tail[0..lengths.tail]);
    try testing.expectEqual(0, lengths.body);
    const empty_len = lengths.head;
    var raw_head: [2048]u8 = undefined;
    @memcpy(raw_head[0..empty_len], fixture.head[0..empty_len]);
    for (1..32) |window| {
        var response = try Response.init(fixture.buffers(), lengths);
        try response.advance(0);
        try testing.expectError(error.InvalidWriteLength, response.advance(lengths.head + 1));
        var output: [4096]u8 = undefined;
        const wire = try collect(&response, &output, window);
        try testing.expectEqualStrings(raw_head[0..empty_len], wire[0..empty_len]);
        try testing.expectEqualStrings("0\r\nX-End: yes\r\n\r\n", wire[empty_len..]);
        try response.advance(0);
        try testing.expectError(error.InvalidWriteLength, response.advance(1));
    }
    ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: X-End\r\n\r\n" ++
        "0\r\nX-End: yes\r\n\r\n");
    const filtered = try prepare(&ingress, fixture.buffers(), .{ .version = .@"HTTP/1.0" }, .{});
    try testing.expectEqual(0, filtered.tail);
    try testing.expectEqualStrings("HTTP/1.0 200 OK\r\nVia: 1.1 tero-edge\r\n" ++
        "Content-Length: 0\r\nConnection: close\r\n\r\n", fixture.head[0..filtered.head]);
}

test "v2 response wire validates output capacities without truncation" {
    var fixture: Fixture = .{};
    var ingress = try fixture.receiver(.ordinary);
    _ = try ingress.feed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
    const lengths = try prepare(&ingress, fixture.buffers(), .{}, .{});
    var buffers = fixture.buffers();
    buffers.head = buffers.head[0..lengths.head];
    buffers.tail = buffers.tail[0..lengths.tail];
    const head_len: u32 = lengths.head - 3;
    _ = try prepare(&ingress, buffers, .{}, .{ .head_bytes = head_len, .fields = 3 });
    try testing.expectError(error.HeadTooLarge, prepare(&ingress, buffers, .{}, .{ .head_bytes = head_len - 1 }));
    try testing.expectError(error.TooManyHeaders, prepare(&ingress, buffers, .{}, .{ .fields = 2 }));
    buffers.head = buffers.head[0 .. lengths.head - 1];
    try testing.expectError(error.OutputTooSmall, prepare(&ingress, buffers, .{}, .{}));
    buffers.head = &fixture.head;
    buffers.tail = buffers.tail[0 .. lengths.tail - 1];
    try testing.expectError(error.TailTooLarge, prepare(&ingress, buffers, .{}, .{}));
    try testing.expectError(error.InvalidResponseLength, Response.init(buffers, lengths));
    buffers = fixture.buffers();
    buffers.body = buffers.body[0..2];
    try testing.expectError(error.WrongBodyStorage, prepare(&ingress, buffers, .{}, .{}));
    try testing.expectError(error.InvalidResponseLength, Response.init(buffers, lengths));
}
