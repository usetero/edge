//! The upstream leg of an httpz request: open a connection, send the body,
//! receive the head, relay the response. Free functions on `SharedCtx` with
//! no dependency on the httpz `Handler`, so another frontend can adopt them.
const std = @import("std");
const httpz = @import("httpz");
const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const upstream_mod = @import("../upstream.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const thread_bufs = @import("thread_bufs.zig");

const ThreadBufs = thread_bufs.ThreadBufs;

// Named event payloads: the type name is the telemetry event name.
const UpstreamRetried = struct { path: []const u8, err: []const u8 };
/// A pooled connection failed and was destroyed instead of re-pooled.
const UpstreamConnectionEvicted = struct { path: []const u8, err: []const u8 };
/// The upstream answered before the body was fully sent and stopped reading;
/// the send failed but a real status was already on the wire.
const UpstreamEarlyResponse = struct { path: []const u8, status: u16, err: []const u8 };

/// What goes upstream: a slice httpz already buffered, or a body still on
/// the inbound socket with its declared length. A stream is consumed by the
/// first send and is never retried.
pub const BodySource = union(enum) {
    bytes: []const u8,
    stream: struct { reader: *std.Io.Reader, len: usize },
};

/// Upper bound on forwarded request headers; excess is an error, not a
/// truncation.
const max_forward_headers = 64;

/// Forwardable request headers into an arena-owned array. `iter` is any
/// iterator whose `next()` yields `.{ .key, .value }`.
fn collectForwardHeaders(arena: std.mem.Allocator, iter: anytype) ![]std.http.Header {
    const out = try arena.alloc(std.http.Header, max_forward_headers);
    var it = iter;
    var count: usize = 0;
    while (it.next()) |kv| {
        if (upstream_mod.shouldSkipRequestHeader(kv.key)) continue;
        if (count >= out.len) return error.TooManyHeaders;
        out[count] = .{ .name = kv.key, .value = kv.value };
        count += 1;
    }
    return out[0..count];
}

pub fn serviceMethod(method: httpz.Method) service_mod.HttpMethod {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        .CONNECT, .OTHER => .OTHER,
    };
}

fn stdMethod(method: httpz.Method) ?std.http.Method {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        .CONNECT => .CONNECT,
        .OTHER => null,
    };
}

/// Single-attempt open on the pooled client; the scrape path uses this.
pub fn openUpstream(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    arena: std.mem.Allocator,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    const method = stdMethod(req.method) orelse return error.UnsupportedMethod;
    const headers = try collectForwardHeaders(arena, req.headers.iterator());
    return exec.openUpstream(ctx, arena, method, req.url.raw, headers, choice);
}

/// Open the upstream request, dialing a second time if the first dial fails.
/// A failed dial has sent nothing, so this is safe regardless of the body's
/// replayability or the error's name. (Seen as a 1-in-5000 `Unexpected` at
/// startup when every handler dials at once; std hides the errno.)
fn dialUpstream(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    method: std.http.Method,
    headers: []const std.http.Header,
    choice: service_mod.UpstreamChoice,
    client: *std.http.Client,
) !std.http.Client.Request {
    return exec.openUpstreamWithClient(ctx, res.arena, method, req.url.raw, headers, choice, client) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.info(UpstreamRetried{ .path = req.url.path, .err = @errorName(err) });
        return exec.openUpstreamWithClient(ctx, res.arena, method, req.url.raw, headers, choice, client);
    };
}

/// Send `body` upstream and relay the response into `res`.
///
/// Retry: a replayable buffered body (or a bodiless method) gets a second
/// attempt on a fresh connection after a transport failure. A stream cannot
/// be replayed and never retries.
pub fn exchange(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    choice: service_mod.UpstreamChoice,
    body: BodySource,
    replayable: bool,
) !void {
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const headers = try collectForwardHeaders(res.arena, req.headers.iterator());
    const method = stdMethod(req.method) orelse return error.UnsupportedMethod;
    if (body == .stream) _ = try bufs.ensurePump(ctx.gpa);
    const retry = body == .bytes and (replayable or method == .GET or method == .HEAD);
    const attempts: usize = if (retry) 2 else 1;
    for (0..attempts) |attempt| {
        const client = if (attempt == 0) ctx.upstreams.getHttpClient() else &ctx.upstreams.retry_client;
        if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(attempt > 0);
        var upstream_req = try dialUpstream(ctx, req, res, method, headers, choice, client);
        defer upstream_req.deinit();
        thread_bufs.trackUpstream(ctx.io, bufs, upstream_req.connection);
        defer thread_bufs.trackUpstream(ctx.io, bufs, null);

        var upstream_res = sendAndReceiveHead(&upstream_req, method, body, bufs) catch |err| blk: {
            // An intake that rejects a request answers as soon as it has seen
            // the headers and stops reading, so our write fails while its
            // response is already in our socket. Relay that instead of a 502.
            // Only for write-side failures: on anything else the peer may
            // never answer, and receiveHead would block until the watchdog.
            if (!bufs.timed_out.load(.acquire) and isSendSideFailure(err)) {
                if (upstream_req.receiveHead(&.{})) |early| {
                    markUpstreamClosing(&upstream_req); // peer stopped reading mid-body
                    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                    ctx.bus.info(UpstreamEarlyResponse{
                        .path = req.url.path,
                        .status = @intFromEnum(early.head.status),
                        .err = @errorName(err),
                    });
                    break :blk early;
                } else |_| {}
            }
            evictUpstream(ctx, &upstream_req, req.url.path, err);
            if (bufs.timed_out.load(.acquire)) return error.UpstreamTimeout;
            if (!retryableTransportError(err)) return err;
            if (attempt + 1 == attempts) return error.UpstreamTransportFailed;
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.info(UpstreamRetried{ .path = req.url.path, .err = @errorName(err) });
            continue;
        };

        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(choice));
        relayResponse(res, &upstream_res, max_response, bufs) catch |err| {
            if (bufs.timed_out.load(.acquire)) {
                evictUpstream(ctx, &upstream_req, req.url.path, err);
                return error.UpstreamTimeout;
            }
            switch (err) {
                error.BodyTooLarge => {
                    evictUpstream(ctx, &upstream_req, req.url.path, err);
                    return error.UpstreamResponseTooLarge;
                },
                error.ReadFailed => evictUpstream(ctx, &upstream_req, req.url.path, err),
                else => {},
            }
            return err;
        };
        return;
    }
    unreachable;
}

fn relayResponse(
    res: *httpz.Response,
    upstream_res: *std.http.Client.Response,
    max_response_body: usize,
    bufs: *ThreadBufs,
) !void {
    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exec.collectUpstreamResponseHeaders(upstream_res, res.arena, &extra_headers);
    res.status = @intFromEnum(upstream_res.head.status);
    for (relayed) |header| res.header(header.name, header.value);
    const upstream_body = upstream_res.reader(bufs.upstream);
    _ = try pipeline_mod.streamReaderToWriter(upstream_body, res.writer(), max_response_body);
}

/// Destroy a failed pooled connection and record it, so the next request
/// dials fresh instead of reusing a dead keep-alive.
pub fn evictUpstream(
    ctx: *exec.SharedCtx,
    upstream_req: *std.http.Client.Request,
    path: []const u8,
    err: anyerror,
) void {
    markUpstreamClosing(upstream_req);
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    ctx.bus.warn(UpstreamConnectionEvicted{ .path = path, .err = @errorName(err) });
}

/// std.http.Client only evicts on the receive side; a send-side failure
/// would return the dead connection to the pool (ziglang/zig#30165).
fn markUpstreamClosing(upstream_req: *std.http.Client.Request) void {
    if (upstream_req.connection) |conn| conn.closing = true;
}

fn sendAndReceiveHead(
    request: *std.http.Client.Request,
    method: std.http.Method,
    body: BodySource,
    bufs: *ThreadBufs,
) !std.http.Client.Response {
    try sendBody(request, method, body, bufs);
    return request.receiveHead(&.{});
}

/// Exact content-length send. A stream pumps client socket -> upstream socket
/// through the thread's pump buffer; nothing body-sized is ever resident.
fn sendBody(
    upstream_req: *std.http.Client.Request,
    method: std.http.Method,
    body: BodySource,
    bufs: *ThreadBufs,
) !void {
    if (!method.requestHasBody()) return upstream_req.sendBodiless();
    const len = switch (body) {
        .bytes => |b| b.len,
        .stream => |st| st.len,
    };
    upstream_req.transfer_encoding = .{ .content_length = len };
    const write_buf = switch (body) {
        .bytes => bufs.upstream,
        .stream => bufs.pump, // sized by exchange() before the send
    };
    std.debug.assert(write_buf.len > 0);
    var body_writer = try upstream_req.sendBodyUnflushed(write_buf);
    switch (body) {
        .bytes => |b| try body_writer.writer.writeAll(b),
        .stream => |st| try st.reader.streamExact(&body_writer.writer, st.len),
    }
    try body_writer.end();
    try upstream_req.connection.?.flush();
}

/// The peer's read side went away while we were writing — the only case
/// where an early response can be waiting in the socket.
fn isSendSideFailure(err: anyerror) bool {
    return switch (err) {
        error.WriteFailed, error.BrokenPipe, error.ConnectionResetByPeer => true,
        else => false,
    };
}

fn retryableTransportError(err: anyerror) bool {
    return switch (err) {
        error.HttpConnectionClosing,
        error.WriteFailed,
        error.ReadFailed,
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.UnexpectedEndOfStream,
        error.AddressUnavailable,
        error.ConnectionRefused,
        error.HostUnreachable,
        error.NetworkUnreachable,
        error.NetworkDown,
        error.Timeout,
        => true,
        else => false,
    };
}

// ============================== Tests ==============================

const testing = std.testing;

test "a failed exchange marks the upstream connection closing" {
    // std only marks a connection closing once the head arrived; a send or
    // head-phase failure leaves reader.state == .ready, which std re-pools.
    var connection: std.http.Client.Connection = undefined;
    connection.closing = false;
    var request: std.http.Client.Request = undefined;
    request.connection = &connection;
    markUpstreamClosing(&request);
    try testing.expect(connection.closing);

    // A request that never obtained a connection must not fault.
    var connectionless: std.http.Client.Request = undefined;
    connectionless.connection = null;
    markUpstreamClosing(&connectionless);
}

test "head-phase protocol failures are not replayable" {
    // A half-read head leaves the response framing indeterminate, so the
    // exchange fails rather than replaying onto a fresh connection.
    // `HttpRequestTruncated` is also what a watchdog socket shutdown produces
    // once some head bytes arrived, which is why the timeout check precedes
    // this classification in `exchange`.
    for ([_]anyerror{
        error.HttpHeadersOversize,
        error.HttpRequestTruncated,
        error.HttpHeadersInvalid,
        error.HttpChunkInvalid,
        error.HttpChunkTruncated,
    }) |err| {
        try testing.expect(!retryableTransportError(err));
    }
    // A pooled connection the peer already closed carries no response bytes,
    // so it is the one head-phase failure worth replaying.
    try testing.expect(retryableTransportError(error.HttpConnectionClosing));
}

test "httpz method maps onto service and std methods" {
    try testing.expectEqual(service_mod.HttpMethod.POST, serviceMethod(.POST));
    try testing.expectEqual(service_mod.HttpMethod.OTHER, serviceMethod(.CONNECT));
    try testing.expectEqual(@as(?std.http.Method, .GET), stdMethod(.GET));
    try testing.expectEqual(@as(?std.http.Method, null), stdMethod(.OTHER));
}

test "only transport failures are replayable" {
    try testing.expect(retryableTransportError(error.HttpConnectionClosing));
    try testing.expect(retryableTransportError(error.ConnectionResetByPeer));
    try testing.expect(retryableTransportError(error.ConnectionRefused));
    try testing.expect(!retryableTransportError(error.OutOfMemory));
    try testing.expect(!retryableTransportError(error.UnsupportedUriScheme));
}

const HeaderPair = struct { key: []const u8, value: []const u8 };

const FakeHeaderIter = struct {
    pairs: []const HeaderPair,
    pos: usize = 0,
    fn next(self: *FakeHeaderIter) ?HeaderPair {
        if (self.pos == self.pairs.len) return null;
        defer self.pos += 1;
        return self.pairs[self.pos];
    }
};

test "collectForwardHeaders drops hop-by-hop headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const pairs = [_]HeaderPair{
        .{ .key = "host", .value = "drop" }, // hop-by-hop
        .{ .key = "dd-api-key", .value = "secret" },
        .{ .key = "content-length", .value = "9" }, // hop-by-hop
        .{ .key = "transfer-encoding", .value = "chunked" }, // hop-by-hop
        .{ .key = "x-keep", .value = "yes" },
    };
    const iter: FakeHeaderIter = .{ .pairs = &pairs };
    const headers = try collectForwardHeaders(arena.allocator(), iter);

    try testing.expectEqual(@as(usize, 2), headers.len);
    try testing.expectEqualStrings("dd-api-key", headers[0].name);
    try testing.expectEqualStrings("secret", headers[0].value);
    try testing.expectEqualStrings("x-keep", headers[1].name);
}

test "only write-side failures are probed for an early upstream response" {
    // These mean the peer's read side went away mid-body, the one situation
    // where a response can already be sitting in our socket.
    try testing.expect(isSendSideFailure(error.WriteFailed));
    try testing.expect(isSendSideFailure(error.BrokenPipe));
    try testing.expect(isSendSideFailure(error.ConnectionResetByPeer));
    // Anything else and the peer may never answer; probing would block the
    // handler on a read until the upstream watchdog fires.
    try testing.expect(!isSendSideFailure(error.ConnectionRefused));
    try testing.expect(!isSendSideFailure(error.HostUnreachable));
    try testing.expect(!isSendSideFailure(error.ReadFailed));
    try testing.expect(!isSendSideFailure(error.UnexpectedEndOfStream));
    try testing.expect(!isSendSideFailure(error.HttpConnectionClosing));
}
