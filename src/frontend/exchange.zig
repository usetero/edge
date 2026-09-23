//! The upstream leg of a request: open a connection, send the body, receive
//! the head, relay the response. Frontend-neutral: the request arrives as an
//! `Inbound` and the response leaves through a `sink` (contract below), so
//! the httpz and stdio frontends share every retry, eviction and early-
//! response rule here.
const std = @import("std");
const exec = @import("exec.zig");
const service_mod = @import("../service/service.zig");
const upstream_mod = @import("upstream.zig");
const pipeline_mod = @import("../pipeline/pipeline.zig");
const thread_bufs = @import("thread_bufs.zig");
const limits_mod = @import("../core/limits.zig");

const ThreadBufs = thread_bufs.ThreadBufs;

// Named event payloads: the type name is the telemetry event name.
const UpstreamConnectionError = struct { err: []const u8, phase: []const u8 };
const UpstreamRetried = struct { path: []const u8, err: []const u8 };
/// A pooled connection failed and was destroyed instead of re-pooled.
const UpstreamConnectionEvicted = struct { path: []const u8, err: []const u8 };
/// The upstream answered before the body was fully sent and stopped reading;
/// the send failed but a real status was already on the wire.
const UpstreamEarlyResponse = struct { path: []const u8, status: u16, err: []const u8 };
/// The watchdog cut this attempt off at its deadline. Without this line the
/// request reports a generic transport failure, and nothing names the stalled
/// intake as the cause.
const UpstreamTimedOut = struct { path: []const u8, phase: []const u8 };
/// A dial slow enough to matter. `std.http.Client` takes no connect timeout,
/// so a stalled dial holds its handler thread and the watchdog has no socket
/// to interrupt; this line is the only way to see one.
const UpstreamDialSlow = struct { path: []const u8, ms: f64 };

/// Dial warn threshold. A pooled connection dials in microseconds and a cold
/// TCP plus TLS handshake to a public intake costs tens of milliseconds, so a
/// whole second means the dial is stalling.
const dial_slow_ns: i128 = std.time.ns_per_s;

/// The parts of an inbound request the upstream leg needs, already lifted
/// out of whatever HTTP server produced it.
pub const Inbound = struct {
    method: std.http.Method,
    /// Path plus query, forwarded to the upstream verbatim.
    target: []const u8,
    /// Path only, for logs and metrics.
    path: []const u8,
    /// Forwardable request headers (hop-by-hop already dropped).
    headers: []const std.http.Header,
    /// Per-request arena; freed by the frontend after the response.
    arena: std.mem.Allocator,
};

// Response sink contract. Duck-typed: any `sink` passed to functions here
// must provide
//
//     fn begin(self, status: u16, headers: []const std.http.Header) !*std.Io.Writer
//     fn end(self) !void
//
// `begin` commits status and headers and returns the body writer; `end`
// finishes the body. Each frontend has a small adapter.

/// What goes upstream. The first send consumes a `lazy` or `streamed` body,
/// so neither is retried.
pub const BodySource = union(enum) {
    /// Fully buffered by the frontend. Zero-copy slice.
    bytes: []const u8,
    /// Still on the client socket. `len` is the declared Content-Length. The
    /// frontend already checked it against max_body_size.
    lazy: struct { reader: *std.Io.Reader, len: usize },
    /// Still on the client socket with no declared length (chunked). The pump
    /// enforces `max_bytes` and forwards the body as chunked. The policy paths
    /// drain it through `paths.residentBody`.
    streamed: struct { reader: *std.Io.Reader, max_bytes: usize },
};

/// Upper bound on forwarded request headers; excess is an error, not a
/// truncation.
const max_forward_headers = limits_mod.MAX_FORWARD_HEADERS;

/// Forwardable request headers into an arena-owned array. `iter` is any
/// iterator whose `next()` yields `.{ .key, .value }`.
pub fn collectForwardHeaders(arena: std.mem.Allocator, iter: anytype) ![]std.http.Header {
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

/// Bounded HTTP status for an error that escaped a request path; every
/// frontend answers with this when nothing has reached the wire yet.
pub fn errorStatus(err: anyerror) u16 {
    return switch (err) {
        // The raw cap is actionable: the sender can split the batch. A
        // decoded-size overrun fails open in paths.zig instead, because the
        // sender cannot see our decode budget and the agent discards a 413
        // permanently.
        error.BodyTooLarge, error.DecodedBodyTooLarge => 413,
        // Retryable: the agent can send the whole batch again, and it
        // discards a batch for good on 400.
        error.InboundBodyTimeout, error.InboundBodyTruncated => 408,
        error.InvalidRequestBody, error.InvalidRequestHeader => 400,
        // Our cap, and the sender can act on it. A 5xx would send an agent
        // into a retry loop against a request that can never succeed.
        error.TooManyHeaders => 431,
        error.UpstreamTimeout => 504,
        error.UpstreamResponseTruncated => 502,
        error.OutOfMemory, error.WriteFailed => 503,
        else => 502,
    };
}

/// Single-attempt open on the pooled client; the scrape path uses this.
pub fn openUpstream(
    ctx: *exec.SharedCtx,
    in: Inbound,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    return open(ctx, in, choice, &ctx.upstreams.http_client);
}

/// Opens a request against the configured upstream on `client`. The retry
/// path gives the client that keeps no idle connections. `in.headers` must be
/// hop-by-hop-filtered and stay valid for the request life. `in.target` goes
/// upstream verbatim.
fn open(
    ctx: *exec.SharedCtx,
    in: Inbound,
    choice: service_mod.UpstreamChoice,
    client: *std.http.Client,
) !std.http.Client.Request {
    const query_start = std.mem.findScalar(u8, in.target, '?');
    const path = if (query_start) |i| in.target[0..i] else in.target;
    const query = if (query_start) |i| in.target[i + 1 ..] else "";

    const upstream_id = ctx.upstream_ids.resolve(choice);
    const uri_str = try ctx.upstreams.buildUpstreamUri(in.arena, upstream_id, path, query);
    const uri = try std.Uri.parse(uri_str);

    return client.request(in.method, uri, .{
        .extra_headers = in.headers,
        .redirect_behavior = .unhandled,
        .headers = .{ .accept_encoding = .omit },
    }) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.err(UpstreamConnectionError{ .err = @errorName(err), .phase = "connect" });
        return err;
    };
}

/// Collects the upstream response headers a frontend relays to the client.
/// It skips hop-by-hop and transport-owned headers. It copies the values
/// into the arena, because the head strings die when the body reader exists.
pub fn collectUpstreamResponseHeaders(
    upstream_res: *std.http.Client.Response,
    arena: std.mem.Allocator,
    buffer: []std.http.Header,
) ![]std.http.Header {
    // RFC 7230 §6.1: headers listed in the Connection field are hop-by-hop
    // and must not be forwarded. Collect all Connection-option tokens first.
    var conn_opts: std.ArrayList([]const u8) = .empty;
    {
        var it = upstream_res.head.iterateHeaders();
        while (it.next()) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
            var tok_it = std.mem.tokenizeScalar(u8, header.value, ',');
            while (tok_it.next()) |tok| {
                const name = std.mem.trim(u8, tok, " \t");
                if (name.len > 0) try conn_opts.append(arena, name);
            }
        }
    }

    var count: usize = 0;
    var it = upstream_res.head.iterateHeaders();
    while (it.next()) |header| {
        if (upstream_mod.shouldSkipResponseHeader(header.name)) continue;
        // Also skip any header nominated as hop-by-hop via Connection.
        var skip = false;
        for (conn_opts.items) |opt| {
            if (std.ascii.eqlIgnoreCase(header.name, opt)) {
                skip = true;
                break;
            }
        }
        if (skip) continue;
        if (count >= buffer.len) break;
        buffer[count] = .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        };
        count += 1;
    }
    return buffer[0..count];
}

/// Open the upstream request, dialing a second time if the first dial fails.
/// A failed dial has sent nothing, so this is safe regardless of the body's
/// replayability or the error's name. (Seen as a 1-in-5000 `Unexpected` at
/// startup when every handler dials at once; std hides the errno.)
fn dialUpstream(
    ctx: *exec.SharedCtx,
    in: Inbound,
    choice: service_mod.UpstreamChoice,
    client: *std.http.Client,
) !std.http.Client.Request {
    const started_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    defer {
        const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - started_ns;
        if (elapsed_ns >= dial_slow_ns) {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.warn(UpstreamDialSlow{
                .path = in.path,
                .ms = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_ms,
            });
        }
    }
    return open(ctx, in, choice, client) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.info(UpstreamRetried{ .path = in.path, .err = @errorName(err) });
        // Counted like any other retry: a dial storm is invisible otherwise,
        // since only this log line records it.
        if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(true);
        return open(ctx, in, choice, client);
    };
}

/// Report a watchdog timeout: warn on the bus, count it, and return the one
/// error `errorStatus` maps to 504. Every path that arms the watchdog must
/// return its timeout through here, or a stall reads as a 502.
pub fn timedOut(ctx: *exec.SharedCtx, path: []const u8, phase: []const u8) error{UpstreamTimeout} {
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    ctx.bus.warn(UpstreamTimedOut{ .path = path, .phase = phase });
    if (ctx.metrics) |metrics| metrics.recordUpstreamTimeout();
    return error.UpstreamTimeout;
}

/// Send `body` upstream and relay the response into `res`.
///
/// Retry: a replayable buffered body (or a bodiless method) gets a second
/// attempt on a fresh connection after a transport failure. A stream cannot
/// be replayed and never retries.
pub fn exchange(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    choice: service_mod.UpstreamChoice,
    body: BodySource,
    replayable: bool,
) !void {
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    if (body == .lazy or body == .streamed) _ = try bufs.ensurePump(ctx.gpa);
    const retry = body == .bytes and (replayable or in.method == .GET or in.method == .HEAD);
    const attempts: usize = if (retry) 2 else 1;
    for (0..attempts) |attempt| {
        const client = if (attempt == 0) &ctx.upstreams.http_client else &ctx.upstreams.retry_client;
        if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(attempt > 0);
        var upstream_req = try dialUpstream(ctx, in, choice, client);
        defer upstream_req.deinit();
        thread_bufs.trackUpstream(ctx.io, bufs, upstream_req.connection);
        defer thread_bufs.trackUpstream(ctx.io, bufs, null);

        var upstream_res = sendAndReceiveHead(&upstream_req, in.method, body, bufs) catch |err| blk: {
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
                        .path = in.path,
                        .status = @intFromEnum(early.head.status),
                        .err = @errorName(err),
                    });
                    break :blk early;
                } else |_| {}
            }
            // Our cap on a streamed body, hit mid-send: half the body is
            // upstream, so the connection must close, but the upstream did
            // nothing wrong and must not be reported as evicted.
            if (err == error.BodyTooLarge) {
                markUpstreamClosing(&upstream_req);
                return err;
            }
            evictUpstream(ctx, &upstream_req, in.path, err);
            if (bufs.timed_out.load(.acquire)) return timedOut(ctx, in.path, "head");
            if (!retryableTransportError(err)) return err;
            if (attempt + 1 == attempts) return error.UpstreamTransportFailed;
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.info(UpstreamRetried{ .path = in.path, .err = @errorName(err) });
            continue;
        };

        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(choice));
        relayResponse(sink, in.arena, &upstream_res, max_response, bufs) catch |err| {
            if (bufs.timed_out.load(.acquire)) {
                evictUpstream(ctx, &upstream_req, in.path, err);
                return timedOut(ctx, in.path, "relay");
            }
            switch (err) {
                error.BodyTooLarge => {
                    evictUpstream(ctx, &upstream_req, in.path, err);
                    return error.UpstreamResponseTooLarge;
                },
                error.ReadFailed => evictUpstream(ctx, &upstream_req, in.path, err),
                else => {},
            }
            return err;
        };
        return;
    }
    unreachable;
}

fn relayResponse(
    sink: anytype,
    arena: std.mem.Allocator,
    upstream_res: *std.http.Client.Response,
    max_response_body: usize,
    bufs: *ThreadBufs,
) !void {
    var extra_headers: [64]std.http.Header = undefined;
    // Read before the body reader exists: creating it invalidates the head.
    const declared = upstream_res.head.content_length;
    const relayed = try collectUpstreamResponseHeaders(upstream_res, arena, &extra_headers);
    const out = try sink.begin(@intFromEnum(upstream_res.head.status), relayed);
    const upstream_body = upstream_res.reader(bufs.upstream);
    const copied = try pipeline_mod.streamReaderToWriter(upstream_body, out, max_response_body);
    // An intake that declares more than it sends has not accepted the batch.
    // The status is already on the wire, so the only honest signal is to fail
    // here: the frontend then closes without finishing the body, and the
    // sender retries instead of recording a success.
    if (declared) |want| {
        if (copied < want) return error.UpstreamResponseTruncated;
    }
    try sink.end();
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

/// Send the request body upstream. A buffered slice goes out with an exact
/// content-length. A `lazy` or `streamed` source pumps socket to socket
/// through the pump buffer that `exchange` sized. The `streamed` pump enforces
/// `max_bytes` mid-stream, because the frontend had no length to pre-check.
fn sendBody(
    upstream_req: *std.http.Client.Request,
    method: std.http.Method,
    body: BodySource,
    bufs: *ThreadBufs,
) !void {
    if (!method.requestHasBody()) return upstream_req.sendBodiless();
    // `lazy` and `streamed` read into the thread's pump buffer; `bytes` reuses
    // the upstream write buffer (the body is already resident).
    const write_buf = switch (body) {
        .bytes => bufs.upstream,
        .lazy, .streamed => bufs.pump,
    };
    std.debug.assert(write_buf.len > 0);
    upstream_req.transfer_encoding = switch (body) {
        .bytes => |b| .{ .content_length = b.len },
        .lazy => |st| .{ .content_length = st.len },
        .streamed => .chunked,
    };
    var body_writer = try upstream_req.sendBodyUnflushed(write_buf);
    switch (body) {
        .bytes => |b| try body_writer.writer.writeAll(b),
        .lazy => |st| try st.reader.streamExact(&body_writer.writer, st.len),
        .streamed => |ch| _ = try pipeline_mod.streamReaderToWriter(ch.reader, &body_writer.writer, ch.max_bytes),
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

test "collectUpstreamResponseHeaders strips hop-by-hop Connection and transport headers" {
    const response_bytes = "HTTP/1.1 200 OK\r\n" ++
        "content-type: application/json\r\n" ++
        "connection: close\r\n" ++
        "x-foo: bar\r\n" ++
        "content-length: 42\r\n" ++
        "transfer-encoding: chunked\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var upstream_res: std.http.Client.Response = .{ .request = undefined, .head = head };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buffer: [16]std.http.Header = undefined;
    const relayed = try collectUpstreamResponseHeaders(&upstream_res, arena.allocator(), &buffer);

    // Exactly the two end-to-end headers survive; hop-by-hop Connection and
    // transport-owned content-length/transfer-encoding are dropped.
    try testing.expectEqual(@as(usize, 2), relayed.len);

    var saw_content_type = false;
    var saw_x_foo = false;
    for (relayed) |header| {
        try testing.expect(!upstream_mod.shouldSkipResponseHeader(header.name));
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            try testing.expectEqualStrings("application/json", header.value);
            saw_content_type = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-foo")) {
            try testing.expectEqualStrings("bar", header.value);
            saw_x_foo = true;
        } else {
            return error.UnexpectedRelayedHeader;
        }
    }
    try testing.expect(saw_content_type);
    try testing.expect(saw_x_foo);
}

test "collectUpstreamResponseHeaders strips Connection-nominated hop-by-hop headers" {
    // An upstream that uses Connection: X-Upstream-State to mark a
    // per-connection field.  That field must not be relayed downstream.
    const response_bytes = "HTTP/1.1 200 OK\r\n" ++
        "content-type: text/plain\r\n" ++
        "connection: X-Upstream-State, Keep-Alive\r\n" ++
        "x-upstream-state: active\r\n" ++
        "keep-alive: timeout=5\r\n" ++
        "x-end-to-end: ok\r\n" ++
        "content-length: 5\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var upstream_res: std.http.Client.Response = .{ .request = undefined, .head = head };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buffer: [16]std.http.Header = undefined;
    const relayed = try collectUpstreamResponseHeaders(&upstream_res, arena.allocator(), &buffer);

    // Only the two genuine end-to-end headers should survive.
    // content-length, connection, x-upstream-state, and keep-alive are all dropped.
    try testing.expectEqual(@as(usize, 2), relayed.len);

    var saw_content_type = false;
    var saw_x_end_to_end = false;
    for (relayed) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            try testing.expectEqualStrings("text/plain", header.value);
            saw_content_type = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-end-to-end")) {
            try testing.expectEqualStrings("ok", header.value);
            saw_x_end_to_end = true;
        } else {
            return error.UnexpectedRelayedHeader;
        }
    }
    try testing.expect(saw_content_type);
    try testing.expect(saw_x_end_to_end);
}
