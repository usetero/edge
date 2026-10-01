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
const failure_capture = @import("failure_capture.zig");

const ThreadBufs = thread_bufs.ThreadBufs;

// Named event payloads: the type name is the telemetry event name.
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
/// The failure dump could not be written. The request still fails as it did.
const UpstreamFailureCaptureFailed = struct { path: []const u8, err: []const u8 };
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

/// What goes upstream: a slice the frontend already buffered, or a body still
/// on the inbound socket with its declared length. A stream is consumed by the
/// first send and is never retried.
pub const BodySource = union(enum) {
    bytes: []const u8,
    stream: struct { reader: *std.Io.Reader, len: usize },
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
    return exec.openUpstream(ctx, in.arena, in.method, in.target, in.headers, choice);
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
    return exec.openUpstreamWithClient(ctx, in.arena, in.method, in.target, in.headers, choice, client) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.info(UpstreamRetried{ .path = in.path, .err = @errorName(err) });
        // Counted like any other retry: a dial storm is invisible otherwise,
        // since only this log line records it.
        if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(true);
        return exec.openUpstreamWithClient(ctx, in.arena, in.method, in.target, in.headers, choice, client);
    };
}

/// Record a watchdog timeout: the warn line names the phase and the path, the
/// counter makes the rate alertable.
fn timedOut(ctx: *exec.SharedCtx, path: []const u8, phase: []const u8) error{UpstreamTimeout} {
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
    const capture = ctx.failure_capture orelse return exchangeAttempts(ctx, in, sink, choice, body, replayable, null);

    // A streamed body is gone once it is sent, so keep a copy while it goes.
    // A full capture directory skips the copy; the failure still reaches
    // `record`, which reports the full directory.
    var tee: ?failure_capture.Tee = null;
    const sent: BodySource = switch (body) {
        .bytes => body,
        .stream => |st| if (!capture.armed()) body else blk: {
            tee = .{ .inner = st.reader, .copy = try .initCapacity(in.arena, st.len) };
            break :blk .{ .stream = .{ .reader = &tee.?.interface, .len = st.len } };
        },
    };
    const started_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    var report: Report = .{};
    const tee_ptr = if (tee) |*t| t else null;
    exchangeAttempts(ctx, in, sink, choice, sent, replayable, &report) catch |err| {
        // A sender that left mid-relay is not an upstream failure. A dump
        // would spend the budget on the disconnect, unless the status it
        // missed is one we capture anyway.
        if (!report.downstream_failed or failure_capture.capturesStatus(report.status)) {
            recordFailure(ctx, capture, in, choice, body, tee_ptr, report, err, started_ns);
        }
        return err;
    };
    if (failure_capture.capturesStatus(report.status)) {
        recordFailure(ctx, capture, in, choice, body, tee_ptr, report, null, started_ns);
    }
}

/// Dumps a batch a policy stage could not read. The untouched forward that
/// follows usually succeeds, so without this the input that broke the decoder
/// is gone. `phase` names the stage.
pub fn recordFailOpen(
    ctx: *exec.SharedCtx,
    in: Inbound,
    choice: service_mod.UpstreamChoice,
    raw_body: []const u8,
    phase: []const u8,
    err: anyerror,
) void {
    const capture = ctx.failure_capture orelse return;
    const url = exec.upstreamUri(ctx, in.arena, in.target, choice) catch |uri_err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(UpstreamFailureCaptureFailed{ .path = in.path, .err = @errorName(uri_err) });
        return;
    };
    capture.record(ctx.bus, in.arena, .{
        .method = in.method,
        .target = in.target,
        .path = in.path,
        .url = url,
        .headers = in.headers,
        .framing = .content_length,
        .body = raw_body,
        .declared_len = raw_body.len,
        .complete = true,
        .status = null,
        .err = @errorName(err),
        .phase = phase,
        .attempts = 0,
        .retried_err = null,
        .watchdog_fired = false,
        .elapsed_ms = 0,
    });
}

/// What `exchangeAttempts` saw, for a failure dump.
const Report = struct {
    phase: []const u8 = "dial",
    status: ?u16 = null,
    attempts: usize = 0,
    retried_err: ?anyerror = null,
    /// The relay failed on the sender's side: it left before the answer did.
    downstream_failed: bool = false,
};

fn recordFailure(
    ctx: *exec.SharedCtx,
    capture: *failure_capture.Capture,
    in: Inbound,
    choice: service_mod.UpstreamChoice,
    body: BodySource,
    /// Null for a buffered body, or when the directory was full at the start.
    tee: ?*failure_capture.Tee,
    report: Report,
    err: ?anyerror,
    started_ns: i96,
) void {
    const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - started_ns;
    const url = exec.upstreamUri(ctx, in.arena, in.target, choice) catch |uri_err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(UpstreamFailureCaptureFailed{ .path = in.path, .err = @errorName(uri_err) });
        return;
    };
    const has_body = in.method.requestHasBody();
    const bytes, const complete = switch (body) {
        .bytes => |b| .{ b, true },
        .stream => |st| if (tee) |t|
            .{ t.copy.written(), !t.copy_failed and t.copy.written().len == st.len }
        else
            .{ "", false },
    };
    const declared: usize = switch (body) {
        .bytes => |b| b.len,
        .stream => |st| st.len,
    };
    const watchdog_fired = if (thread_bufs.get(ctx.io, ctx.gpa, ctx.limits)) |bufs|
        bufs.timed_out.load(.acquire)
    else |_|
        false;
    capture.record(ctx.bus, in.arena, .{
        .method = in.method,
        .target = in.target,
        .path = in.path,
        .url = url,
        .headers = in.headers,
        .framing = if (has_body) .content_length else .none,
        .body = bytes,
        .declared_len = if (has_body) declared else null,
        .complete = complete,
        .status = report.status,
        .err = if (err) |e| @errorName(e) else null,
        .phase = report.phase,
        .attempts = report.attempts,
        .retried_err = if (report.retried_err) |e| @errorName(e) else null,
        .watchdog_fired = watchdog_fired,
        .elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_ms,
    });
}

/// The attempt loop behind `exchange`. `report`, when set, records how far
/// the exchange got.
fn exchangeAttempts(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    choice: service_mod.UpstreamChoice,
    body: BodySource,
    replayable: bool,
    report_out: ?*Report,
) !void {
    var unused: Report = .{};
    const report = report_out orelse &unused;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    if (body == .stream) _ = try bufs.ensurePump(ctx.gpa);
    const retry = body == .bytes and (replayable or in.method == .GET or in.method == .HEAD);
    const attempts: usize = if (retry) 2 else 1;
    for (0..attempts) |attempt| {
        const client = if (attempt == 0) ctx.upstreams.getHttpClient() else &ctx.upstreams.retry_client;
        if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(attempt > 0);
        report.attempts = attempt + 1;
        report.phase = "dial";
        var upstream_req = try dialUpstream(ctx, in, choice, client);
        defer upstream_req.deinit();
        thread_bufs.trackUpstream(ctx.io, bufs, upstream_req.connection);
        defer thread_bufs.trackUpstream(ctx.io, bufs, null);

        report.phase = "send_or_head";
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
            evictUpstream(ctx, &upstream_req, in.path, err);
            if (bufs.timed_out.load(.acquire)) return timedOut(ctx, in.path, "head");
            if (!retryableTransportError(err)) return err;
            if (attempt + 1 == attempts) return error.UpstreamTransportFailed;
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.info(UpstreamRetried{ .path = in.path, .err = @errorName(err) });
            report.retried_err = err;
            continue;
        };
        report.status = @intFromEnum(upstream_res.head.status);

        report.phase = "relay";
        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(choice));
        relayResponse(sink, in.arena, &upstream_res, max_response, bufs) catch |err| {
            // During the relay only the sink writes, so this is the sender.
            if (err == error.WriteFailed) report.downstream_failed = true;
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
        report.phase = "response";
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
    const relayed = try exec.collectUpstreamResponseHeaders(upstream_res, arena, &extra_headers);
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
