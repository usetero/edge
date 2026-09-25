//! Connection driver for the std.Io-native frontend: owns one accepted TCP
//! connection end-to-end. Spawned as a concurrent task per
//! connection; written as straight blocking code against std.Io, so the
//! concurrency model is whatever Io implementation the composition root
//! selected.
//!
//! Transport glue only: it lifts a std.http.Server request into the
//! frontend-neutral `exchange.Inbound` + `paths.InboundBody`, and answers
//! through a `Sink` over `respondStreaming`. Routing, planning, the upstream
//! leg and every policy path are shared with the httpz frontend
//! (../paths.zig, ../exchange.zig, ../endpoints.zig).
//!
//! Per-connection memory is the slab's socket and staging buffers plus a
//! reset-retained arena for cold per-request data (duped head strings,
//! transforms). Body-sized scratch is per thread (../thread_bufs.zig): a
//! connection task runs to completion on one pool thread under the Threaded
//! Io, so thread-local scratch is per concurrent connection here too.
const std = @import("std");

const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const upstream_mod = @import("../upstream.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const conn_slab_mod = @import("../../core/conn_slab.zig");
const arena_pool_mod = @import("../../core/arena_pool.zig");
const limits_mod = @import("../../core/limits.zig");
const exchange = @import("../exchange.zig");
const paths = @import("../paths.zig");
const endpoints = @import("../endpoints.zig");
const deadline_reader_mod = @import("deadline_reader.zig");
const head_repair_mod = @import("head_repair.zig");

const Inbound = exchange.Inbound;
const InboundBody = paths.InboundBody;

const log = std.log.scoped(.conn);

// Named event payloads: the type name is the telemetry event name.
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// A connection refused before it carried a request, with the status sent.
const ConnectionShed = struct { reason: []const u8, answered: u16 };
/// An inbound read hit its deadline. `idle` is a keep-alive wait with no
/// request in flight; `request` means a partial request stalled, which drops
/// that request, so it answers 408 first.
const InboundTimeout = struct { phase: []const u8, answered: u16 };
/// A head std refused only over its `content-encoding` value, which we
/// rewrote and parsed again rather than answer 400 and lose the batch. Warned
/// once per cause: `reason` is the `head_repair.Reason` tag, and `encoding` is
/// what the sender sent.
const HeadRepaired = struct { encoding: []const u8, reason: []const u8 };
/// A head that failed to parse. Answered 400, then closed.
const RequestRejected = struct { reason: []const u8, answered: u16 };
/// The response was already on the wire when the request failed. The body
/// truncates and the connection closes, so the sender must retry: there is no
/// status left to change.
const ResponseTruncated = struct { path: []const u8, status: u16, err: []const u8 };
/// Even the fixed error response failed to reach the client.
const ResponseUndeliverable = struct { answered: u16, err: []const u8 };

/// Per-connection environment: the frontend-neutral shared context plus the
/// stdio frontend's own state (slab slot buffers, arena pool).
const Env = struct {
    shared: *exec.SharedCtx,
    slab: *conn_slab_mod.ConnSlab,
    arenas: *arena_pool_mod.ArenaPool,
    /// The inbound reader, so a body read that hit its deadline is reported
    /// as the client stall it is (408) instead of a generic read failure
    /// (502), which would point at the upstream.
    inbound: *deadline_reader_mod.DeadlineReader,
    /// Set for a request whose head we repaired: the `content-encoding` to
    /// decide and forward on, where the parsed head says something else.
    /// See `head_repair.Repaired.forward`.
    encoding_override: ?[]const u8 = null,
    /// The chunked request body of the current request, if any.
    chunked: ChunkedBody = .{},
};

/// A chunked request body read through std. std reports a sender that stops
/// before the last chunk as the end of the body; only the server state shows
/// that the body is partial. This reader fails that read instead, so the
/// upstream never gets the closing chunk of a partial body.
const ChunkedBody = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    inner: *std.Io.Reader = undefined,
    server: *const std.http.Server = undefined,
    /// Set when the body ended before its last chunk.
    truncated: bool = false,

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ChunkedBody = @alignCast(@fieldParentPtr("interface", r));
        return self.inner.stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => {
                if (self.server.reader.state == .ready) return error.EndOfStream;
                self.truncated = true;
                return error.ReadFailed;
            },
            else => |e| e,
        };
    }
};

/// The response side of the sink contract (exchange.zig) over a
/// std.http.Server request. `begin` opens a streaming response; `end`
/// terminates and flushes it. `status` is 0 until `begin` runs, which is how
/// the error path knows whether anything is on the wire yet.
pub const Sink = struct {
    request: *std.http.Server.Request,
    /// Staging for the response BodyWriter. The request body is fully
    /// consumed before `begin`, so its slab region is reused here.
    buffer: []u8,
    body: ?std.http.BodyWriter = null,
    /// Sink for a bodiless status, which is answered before the relay runs.
    discard: std.Io.Writer.Discarding = .init(&.{}),
    status: u16 = 0,

    /// 204 and 304 carry no body, and 1xx is interim. Streaming them frames
    /// a chunked body onto a status that must not have one, which some
    /// clients reject outright.
    fn isBodiless(status: u16) bool {
        return status == 204 or status == 304 or (status >= 100 and status < 200);
    }

    pub fn begin(self: *Sink, status: u16, headers: []const std.http.Header) !*std.Io.Writer {
        self.status = status;
        if (isBodiless(status)) {
            try self.request.respond("", .{
                .status = @enumFromInt(status),
                .extra_headers = headers,
            });
            // Nothing to write, and `end` has nothing to finish. The relay
            // still writes into this, so hand it a discard.
            self.discard = .init(&.{});
            return &self.discard.writer;
        }
        self.body = try self.request.respondStreaming(self.buffer, .{
            .respond_options = .{ .status = @enumFromInt(status), .extra_headers = headers },
        });
        return &self.body.?.writer;
    }

    pub fn end(self: *Sink) !void {
        const body = &(self.body orelse return);
        try body.end();
        try body.flush();
    }
};

/// Entry point spawned via Lifecycle.spawn. Only error.Canceled escapes;
/// everything else is handled by closing the connection.
pub fn serveConnection(
    shared: *exec.SharedCtx,
    slab: *conn_slab_mod.ConnSlab,
    arenas: *arena_pool_mod.ArenaPool,
    stream: std.Io.net.Stream,
) std.Io.Cancelable!void {
    const io = shared.io;
    defer stream.close(io);

    // `inbound` is filled once the slab slot provides its receive buffer.
    var env: Env = undefined;

    // A full slab still keeps a couple of slots back, so a health probe can
    // be read and answered during the spike that filled it. A connection
    // served from the reserve gets exactly one request, and only a control
    // path: anything else is shed after the head, not before it.
    var reserved = false;
    const conn_id = slab.claim(io) orelse claim_reserved: {
        if (slab.claimReserved(io)) |id| {
            reserved = true;
            break :claim_reserved id;
        }
        // Load shed: no slab slot at all. One fixed write, then close.
        if (shared.metrics) |metrics| metrics.recordConnectionShed(.slab_full);
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        shared.bus.warn(ConnectionShed{ .reason = "connection_slab_full", .answered = 503 });
        writeRawResponse(shared, io, stream, shed_response, 503);
        return;
    };
    defer slab.release(io, conn_id);
    // Tracks slab occupancy, so it pairs with the claim, not with the accept:
    // a shed connection never counts as active.
    if (shared.metrics) |metrics| metrics.recordConnectionsActive(1);
    defer if (shared.metrics) |metrics| metrics.recordConnectionsActive(-1);
    const arena_slot = arenas.claim(io);
    defer arenas.release(io, arena_slot);

    slab.trackSocket(io, conn_id, stream);
    var inbound: deadline_reader_mod.DeadlineReader = .init(io, stream, slab.recvBuf(conn_id));
    env = .{ .shared = shared, .slab = slab, .arenas = arenas, .inbound = &inbound };
    var net_writer = std.Io.net.Stream.Writer.init(stream, io, slab.sendBuf(conn_id));
    var server = std.http.Server.init(&inbound.interface, &net_writer.interface);

    while (server.reader.state == .ready) {
        env.encoding_override = null;
        env.chunked = .{};
        // Where this head starts in the receive buffer. `receiveHead` tosses
        // the head on success, which only moves `seek`, so on failure the
        // bytes are still there and `repairHead` can look at them.
        const head_start = inbound.interface.seek;
        var request = server.receiveHead() catch |err| repaired: {
            switch (err) {
                // Cancellation surfaces as ReadFailed through the reader, as
                // does a deadline; `inbound` says which.
                error.HttpConnectionClosing, error.ReadFailed => {
                    reportReadEnd(shared, io, stream, &inbound, err);
                    return;
                },
                // std refuses a whole head over one `content-encoding` value
                // it cannot name, and 400 makes the agent discard the batch.
                // Rewrite the value and parse again where that is the only
                // fault.
                error.HttpHeadersInvalid => {
                    if (repairHead(&env, &server, arena_slot, head_start)) |request_again| {
                        break :repaired request_again;
                    }
                },
                else => {},
            }
            // Malformed head: answer 400 on the raw writer and close.
            if (shared.metrics) |metrics| metrics.recordInvalidRequest();
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            shared.bus.warn(RequestRejected{ .reason = @errorName(err), .answered = 400 });
            const reject = "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            writeRawResponse(shared, io, stream, reject, 400);
            return;
        };
        if (reserved and !isControlPath(pathOf(request.head.target))) {
            // The reserve exists for the control paths. Everything else is
            // shed here, one step later than usual, with the same status.
            if (shared.metrics) |metrics| metrics.recordConnectionShed(.slab_full);
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            shared.bus.warn(ConnectionShed{ .reason = "connection_slab_full", .answered = 503 });
            request.respond("", .{
                .status = .service_unavailable,
                .keep_alive = false,
                .extra_headers = &.{.{ .name = "retry-after", .value = retry_after_value }},
            }) catch |err| {
                undeliverable(shared, 503, err);
            };
            return;
        }
        handleRequest(&env, conn_id, arena_slot, &request) catch |err| {
            // handleRequest already reported and answered what it could; this
            // only decides the connection's fate.
            log.debug("request handling failed: {s}", .{@errorName(err)});
            return; // connection state unknown; close it
        };
        inbound.endRequest();
        arenas.reset(arena_slot);
        // A reserved slot serves one request, so the next probe finds it free.
        if (reserved) return;
    }
}

/// One request: metrics bookkeeping around `dispatch`, and the bounded error
/// response when dispatch throws before anything reached the wire. Returns
/// the error afterwards so the caller closes the connection.
fn handleRequest(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
) !void {
    const ctx = env.shared;
    const arena = env.arenas.allocator(arena_slot);
    const start_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    if (ctx.metrics) |metrics| metrics.recordInFlight(1);
    defer if (ctx.metrics) |metrics| metrics.recordInFlight(-1);

    // Head strings die when the body reader is created; the target must
    // outlive that for the upstream leg, logs and metrics.
    const target = try arena.dupe(u8, originForm(request.head.target));
    const path = pathOf(target);
    const method = service_mod.HttpMethod.fromStd(request.head.method);
    const known_path = exec.classifyKnownPath(path, method);
    if (ctx.metrics) |metrics| {
        metrics.recordRequest(exec.methodLabel(method), known_path);
    }

    var sink: Sink = .{ .request = request, .buffer = env.slab.bodyBuf(conn_id) };
    var failed: ?anyerror = null;
    dispatch(env, conn_id, arena, request, target, path, method, &sink) catch |raw_err| {
        // The shared path reports a stalled read as a generic read failure.
        // Only this frontend knows the deadline fired, so name it here: the
        // sender stalled, the upstream did not.
        const client_stalled = env.inbound.expired == .request;
        const err = if (client_stalled)
            error.InboundBodyTimeout
        else if (env.chunked.truncated)
            error.InboundBodyTruncated
        else
            raw_err;
        if (client_stalled) {
            if (ctx.metrics) |metrics| metrics.recordInboundTimeout(.request);
        }
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.err(RequestFailed{
            .method = @tagName(request.head.method),
            .path = path,
            .err = @errorName(err),
        });
        if (ctx.metrics) |metrics| {
            metrics.recordRequestError(known_path, .uncaught);
        }
        failed = err;
        if (sink.status != 0) {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.warn(ResponseTruncated{
                .path = path,
                .status = sink.status,
                .err = @errorName(err),
            });
        } else {
            sink.status = exchange.errorStatus(err);
            request.respond("", .{
                .status = @enumFromInt(sink.status),
                .keep_alive = false,
            }) catch |respond_err| {
                log.debug("error response failed: {s}", .{@errorName(respond_err)});
            };
        }
    };

    paths.finishRequest(ctx, @tagName(request.head.method), path, known_path, sink.status, start_ns);
    if (failed) |err| return err;
}

fn dispatch(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    target: []const u8,
    path: []const u8,
    method: service_mod.HttpMethod,
    sink: *Sink,
) !void {
    const ctx = env.shared;

    // Claim the whole `/_edge/` namespace for every method, so no control
    // path falls through to the passthrough and reaches the intake.
    if (std.mem.startsWith(u8, path, "/_edge/") and request.head.method != .GET) {
        sink.status = 405;
        return request.respond("", .{ .status = .method_not_allowed });
    }
    if (std.mem.eql(u8, path, "/_edge/metrics")) {
        // std.http.Server keeps no counters of its own.
        return endpoints.metrics(ctx, sink, null);
    }
    if (std.mem.eql(u8, path, "/_edge/policies")) {
        const json = std.mem.eql(u8, queryParam(target, "format") orelse "", "json");
        return endpoints.policies(ctx, sink, json);
    }
    if (std.mem.startsWith(u8, path, "/_edge/tap/")) {
        const stage: exec.TapState.Stage = if (std.mem.eql(u8, path, "/_edge/tap/pre"))
            .pre
        else if (std.mem.eql(u8, path, "/_edge/tap/post"))
            .post
        else {
            sink.status = 404;
            return request.respond("", .{ .status = .not_found });
        };
        const n: u32 = if (queryParam(target, "n")) |raw| std.fmt.parseInt(u32, raw, 10) catch 50 else 50;
        return endpoints.recordTap(ctx, sink, stage, n);
    }
    if (std.mem.startsWith(u8, path, "/_edge/")) {
        sink.status = 404;
        return request.respond("", .{ .status = .not_found });
    }

    const outcome = exec.planRequest(
        ctx,
        method,
        path,
        request.head.content_type orelse "",
        env.encoding_override orelse exec.contentEncodingName(request.head.transfer_compression),
    ) orelse {
        sink.status = 404;
        return request.respond("", .{ .status = .not_found });
    };
    if (outcome == .respond) {
        const static = outcome.respond;
        sink.status = static.status;
        return request.respond(static.body, .{
            .status = @enumFromInt(static.status),
            .extra_headers = &.{
                .{ .name = "content-type", .value = static.content_type },
            },
        });
    }

    const headers_buf = try arena.alloc(std.http.Header, limits_mod.MAX_FORWARD_HEADERS);
    const in: Inbound = .{
        .method = request.head.method,
        .target = target,
        .path = path,
        .headers = try collectRequestHeaders(request, arena, headers_buf, env.encoding_override),
        .arena = arena,
    };
    const body = try inboundBodyOf(request, ctx.limits, env.slab.bodyBuf(conn_id), arena, &env.chunked);
    switch (outcome) {
        .respond => unreachable,
        .forward_raw => |fwd| try paths.execForwardRaw(ctx, in, sink, body, fwd),
        .pipe_stream => |pipe| try paths.execPipeStream(ctx, in, sink, body, pipe),
        .pipe_buffered => |pipe| try paths.execPipeBuffered(ctx, in, sink, body, pipe),
        .fetch_filtered => |fetch| try paths.execFetchFiltered(ctx, in, sink, body, fetch),
    }
}

fn pathOf(target: []const u8) []const u8 {
    const relative = originForm(target);
    const query_start = std.mem.findScalar(u8, relative, '?');
    return if (query_start) |i| relative[0..i] else relative;
}

/// `Retry-After` as a header value, from the one constant that sets it.
pub const retry_after_value = std.fmt.comptimePrint("{d}", .{limits_mod.SHED_RETRY_AFTER_SECONDS});

/// The fixed answer to a connection we cannot serve. 503 with `Retry-After`,
/// not 429: the edge ran out of connections process-wide, which is a condition
/// of this proxy and not an allowance we granted one sender. The OTLP spec
/// admits either status and scopes `Retry-After` to both, and collectors in
/// gateway mode already read 429 as a non-retryable tenant limit, so 429 here
/// would invite exactly that reading. The header is the part a sender acts on.
pub const shed_response =
    "HTTP/1.1 503 Service Unavailable\r\n" ++
    "content-length: 0\r\nconnection: close\r\n" ++
    "retry-after: " ++ retry_after_value ++ "\r\n\r\n";

/// The paths the edge answers itself. They never reach an upstream, so they
/// are the ones worth keeping a connection slot for.
fn isControlPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/_health") or std.mem.startsWith(u8, path, "/_edge/");
}

/// The origin-form of a request target. A sender behind a proxy setting
/// sends the absolute-form (`GET http://host/path HTTP/1.1`), and RFC 9112
/// §3.2.2 requires a server to accept it. Routing uses the path only.
fn originForm(target: []const u8) []const u8 {
    for ([_][]const u8{ "http://", "https://" }) |scheme| {
        if (!std.ascii.startsWithIgnoreCase(target, scheme)) continue;
        const after_scheme = target[scheme.len..];
        const slash = std.mem.findScalar(u8, after_scheme, '/') orelse return "/";
        return after_scheme[slash..];
    }
    return target;
}

/// Value of `name` in the target's query string, undecoded.
fn queryParam(target: []const u8, name: []const u8) ?[]const u8 {
    const query_start = std.mem.findScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[query_start + 1 ..], '&');
    while (it.next()) |pair| {
        if (pair.len > name.len and pair[name.len] == '=' and std.mem.eql(u8, pair[0..name.len], name)) {
            return pair[name.len + 1 ..];
        }
    }
    return null;
}

/// Classify the body and enforce max_body_size before the shared path sees
/// it. A Content-Length body stays on the socket as `.lazy`. A chunked body
/// stays on the socket as `.streamed` with `max_body_size` as its cap, so no
/// body-sized buffer lands in the per-connection arena. Invalidates the head
/// strings.
fn inboundBodyOf(
    request: *std.http.Server.Request,
    limits: limits_mod.Limits,
    buffer: []u8,
    arena: std.mem.Allocator,
    chunked: *ChunkedBody,
) !InboundBody {
    const head = request.head;
    if (!head.method.requestHasBody()) return .{ .bytes = "" };
    if (head.transfer_encoding == .chunked) {
        const reader = try request.readerExpectContinue(buffer);
        chunked.* = .{ .inner = reader, .server = request.server };
        return .{ .streamed = .{ .reader = &chunked.interface, .max_bytes = limits.max_body_size } };
    }
    const len = head.content_length orelse {
        // A request with neither framing header has no body (RFC 9112 §6.3).
        // std asserts that the body reader exists before a response, so make
        // it. It leaves the connection to close after the response.
        _ = try request.readerExpectContinue(buffer);
        return .{ .bytes = "" };
    };
    if (len == 0) return .{ .bytes = "" };
    if (len > limits.max_body_size) return error.BodyTooLarge;
    const reader = try request.readerExpectContinue(buffer);
    // A body at or below `large_body_buffer_size` stays resident, so a
    // transport failure can dial again. A larger body streams, is consumed by
    // its first send, and fails with 502 on a transport error; the Datadog
    // agent then retries it. A higher line costs one body-sized buffer per
    // concurrent request. httpz uses the same line (`lazy_read_size`).
    if (len <= limits.large_body_buffer_size) {
        var capture: std.Io.Writer.Allocating = try .initCapacity(arena, @intCast(len));
        // std reports a sender that closes before `len` bytes as the end of
        // the stream. That body is partial, so it must not pass as a batch.
        reader.streamExact64(&capture.writer, len) catch |err| return switch (err) {
            error.EndOfStream => error.InboundBodyTruncated,
            error.ReadFailed, error.WriteFailed => |e| e,
        };
        return .{ .bytes = capture.written() };
    }
    return .{ .lazy = .{ .reader = reader, .len = @intCast(len) } };
}

/// Arena copies of the headers to forward. Call before the body reader
/// exists: the body read overwrites the head. Where the head was repaired,
/// `encoding` replaces the `content-encoding` value.
fn collectRequestHeaders(
    request: *std.http.Server.Request,
    arena: std.mem.Allocator,
    buffer: []std.http.Header,
    encoding: ?[]const u8,
) ![]std.http.Header {
    var count: usize = 0;
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        // std keeps a bare LF inside a value. An upstream that ends a line on
        // LF would read a header that the name filter below never saw.
        if (std.mem.findAny(u8, header.value, "\r\n") != null) return error.InvalidRequestHeader;
        if (upstream_mod.shouldSkipRequestHeader(header.name)) continue;
        if (count >= buffer.len) return error.TooManyHeaders;
        const repaired = encoding != null and std.ascii.eqlIgnoreCase(header.name, "content-encoding");
        buffer[count] = .{
            .name = try arena.dupe(u8, header.name),
            // The repaired value is already in the arena; the rest of the head
            // is not, so it is duped here.
            .value = if (repaired) encoding.? else try arena.dupe(u8, header.value),
        };
        count += 1;
    }
    return buffer[0..count];
}

/// Parses a head std refused over its `content-encoding` value, and reports
/// it. Returns null when the head has any other fault, which leaves the
/// caller's 400 to answer.
///
/// The bytes are still in the receive buffer: `http.Reader.receiveHead` ends
/// with `toss`, which only moves the read cursor.
fn repairHead(
    env: *Env,
    server: *std.http.Server,
    arena_slot: u16,
    head_start: usize,
) ?std.http.Server.Request {
    const buffer = env.inbound.interface.buffer;
    const head_end = env.inbound.interface.seek;
    // `fillMore` may rebase the buffer while the head arrives, which leaves
    // the snapshot pointing at bytes that moved. `repair` checks that the
    // slice ends like a head and parses, so a stale span reads as
    // unrepairable and gets the 400.
    if (head_start >= head_end or head_end > buffer.len) return null;

    const fixed = head_repair_mod.repair(
        buffer[head_start..head_end],
        env.arenas.allocator(arena_slot),
    ) catch return null;

    // Warn once per cause for the whole process. The sender's spelling does
    // not change between requests, so the second line tells an operator
    // nothing the first did not, and a line per request at full rate is its
    // own outage.
    const shared = env.shared;
    const bit = @as(u8, 1) << @intFromEnum(fixed.reason);
    if (shared.head_repairs_seen.fetchOr(bit, .monotonic) & bit == 0) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        shared.bus.warn(HeadRepaired{ .encoding = fixed.encoding, .reason = @tagName(fixed.reason) });
    }
    env.encoding_override = fixed.forward;
    return .{
        .server = server,
        .head = fixed.head,
        .head_buffer = fixed.head_buffer,
    };
}

/// Reports why the read side ended, and answers when a request was in flight.
///
/// Three outcomes hide behind one error: the peer closed a keep-alive
/// connection (routine), our idle deadline reclaimed the slot (routine, but it
/// is the capacity signal), or a partial request stalled past the request
/// deadline. The last one drops a request the sender believes is in progress,
/// so it gets a 408 and a warn line.
fn reportReadEnd(
    shared: *exec.SharedCtx,
    io: std.Io,
    stream: std.Io.net.Stream,
    inbound: *deadline_reader_mod.DeadlineReader,
    err: anyerror,
) void {
    const phase = inbound.expired orelse {
        // No deadline fired: the peer went away, or we were canceled.
        log.debug("inbound read ended: {s}", .{@errorName(inbound.err orelse err)});
        return;
    };
    if (shared.metrics) |metrics| metrics.recordInboundTimeout(switch (phase) {
        .idle => .idle,
        .request => .request,
    });
    switch (phase) {
        .idle => {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            shared.bus.debug(InboundTimeout{ .phase = "idle", .answered = 0 });
        },
        .request => {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            shared.bus.warn(InboundTimeout{ .phase = "request", .answered = 408 });
            const timeout = "HTTP/1.1 408 Request Timeout\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            writeRawResponse(shared, io, stream, timeout, 408);
        },
    }
}

/// Fixed response on the raw stream, for failures before the HTTP state
/// machine can answer (load shed, malformed head, read deadline). A failure
/// here means the client never learned the status, which is the one drop we
/// cannot back-propagate, so it is logged rather than ignored.
pub fn writeRawResponse(
    shared: *exec.SharedCtx,
    io: std.Io,
    stream: std.Io.net.Stream,
    response: []const u8,
    status: u16,
) void {
    var buf: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, io, &buf);
    writer.interface.writeAll(response) catch |err| return undeliverable(shared, status, err);
    writer.interface.flush() catch |err| return undeliverable(shared, status, err);
}

fn undeliverable(shared: *exec.SharedCtx, status: u16, err: anyerror) void {
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    shared.bus.warn(ResponseUndeliverable{ .answered = status, .err = @errorName(err) });
}

// ============================== Tests ==============================

const testing = std.testing;

test "query parameters are read from the target" {
    try testing.expectEqualStrings("json", queryParam("/_edge/policies?format=json", "format").?);
    try testing.expectEqualStrings("20", queryParam("/_edge/tap/pre?x=1&n=20", "n").?);
    try testing.expectEqual(@as(?[]const u8, null), queryParam("/_edge/tap/pre?nn=20", "n"));
    try testing.expectEqual(@as(?[]const u8, null), queryParam("/_edge/tap/pre", "n"));
    try testing.expectEqualStrings("/a/b", pathOf("/a/b?c=d"));
    try testing.expectEqualStrings("/a/b", pathOf("/a/b"));
}

var test_chunked: ChunkedBody = .{};

/// Only `max_body_size` and `large_body_buffer_size` matter here. `resolve`
/// sets `large_body_buffer_size` to min(max_body_size, 64 KiB), so both are 128.
const test_limits: limits_mod.Limits = .resolve(.{ .max_body_size = 128, .max_connections = 4 });

/// Drives a `std.http.Server` from an in-memory raw request. The struct is
/// self-referential, so build it in place with `parseRequestInto` and never
/// return it by value.
const Parsed = struct {
    in_reader: std.Io.Reader,
    discard_buf: [16]u8 = undefined,
    discard: std.Io.Writer.Discarding,
    server: std.http.Server,
    request: std.http.Server.Request,
};

fn parseRequestInto(p: *Parsed, raw: []const u8) !void {
    p.in_reader = std.Io.Reader.fixed(raw);
    p.discard = std.Io.Writer.Discarding.init(&p.discard_buf);
    p.server = std.http.Server.init(&p.in_reader, &p.discard.writer);
    p.request = try p.server.receiveHead();
}

test "inboundBodyOf: chunked body stays on the socket as .streamed (no arena capture)" {
    const raw =
        "POST /forward HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "5\r\nhello\r\n" ++
        "6\r\n world\r\n" ++
        "0\r\n\r\n";
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const limits = test_limits;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cap_before = arena_state.queryCapacity();

    const body = try inboundBodyOf(&p.request, limits, &body_buf, arena, &test_chunked);

    // The body stays on the socket with the max_body_size cap.
    try testing.expect(body == .streamed);
    try testing.expectEqual(@as(usize, limits.max_body_size), body.streamed.max_bytes);
    // The arena capacity is unchanged: no body-sized retention.
    try testing.expectEqual(cap_before, arena_state.queryCapacity());

    // The pump yields the exact decoded body.
    var out_buf: [64]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);
    const n = try pipeline_mod.streamReaderToWriter(body.streamed.reader, &out_writer, limits.max_body_size);
    try testing.expectEqual(@as(usize, 11), n);
    try testing.expectEqualStrings("hello world", out_buf[0..n]);
}

test "inboundBodyOf: chunked body over max_body_size is rejected mid-stream" {
    // A chunked body larger than max_body_size fails with BodyTooLarge during
    // the pump.
    const raw =
        "POST /forward HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "\r\n" ++
        "80\r\n" ++ "a" ** 128 ++ "\r\n" ++ // 128 == max_body_size: this fits exactly
        "10\r\n" ++ "0123456789abcdef\r\n" ++ // 16 more bytes -> over cap
        "0\r\n\r\n";
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const limits = test_limits;

    const body = try inboundBodyOf(&p.request, limits, &body_buf, testing.allocator, &test_chunked);
    try testing.expect(body == .streamed);

    // The pump rejects the over-cap body; it does not truncate it.
    var sink: std.Io.Writer.Discarding = .init(&body_buf);
    try testing.expectError(
        error.BodyTooLarge,
        pipeline_mod.streamReaderToWriter(body.streamed.reader, &sink.writer, body.streamed.max_bytes),
    );
}

test "inboundBodyOf: a Content-Length body is never .streamed" {
    // A Content-Length body is `.bytes` at or below `large_body_buffer_size`,
    // so the batch stays replayable, and `.lazy` above it. It is never
    // `.streamed`.
    const raw =
        "POST /forward HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Content-Length: 11\r\n" ++
        "\r\n" ++
        "hello world";
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const limits = test_limits;

    // The resident capture allocates, so the test owns an arena.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 11 bytes, under the 128-byte test threshold: captured resident.
    const body = try inboundBodyOf(&p.request, limits, &body_buf, arena, &test_chunked);
    try testing.expect(body == .bytes);
    try testing.expectEqualStrings("hello world", body.bytes);

    // The same path above the threshold stays lazy on the socket.
    var small = limits;
    small.large_body_buffer_size = 4;
    var p2: Parsed = undefined;
    try parseRequestInto(&p2, raw);
    const lazy_body = try inboundBodyOf(&p2.request, small, &body_buf, arena, &test_chunked);
    try testing.expect(lazy_body == .lazy);
    try testing.expectEqual(@as(usize, 11), lazy_body.lazy.len);
}

test "inboundBodyOf: bodiless method yields empty .bytes" {
    const raw = "GET /forward HTTP/1.1\r\nHost: x\r\n\r\n";
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const limits = test_limits;

    const body = try inboundBodyOf(&p.request, limits, &body_buf, testing.allocator, &test_chunked);
    try testing.expect(body == .bytes);
    try testing.expectEqual(@as(usize, 0), body.bytes.len);
}

test "inboundBodyOf: Content-Length over max_body_size is rejected up front" {
    const raw =
        "POST /forward HTTP/1.1\r\n" ++
        "Host: x\r\n" ++
        "Content-Length: 4096\r\n" ++
        "\r\n" ++ "a" ** 4096;
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const limits = test_limits;

    try testing.expectError(
        error.BodyTooLarge,
        inboundBodyOf(&p.request, limits, &body_buf, testing.allocator, &test_chunked),
    );
}

fn pumpCutChunked(raw: []const u8, chunked: *ChunkedBody) !usize {
    var p: Parsed = undefined;
    try parseRequestInto(&p, raw);
    var body_buf: [256]u8 = undefined;
    const body = try inboundBodyOf(&p.request, test_limits, &body_buf, testing.allocator, chunked);
    try testing.expect(body == .streamed);
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    return pipeline_mod.streamReaderToWriter(body.streamed.reader, &out, test_limits.max_body_size);
}

const cut_head = "POST /forward HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";

test "inboundBodyOf: a chunked body cut short fails the pump" {
    // Cut between chunks and inside a chunk. Either way the pump fails, so
    // the closing chunk never goes upstream.
    for ([_][]const u8{ "5\r\nhello\r\n", "5\r\nhello\r\n6\r\n wo" }) |cut| {
        var chunked: ChunkedBody = .{};
        var raw_buf: [256]u8 = undefined;
        const raw = try std.fmt.bufPrint(&raw_buf, "{s}{s}", .{ cut_head, cut });
        try testing.expectError(error.ReadFailed, pumpCutChunked(raw, &chunked));
    }
}

test "ChunkedBody: an end of body before the last chunk is a failed read" {
    // std can report the end of a body that has not reached its last chunk.
    // The server state shows it: the head is received, the body is not done.
    var p: Parsed = undefined;
    try parseRequestInto(&p, cut_head);
    var inner: std.Io.Reader = .fixed("hello");
    var chunked: ChunkedBody = .{ .inner = &inner, .server = &p.server };
    var out_buf: [16]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.ReadFailed, pipeline_mod.streamReaderToWriter(&chunked.interface, &out, 64));
    try testing.expect(chunked.truncated);
    try testing.expectEqualStrings("hello", out.buffered());
}

test "inboundBodyOf: a whole chunked body is not truncated" {
    var chunked: ChunkedBody = .{};
    try testing.expectEqual(@as(usize, 5), try pumpCutChunked(cut_head ++ "5\r\nhello\r\n0\r\n\r\n", &chunked));
    try testing.expect(!chunked.truncated);
}
