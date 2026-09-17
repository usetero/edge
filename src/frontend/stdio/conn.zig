//! Connection driver for the std.Io-native frontend: owns one accepted TCP
//! connection end-to-end (PLAN.md §9). Spawned as a concurrent task per
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
const runtime_metrics = @import("../../runtime/runtime_metrics.zig");
const exchange = @import("../exchange.zig");
const paths = @import("../paths.zig");
const endpoints = @import("../endpoints.zig");
const deadline_reader_mod = @import("deadline_reader.zig");

const Inbound = exchange.Inbound;
const InboundBody = paths.InboundBody;

const log = std.log.scoped(.conn);

// Named event payloads: the type name is the telemetry event name.
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// Per-request trace at debug level.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };
/// Same shape at warn level, for a request that held its connection task.
const RequestSlow = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };
/// A connection refused before it carried a request, with the 503 sent.
const ConnectionShed = struct { reason: []const u8, answered: u16 };
/// An inbound read hit its deadline. `idle` is a keep-alive wait with no
/// request in flight; `request` means a partial request stalled, which drops
/// that request, so it answers 408 first.
const InboundTimeout = struct { phase: []const u8, answered: u16 };
/// A head that failed to parse. Answered 400, then closed.
const RequestRejected = struct { reason: []const u8, answered: u16 };
/// The response was already on the wire when the request failed. The body
/// truncates and the connection closes, so the sender must retry: there is no
/// status left to change.
const ResponseTruncated = struct { path: []const u8, status: u16, err: []const u8 };
/// Even the fixed error response failed to reach the client.
const ResponseUndeliverable = struct { answered: u16, err: []const u8 };

/// Warn past this, matching the httpz frontend: `RequestCompleted` is debug
/// level, which production turns off.
const slow_request_seconds: f64 = 5;

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
        const shed = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        writeRawResponse(shared, io, stream, shed, 503);
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
        var request = server.receiveHead() catch |err| switch (err) {
            // Cancellation surfaces as ReadFailed through the reader, as does
            // a deadline; `inbound` says which.
            error.HttpConnectionClosing, error.ReadFailed => {
                reportReadEnd(shared, io, stream, &inbound, err);
                return;
            },
            else => {
                // Malformed head (incl. unsupported content-encoding, see
                // wiring-notes): answer 400 on the raw writer and close.
                if (shared.metrics) |metrics| metrics.recordInvalidRequest();
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                shared.bus.warn(RequestRejected{ .reason = @errorName(err), .answered = 400 });
                const reject = "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                writeRawResponse(shared, io, stream, reject, 400);
                return;
            },
        };
        if (reserved and !isControlPath(pathOf(request.head.target))) {
            // The reserve exists for the control paths. Everything else is
            // shed here, one step later than usual, with the same status.
            if (shared.metrics) |metrics| metrics.recordConnectionShed(.slab_full);
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            shared.bus.warn(ConnectionShed{ .reason = "connection_slab_full", .answered = 503 });
            request.respond("", .{ .status = .service_unavailable, .keep_alive = false }) catch |err| {
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
    dispatch(env, conn_id, arena, request, target, &sink) catch |raw_err| {
        // The shared path reports a stalled read as a generic read failure.
        // Only this frontend knows the deadline fired, so name it here: the
        // sender stalled, the upstream did not.
        const client_stalled = env.inbound.expired == .request;
        const err = if (client_stalled) error.InboundBodyTimeout else raw_err;
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
        }
        if (sink.status == 0) {
            sink.status = exchange.errorStatus(err);
            request.respond("", .{
                .status = @enumFromInt(sink.status),
                .keep_alive = false,
            }) catch |respond_err| {
                log.debug("error response failed: {s}", .{@errorName(respond_err)});
            };
        }
    };

    const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    if (ctx.metrics) |metrics| {
        metrics.recordRequestDuration(known_path, elapsed_s);
        metrics.recordResponse(known_path, runtime_metrics.statusClass(sink.status));
    }
    if (elapsed_s >= slow_request_seconds) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(RequestSlow{
            .method = @tagName(request.head.method),
            .path = path,
            .status = sink.status,
            .duration_ms = elapsed_s * std.time.ms_per_s,
        });
    } else {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.debug(RequestCompleted{
            .method = @tagName(request.head.method),
            .path = path,
            .status = sink.status,
            .duration_ms = elapsed_s * std.time.ms_per_s,
        });
    }
    if (failed) |err| return err;
}

fn dispatch(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena: std.mem.Allocator,
    request: *std.http.Server.Request,
    target: []const u8,
    sink: *Sink,
) !void {
    const ctx = env.shared;
    const path = pathOf(target);
    const method = service_mod.HttpMethod.fromStd(request.head.method);

    // Claim the whole namespace whatever the method. Matching only GET let
    // `POST /_edge/metrics` fall through to the wildcard passthrough and
    // travel to the intake, the same way `POST /_health` did.
    if (std.mem.startsWith(u8, path, "/_edge/") and request.head.method != .GET) {
        sink.status = 405;
        return request.respond("", .{ .status = .method_not_allowed });
    }
    if (request.head.method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) {
        // std.http.Server keeps no counters of its own.
        return endpoints.metrics(ctx, sink, null);
    }
    if (request.head.method == .GET and std.mem.eql(u8, path, "/_edge/policies")) {
        const json = std.mem.eql(u8, queryParam(target, "format") orelse "", "json");
        return endpoints.policies(ctx, sink, json);
    }
    if (request.head.method == .GET and std.mem.startsWith(u8, path, "/_edge/tap/")) {
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
        exec.contentEncodingName(request.head.transfer_compression),
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

    const headers_buf = try arena.alloc(std.http.Header, 64);
    const in: Inbound = .{
        .method = request.head.method,
        .target = target,
        .path = path,
        .headers = try collectRequestHeaders(request, arena, headers_buf),
        .arena = arena,
    };
    const body = try inboundBodyOf(request, ctx.limits, env.slab.bodyBuf(conn_id), arena);
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

/// The paths the edge answers itself. They never reach an upstream, so they
/// are the ones worth keeping a connection slot for.
fn isControlPath(path: []const u8) bool {
    return std.mem.eql(u8, path, "/_health") or std.mem.startsWith(u8, path, "/_edge/");
}

/// The origin-form of a request target.
///
/// A sender configured with a proxy sends the absolute-form
/// (`GET http://host/path HTTP/1.1`), which RFC 9112 §3.2.2 requires a server
/// to accept. Treating the whole URL as a path routed it to the wildcard
/// passthrough and shipped a mangled target upstream, so `/_health` behind a
/// proxy setting became intake traffic.
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
/// it. A Content-Length body stays on the socket as `.lazy`; the shared path
/// streams or drains it. A chunked body has no declared length, so it is
/// drained into the arena here. Invalidates the head strings.
fn inboundBodyOf(
    request: *std.http.Server.Request,
    limits: limits_mod.Limits,
    buffer: []u8,
    arena: std.mem.Allocator,
) !InboundBody {
    const head = request.head;
    if (!head.method.requestHasBody()) return .{ .bytes = "" };
    if (head.transfer_encoding == .chunked) {
        const reader = try request.readerExpectContinue(buffer);
        var capture: std.Io.Writer.Allocating = .init(arena);
        _ = try pipeline_mod.streamReaderToWriter(reader, &capture.writer, limits.max_body_size);
        return .{ .bytes = capture.written() };
    }
    const len = head.content_length orelse 0;
    if (len == 0) return .{ .bytes = "" };
    if (len > limits.max_body_size) return error.BodyTooLarge;
    const reader = try request.readerExpectContinue(buffer);
    // A streamed body is consumed by its first send and can never be
    // replayed, so a transport failure mid-exchange ends the batch with a
    // 502. Bodies below the streaming threshold stay resident and can be
    // dialed again; httpz draws the same line at `lazy_read_size`.
    //
    // Above the threshold the batch is not replayable, which is deliberate.
    // The Datadog agent retries a 5xx with exponential backoff, so the cost
    // is a delayed batch and a duplicate risk rather than lost data. Raising
    // the line to `max_body_size` would make every batch replayable, at the
    // price of one `max_body_size` buffer per concurrent request: the memory
    // a policy deployment already pays through `residentBody`, and a
    // passthrough deployment does not. See bench/matrix a30.
    if (len <= limits.large_body_buffer_size) {
        var capture: std.Io.Writer.Allocating = .init(arena);
        _ = try pipeline_mod.streamReaderToWriter(reader, &capture.writer, limits.max_body_size);
        return .{ .bytes = capture.written() };
    }
    return .{ .lazy = .{ .reader = reader, .len = @intCast(len) } };
}

/// Collected, arena-duped request headers. Must run BEFORE the body reader
/// is created: readerExpectNone invalidates the head strings.
fn collectRequestHeaders(
    request: *std.http.Server.Request,
    arena: std.mem.Allocator,
    buffer: []std.http.Header,
) ![]std.http.Header {
    var count: usize = 0;
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (upstream_mod.shouldSkipRequestHeader(header.name)) continue;
        if (count >= buffer.len) return error.TooManyHeaders;
        buffer[count] = .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        };
        count += 1;
    }
    return buffer[0..count];
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
fn writeRawResponse(
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
