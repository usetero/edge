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

const Inbound = exchange.Inbound;
const InboundBody = paths.InboundBody;

const log = std.log.scoped(.conn);

// Named event payloads: the type name is the telemetry event name.
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// Per-request trace at debug level.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };

/// Per-connection environment: the frontend-neutral shared context plus the
/// stdio frontend's own state (slab slot buffers, arena pool).
const Env = struct {
    shared: *exec.SharedCtx,
    slab: *conn_slab_mod.ConnSlab,
    arenas: *arena_pool_mod.ArenaPool,
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
    status: u16 = 0,

    pub fn begin(self: *Sink, status: u16, headers: []const std.http.Header) !*std.Io.Writer {
        self.status = status;
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

    var env: Env = .{ .shared = shared, .slab = slab, .arenas = arenas };

    const conn_id = slab.claim(io) orelse {
        // Load shed: no slab slot. One fixed write, then close.
        const shed = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        writeRawResponse(io, stream, shed);
        return;
    };
    defer slab.release(io, conn_id);
    const arena_slot = arenas.claim(io);
    defer arenas.release(io, arena_slot);

    var net_reader = std.Io.net.Stream.Reader.init(stream, io, slab.recvBuf(conn_id));
    var net_writer = std.Io.net.Stream.Writer.init(stream, io, slab.sendBuf(conn_id));
    var server = std.http.Server.init(&net_reader.interface, &net_writer.interface);

    while (server.reader.state == .ready) {
        var request = server.receiveHead() catch |err| switch (err) {
            // Cancellation surfaces as ReadFailed through the net reader.
            error.HttpConnectionClosing, error.ReadFailed => return,
            else => {
                // Malformed head (incl. unsupported content-encoding, see
                // wiring-notes): answer 400 on the raw writer and close.
                const reject = "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                writeRawResponse(io, stream, reject);
                return;
            },
        };
        handleRequest(&env, conn_id, arena_slot, &request) catch |err| {
            log.debug("request handling failed: {s}", .{@errorName(err)});
            return; // connection state unknown; close it
        };
        arenas.reset(arena_slot);
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

    // Head strings die when the body reader is created; the target must
    // outlive that for the upstream leg, logs and metrics.
    const target = try arena.dupe(u8, request.head.target);
    const path = pathOf(target);
    const method = service_mod.HttpMethod.fromStd(request.head.method);
    const known_path = exec.classifyKnownPath(path, method);
    if (ctx.metrics) |metrics| {
        metrics.recordRequest(exec.methodLabel(method), known_path);
    }

    var sink: Sink = .{ .request = request, .buffer = env.slab.bodyBuf(conn_id) };
    var failed: ?anyerror = null;
    dispatch(env, conn_id, arena, request, target, &sink) catch |err| {
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
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    ctx.bus.debug(RequestCompleted{
        .method = @tagName(request.head.method),
        .path = path,
        .status = sink.status,
        .duration_ms = elapsed_s * std.time.ms_per_s,
    });
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
    const query_start = std.mem.findScalar(u8, target, '?');
    return if (query_start) |i| target[0..i] else target;
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

/// Best-effort fixed response on the raw stream (pre-HTTP-state failures:
/// load shed, malformed head). Errors are ignored — the connection is being
/// closed either way.
fn writeRawResponse(io: std.Io, stream: std.Io.net.Stream, response: []const u8) void {
    var buf: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, io, &buf);
    writer.interface.writeAll(response) catch return;
    writer.interface.flush() catch return;
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
