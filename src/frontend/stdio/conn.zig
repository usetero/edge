//! Connection driver for the std.Io-native frontend: owns one accepted TCP
//! connection end-to-end (PLAN.md §9). Spawned as a concurrent task per
//! connection; written as straight blocking code against std.Io, so the
//! concurrency model is whatever Io implementation the composition root
//! selected.
//!
//! Transport glue only: body acquisition, response writing, and slab buffer
//! plumbing live here; routing, planning, and all policy/transform logic is
//! in frontend/exec.zig, shared with the httpz frontend
//! (PLAN-FRONTEND-SWAP.md §3).
//!
//! All hot-path memory comes from the connection's slab regions; the only
//! per-request allocations are cold (upstream URL string, duped headers,
//! record transforms) and come from reset-retained arenas.
const std = @import("std");

const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const upstream_mod = @import("../upstream.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const conn_slab_mod = @import("../../core/conn_slab.zig");
const arena_pool_mod = @import("../../core/arena_pool.zig");
const prom = @import("../../signals/prometheus/root.zig");

const log = std.log.scoped(.conn);

// Named event payloads: the type name is the telemetry event name.
const PipelineAborted = struct { err: []const u8 };

/// Per-connection environment: the frontend-neutral shared context plus the
/// stdio frontend's own state (slab slot buffers, arena pool).
const Env = struct {
    shared: *exec.SharedCtx,
    slab: *conn_slab_mod.ConnSlab,
    arenas: *arena_pool_mod.ArenaPool,
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

fn handleRequest(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
) !void {
    const ctx = env.shared;
    const start_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    const method = service_mod.HttpMethod.fromStd(request.head.method);
    const known_path = exec.classifyKnownPath(requestPath(request), method);
    if (ctx.metrics) |metrics| {
        metrics.recordRequest(exec.methodLabel(method), known_path);
    }
    defer if (ctx.metrics) |metrics| {
        const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        metrics.recordRequestDuration(known_path, elapsed_s);
    };

    // Internal observability endpoint, checked before routing — parity with
    // the old proxyHandler's /_edge/metrics short-circuit.
    if (request.head.method == .GET and std.mem.eql(u8, requestPath(request), "/_edge/metrics")) {
        return execEdgeMetrics(env, arena_slot, request);
    }

    const outcome = exec.planRequest(
        ctx,
        method,
        requestPath(request),
        request.head.content_type orelse "",
        exec.contentEncodingName(request.head.transfer_compression),
    ) orelse {
        try request.respond("", .{ .status = .not_found });
        return;
    };
    switch (outcome) {
        .respond => |static| try execRespond(request, static),
        .forward_raw => |fwd| try execForwardRaw(env, conn_id, arena_slot, request, fwd),
        .pipe_stream => |pipe| try execPipeStream(env, conn_id, arena_slot, request, pipe),
        .pipe_buffered => |pipe| try execPipeBuffered(env, conn_id, arena_slot, request, pipe),
        .fetch_filtered => |fetch| try execFetchFiltered(env, conn_id, arena_slot, request, fetch),
    }
}

fn requestPath(request: *const std.http.Server.Request) []const u8 {
    const target = request.head.target;
    const query_start = std.mem.findScalar(u8, target, '?');
    return if (query_start) |i| target[0..i] else target;
}

fn execEdgeMetrics(env: *Env, arena_slot: u16, request: *std.http.Server.Request) !void {
    const arena = env.arenas.allocator(arena_slot);
    var out: std.Io.Writer.Allocating = .init(arena);
    if (env.shared.metrics) |metrics| try metrics.writePrometheus(&out.writer);
    try request.respond(out.written(), .{
        .extra_headers = &.{.{ .name = "content-type", .value = "text/plain; version=0.0.4" }},
    });
}

fn execRespond(request: *std.http.Server.Request, static: service_mod.StaticResponse) !void {
    try request.respond(static.body, .{
        .status = @enumFromInt(static.status),
        .extra_headers = &.{
            .{ .name = "content-type", .value = static.content_type },
        },
    });
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

fn openUpstream(
    env: *Env,
    request: *std.http.Server.Request,
    arena: std.mem.Allocator,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    var headers_buf: [64]std.http.Header = undefined;
    const headers = try collectRequestHeaders(request, arena, &headers_buf);
    return exec.openUpstream(env.shared, arena, request.head.method, request.head.target, headers, choice);
}

/// Relays the upstream response (status, filtered headers, body) to the
/// client. `body_filter` optionally interposes on the body stream
/// (prometheus). Returns bytes forwarded to the client.
fn relayResponse(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    request: *std.http.Server.Request,
    upstream_req: *std.http.Client.Request,
    arena: std.mem.Allocator,
    max_response_body: usize,
    body_filter: ?*prom.streaming_filter.FilteringWriter,
) !void {
    var upstream_res = try upstream_req.receiveHead(&.{});

    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, arena, &extra_headers);

    const status: std.http.Status = upstream_res.head.status;
    // Request body is fully consumed by now; its slab region backs the
    // response BodyWriter staging.
    var body_writer = try request.respondStreaming(env.slab.bodyBuf(conn_id), .{
        .respond_options = .{
            .status = status,
            .extra_headers = relayed,
        },
    });

    const upstream_body = upstream_res.reader(env.slab.upstreamBuf(conn_id));
    if (body_filter) |filter| {
        _ = try pipeline_mod.streamReaderToWriter(upstream_body, filter.writer(), max_response_body);
        _ = try filter.finish();
    } else {
        _ = try pipeline_mod.streamReaderToWriter(upstream_body, &body_writer.writer, max_response_body);
    }
    try body_writer.end();
    try body_writer.flush();
}

fn execForwardRaw(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    fwd: service_mod.Forward,
) !void {
    const ctx = env.shared;
    const arena = env.arenas.allocator(arena_slot);
    var upstream_req = openUpstream(env, request, arena, fwd.upstream) catch {
        try request.respond("", .{ .status = .bad_gateway });
        return;
    };
    defer upstream_req.deinit();

    const head = request.head;
    const has_body = head.method.requestHasBody() and
        (head.transfer_encoding == .chunked or (head.content_length orelse 0) > 0);

    if (has_body) {
        const body_reader = try request.readerExpectContinue(env.slab.bodyBuf(conn_id));
        upstream_req.transfer_encoding = if (head.content_length) |len|
            .{ .content_length = len }
        else
            .chunked;
        var body_writer = try upstream_req.sendBodyUnflushed(env.slab.upstreamBuf(conn_id));
        _ = try pipeline_mod.streamReaderToWriter(body_reader, &body_writer.writer, std.math.maxInt(usize));
        try body_writer.end();
    } else if (head.method.requestHasBody()) {
        upstream_req.transfer_encoding = .{ .content_length = 0 };
        var body_writer = try upstream_req.sendBodyUnflushed(env.slab.upstreamBuf(conn_id));
        try body_writer.end();
    } else {
        try upstream_req.sendBodiless();
    }

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(fwd.upstream));
    try relayResponse(env, conn_id, request, &upstream_req, arena, max_response, null);
}

fn execPipeStream(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    pipe: service_mod.PipeStream,
) !void {
    const ctx = env.shared;
    // No policy targets this signal: the pipe is an identity transform, so
    // skip the framer/codec/chunked overhead and relay the raw bytes
    // (master's prefilter "forward unchanged" decision).
    if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
        return execForwardRaw(env, conn_id, arena_slot, request, .{ .upstream = pipe.upstream });
    }
    const arena = env.arenas.allocator(arena_slot);
    var upstream_req = openUpstream(env, request, arena, pipe.upstream) catch {
        try request.respond("", .{ .status = .bad_gateway });
        return;
    };
    defer upstream_req.deinit();

    const body_reader = try request.readerExpectContinue(env.slab.bodyBuf(conn_id));

    // Filtering changes length: always chunked.
    upstream_req.transfer_encoding = .chunked;
    var body_writer = try upstream_req.sendBodyUnflushed(env.slab.upstreamBuf(conn_id));

    var sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format);
    defer sink.deinit();

    const stats = pipeline_mod.run(.{
        .decode = pipe.codec,
        .format = pipe.format,
        .encode = pipe.codec,
        .max_decoded_bytes = ctx.limits.max_body_size,
        .zstd_window_len = ctx.limits.zstd_window_len,
    }, body_reader, &body_writer.writer, .{
        .decoder = env.slab.decodeBuf(conn_id),
        .encoder = env.slab.encodeBuf(conn_id),
        .scratch = env.slab.recordScratch(conn_id),
        .chunk = env.slab.chunkBuf(conn_id),
    }, &sink) catch |err| {
        // PLAN §6.5.1: mid-stream decode/transport failure aborts the
        // exchange; bytes already sent upstream stay sent. The client gets
        // a 502 if its response hasn't started (it hasn't), then we close.
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.err(PipelineAborted{ .err = @errorName(err) });
        if (upstream_req.connection) |conn| conn.closing = true;
        try request.respond("", .{ .status = .bad_gateway, .keep_alive = false });
        return error.PipelineAborted;
    };
    try body_writer.end();

    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
    }

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
    try relayResponse(env, conn_id, request, &upstream_req, arena, max_response, null);
}

fn execPipeBuffered(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    pipe: service_mod.PipeBuffered,
) !void {
    const ctx = env.shared;
    const arena = env.arenas.allocator(arena_slot);

    // Capture the RAW body first so any later failure fails open by
    // forwarding the original bytes — exact old-module semantics.
    const body_reader = try request.readerExpectContinue(env.slab.bodyBuf(conn_id));
    var raw_capture: std.Io.Writer.Allocating = .init(arena);
    _ = try pipeline_mod.streamReaderToWriter(body_reader, &raw_capture.writer, ctx.limits.max_body_size);
    const raw_body = raw_capture.written();

    const processed: exec.BufferedResult = exec.processBuffered(ctx, pipe, arena, raw_body) catch |err| blk: {
        log.warn("buffered transform failed open: {s}", .{@errorName(err)});
        break :blk .{ .body = raw_body, .all_dropped = false };
    };

    if (processed.all_dropped) {
        // Nothing left to forward: old modules answered for the upstream.
        try request.respond("{}", .{
            .status = .ok,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        });
        return;
    }

    var upstream_req = openUpstream(env, request, arena, pipe.upstream) catch {
        try request.respond("", .{ .status = .bad_gateway });
        return;
    };
    defer upstream_req.deinit();
    upstream_req.transfer_encoding = .{ .content_length = processed.body.len };
    var body_writer = try upstream_req.sendBodyUnflushed(env.slab.upstreamBuf(conn_id));
    var fixed = std.Io.Reader.fixed(processed.body);
    _ = try pipeline_mod.streamReaderToWriter(&fixed, &body_writer.writer, processed.body.len);
    try body_writer.end();

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
    try relayResponse(env, conn_id, request, &upstream_req, arena, max_response, null);
}

fn execFetchFiltered(
    env: *Env,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    fetch: service_mod.FetchFiltered,
) !void {
    const ctx = env.shared;
    const arena = env.arenas.allocator(arena_slot);
    var upstream_req = openUpstream(env, request, arena, fetch.upstream) catch {
        try request.respond("", .{ .status = .bad_gateway });
        return;
    };
    defer upstream_req.deinit();
    try upstream_req.sendBodiless();

    var upstream_res = try upstream_req.receiveHead(&.{});
    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, arena, &extra_headers);

    var body_writer = try request.respondStreaming(env.slab.bodyBuf(conn_id), .{
        .respond_options = .{
            .status = upstream_res.head.status,
            .extra_headers = relayed,
        },
    });

    // The prometheus filter's working buffers live in the (otherwise idle on
    // GET) record-scratch region: 4K line + 2K metadata + 8K writer staging.
    const scratch = env.slab.recordScratch(conn_id);
    var filter: prom.streaming_filter.PolicyStreamingFilter = .init(.{
        .line_buffer = scratch[0..4096],
        .metadata_buffer = scratch[4096..6144],
        .max_input_bytes = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes,
        .max_output_bytes = if (fetch.max_output_bytes == 0) std.math.maxInt(usize) else fetch.max_output_bytes,
        .registry = ctx.registry,
        .bus = ctx.bus,
        .allocator = arena,
    });
    var filtering: prom.streaming_filter.FilteringWriter = .init(.{
        .filter = &filter,
        .inner = &body_writer.writer,
        .buffer = scratch[6144..14336],
    });

    const upstream_body = upstream_res.reader(env.slab.upstreamBuf(conn_id));
    const max_in = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes;
    _ = try pipeline_mod.streamReaderToWriter(upstream_body, filtering.writer(), max_in);
    _ = try filtering.finish();
    try body_writer.end();
    try body_writer.flush();
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
