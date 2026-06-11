//! Connection driver: owns one accepted TCP connection end-to-end
//! (PLAN.md §9). Spawned as a concurrent task per connection; written as
//! straight blocking code against std.Io, so the concurrency model is
//! whatever Io implementation the composition root selected.
//!
//! All hot-path memory comes from the connection's slab regions; the only
//! per-request allocations are cold (upstream URL string, duped headers,
//! record transforms) and come from reset-retained arenas.
const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");

const service_mod = @import("../service/service.zig");
const router_mod = @import("router.zig");
const upstream_mod = @import("upstream.zig");
const pipeline_mod = @import("../pipeline/pipeline.zig");
const encoding_mod = @import("../pipeline/encoding.zig");
const framer_mod = @import("../pipeline/framer.zig");
const limits_mod = @import("../core/limits.zig");
const conn_slab_mod = @import("../core/conn_slab.zig");
const arena_pool_mod = @import("../core/arena_pool.zig");
const runtime_metrics_mod = @import("../runtime/runtime_metrics.zig");
const dd_logs = @import("../signals/datadog/logs.zig");
const dd_metrics = @import("../signals/datadog/metrics.zig");
const otlp_logs = @import("../signals/otlp/logs.zig");
const otlp_metrics = @import("../signals/otlp/metrics.zig");
const otlp_traces = @import("../signals/otlp/traces.zig");
const prom = @import("../signals/prometheus/root.zig");

const log = std.log.scoped(.conn);

const EventBus = o11y.EventBus;

// Named event payloads: the type name is the telemetry event name.
const UpstreamConnectionError = struct { err: []const u8, phase: []const u8 };
const PipelineAborted = struct { err: []const u8 };
const RequestRejected = struct { reason: []const u8 };

/// Resolved upstream table; built once at startup from config URLs
/// (logs_url/metrics_url orelse upstream_url, per the old app.zig wiring).
pub const UpstreamIds = struct {
    default: upstream_mod.UpstreamId,
    logs: upstream_mod.UpstreamId,
    metrics: upstream_mod.UpstreamId,

    pub fn resolve(self: UpstreamIds, choice: service_mod.UpstreamChoice) upstream_mod.UpstreamId {
        return switch (choice) {
            .default => self.default,
            .logs => self.logs,
            .metrics => self.metrics,
        };
    }
};

/// Shared, read-only state for every connection task.
pub const SharedCtx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    router: *const router_mod.Router,
    services: []const service_mod.Service,
    upstreams: *upstream_mod.UpstreamManager,
    upstream_ids: UpstreamIds,
    registry: *policy.Registry,
    bus: *EventBus,
    metrics: ?*runtime_metrics_mod.RuntimeMetrics,
    limits: limits_mod.Limits,
    slab: *conn_slab_mod.ConnSlab,
    arenas: *arena_pool_mod.ArenaPool,
};

/// Entry point spawned via Lifecycle.spawn. Only error.Canceled escapes;
/// everything else is handled by closing the connection.
pub fn serveConnection(ctx: *SharedCtx, stream: std.Io.net.Stream) std.Io.Cancelable!void {
    defer stream.close(ctx.io);

    const conn_id = ctx.slab.claim(ctx.io) orelse {
        // Load shed: no slab slot. One fixed write, then close.
        const shed = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
        writeRawResponse(ctx.io, stream, shed);
        return;
    };
    defer ctx.slab.release(ctx.io, conn_id);
    const arena_slot = ctx.arenas.claim(ctx.io);
    defer ctx.arenas.release(ctx.io, arena_slot);

    var net_reader = std.Io.net.Stream.Reader.init(stream, ctx.io, ctx.slab.recvBuf(conn_id));
    var net_writer = std.Io.net.Stream.Writer.init(stream, ctx.io, ctx.slab.sendBuf(conn_id));
    var server = std.http.Server.init(&net_reader.interface, &net_writer.interface);

    while (server.reader.state == .ready) {
        var request = server.receiveHead() catch |err| switch (err) {
            // Cancellation surfaces as ReadFailed through the net reader.
            error.HttpConnectionClosing, error.ReadFailed => return,
            else => {
                // Malformed head (incl. unsupported content-encoding, see
                // wiring-notes): answer 400 on the raw writer and close.
                const reject = "HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                writeRawResponse(ctx.io, stream, reject);
                return;
            },
        };
        handleRequest(ctx, conn_id, arena_slot, &request) catch |err| {
            log.debug("request handling failed: {s}", .{@errorName(err)});
            return; // connection state unknown; close it
        };
        ctx.arenas.reset(arena_slot);
    }
}

fn handleRequest(
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
) !void {
    const start_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    const method = service_mod.HttpMethod.fromStd(request.head.method);
    const known_path = classifyKnownPath(requestPath(request), method);
    if (ctx.metrics) |metrics| {
        metrics.recordRequest(methodLabel(method), known_path);
    }
    defer if (ctx.metrics) |metrics| {
        const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        metrics.recordRequestDuration(known_path, elapsed_s);
    };

    // Internal observability endpoint, checked before routing — parity with
    // the old proxyHandler's /_edge/metrics short-circuit.
    if (request.head.method == .GET and std.mem.eql(u8, requestPath(request), "/_edge/metrics")) {
        return execEdgeMetrics(ctx, arena_slot, request);
    }

    const outcome = planRequest(ctx, request) orelse {
        try request.respond("", .{ .status = .not_found });
        return;
    };
    switch (outcome) {
        .respond => |static| try execRespond(request, static),
        .forward_raw => |fwd| try execForwardRaw(ctx, conn_id, arena_slot, request, fwd),
        .pipe_stream => |pipe| try execPipeStream(ctx, conn_id, arena_slot, request, pipe),
        .pipe_buffered => |pipe| try execPipeBuffered(ctx, conn_id, arena_slot, request, pipe),
        .fetch_filtered => |fetch| try execFetchFiltered(ctx, conn_id, arena_slot, request, fetch),
    }
}

/// Known-path classification for low-cardinality request metrics. Ported
/// verbatim from the old proxy/server.zig classifyKnownPath.
fn classifyKnownPath(path: []const u8, method: service_mod.HttpMethod) runtime_metrics_mod.KnownPathLabel {
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/logs")) return .api_v2_logs;
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/series")) return .api_v2_series;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/logs")) return .v1_logs;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/metrics")) return .v1_metrics;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/traces")) return .v1_traces;
    if (method == .GET and
        (std.mem.eql(u8, path, "/metrics") or std.mem.startsWith(u8, path, "/metrics/"))) return .metrics;
    if (method == .GET and std.mem.eql(u8, path, "/_health")) return .health;
    if (method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) return .edge_metrics;
    return .other;
}

fn methodLabel(method: service_mod.HttpMethod) runtime_metrics_mod.MethodLabel {
    return switch (method) {
        .GET => .get,
        .POST => .post,
        .PUT => .put,
        .DELETE => .delete,
        .PATCH => .patch,
        .HEAD => .head,
        .OPTIONS => .options,
        .OTHER => .other,
    };
}

fn requestPath(request: *const std.http.Server.Request) []const u8 {
    const target = request.head.target;
    const query_start = std.mem.findScalar(u8, target, '?');
    return if (query_start) |i| target[0..i] else target;
}

fn execEdgeMetrics(ctx: *SharedCtx, arena_slot: u16, request: *std.http.Server.Request) !void {
    const arena = ctx.arenas.allocator(arena_slot);
    var out: std.Io.Writer.Allocating = .init(arena);
    if (ctx.metrics) |metrics| try metrics.writePrometheus(&out.writer);
    try request.respond(out.written(), .{
        .extra_headers = &.{.{ .name = "content-type", .value = "text/plain; version=0.0.4" }},
    });
}

fn planRequest(ctx: *SharedCtx, request: *std.http.Server.Request) ?service_mod.Outcome {
    const path = requestPath(request);
    const method = service_mod.HttpMethod.fromStd(request.head.method);
    const match = ctx.router.route(path, method) orelse return null;

    const plan_request: service_mod.PlanRequest = .{
        .method = method,
        .path = path,
        .content_type = request.head.content_type orelse "",
        .content_encoding = contentEncodingName(request.head.transfer_compression),
    };
    const svc = &ctx.services[@intFromEnum(match.service)];
    return svc.plan(plan_request);
}

/// Maps std's parsed Content-Encoding back to the header string our codec
/// layer understands. identity covers the absent-header case.
fn contentEncodingName(ce: std.http.ContentEncoding) []const u8 {
    return switch (ce) {
        .identity => "",
        .gzip => "gzip",
        .zstd => "zstd",
        // Not supported by the codec layer: plan() fail-opens to forward_raw.
        .deflate => "deflate",
        .compress => "compress",
    };
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
    ctx: *SharedCtx,
    request: *std.http.Server.Request,
    arena: std.mem.Allocator,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    const target = request.head.target;
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |i| target[0..i] else target;
    const query = if (query_start) |i| target[i + 1 ..] else "";

    const upstream_id = ctx.upstream_ids.resolve(choice);
    const uri_str = try ctx.upstreams.buildUpstreamUri(arena, upstream_id, path, query);
    const uri = try std.Uri.parse(uri_str);

    var headers_buf: [64]std.http.Header = undefined;
    const headers = try collectRequestHeaders(request, arena, &headers_buf);

    return ctx.upstreams.getHttpClient().request(request.head.method, uri, .{
        .extra_headers = headers,
        .headers = .{ .accept_encoding = .omit },
    }) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.err(UpstreamConnectionError{ .err = @errorName(err), .phase = "connect" });
        return err;
    };
}

/// Relays the upstream response (status, filtered headers, body) to the
/// client. `body_filter` optionally interposes on the body stream
/// (prometheus). Returns bytes forwarded to the client.
fn relayResponse(
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    request: *std.http.Server.Request,
    upstream_req: *std.http.Client.Request,
    arena: std.mem.Allocator,
    max_response_body: usize,
    body_filter: ?*prom.streaming_filter.FilteringWriter,
) !void {
    var upstream_res = try upstream_req.receiveHead(&.{});

    var extra_headers: [64]std.http.Header = undefined;
    var header_count: usize = 0;
    var header_it = upstream_res.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (upstream_mod.shouldSkipResponseHeader(header.name)) continue;
        if (header_count >= extra_headers.len) break;
        extra_headers[header_count] = .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        };
        header_count += 1;
    }

    const status: std.http.Status = upstream_res.head.status;
    // Request body is fully consumed by now; its slab region backs the
    // response BodyWriter staging.
    var body_writer = try request.respondStreaming(ctx.slab.bodyBuf(conn_id), .{
        .respond_options = .{
            .status = status,
            .extra_headers = extra_headers[0..header_count],
        },
    });

    const upstream_body = upstream_res.reader(ctx.slab.upstreamBuf(conn_id));
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
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    fwd: service_mod.Forward,
) !void {
    const arena = ctx.arenas.allocator(arena_slot);
    var upstream_req = try openUpstream(ctx, request, arena, fwd.upstream);
    defer upstream_req.deinit();

    const head = request.head;
    const has_body = head.method.requestHasBody() and
        (head.transfer_encoding == .chunked or (head.content_length orelse 0) > 0);

    if (has_body) {
        const body_reader = try request.readerExpectContinue(ctx.slab.bodyBuf(conn_id));
        upstream_req.transfer_encoding = if (head.content_length) |len|
            .{ .content_length = len }
        else
            .chunked;
        var body_writer = try upstream_req.sendBodyUnflushed(ctx.slab.upstreamBuf(conn_id));
        _ = try pipeline_mod.streamReaderToWriter(body_reader, &body_writer.writer, std.math.maxInt(usize));
        try body_writer.end();
    } else if (head.method.requestHasBody()) {
        upstream_req.transfer_encoding = .{ .content_length = 0 };
        var body_writer = try upstream_req.sendBodyUnflushed(ctx.slab.upstreamBuf(conn_id));
        try body_writer.end();
    } else {
        try upstream_req.sendBodiless();
    }

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(fwd.upstream));
    try relayResponse(ctx, conn_id, request, &upstream_req, arena, max_response, null);
}

fn execPipeStream(
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    pipe: service_mod.PipeStream,
) !void {
    const arena = ctx.arenas.allocator(arena_slot);
    var upstream_req = try openUpstream(ctx, request, arena, pipe.upstream);
    defer upstream_req.deinit();

    const body_reader = try request.readerExpectContinue(ctx.slab.bodyBuf(conn_id));

    // Filtering changes length: always chunked.
    upstream_req.transfer_encoding = .chunked;
    var body_writer = try upstream_req.sendBodyUnflushed(ctx.slab.upstreamBuf(conn_id));

    var sink = RecordSink.init(ctx, pipe.signal, pipe.format);
    defer sink.deinit();

    const stats = pipeline_mod.run(.{
        .decode = pipe.codec,
        .format = pipe.format,
        .encode = pipe.codec,
        .max_decoded_bytes = ctx.limits.max_body_size,
        .zstd_window_len = ctx.limits.zstd_window_len,
    }, body_reader, &body_writer.writer, .{
        .decoder = ctx.slab.decodeBuf(conn_id),
        .encoder = ctx.slab.encodeBuf(conn_id),
        .scratch = ctx.slab.recordScratch(conn_id),
        .chunk = ctx.slab.chunkBuf(conn_id),
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
        metrics.recordPolicyBatch(routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
    }

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
    try relayResponse(ctx, conn_id, request, &upstream_req, arena, max_response, null);
}

fn execPipeBuffered(
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    pipe: service_mod.PipeBuffered,
) !void {
    const arena = ctx.arenas.allocator(arena_slot);

    // Capture the RAW body first so any later failure fails open by
    // forwarding the original bytes — exact old-module semantics.
    const body_reader = try request.readerExpectContinue(ctx.slab.bodyBuf(conn_id));
    var raw_capture: std.Io.Writer.Allocating = .init(arena);
    _ = try pipeline_mod.streamReaderToWriter(body_reader, &raw_capture.writer, ctx.limits.max_body_size);
    const raw_body = raw_capture.written();

    const processed: BufferedResult = processBuffered(ctx, pipe, arena, raw_body) catch |err| blk: {
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

    var upstream_req = try openUpstream(ctx, request, arena, pipe.upstream);
    defer upstream_req.deinit();
    upstream_req.transfer_encoding = .{ .content_length = processed.body.len };
    var body_writer = try upstream_req.sendBodyUnflushed(ctx.slab.upstreamBuf(conn_id));
    var fixed = std.Io.Reader.fixed(processed.body);
    _ = try pipeline_mod.streamReaderToWriter(&fixed, &body_writer.writer, processed.body.len);
    try body_writer.end();

    const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
    try relayResponse(ctx, conn_id, request, &upstream_req, arena, max_response, null);
}

const BufferedResult = struct {
    body: []const u8,
    all_dropped: bool,
};

/// Signal-agnostic view of the per-signal StreamProcessResult types.
const BatchSummary = struct {
    original_count: usize,
    dropped_count: usize,
    all_dropped: bool,

    fn of(result: anytype) BatchSummary {
        return .{
            .original_count = result.original_count,
            .dropped_count = result.dropped_count,
            .all_dropped = result.allDropped(),
        };
    }
};

/// Decode → batch transform → re-encode, all arena-bounded. The batch fns
/// are the same code the old modules ran, so filter semantics are identical.
fn processBuffered(
    ctx: *SharedCtx,
    pipe: service_mod.PipeBuffered,
    arena: std.mem.Allocator,
    raw_body: []const u8,
) !BufferedResult {
    var raw_reader = std.Io.Reader.fixed(raw_body);
    const decode_buf = try arena.alloc(u8, pipe.codec.decoderBufferLen(ctx.limits.zstd_window_len));
    var decoder: encoding_mod.Decoder = .init(pipe.codec, &raw_reader, decode_buf, ctx.limits.zstd_window_len);
    var decoded_capture: std.Io.Writer.Allocating = .init(arena);
    _ = try pipeline_mod.streamReaderToWriter(decoder.reader(), &decoded_capture.writer, ctx.limits.max_body_size);

    var decoded_reader = std.Io.Reader.fixed(decoded_capture.written());
    var transformed: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const registry = ctx.registry;
    // The per-signal StreamProcessResult types are distinct; normalize.
    const in = &decoded_reader;
    const out = &transformed.writer;
    const ct = "application/json";
    const summary: BatchSummary = switch (pipe.kind) {
        .datadog_metrics_json => .of(try dd_metrics.processMetricsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_logs_json => .of(try otlp_logs.processLogsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_metrics_json => .of(try otlp_metrics.processMetricsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_traces_json => .of(try otlp_traces.processTracesStream(arena, registry, ctx.bus, in, out, ct)),
    };

    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(bufferedRouteLabel(pipe.kind), summary.original_count, summary.dropped_count);
    }
    if (summary.all_dropped) return .{ .body = &.{}, .all_dropped = true };

    // Re-encode in the original codec so the forwarded content-encoding
    // header stays truthful.
    var encoded: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const encode_buf = try arena.alloc(u8, pipe.codec.encoderBufferLen());
    var encoder: encoding_mod.Encoder = try .init(pipe.codec, &encoded.writer, encode_buf);
    defer encoder.deinit();
    try encoder.writer().writeAll(transformed.written());
    try encoder.finish();
    return .{ .body = encoded.written(), .all_dropped = false };
}

fn execFetchFiltered(
    ctx: *SharedCtx,
    conn_id: conn_slab_mod.ConnId,
    arena_slot: u16,
    request: *std.http.Server.Request,
    fetch: service_mod.FetchFiltered,
) !void {
    const arena = ctx.arenas.allocator(arena_slot);
    var upstream_req = try openUpstream(ctx, request, arena, fetch.upstream);
    defer upstream_req.deinit();
    try upstream_req.sendBodiless();

    var upstream_res = try upstream_req.receiveHead(&.{});
    var extra_headers: [64]std.http.Header = undefined;
    var header_count: usize = 0;
    var header_it = upstream_res.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (upstream_mod.shouldSkipResponseHeader(header.name)) continue;
        if (header_count >= extra_headers.len) break;
        extra_headers[header_count] = .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        };
        header_count += 1;
    }

    var body_writer = try request.respondStreaming(ctx.slab.bodyBuf(conn_id), .{
        .respond_options = .{
            .status = upstream_res.head.status,
            .extra_headers = extra_headers[0..header_count],
        },
    });

    // The prometheus filter's working buffers live in the (otherwise idle on
    // GET) record-scratch region: 4K line + 2K metadata + 8K writer staging.
    const scratch = ctx.slab.recordScratch(conn_id);
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

    const upstream_body = upstream_res.reader(ctx.slab.upstreamBuf(conn_id));
    const max_in = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes;
    _ = try pipeline_mod.streamReaderToWriter(upstream_body, filtering.writer(), max_in);
    _ = try filtering.finish();
    try body_writer.end();
    try body_writer.flush();
}

/// Per-record policy evaluation: wraps each record as a minimal one-element
/// batch and runs it through the SAME batch transform the old modules used.
/// Semantics are therefore identical to the buffered path; memory is bounded
/// by one record (the arena resets between records). A future pass can bind
/// the engine directly per record to shave the wrap/parse overhead.
pub const RecordSink = struct {
    ctx: *SharedCtx,
    signal: service_mod.Signal,
    format: framer_mod.WireFormat,
    record_arena: std.heap.ArenaAllocator,
    /// Batch totals for recordPolicyBatch.
    records: u64 = 0,
    dropped: u64 = 0,

    pub fn init(ctx: *SharedCtx, signal: service_mod.Signal, format: framer_mod.WireFormat) RecordSink {
        return .{
            .ctx = ctx,
            .signal = signal,
            .format = format,
            .record_arena = .init(ctx.gpa),
        };
    }

    pub fn deinit(self: *RecordSink) void {
        self.record_arena.deinit();
        self.* = undefined;
    }

    pub fn onRecord(self: *RecordSink, bytes: []const u8) !framer_mod.Decision {
        // Replace bytes from the PREVIOUS record die here; the framer has
        // already written them (emit happens before the next onRecord).
        _ = self.record_arena.reset(.retain_capacity);
        const arena = self.record_arena.allocator();
        self.records += 1;

        return switch (self.format) {
            .json_array => self.evalJsonRecord(arena, bytes),
            .otlp_protobuf => self.evalProtobufRecord(arena, bytes),
            // raw/ndjson/prom_text never reach a policy sink today.
            else => .keep,
        };
    }

    fn evalJsonRecord(self: *RecordSink, arena: std.mem.Allocator, bytes: []const u8) !framer_mod.Decision {
        // One-element batch: "[<record>]".
        const wrapped = try std.mem.concat(arena, u8, &.{ "[", bytes, "]" });
        var reader = std.Io.Reader.fixed(wrapped);
        var out: std.Io.Writer.Allocating = .init(arena);
        const result = try dd_logs.processLogsStream(
            arena,
            self.ctx.registry,
            self.ctx.bus,
            &reader,
            &out.writer,
            "application/json",
        );
        if (result.allDropped()) {
            self.dropped += 1;
            return .drop;
        }
        const written = std.mem.trim(u8, out.written(), " \t\r\n");
        if (written.len < 2 or written[0] != '[' or written[written.len - 1] != ']') {
            return .keep; // unexpected shape: fail safe, forward original
        }
        const inner = std.mem.trim(u8, written[1 .. written.len - 1], " \t\r\n");
        if (inner.len == 0) {
            self.dropped += 1;
            return .drop;
        }
        if (std.mem.eql(u8, inner, bytes)) return .keep;
        return .{ .replace = inner };
    }

    fn evalProtobufRecord(self: *RecordSink, arena: std.mem.Allocator, bytes: []const u8) !framer_mod.Decision {
        // One-element batch: field 1, LEN, payload — a valid Export*Request.
        var wrapped: std.Io.Writer.Allocating = try .initCapacity(arena, bytes.len + 12);
        try wrapped.writer.writeByte(0x0A);
        try writeVarint(&wrapped.writer, bytes.len);
        try wrapped.writer.writeAll(bytes);

        var reader = std.Io.Reader.fixed(wrapped.written());
        var out: std.Io.Writer.Allocating = .init(arena);
        const registry = self.ctx.registry;
        // The per-signal StreamProcessResult types are distinct; normalize.
        const in = &reader;
        const ow = &out.writer;
        const ct = "application/x-protobuf";
        const all_dropped = switch (self.signal) {
            .log => blk: {
                const result = try otlp_logs.processLogsStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
            .metric => blk: {
                const result = try otlp_metrics.processMetricsStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
            .trace => blk: {
                const result = try otlp_traces.processTracesStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
        };
        if (all_dropped) {
            self.dropped += 1;
            return .drop;
        }
        const payload = stripLenField(out.written()) orelse return .keep;
        if (payload.len == 0) {
            self.dropped += 1;
            return .drop;
        }
        if (std.mem.eql(u8, payload, bytes)) return .keep;
        return .{ .replace = payload };
    }
};

/// Unwraps a single field-1 LEN message: returns the payload, or null when
/// the buffer isn't exactly one such field (caller fails safe with .keep).
fn stripLenField(buffer: []const u8) ?[]const u8 {
    if (buffer.len < 2 or buffer[0] != 0x0A) return null;
    var len: usize = 0;
    var shift: u6 = 0;
    var i: usize = 1;
    while (i < buffer.len) : (i += 1) {
        const byte = buffer[i];
        len |= @as(usize, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) break;
        shift += 7;
        if (shift > 35) return null;
    } else return null;
    const payload_start = i + 1;
    if (payload_start + len != buffer.len) return null;
    return buffer[payload_start..][0..len];
}

fn writeVarint(out: *std.Io.Writer, value: usize) !void {
    var v: u64 = value;
    while (v >= 0x80) {
        try out.writeByte(@intCast((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try out.writeByte(@intCast(v));
}

fn routeLabel(signal: service_mod.Signal, format: framer_mod.WireFormat) runtime_metrics_mod.PolicyTelemetryLabel {
    return switch (format) {
        .json_array => .datadog_logs,
        .otlp_protobuf => switch (signal) {
            .log => .otlp_logs,
            .metric => .otlp_metrics,
            .trace => .otlp_traces,
        },
        // raw/ndjson/prom_text outcomes never run the record pipeline.
        else => unreachable,
    };
}

fn bufferedRouteLabel(kind: service_mod.BufferedKind) runtime_metrics_mod.PolicyTelemetryLabel {
    return switch (kind) {
        .datadog_metrics_json => .datadog_metrics,
        .otlp_logs_json => .otlp_logs,
        .otlp_metrics_json => .otlp_metrics,
        .otlp_traces_json => .otlp_traces,
    };
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

test "stripLenField unwraps single-field messages" {
    const buf = [_]u8{ 0x0A, 0x03, 'a', 'b', 'c' };
    try testing.expectEqualStrings("abc", stripLenField(&buf).?);

    // Empty payload
    const empty = [_]u8{ 0x0A, 0x00 };
    try testing.expectEqualStrings("", stripLenField(&empty).?);

    // Trailing garbage -> null
    const trailing = [_]u8{ 0x0A, 0x01, 'x', 0x55 };
    try testing.expectEqual(@as(?[]const u8, null), stripLenField(&trailing));

    // Wrong tag -> null
    const wrong = [_]u8{ 0x12, 0x01, 'x' };
    try testing.expectEqual(@as(?[]const u8, null), stripLenField(&wrong));
}

test "classifyKnownPath matches core routes" {
    // Parity with the old classifyRoute/classifyKnownPath tests.
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.api_v2_logs, classifyKnownPath("/api/v2/logs", .POST));
    const series = classifyKnownPath("/api/v2/series", .POST);
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.api_v2_series, series);
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.v1_logs, classifyKnownPath("/v1/logs", .POST));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.metrics, classifyKnownPath("/metrics", .GET));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.health, classifyKnownPath("/_health", .GET));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.other, classifyKnownPath("/anything", .GET));
}

test "contentEncodingName round-trips through the codec layer" {
    try testing.expectEqual(
        encoding_mod.ContentEncoding.identity,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.identity)).?,
    );
    try testing.expectEqual(
        encoding_mod.ContentEncoding.gzip,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.gzip)).?,
    );
    try testing.expectEqual(
        encoding_mod.ContentEncoding.zstd,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.zstd)).?,
    );
    // deflate/compress are unsupported by the codec layer: plan() fail-opens.
    try testing.expectEqual(
        @as(?encoding_mod.ContentEncoding, null),
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.deflate)),
    );
}
