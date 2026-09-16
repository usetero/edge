//! The four request executors the router can choose: raw forward, streamed
//! record pipeline, whole-body transform, and filtered scrape. Free functions
//! on `SharedCtx`; the httpz `Handler` only dispatches to them.
//!
//! Frontend-neutral: the request arrives as an `exchange.Inbound` plus an
//! `InboundBody`, and the response leaves through a `sink` (see exchange.zig
//! for the contract). The frontend decides whether a body is already
//! buffered or still on the socket, and enforces max_body_size before
//! handing over a lazy one; everything after that is shared.
const std = @import("std");
const exec = @import("exec.zig");
const service_mod = @import("../service/service.zig");
const pipeline_mod = @import("../pipeline/pipeline.zig");
const limits_mod = @import("../core/limits.zig");
const prom = @import("../signals/prometheus/root.zig");
const exchange = @import("exchange.zig");
const thread_bufs = @import("thread_bufs.zig");

const log = std.log.scoped(.httpz_server);
const BodySource = exchange.BodySource;
const Inbound = exchange.Inbound;

pub const InboundBody = union(enum) {
    /// Fully buffered by the frontend. Zero-copy slice.
    bytes: []const u8,
    /// Still on the client socket. `len` is the declared Content-Length,
    /// already checked against max_body_size by the frontend.
    lazy: struct { reader: *std.Io.Reader, len: usize },
};

fn bufferLazyBody(reader: *std.Io.Reader, dst: []u8, len: usize) ![]const u8 {
    std.debug.assert(len <= dst.len);
    var fixed: std.Io.Writer = .fixed(dst[0..len]);
    try reader.streamExact(&fixed, len);
    return dst[0..len];
}

/// Forward an inbound body as-is: buffered bytes go with the route's replay
/// policy; a lazy body streams socket to socket and cannot be replayed.
fn forwardInbound(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    upstream: service_mod.UpstreamChoice,
    inbound: InboundBody,
    replayable: bool,
) !void {
    switch (inbound) {
        .bytes => |b| return exchange.exchange(ctx, in, sink, upstream, .{ .bytes = b }, replayable),
        .lazy => |l| {
            const body: BodySource = .{ .stream = .{ .reader = l.reader, .len = l.len } };
            return exchange.exchange(ctx, in, sink, upstream, body, false);
        },
    }
}

/// Drain a lazy body into this thread's body buffer; the policy paths read
/// the body twice (probe, then encode), so it must be resident.
fn residentBody(ctx: *exec.SharedCtx, inbound: InboundBody) ![]const u8 {
    return switch (inbound) {
        .bytes => |b| b,
        .lazy => |l| blk: {
            const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
            const dst = try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size);
            break :blk try bufferLazyBody(l.reader, dst, l.len);
        },
    };
}

pub fn execForwardRaw(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    body: InboundBody,
    fwd: service_mod.Forward,
) !void {
    return forwardInbound(ctx, in, sink, fwd.upstream, body, fwd.replayable);
}

pub fn execPipeStream(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    body: InboundBody,
    pipe: service_mod.PipeStream,
) !void {
    if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
        return forwardInbound(ctx, in, sink, pipe.upstream, body, pipe.signal == .log);
    }
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const raw_body = try residentBody(ctx, body);
    try bufs.prepare(ctx.gpa, ctx.limits, pipe.codec);
    var body_reader = std.Io.Reader.fixed(raw_body);
    const initial_capacity = @max(@min(raw_body.len, limits_mod.LARGE_BODY_BUFFER_BYTES), 64);
    const spec: pipeline_mod.PipelineSpec = .{
        .decode = pipe.codec,
        .format = pipe.format,
        .encode = .identity,
        .max_decoded_bytes = ctx.limits.max_decoded_bytes,
        .zstd_window_len = ctx.limits.zstd_window_len,
    };
    const buffers: pipeline_mod.Buffers = .{
        .decoder = bufs.decode,
        .encoder = bufs.encode,
        .scratch = bufs.scratch,
        .chunk = bufs.chunk,
    };

    var probe = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    probe.probe = true;
    defer probe.deinit();
    var discard: std.Io.Writer.Discarding = .init(&.{});
    const probe_result = pipeline_mod.run(spec, &body_reader, &discard.writer, buffers, &probe);
    const changed = if (probe_result) |probe_stats| blk: {
        break :blk probe_stats.dropped > 0 or probe_stats.replaced > 0;
    } else |err| switch (err) {
        error.BatchChanged => true,
        error.ReadFailed => return error.InvalidRequestBody,
        else => return err,
    };

    if (!changed) {
        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), probe.records, 0);
            metrics.recordPrefilterDecision(exec.prefilterRouteLabel(pipe.signal, pipe.format), .fast_path);
        }
        return exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
    }

    if (ctx.metrics) |metrics| {
        metrics.recordPrefilterDecision(exec.prefilterRouteLabel(pipe.signal, pipe.format), .policy_path);
    }
    body_reader = .fixed(raw_body);
    var output: std.Io.Writer.Allocating = try .initCapacity(in.arena, initial_capacity);
    var record_sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    defer record_sink.deinit();
    var encode_spec = spec;
    encode_spec.encode = pipe.codec;
    const encoded = pipeline_mod.run(encode_spec, &body_reader, &output.writer, buffers, &record_sink);
    const stats = encoded catch |err| switch (err) {
        error.ReadFailed => return error.InvalidRequestBody,
        else => return err,
    };
    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
    }
    try exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = output.written() }, pipe.signal == .log);
}

pub fn execPipeBuffered(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    body: InboundBody,
    pipe: service_mod.PipeBuffered,
) !void {
    const raw_body = try residentBody(ctx, body);

    const processed: exec.BufferedResult = exec.processBuffered(ctx, pipe, in.arena, raw_body) catch |err| blk: {
        if (err == error.BodyTooLarge or err == error.DecodedBodyTooLarge) return err;
        log.warn("buffered transform failed open: {s}", .{@errorName(err)});
        break :blk .{ .body = raw_body, .all_dropped = false };
    };

    if (processed.all_dropped) {
        const out = try sink.begin(200, &.{.{ .name = "content-type", .value = "application/json" }});
        try out.writeAll("{}");
        return sink.end();
    }

    try exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = processed.body }, pipe.signal == .log);
}

pub fn execFetchFiltered(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    body: InboundBody,
    fetch: service_mod.FetchFiltered,
) !void {
    _ = body; // a scrape has no request body
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    var upstream_req = exchange.openUpstream(ctx, in, fetch.upstream) catch {
        _ = try sink.begin(502, &.{});
        return sink.end();
    };
    defer upstream_req.deinit();
    thread_bufs.trackUpstream(ctx.io, bufs, upstream_req.connection);
    defer thread_bufs.trackUpstream(ctx.io, bufs, null);
    var upstream_res = blk: {
        errdefer |err| exchange.evictUpstream(ctx, &upstream_req, in.path, err);
        try upstream_req.sendBodiless();
        break :blk try upstream_req.receiveHead(&.{});
    };
    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, in.arena, &extra_headers);
    const out = try sink.begin(@intFromEnum(upstream_res.head.status), relayed);

    try thread_bufs.growBuffer(ctx.gpa, &bufs.scratch, 14336);
    const scratch = bufs.scratch;
    var filter: prom.streaming_filter.PolicyStreamingFilter = .init(.{
        .line_buffer = scratch[0..4096],
        .metadata_buffer = scratch[4096..6144],
        .max_input_bytes = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes,
        .max_output_bytes = if (fetch.max_output_bytes == 0) std.math.maxInt(usize) else fetch.max_output_bytes,
        .registry = ctx.registry,
        .bus = ctx.bus,
        .allocator = in.arena,
    });
    var filtering: prom.streaming_filter.FilteringWriter = .init(.{
        .filter = &filter,
        .inner = out,
        .buffer = scratch[6144..14336],
    });

    const upstream_body = upstream_res.reader(bufs.upstream);
    const max_in = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes;
    _ = try pipeline_mod.streamReaderToWriter(upstream_body, filtering.writer(), max_in);
    _ = try filtering.finish();
    try sink.end();
}
