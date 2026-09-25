//! The four request executors the router can choose: raw forward, streamed
//! record pipeline, whole-body transform, and filtered scrape. Free functions
//! on `SharedCtx`; each frontend's dispatch only calls into them.
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
const encoding_mod = @import("../pipeline/encoding.zig");
const buffered = @import("../pipeline/compress_buffered.zig");
const limits_mod = @import("../core/limits.zig");
const prom = @import("../signals/prometheus/root.zig");
const exchange = @import("exchange.zig");
const thread_bufs = @import("thread_bufs.zig");

const log = std.log.scoped(.httpz_server);
const BodySource = exchange.BodySource;
const Inbound = exchange.Inbound;

// Named event payloads: the type name is the telemetry event name.
/// A policy stage could not read the batch, so the batch went upstream
/// untouched. The edge must never be the reason data disappears: only the
/// intake can accept or reject a payload.
const PolicyFailedOpen = struct { path: []const u8, stage: []const u8, err: []const u8 };
/// Policy kept nothing in the batch. Intended behaviour, and the first thing
/// to look at when an operator asks where their data went. `forwarded` says
/// what the intake saw: the record path sends the empty batch on, and the
/// buffered path answers success and sends nothing. Warned once for the
/// process, then a line per batch at debug: at full rate a line per batch is
/// its own outage, and `edge_policy_records_dropped_total` carries the rate.
const BatchDropped = struct { path: []const u8, signal: []const u8, forwarded: bool };

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

/// Forward the untouched batch after a policy stage failed to read it, and
/// say so. Counted as a module error, because the policy module failed even
/// though the request succeeds.
fn failOpen(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    pipe: service_mod.PipeStream,
    raw_body: []const u8,
    stage: []const u8,
    err: anyerror,
) !void {
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    ctx.bus.warn(PolicyFailedOpen{ .path = in.path, .stage = stage, .err = @errorName(err) });
    if (ctx.metrics) |metrics| {
        metrics.recordRequestError(exec.classifyKnownPath(in.path, .POST), .module);
    }
    return exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
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
    // A probe is a dry run and captures no tap records, and an unchanged
    // batch then skips the real pass entirely — so an armed tap would report
    // nothing exactly when policies are loaded and match nothing. Give up the
    // fast path while a tap is armed. It is a debug endpoint, armed for about
    // a second, so the extra pass costs nothing real.
    const tap_armed = if (ctx.tap) |tap| tap.isArmed() else false;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const raw_body = try residentBody(ctx, body);
    try bufs.prepare(ctx.gpa, ctx.limits, pipe.codec);
    // zstd decodes with libzstd first (see `encoding.Decoder`), and the
    // pipeline then reads the decoded bytes as identity.
    const zstd_decoded: ?[]u8 = if (pipe.codec == .zstd)
        buffered.decompressZstd(ctx.gpa, raw_body, ctx.limits.max_decoded_bytes, ctx.limits.zstd_window_len) catch |err|
            return failOpen(ctx, in, sink, pipe, raw_body, "probe", err)
    else
        null;
    defer if (zstd_decoded) |decoded| ctx.gpa.free(decoded);
    const decode_input = zstd_decoded orelse raw_body;
    const decode: encoding_mod.ContentEncoding = if (zstd_decoded != null) .identity else pipe.codec;
    var body_reader = encoding_mod.residentReader(decode, decode_input);
    const initial_capacity = @max(@min(raw_body.len, limits_mod.LARGE_BODY_BUFFER_BYTES), 64);
    const spec: pipeline_mod.PipelineSpec = .{
        .decode = decode,
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
        // A body we cannot read is still the customer's data. Forward it and
        // let the intake judge it, exactly as execPipeBuffered does.
        // A decode budget the sender cannot see must not destroy the batch.
        error.ReadFailed, error.DecodedBodyTooLarge => return failOpen(ctx, in, sink, pipe, raw_body, "probe", err),
        else => return err,
    };

    if (!changed and !tap_armed) {
        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), probe.records, 0);
        }
        return exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
    }
    body_reader = encoding_mod.residentReader(decode, decode_input);
    var output: std.Io.Writer.Allocating = try .initCapacity(in.arena, initial_capacity);
    var record_sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    defer record_sink.deinit();
    var encode_spec = spec;
    encode_spec.encode = pipe.codec;
    const encoded = pipeline_mod.run(encode_spec, &body_reader, &output.writer, buffers, &record_sink);
    const stats = encoded catch |err| switch (err) {
        error.ReadFailed, error.DecodedBodyTooLarge => return failOpen(ctx, in, sink, pipe, raw_body, "encode", err),
        else => return err,
    };
    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
    }
    if (stats.records > 0 and stats.dropped == stats.records) {
        reportBatchDropped(ctx, in.path, pipe.signal, true);
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
        // `BodyTooLarge` is the raw cap: the sender framed a batch we will not
        // carry, and it can split it. `DecodedBodyTooLarge` is our decode
        // budget, which the sender cannot see, so refusing it destroys data
        // the intake would have taken — the agent discards a 413 for good.
        // Fail open on that one and let the intake judge the payload.
        if (err == error.BodyTooLarge) return err;
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(PolicyFailedOpen{
            .path = in.path,
            .stage = "buffered",
            .err = @errorName(err),
        });
        if (ctx.metrics) |metrics| {
            metrics.recordRequestError(exec.classifyKnownPath(in.path, .POST), .module);
        }
        break :blk .{ .body = raw_body, .all_dropped = false };
    };

    if (processed.all_dropped) {
        reportBatchDropped(ctx, in.path, pipe.signal, false);
        const out = try sink.begin(200, &.{.{ .name = "content-type", .value = "application/json" }});
        try out.writeAll("{}");
        return sink.end();
    }

    try exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = processed.body }, pipe.signal == .log);
}

/// Reports a batch that policy emptied. Warn once, then debug per batch.
fn reportBatchDropped(
    ctx: *exec.SharedCtx,
    path: []const u8,
    signal: service_mod.Signal,
    forwarded: bool,
) void {
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    const event: BatchDropped = .{ .path = path, .signal = @tagName(signal), .forwarded = forwarded };
    if (ctx.batch_dropped_seen.swap(true, .monotonic)) {
        ctx.bus.debug(event);
    } else {
        ctx.bus.warn(event);
    }
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
