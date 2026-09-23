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
const limits_mod = @import("../core/limits.zig");
const prom = @import("../signals/prometheus/root.zig");
const runtime_metrics = @import("../runtime/runtime_metrics.zig");
const exchange = @import("exchange.zig");
const thread_bufs = @import("thread_bufs.zig");

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
/// Per-request trace at debug level.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };
/// Same shape at warn level, for a request that held its thread or task.
const RequestSlow = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };

/// Warn past this. `RequestCompleted` is debug level, which production turns
/// off. Without this line, a request that waited seconds on a stalled
/// upstream leaves no record.
const slow_request_seconds: f64 = 5;

/// The frontend decides the variant. See `exchange.BodySource`.
pub const InboundBody = exchange.BodySource;

/// Drain a lazy or streamed body into this thread's body buffer. The policy
/// paths read the body twice (probe, then encode), so it must be resident.
/// The thread buffer, not the connection arena, holds the body-sized memory.
fn residentBody(ctx: *exec.SharedCtx, inbound: InboundBody) ![]const u8 {
    if (inbound == .bytes) return inbound.bytes;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const dst = try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size);
    switch (inbound) {
        .bytes => unreachable,
        .lazy => |l| {
            std.debug.assert(l.len <= dst.len);
            var fixed: std.Io.Writer = .fixed(dst[0..l.len]);
            l.reader.streamExact(&fixed, l.len) catch |err| return switch (err) {
                // The sender closed before `len` bytes arrived.
                error.EndOfStream => error.InboundBodyTruncated,
                error.ReadFailed, error.WriteFailed => |e| e,
            };
            return dst[0..l.len];
        },
        .streamed => |st| {
            var fixed: std.Io.Writer = .fixed(dst);
            const n = try pipeline_mod.streamReaderToWriter(st.reader, &fixed, st.max_bytes);
            return dst[0..n];
        },
    }
}

/// Request-end bookkeeping for both frontends: duration and response
/// metrics, then one trace line. The line is `RequestSlow` at warn level past
/// `slow_request_seconds`, and `RequestCompleted` at debug level otherwise.
pub fn finishRequest(
    ctx: *exec.SharedCtx,
    method: []const u8,
    path: []const u8,
    known_path: runtime_metrics.KnownPathLabel,
    status: u16,
    start_ns: i128,
) void {
    const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
    const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    if (ctx.metrics) |metrics| {
        metrics.recordRequestDuration(known_path, elapsed_s);
        metrics.recordResponse(known_path, runtime_metrics.statusClass(status));
    }
    const duration_ms = elapsed_s * std.time.ms_per_s;
    if (elapsed_s >= slow_request_seconds) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(RequestSlow{ .method = method, .path = path, .status = status, .duration_ms = duration_ms });
    } else {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.debug(RequestCompleted{ .method = method, .path = path, .status = status, .duration_ms = duration_ms });
    }
}

pub fn execForwardRaw(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    body: InboundBody,
    fwd: service_mod.Forward,
) !void {
    return exchange.exchange(ctx, in, sink, fwd.upstream, body, fwd.replayable);
}

/// Report that a policy stage failed to read the batch. Counted as a module
/// error, because the policy module failed even though the request succeeds.
fn reportFailOpen(ctx: *exec.SharedCtx, path: []const u8, stage: []const u8, err: anyerror) void {
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    ctx.bus.warn(PolicyFailedOpen{ .path = path, .stage = stage, .err = @errorName(err) });
    if (ctx.metrics) |metrics| {
        metrics.recordRequestError(exec.classifyKnownPath(path, .POST), .module);
    }
}

/// Forward the untouched batch after a policy stage failed to read it, and
/// say so.
fn failOpen(
    ctx: *exec.SharedCtx,
    in: Inbound,
    sink: anytype,
    pipe: service_mod.PipeStream,
    raw_body: []const u8,
    stage: []const u8,
    err: anyerror,
) !void {
    reportFailOpen(ctx, in.path, stage, err);
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
        return exchange.exchange(ctx, in, sink, pipe.upstream, body, pipe.signal == .log);
    }
    // A probe is a dry run and captures no tap records, and an unchanged
    // batch then skips the real pass entirely — so an armed tap would report
    // nothing exactly when policies are loaded and match nothing. Give up the
    // fast path while a tap is armed. It is a debug endpoint, armed for about
    // a second, so the extra pass costs nothing real.
    const tap_armed = if (ctx.tap) |tap| tap.isArmed() else false;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    // The whole body, before anything decodes it.
    const raw_body = try residentBody(ctx, body);
    try bufs.prepare(ctx.gpa, ctx.limits);
    const decoder = try bufs.ensureDecoder(ctx.gpa);
    const initial_capacity = @max(@min(raw_body.len, limits_mod.LARGE_BODY_BUFFER_BYTES), 64);
    const spec: pipeline_mod.PipelineSpec = .{
        .decode = pipe.codec,
        .format = pipe.format,
        .encode = .identity,
        .max_decoded_bytes = ctx.limits.max_decoded_bytes,
        .zstd_window_len = ctx.limits.zstd_window_len,
    };
    const buffers: pipeline_mod.Buffers = .{ .scratch = bufs.scratch, .chunk = bufs.chunk };

    var probe = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    probe.probe = true;
    var discard: std.Io.Writer.Discarding = .init(&.{});
    const probe_codecs: pipeline_mod.Codecs = .{ .decoder = decoder, .encoder = null };
    const probe_result = pipeline_mod.run(spec, raw_body, &discard.writer, buffers, probe_codecs, &probe);
    const changed = if (probe_result) |probe_stats| blk: {
        break :blk probe_stats.dropped > 0 or probe_stats.replaced > 0;
    } else |err| switch (err) {
        error.BatchChanged => true,
        // A body we cannot read is still the customer's data. Forward it and
        // let the intake judge it, exactly as execPipeBuffered does.
        // A decode budget the sender cannot see must not destroy the batch.
        error.Corrupt,
        error.Truncated,
        error.WindowTooLarge,
        error.DecodedBodyTooLarge,
        => return failOpen(ctx, in, sink, pipe, raw_body, "probe", err),
        else => return err,
    };

    if (!changed and !tap_armed) {
        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), probe.records, 0);
        }
        return exchange.exchange(ctx, in, sink, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
    }
    var output: std.Io.Writer.Allocating = try .initCapacity(in.arena, initial_capacity);
    var record_sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    var encode_spec = spec;
    encode_spec.encode = pipe.codec;
    const pooled = if (pipe.codec != .identity) try thread_bufs.encoder_pool.acquire(ctx.gpa) else null;
    defer if (pooled) |p| thread_bufs.encoder_pool.release(ctx.gpa, p);
    const codecs: pipeline_mod.Codecs = .{ .decoder = decoder, .encoder = if (pooled) |p| &p.encoder else null };
    const encoded = pipeline_mod.run(encode_spec, raw_body, &output.writer, buffers, codecs, &record_sink);
    const stats = encoded catch |err| switch (err) {
        error.Corrupt,
        error.Truncated,
        error.WindowTooLarge,
        error.DecodedBodyTooLarge,
        => return failOpen(ctx, in, sink, pipe, raw_body, "encode", err),
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
        // BodyTooLarge is the raw cap, which the sender can act on. Fail open
        // on any other error; see exchange.errorStatus.
        if (err == error.BodyTooLarge) return err;
        reportFailOpen(ctx, in.path, "buffered", err);
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
    // A dead keep-alive fails during send or receiveHead. Body handling below
    // also evicts incomplete responses and distinguishes watchdog timeouts.
    var upstream_res = blk: {
        upstream_req.sendBodiless() catch |err| break :blk err;
        break :blk upstream_req.receiveHead(&.{});
    } catch |err| {
        exchange.evictUpstream(ctx, &upstream_req, in.path, err);
        if (bufs.timed_out.load(.acquire)) return exchange.timedOut(ctx, in.path, "head");
        return err;
    };
    const declared = upstream_res.head.content_length;
    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exchange.collectUpstreamResponseHeaders(&upstream_res, in.arena, &extra_headers);
    const out = try sink.begin(@intFromEnum(upstream_res.head.status), relayed);

    try thread_bufs.growBuffer(ctx.gpa, &bufs.scratch, 14336);
    const scratch = bufs.scratch;
    const max_in = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes;
    var filter: prom.streaming_filter.PolicyStreamingFilter = .init(.{
        .line_buffer = scratch[0..4096],
        .metadata_buffer = scratch[4096..6144],
        .max_input_bytes = max_in,
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
    const copied = pipeline_mod.streamReaderToWriter(upstream_body, filtering.writer(), max_in);
    // Socket shutdown can surface as EOF, so a successful copy does not prove
    // the response completed. Never finish a timed-out or short exposition.
    if (bufs.timed_out.load(.acquire)) {
        exchange.evictUpstream(ctx, &upstream_req, in.path, error.UpstreamTimeout);
        return exchange.timedOut(ctx, in.path, "relay");
    }
    const n = try copied;
    if (declared) |want| {
        if (n < want) {
            exchange.evictUpstream(ctx, &upstream_req, in.path, error.UpstreamResponseTruncated);
            return error.UpstreamResponseTruncated;
        }
    }
    _ = try filtering.finish();
    try sink.end();
}
