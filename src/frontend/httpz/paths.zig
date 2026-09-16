//! The four request executors the router can choose: raw forward, streamed
//! record pipeline, whole-body transform, and filtered scrape. Free functions
//! on `SharedCtx`; the httpz `Handler` only dispatches to them.
//!
//! Inbound bodies: httpz hands bodies at or above `lazy_read_size` over
//! unread. Two consequences are owned here. httpz skips its own
//! max_body_size check for lazy bodies, so `inboundBody` enforces it from the
//! declared Content-Length before a byte is read. And `req.body()` on a lazy
//! request holds only the prefix that arrived with the headers, so every
//! consumer goes through `inboundBody`.
const std = @import("std");
const httpz = @import("httpz");
const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const limits_mod = @import("../../core/limits.zig");
const prom = @import("../../signals/prometheus/root.zig");
const exchange = @import("exchange.zig");
const thread_bufs = @import("thread_bufs.zig");

const log = std.log.scoped(.httpz_server);
const BodySource = exchange.BodySource;

pub const InboundBody = union(enum) {
    bytes: []const u8,
    lazy: usize,
};

/// Per-read timeout for pulling a lazy body off the client socket. This is
/// SO_RCVTIMEO, so it bounds one read, not the transfer; `DeadlineReader`
/// bounds the transfer.
const lazy_read_timeout_ms: usize = limits_mod.REQUEST_TIMEOUT_SECONDS * 1000;

/// Whole-body deadline for a lazy inbound body.
const inbound_body_timeout_ns: i128 = @as(i128, limits_mod.REQUEST_TIMEOUT_SECONDS) * std.time.ns_per_s;

/// Absolute deadline over a lazy body read.
///
/// `req.reader(ms)` sets SO_RCVTIMEO, which restarts on every read, so a
/// client that sends one byte just inside the timeout holds its handler
/// thread for as long as it likes. A few dozen such clients take the whole
/// pool and the server stops answering, health checks included. This wraps
/// the httpz reader and fails the transfer once the deadline passes.
const DeadlineReader = struct {
    interface: std.Io.Reader,
    inner: *std.Io.Reader,
    io: std.Io,
    deadline_ns: i128,
    /// Set when the deadline fired, so the caller can close the connection
    /// instead of leaving an undrained body on it.
    expired: bool = false,

    fn init(io: std.Io, inner: *std.Io.Reader) DeadlineReader {
        return .{
            .interface = .{
                .end = 0,
                .seek = 0,
                .buffer = &.{},
                .vtable = &.{ .stream = DeadlineReader.stream },
            },
            .inner = inner,
            .io = io,
            .deadline_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds() + inbound_body_timeout_ns,
        };
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *DeadlineReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (std.Io.Timestamp.now(self.io, .awake).toNanoseconds() > self.deadline_ns) {
            self.expired = true;
            return error.ReadFailed;
        }
        return self.inner.stream(w, limit);
    }
};

fn inboundBody(req: *httpz.Request, limits: limits_mod.Limits) !InboundBody {
    if (req.unread_body == 0) return .{ .bytes = req.body() orelse "" };
    if (req.body_len > limits.max_body_size) return error.BodyTooLarge;
    return .{ .lazy = req.body_len };
}

fn bufferLazyBody(io: std.Io, req: *httpz.Request, dst: []u8, len: usize) ![]const u8 {
    std.debug.assert(len <= dst.len);
    var reader = try req.reader(lazy_read_timeout_ms);
    var bounded = DeadlineReader.init(io, &reader.interface);
    var sink: std.Io.Writer = .fixed(dst[0..len]);
    bounded.interface.streamExact(&sink, len) catch |err| {
        if (bounded.expired) return error.InboundBodyTimeout;
        return err;
    };
    return dst[0..len];
}

/// Forward an inbound body as-is: buffered bytes go with the route's replay
/// policy; a lazy body streams socket to socket and cannot be replayed.
fn forwardInbound(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    upstream: service_mod.UpstreamChoice,
    inbound: InboundBody,
    replayable: bool,
) !void {
    switch (inbound) {
        .bytes => |b| return exchange.exchange(ctx, req, res, upstream, .{ .bytes = b }, replayable),
        .lazy => |len| {
            var reader = try req.reader(lazy_read_timeout_ms);
            const body: BodySource = .{ .stream = .{ .reader = &reader.interface, .len = len } };
            return exchange.exchange(ctx, req, res, upstream, body, false);
        },
    }
}

/// Drain a lazy body into this thread's body buffer; the policy paths read
/// the body twice (probe, then encode), so it must be resident.
fn residentBody(ctx: *exec.SharedCtx, req: *httpz.Request, inbound: InboundBody) ![]const u8 {
    return switch (inbound) {
        .bytes => |b| b,
        .lazy => |len| blk: {
            const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
            break :blk try bufferLazyBody(ctx.io, req, try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size), len);
        },
    };
}

pub fn execForwardRaw(ctx: *exec.SharedCtx, req: *httpz.Request, res: *httpz.Response, fwd: service_mod.Forward) !void {
    switch (try inboundBody(req, ctx.limits)) {
        .bytes => |b| return exchange.exchange(ctx, req, res, fwd.upstream, .{ .bytes = b }, fwd.replayable),
        .lazy => |len| {
            var reader = try req.reader(lazy_read_timeout_ms);
            var bounded = DeadlineReader.init(ctx.io, &reader.interface);
            const body: BodySource = .{ .stream = .{ .reader = &bounded.interface, .len = len } };
            exchange.exchange(ctx, req, res, fwd.upstream, body, false) catch |err| {
                if (bounded.expired) return error.InboundBodyTimeout;
                return err;
            };
        },
    }
}

pub fn execPipeStream(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    pipe: service_mod.PipeStream,
) !void {
    const inbound = try inboundBody(req, ctx.limits);
    if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
        switch (inbound) {
            .bytes => |b| return exchange.exchange(ctx, req, res, pipe.upstream, .{ .bytes = b }, pipe.signal == .log),
            .lazy => |len| {
                var reader = try req.reader(lazy_read_timeout_ms);
                var bounded = DeadlineReader.init(ctx.io, &reader.interface);
                const body: BodySource = .{ .stream = .{ .reader = &bounded.interface, .len = len } };
                exchange.exchange(ctx, req, res, pipe.upstream, body, false) catch |err| {
                    if (bounded.expired) return error.InboundBodyTimeout;
                    return err;
                };
                return;
            },
        }
    }
    // A probe is a dry run and captures no tap records, and an unchanged
    // batch then skips the real pass entirely — so an armed tap would report
    // nothing exactly when policies are loaded and match nothing. Give up the
    // fast path while a tap is armed. It is a debug endpoint, armed for about
    // a second, so the extra pass costs nothing real.
    const tap_armed = if (ctx.tap) |tap| tap.isArmed() else false;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const raw_body = switch (inbound) {
        .bytes => |b| b,
        .lazy => |len| try bufferLazyBody(
            ctx.io,
            req,
            try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size),
            len,
        ),
    };
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

    if (!changed and !tap_armed) {
        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), probe.records, 0);
            metrics.recordPrefilterDecision(exec.prefilterRouteLabel(pipe.signal, pipe.format), .fast_path);
        }
        return exchange.exchange(ctx, req, res, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
    }

    if (ctx.metrics) |metrics| {
        metrics.recordPrefilterDecision(exec.prefilterRouteLabel(pipe.signal, pipe.format), .policy_path);
    }
    body_reader = .fixed(raw_body);
    var output: std.Io.Writer.Allocating = try .initCapacity(res.arena, initial_capacity);
    var sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
    defer sink.deinit();
    var encode_spec = spec;
    encode_spec.encode = pipe.codec;
    const encoded = pipeline_mod.run(encode_spec, &body_reader, &output.writer, buffers, &sink);
    const stats = encoded catch |err| switch (err) {
        error.ReadFailed => return error.InvalidRequestBody,
        else => return err,
    };
    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
    }
    try exchange.exchange(ctx, req, res, pipe.upstream, .{ .bytes = output.written() }, pipe.signal == .log);
}

pub fn execPipeBuffered(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    pipe: service_mod.PipeBuffered,
) !void {
    const raw_body = switch (try inboundBody(req, ctx.limits)) {
        .bytes => |b| b,
        .lazy => |len| blk: {
            const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
            break :blk try bufferLazyBody(
                ctx.io,
                req,
                try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size),
                len,
            );
        },
    };

    const processed: exec.BufferedResult = exec.processBuffered(ctx, pipe, res.arena, raw_body) catch |err| blk: {
        if (err == error.BodyTooLarge or err == error.DecodedBodyTooLarge) return err;
        log.warn("buffered transform failed open: {s}", .{@errorName(err)});
        break :blk .{ .body = raw_body, .all_dropped = false };
    };

    if (processed.all_dropped) {
        res.status = 200;
        res.header("content-type", "application/json");
        res.body = "{}";
        return;
    }

    try exchange.exchange(ctx, req, res, pipe.upstream, .{ .bytes = processed.body }, pipe.signal == .log);
}

pub fn execFetchFiltered(
    ctx: *exec.SharedCtx,
    req: *httpz.Request,
    res: *httpz.Response,
    fetch: service_mod.FetchFiltered,
) !void {
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    var upstream_req = exchange.openUpstream(ctx, req, res.arena, fetch.upstream) catch {
        res.status = 502;
        res.body = "";
        return;
    };
    defer upstream_req.deinit();
    thread_bufs.trackUpstream(ctx.io, bufs, upstream_req.connection);
    defer thread_bufs.trackUpstream(ctx.io, bufs, null);
    var upstream_res = blk: {
        errdefer |err| exchange.evictUpstream(ctx, &upstream_req, req.url.path, err);
        try upstream_req.sendBodiless();
        break :blk try upstream_req.receiveHead(&.{});
    };
    var extra_headers: [64]std.http.Header = undefined;
    const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, res.arena, &extra_headers);
    res.status = @intFromEnum(upstream_res.head.status);
    for (relayed) |header| res.header(header.name, header.value);

    try thread_bufs.growBuffer(ctx.gpa, &bufs.scratch, 14336);
    const scratch = bufs.scratch;
    var filter: prom.streaming_filter.PolicyStreamingFilter = .init(.{
        .line_buffer = scratch[0..4096],
        .metadata_buffer = scratch[4096..6144],
        .max_input_bytes = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes,
        .max_output_bytes = if (fetch.max_output_bytes == 0) std.math.maxInt(usize) else fetch.max_output_bytes,
        .registry = ctx.registry,
        .bus = ctx.bus,
        .allocator = res.arena,
    });
    var filtering: prom.streaming_filter.FilteringWriter = .init(.{
        .filter = &filter,
        .inner = res.writer(),
        .buffer = scratch[6144..14336],
    });

    const upstream_body = upstream_res.reader(bufs.upstream);
    const max_in = if (fetch.max_input_bytes == 0) std.math.maxInt(usize) else fetch.max_input_bytes;
    _ = try pipeline_mod.streamReaderToWriter(upstream_body, filtering.writer(), max_in);
    _ = try filtering.finish();
}
