//! httpz frontend (PLAN-FRONTEND-SWAP.md §4): inbound HTTP rides httpz's
//! own kqueue/epoll event loop + worker thread pool instead of one
//! Io.Threaded task per connection. The process-wide `Io` keeps serving the
//! upstream client, policy loader, and lifecycle; httpz only needs it for
//! net types.
//!
//! Bodies arrive fully buffered (bounded by limits.max_body_size), so the
//! streaming pipe outcome degrades to buffered here — identical to what the
//! pre-rewrite httpz stack did. All routing/planning/transform logic comes
//! from frontend/exec.zig, shared with the stdio frontend.
const std = @import("std");
const httpz = @import("httpz");

const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const upstream_mod = @import("../upstream.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const encoding_mod = @import("../../pipeline/encoding.zig");
const runtime_metrics = @import("../../runtime/runtime_metrics.zig");
const limits_mod = @import("../../core/limits.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const prom = @import("../../signals/prometheus/root.zig");

const log = std.log.scoped(.httpz_server);

// Bound a stalled upstream without adding another deployment tuning knob.
// The watchdog is process-wide; requests only update their handler-local slot.
const upstream_attempt_timeout_ns: i128 = 30 * std.time.ns_per_s;
const upstream_watchdog_interval_ms: u64 = 100;

// Named event payloads: the type name is the telemetry event name.
const UpstreamRetried = struct { path: []const u8, err: []const u8 };
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// A pooled upstream connection failed and was destroyed instead of re-pooled,
/// so the next request dials fresh (breaks the stale-keepalive poison loop).
/// Eligible log intakes replay the prepared payload once on a fresh connection.
const UpstreamConnectionEvicted = struct { path: []const u8, err: []const u8 };
/// The upstream answered before the request body was fully sent and stopped
/// reading, so the send failed but a real status was already on the wire.
const UpstreamEarlyResponse = struct { path: []const u8, status: u16, err: []const u8 };
/// Per-request trace, emitted at debug so it's off unless log_level=debug.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };

/// Derives the httpz tuning from limits.zig. httpz applies `max_conn` to each
/// event-loop worker, so divide the process-wide connection cap across them.
pub fn configFromLimits(limits: limits_mod.Limits, address: [4]u8, port: u16) httpz.Config {
    const requested_workers = limits.worker_count orelse 1;
    const worker_count: u16 = @intCast(@min(@as(usize, requested_workers), limits.max_connections));
    // httpz applies max_conn per worker. Rounding down preserves the process cap.
    const per_worker: u16 = @intCast(@min(
        @max(1, limits.max_connections / worker_count),
        std.math.maxInt(u16),
    ));
    return .{
        .address = .{ .ip = .{ .ip4 = .{ .bytes = address, .port = port } } },
        .request = .{
            .max_body_size = limits.max_body_size,
            .buffer_size = limits.recv_buf,
            // Bodies at or above this arrive unread: httpz hands the connection
            // over after the headers and the handler pulls the body from the
            // socket. Below it, httpz buffers as before. Set to the pool buffer
            // size so anything that would have missed the pool (and gone to an
            // arena allocation of body size, growing 1.5x) streams instead.
            // Two consequences are owned by `inboundBody`: httpz skips its own
            // max_body_size check for lazy bodies, and `req.body()` then holds
            // only the prefix that arrived with the headers.
            .lazy_read_size = limits.large_body_buffer_size,
        },
        // Handler threads bound concurrency, since each owns a whole upstream
        // exchange. limits.zig derives the count; it is never left to httpz. Its count
        // bounds the number of retained per-thread pipeline workspaces.
        // The large-buffer pool is eagerly allocated (count x size at startup)
        // and httpz's defaults are 16 x max_body_size; we bound it from limits.
        // Misses fall back to exact-size per-request arena allocs, so this is
        // a memory cap, not a body-size cap.
        .workers = .{
            .count = worker_count,
            .max_conn = per_worker,
            .large_buffer_count = limits.large_body_buffer_count,
            .large_buffer_size = limits.large_body_buffer_size,
        },
        .thread_pool = .{ .count = limits.thread_pool_count },
        // httpz defaults both to ~68 years, so a half-open or slow client would
        // hold one of `max_connections` slots indefinitely.
        .timeout = .{
            .request = limits_mod.REQUEST_TIMEOUT_SECONDS,
            .keepalive = limits_mod.KEEPALIVE_TIMEOUT_SECONDS,
        },
    };
}

/// Only transport staging is allocated for passthrough. Codec and policy
/// workspaces grow on demand and are retained for the handler thread.
const ThreadBufs = struct {
    decode: []u8 = &.{},
    encode: []u8 = &.{},
    scratch: []u8 = &.{},
    chunk: []u8 = &.{},
    upstream: []u8,
    record: exec.RecordScratch,
    deadline_lock: std.Io.Mutex = .init,
    connection: ?*std.http.Client.Connection = null,
    deadline_ns: i128 = 0,
    /// Staging for a streamed body. `Reader.stream` reads from the client
    /// socket straight into the upstream writer's buffer, so this size is the
    /// chunk size of the whole pump. At the 20 KiB upstream write buffer a
    /// 1 MB body is ~52 blocking read/write round trips on the handler thread,
    /// and throughput fell to a third of the buffered path; a larger window
    /// keeps the client's TCP window open and amortizes the syscalls.
    pump: []u8 = &.{},
    /// Landing buffer for a lazy body the policy path must hold resident.
    /// Per thread and never freed per request: the alternative, draining into
    /// the per-connection request arena, frees the node back into libc malloc
    /// after every request and malloc keeps it mapped, so RSS grew ~1.1 MB per
    /// connection (67/128/322 MB at 16/64/250 connections, measured) even
    /// though only `thread_pool_count` bodies are ever live at once. Sized to
    /// max_body_size, so it is bounded by threads alone.
    body: []u8 = &.{},
    timed_out: std.atomic.Value(bool) = .init(false),

    /// Lazily sized on first streamed body; retained for the thread like the
    /// codec workspaces. Freed in freeThreadBufs.
    fn ensurePump(self: *ThreadBufs, allocator: std.mem.Allocator) ![]u8 {
        if (self.pump.len == 0) self.pump = try allocator.alloc(u8, pump_buffer_bytes);
        return self.pump;
    }

    /// Lazily sized on the first lazy body a policy path has to buffer.
    fn ensureBody(self: *ThreadBufs, allocator: std.mem.Allocator, max_body_size: usize) ![]u8 {
        if (self.body.len == 0) self.body = try allocator.alloc(u8, max_body_size);
        return self.body;
    }

    fn prepare(
        self: *ThreadBufs,
        allocator: std.mem.Allocator,
        limits: limits_mod.Limits,
        codec: encoding_mod.ContentEncoding,
    ) !void {
        try growBuffer(allocator, &self.decode, codec.decoderBufferLen(limits.zstd_window_len));
        try growBuffer(allocator, &self.encode, codec.encoderBufferLen());
        try growBuffer(allocator, &self.scratch, limits.record_scratch);
        try growBuffer(allocator, &self.chunk, limits.chunk_buf);
    }
};

threadlocal var tl_bufs: ?*ThreadBufs = null;
var bufs_registry_mutex: std.Io.Mutex = .init;
var bufs_registry: std.ArrayList(*ThreadBufs) = .empty;

fn growBuffer(allocator: std.mem.Allocator, buffer: *[]u8, len: usize) !void {
    if (buffer.len < len) buffer.* = try allocator.realloc(buffer.*, len);
}

fn threadBufs(io: std.Io, allocator: std.mem.Allocator, limits: limits_mod.Limits) !*ThreadBufs {
    if (tl_bufs) |bufs| return bufs;
    const bufs = try allocator.create(ThreadBufs);
    errdefer allocator.destroy(bufs);
    const upstream = try allocator.alloc(u8, limits.upstream_write_buf);
    errdefer allocator.free(upstream);
    bufs.* = .{ .upstream = upstream, .record = .init(allocator) };
    errdefer bufs.record.deinit();
    bufs_registry_mutex.lockUncancelable(io);
    defer bufs_registry_mutex.unlock(io);
    try bufs_registry.append(allocator, bufs);
    tl_bufs = bufs;
    return bufs;
}

fn trackUpstream(io: std.Io, bufs: *ThreadBufs, connection: ?*std.http.Client.Connection) void {
    bufs.deadline_lock.lockUncancelable(io);
    defer bufs.deadline_lock.unlock(io);
    bufs.connection = connection;
    if (connection) |_| {
        // From now, not from when the inbound request arrived. A slow client
        // that took most of the request timeout to deliver its body would
        // otherwise leave the upstream almost no budget, and a healthy
        // upstream would be cut off and reported as a 504.
        bufs.deadline_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds() + upstream_attempt_timeout_ns;
        bufs.timed_out.store(false, .release);
    }
}

fn expireTrackedUpstreams(ctx: *exec.SharedCtx, force: bool) void {
    const now = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    bufs_registry_mutex.lockUncancelable(ctx.io);
    defer bufs_registry_mutex.unlock(ctx.io);
    for (bufs_registry.items) |bufs| {
        bufs.deadline_lock.lockUncancelable(ctx.io);
        defer bufs.deadline_lock.unlock(ctx.io);
        const connection = bufs.connection orelse continue;
        if (!force and now < bufs.deadline_ns) continue;
        if (bufs.timed_out.swap(true, .acq_rel)) continue;
        connection.closing = true;
        connection.stream_reader.stream.shutdown(ctx.io, .both) catch |err| {
            log.debug("failed to interrupt upstream: {s}", .{@errorName(err)});
        };
    }
}

fn watchUpstreamDeadlines(server: *HttpServer) std.Io.Cancelable!void {
    while (!server.handler.stopping.load(.acquire)) {
        try server.ctx.io.sleep(.fromMilliseconds(upstream_watchdog_interval_ms), .awake);
        expireTrackedUpstreams(server.ctx, false);
    }
}

/// Called only after every handler thread has been joined.
fn freeThreadBufs(io: std.Io, allocator: std.mem.Allocator) void {
    bufs_registry_mutex.lockUncancelable(io);
    defer bufs_registry_mutex.unlock(io);
    for (bufs_registry.items) |bufs| {
        allocator.free(bufs.decode);
        allocator.free(bufs.encode);
        allocator.free(bufs.scratch);
        allocator.free(bufs.chunk);
        allocator.free(bufs.upstream);
        allocator.free(bufs.pump);
        allocator.free(bufs.body);
        bufs.record.deinit();
        allocator.destroy(bufs);
    }
    bufs_registry.deinit(allocator);
    bufs_registry = .empty;
    tl_bufs = null;
}

pub const HttpServer = struct {
    ctx: *exec.SharedCtx,
    lifecycle: *lifecycle_mod.Lifecycle,
    handler: *Handler,
    server: httpz.Server(*Handler),
    listen_done: std.Io.Event = .unset,

    pub fn init(
        ctx: *exec.SharedCtx,
        lifecycle: *lifecycle_mod.Lifecycle,
        listen_address: [4]u8,
        listen_port: u16,
    ) !HttpServer {
        const handler = try ctx.gpa.create(Handler);
        errdefer ctx.gpa.destroy(handler);
        handler.* = .{ .ctx = ctx };

        const config = configFromLimits(ctx.limits, listen_address, listen_port);
        const server = try httpz.Server(*Handler).init(ctx.io, ctx.gpa, config, handler);
        log.info(
            "httpz frontend: {d} worker(s), {d} handler threads, {d} max connections, lazy pipeline scratch",
            .{
                config.workerCount(),
                config.threadPoolCount(),
                (config.workers.max_conn orelse 0) * config.workerCount(),
            },
        );
        return .{
            .ctx = ctx,
            .lifecycle = lifecycle,
            .handler = handler,
            .server = server,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        self.server.deinit();
        // Handler pool is joined by now; reclaim each thread's pipeline scratch.
        freeThreadBufs(self.ctx.io, self.ctx.gpa);
        self.ctx.gpa.destroy(self.handler);
        self.* = undefined;
    }

    /// Blocks in httpz's accept/event loop until `stopAccepting`. Spawned
    /// into the lifecycle group like the stdio accept loop; cancellation
    /// can't interrupt the blocking listen, which is why Engine.stop calls
    /// stopAccepting() before Lifecycle.shutdown.
    pub fn run(self: *HttpServer) std.Io.Cancelable!void {
        self.lifecycle.spawn(self.ctx.io, watchUpstreamDeadlines, .{self}) catch {
            self.listen_done.set(self.ctx.io);
            self.lifecycle.requestShutdown(self.ctx.io);
            return;
        };
        self.server.listen() catch |err| {
            log.err("httpz listen failed: {s}", .{@errorName(err)});
        };
        const stopped = self.handler.stopping.load(.acquire);
        self.listen_done.set(self.ctx.io);
        if (!stopped) self.lifecycle.requestShutdown(self.ctx.io);
    }

    /// Stop dispatch, interrupt stalled upstream I/O, and wait for httpz to join
    /// its handler pools before returning.
    pub fn stopAccepting(self: *HttpServer) void {
        self.handler.stopping.store(true, .release);
        expireTrackedUpstreams(self.ctx, true);
        if (!self.listen_done.isSet()) self.server.stop();
        self.listen_done.waitUncancelable(self.ctx.io);
    }
};

/// Upper bound on forwarded request headers (datadog/prom intakes stay well
/// under this). Excess returns error.TooManyHeaders rather than truncating.
const max_forward_headers = 64;

/// Collects forwardable request headers into an arena-owned array. Header
/// strings remain owned by the inbound request for the whole exchange.
/// `iter` is any iterator whose `next()` yields `.{ .key, .value }`.
fn collectForwardHeaders(arena: std.mem.Allocator, iter: anytype) ![]std.http.Header {
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

/// What `exchange` forwards upstream: a slice httpz already buffered, or a
/// body still on the inbound socket with its declared length.
const BodySource = union(enum) {
    bytes: []const u8,
    /// Read once, straight from the client socket to the upstream socket.
    /// Cannot be replayed, so `exchange` never retries it.
    stream: struct { reader: *std.Io.Reader, len: usize },
};

/// Inbound body as the handler must treat it.
const InboundBody = union(enum) {
    /// Fully buffered by httpz. Zero-copy slice.
    bytes: []const u8,
    /// At or above lazy_read_size; still on the socket. The declared
    /// Content-Length, already checked against max_body_size.
    lazy: usize,
};

/// Chunk size for pumping a streamed body client socket -> upstream socket.
const pump_buffer_bytes: usize = 512 * 1024;

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
    /// Set when the deadline fired, so the handler can close the connection
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

/// Classify the inbound body and enforce the cap httpz skips for lazy reads
/// (request.zig: the max_body_size check is bypassed when lazy_read_size is
/// set). Checked from the declared length before any body byte is read.
fn inboundBody(req: *httpz.Request, limits: limits_mod.Limits) !InboundBody {
    if (req.unread_body == 0) return .{ .bytes = req.body() orelse "" };
    if (req.body_len > limits.max_body_size) return error.BodyTooLarge;
    return .{ .lazy = req.body_len };
}

/// Drain a lazy body into the request arena. Used by the paths that must
/// read the body twice (the policy probe, the buffered transforms); the
/// result is what `req.body()` would have held had httpz buffered it, at the
/// same one-exact-copy cost.
fn bufferLazyBody(io: std.Io, req: *httpz.Request, dst: []u8, len: usize) ![]const u8 {
    // `len` was checked against max_body_size by inboundBody, and `dst` is
    // sized to max_body_size, so this cannot overrun.
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

pub const Handler = struct {
    ctx: *exec.SharedCtx,
    stopping: std.atomic.Value(bool) = .init(false),
    /// httpz entry point (takes precedence over httpz's router). Must not
    /// return errors; failures discard buffered headers and partial response
    /// data.
    pub fn handle(self: *Handler, req: *httpz.Request, res: *httpz.Response) void {
        if (self.stopping.load(.acquire)) {
            res.status = 503;
            res.keepalive = false;
            return;
        }
        const ctx = self.ctx;
        const start_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
        const method = serviceMethod(req.method);
        const known_path = exec.classifyKnownPath(req.url.path, method);
        if (ctx.metrics) |metrics| {
            metrics.recordRequest(exec.methodLabel(method), known_path);
        }

        self.dispatch(req, res) catch |err| {
            // A request reaching here threw past all in-handler recovery (retries,
            // fail-open) — a real failure, not a routine 4xx/5xx. Log it as such.
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.err(RequestFailed{
                .method = @tagName(req.method),
                .path = req.url.path,
                .err = @errorName(err),
            });
            res.clearWriter();
            res.headers.reset();
            res.status = errorStatus(err);
            res.body = "";
            // The body is part-read, so the connection cannot be reused: httpz
            // would drain the remainder, which is the same unbounded wait we
            // just escaped.
            if (err == error.InboundBodyTimeout) res.keepalive = false;
            if (ctx.metrics) |metrics| {
                metrics.recordRequestError(known_path, .uncaught);
            }
        };

        // Lifecycle observability is emitted here, AFTER the catch applies the
        // final status, so the duration metric and completion event reflect the
        // bounded error response instead of dispatch's partial status.
        const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        if (ctx.metrics) |metrics| {
            metrics.recordRequestDuration(known_path, elapsed_s);
            metrics.recordResponse(known_path, runtime_metrics.statusClass(res.status));
        }
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.debug(RequestCompleted{
            .method = @tagName(req.method),
            .path = req.url.path,
            .status = res.status,
            .duration_ms = elapsed_s * std.time.ms_per_s,
        });
    }

    fn dispatch(self: *Handler, req: *httpz.Request, res: *httpz.Response) !void {
        const ctx = self.ctx;
        const method = serviceMethod(req.method);
        const path = req.url.path;

        // Internal observability endpoint, checked before routing — parity
        // with the stdio driver's /_edge/metrics short-circuit.
        if (req.method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) {
            res.header("content-type", "text/plain; version=0.0.4");
            exec.refreshPolicyGauge(ctx);
            if (ctx.metrics) |metrics| {
                try metrics.writePrometheus(res.writer());
            }
            // httpz's own counters: accept rate, keepalive/request timeouts,
            // large-buffer pool misses, and rejects for oversized bodies and
            // headers. httpz_connections going flat while httpz_requests keeps
            // climbing is the signature of the connection cap being reached.
            try httpz.writeMetrics(res.writer());
            return;
        }

        // Dump the loaded policy snapshot (id/signal/enabled/name). Pairs with
        // the gauge: shows *which* policies are active, not just how many.
        if (req.method == .GET and std.mem.eql(u8, path, "/_edge/policies")) {
            const json = std.mem.eql(u8, (try req.query()).get("format") orelse "", "json");
            res.header("content-type", if (json) "application/json" else "text/plain; charset=utf-8");
            try exec.writePolicies(ctx.registry, res.writer(), json);
            return;
        }

        // Debug tap (config-gated): block this request up to 1s while data-plane
        // threads stream the next N records into our buffer, before or after
        // policy evaluation. ctx.tap is null unless enabled in config.
        if (req.method == .GET and std.mem.startsWith(u8, path, "/_edge/tap/")) {
            const stage: exec.TapState.Stage = if (std.mem.eql(u8, path, "/_edge/tap/pre"))
                .pre
            else if (std.mem.eql(u8, path, "/_edge/tap/post"))
                .post
            else {
                res.status = 404;
                return;
            };
            return self.handleTap(req, res, stage);
        }

        const outcome = exec.planRequest(
            ctx,
            method,
            path,
            req.header("content-type") orelse "",
            req.header("content-encoding") orelse "",
        ) orelse {
            res.status = 404;
            res.body = "";
            return;
        };
        switch (outcome) {
            .respond => |static| {
                res.status = static.status;
                res.header("content-type", static.content_type);
                res.body = static.body;
            },
            .forward_raw => |fwd| try self.execForwardRaw(req, res, fwd),
            .pipe_stream => |pipe| try self.execPipeStream(req, res, pipe),
            .pipe_buffered => |pipe| try self.execPipeBuffered(req, res, pipe),
            .fetch_filtered => |fetch| try self.execFetchFiltered(req, res, fetch),
        }
    }

    /// Serves `/_edge/tap/{pre,post}`. Arms the single tap slot, blocks up to
    /// 1s while data-plane threads fill our buffer with the next N records,
    /// then returns the batch. The buffer is freed on return — nothing is
    /// retained between taps.
    fn handleTap(self: *Handler, req: *httpz.Request, res: *httpz.Response, stage: exec.TapState.Stage) !void {
        const ctx = self.ctx;
        const tap = ctx.tap orelse {
            res.status = 404;
            res.body = "tap disabled (set tap_enabled in config)\n";
            return;
        };

        // ?n=<count>, default 50, capped so a single tap can't buffer forever.
        var n: u32 = 50;
        if ((try req.query()).get("n")) |raw| {
            n = std.fmt.parseInt(u32, raw, 10) catch 50;
        }
        n = std.math.clamp(n, 1, 1000);

        var buf: std.Io.Writer.Allocating = .init(ctx.gpa);
        defer buf.deinit();

        if (!tap.arm(stage, n, &buf.writer)) {
            res.status = 409;
            res.body = "a tap is already active\n";
            return;
        }
        // Always release the slot, even on error, before reading the buffer.
        errdefer tap.disarm();

        // Wait until the batch fills or 1s elapses, polling in small steps so
        // we don't pin a handler thread for the full second when data is flowing.
        const deadline_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() + std.time.ns_per_s;
        while (!tap.finished()) {
            if (std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() >= deadline_ns) break;
            ctx.io.sleep(.fromNanoseconds(5 * std.time.ns_per_ms), .awake) catch break;
        }
        tap.disarm(); // stop producers before we read `buf`

        res.header("content-type", "application/octet-stream");
        try res.writer().writeAll(buf.written());
    }

    /// Hop-by-hop-filters and arena-dupes the inbound headers, then opens
    /// the upstream request via the shared executor.
    fn openUpstream(
        self: *Handler,
        req: *httpz.Request,
        arena: std.mem.Allocator,
        choice: service_mod.UpstreamChoice,
    ) !std.http.Client.Request {
        const method = stdMethod(req.method) orelse return error.UnsupportedMethod;
        const headers = try collectForwardHeaders(arena, req.headers.iterator());
        return exec.openUpstream(self.ctx, arena, method, req.url.raw, headers, choice);
    }

    /// Relays the upstream response (status, filtered headers, body) into
    /// the buffered httpz response, bounded by max_response_body.
    fn relayResponse(
        self: *Handler,
        res: *httpz.Response,
        upstream_res: *std.http.Client.Response,
        max_response_body: usize,
        bufs: *ThreadBufs,
    ) !void {
        _ = self;
        var extra_headers: [64]std.http.Header = undefined;
        const relayed = try exec.collectUpstreamResponseHeaders(upstream_res, res.arena, &extra_headers);
        res.status = @intFromEnum(upstream_res.head.status);
        for (relayed) |header| res.header(header.name, header.value);

        const upstream_body = upstream_res.reader(bufs.upstream);
        _ = try pipeline_mod.streamReaderToWriter(upstream_body, res.writer(), max_response_body);
    }

    fn execForwardRaw(self: *Handler, req: *httpz.Request, res: *httpz.Response, fwd: service_mod.Forward) !void {
        switch (try inboundBody(req, self.ctx.limits)) {
            .bytes => |b| return self.exchange(req, res, fwd.upstream, .{ .bytes = b }, fwd.replayable),
            .lazy => |len| {
                var reader = try req.reader(lazy_read_timeout_ms);
                var bounded = DeadlineReader.init(self.ctx.io, &reader.interface);
                const body: BodySource = .{ .stream = .{ .reader = &bounded.interface, .len = len } };
                self.exchange(req, res, fwd.upstream, body, false) catch |err| {
                    if (bounded.expired) return error.InboundBodyTimeout;
                    return err;
                };
            },
        }
    }

    /// Exactly one evaluation precedes this function. Only transport failure
    /// before a response head can replay; upstream HTTP statuses pass through.
    /// Open the upstream request, dialing a second time if the first dial
    /// fails. A failed dial has sent nothing, so this is safe regardless of
    /// the body's replayability or the error's name — unlike the send-side
    /// retry in `exchange`, which needs both. Observed as a 1-in-5000
    /// `error.Unexpected` at phase="connect" in the first 200 ms after
    /// startup, when every handler dials at once; std does not surface the
    /// errno, and "Unexpected" is not in the send-side retry's list, so the
    /// request went straight to 502.
    fn dialUpstream(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        method: std.http.Method,
        headers: []const std.http.Header,
        choice: service_mod.UpstreamChoice,
        client: *std.http.Client,
    ) !std.http.Client.Request {
        const ctx = self.ctx;
        return exec.openUpstreamWithClient(ctx, res.arena, method, req.url.raw, headers, choice, client) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.info(UpstreamRetried{ .path = req.url.path, .err = @errorName(err) });
            return exec.openUpstreamWithClient(ctx, res.arena, method, req.url.raw, headers, choice, client);
        };
    }

    fn exchange(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        choice: service_mod.UpstreamChoice,
        body: BodySource,
        replayable: bool,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        const headers = try collectForwardHeaders(res.arena, req.headers.iterator());
        const method = stdMethod(req.method) orelse return error.UnsupportedMethod;
        // The pump is per-thread and lazily sized; allocate it here with the
        // gpa that freeThreadBufs releases it with.
        if (body == .stream) _ = try bufs.ensurePump(ctx.gpa);
        // A streamed body is consumed by the first attempt; there is nothing
        // left to replay, whatever the caller asked for.
        const retry = body == .bytes and (replayable or method == .GET or method == .HEAD);
        const attempts: usize = if (retry) 2 else 1;
        for (0..attempts) |attempt| {
            const client = if (attempt == 0) ctx.upstreams.getHttpClient() else &ctx.upstreams.retry_client;
            if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(attempt > 0);
            var upstream_req = try self.dialUpstream(req, res, method, headers, choice, client);
            defer upstream_req.deinit();
            trackUpstream(ctx.io, bufs, upstream_req.connection);
            defer trackUpstream(ctx.io, bufs, null);
            var upstream_res = sendAndReceiveHead(&upstream_req, method, body, bufs) catch |err| blk: {
                // An intake that rejects a request (403 bad key, 413, 429) often
                // answers as soon as it has seen the headers and stops reading.
                // Our body write then fails against a peer that has closed its
                // read side, but the response is already in our socket. Read it
                // and relay it: the agent learns the real status instead of a
                // 502 from the proxy, and nothing is retried against a verdict.
                // Only for write-side failures — on anything else the peer may
                // never answer and receiveHead would sit on the read until the
                // upstream watchdog fires.
                if (!bufs.timed_out.load(.acquire) and isSendSideFailure(err)) {
                    if (upstream_req.receiveHead(&.{})) |early| {
                        // Peer stopped reading mid-body; this connection can
                        // never carry another request. Quietly, not evict():
                        // this is the upstream's answer, not a transport fault.
                        markUpstreamClosing(&upstream_req);
                        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                        ctx.bus.info(UpstreamEarlyResponse{
                            .path = req.url.path,
                            .status = @intFromEnum(early.head.status),
                            .err = @errorName(err),
                        });
                        break :blk early;
                    } else |_| {}
                }
                const may_retry = self.evictAndMayRetry(&upstream_req, req.url.path, err);
                if (bufs.timed_out.load(.acquire)) return error.UpstreamTimeout;
                if (!may_retry) return err;
                if (attempt + 1 == attempts) return error.UpstreamTransportFailed;
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                ctx.bus.info(UpstreamRetried{ .path = req.url.path, .err = @errorName(err) });
                continue;
            };
            const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(choice));
            self.relayResponse(res, &upstream_res, max_response, bufs) catch |err| {
                if (bufs.timed_out.load(.acquire)) {
                    self.evictUpstream(&upstream_req, req.url.path, err);
                    return error.UpstreamTimeout;
                }
                switch (err) {
                    error.BodyTooLarge => {
                        self.evictUpstream(&upstream_req, req.url.path, err);
                        return error.UpstreamResponseTooLarge;
                    },
                    error.ReadFailed => self.evictUpstream(&upstream_req, req.url.path, err),
                    else => {},
                }
                return err;
            };
            return;
        }
        unreachable;
    }

    /// Evicts the connection, then reports whether the caller may replay.
    ///
    /// Eviction is unconditional and runs before the replay decision. std covers
    /// most of this already: `receiveHead` marks the connection closing on any
    /// head failure, and `Request.deinit` marks it once a body was left
    /// undrained. It does not cover a send-side failure, which leaves
    /// `reader.state == .ready` and returns a dead socket to the pool. Evicting
    /// on every error keeps that guarantee ours rather than the dependency's,
    /// and costs at most one extra dial on an already-failing request.
    fn evictAndMayRetry(
        self: *Handler,
        upstream_req: *std.http.Client.Request,
        path: []const u8,
        err: anyerror,
    ) bool {
        self.evictUpstream(upstream_req, path, err);
        return retryableTransportError(err);
    }

    /// Destroy a failed pooled upstream connection and record it (warn). Keeps the
    /// dead conn out of the pool so the next request dials fresh.
    fn evictUpstream(
        self: *Handler,
        upstream_req: *std.http.Client.Request,
        path: []const u8,
        err: anyerror,
    ) void {
        markUpstreamClosing(upstream_req); // don't re-pool it
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        self.ctx.bus.warn(UpstreamConnectionEvicted{ .path = path, .err = @errorName(err) });
    }

    fn execPipeStream(self: *Handler, req: *httpz.Request, res: *httpz.Response, pipe: service_mod.PipeStream) !void {
        const ctx = self.ctx;
        const inbound = try inboundBody(req, ctx.limits);
        if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
            // Passthrough never looks at the body, so a lazy one goes socket to
            // socket and peak memory stops scaling with body size. Streaming
            // forfeits the replay retry: a consumed socket cannot be re-sent.
            switch (inbound) {
                .bytes => |b| return self.exchange(req, res, pipe.upstream, .{ .bytes = b }, pipe.signal == .log),
                .lazy => |len| {
                    var reader = try req.reader(lazy_read_timeout_ms);
                    var bounded = DeadlineReader.init(ctx.io, &reader.interface);
                    const body: BodySource = .{ .stream = .{ .reader = &bounded.interface, .len = len } };
                    self.exchange(req, res, pipe.upstream, body, false) catch |err| {
                        if (bounded.expired) return error.InboundBodyTimeout;
                        return err;
                    };
                    return;
                },
            }
        }
        // A probe is a dry run and captures no tap records, and an unchanged
        // batch then skips the real pass entirely — so an armed tap would
        // report nothing exactly when policies are loaded and match nothing.
        // Give up the fast path while a tap is armed. It is a debug endpoint,
        // armed for about a second, so the extra pass costs nothing real.
        const tap_armed = if (ctx.tap) |tap| tap.isArmed() else false;
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        // The probe re-reads the body when a policy changes it, so this path
        // needs it resident either way — in the thread's buffer, not the
        // connection's arena.
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
        // flate.Compress.init asserts its sink holds more than 8 bytes, so an
        // empty or near-empty body would panic on an exactly-sized buffer.
        const initial_capacity = @max(@min(raw_body.len, limits_mod.LARGE_BODY_BUFFER_BYTES), 64);
        // Probe first, retaining nothing. When a batch comes back unchanged
        // the bytes the client sent are already the right answer, so the only
        // thing worth knowing up front is whether any record changes at all.
        // Re-compressing the body is the largest single cost on this path, and
        // a batch that keeps every record verbatim would re-encode to an
        // equivalent of what already arrived.
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
            // `desynced` copies the remainder verbatim, so it still matches the
            // input. A clean probe means nothing changed.
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
            return self.exchange(req, res, pipe.upstream, .{ .bytes = raw_body }, pipe.signal == .log);
        }

        // Something changed, so do the real pass: decode, evaluate and encode
        // straight through, exactly as before. `output` holds the encoded body,
        // so peak memory matches a run without this fast path.
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
        try self.exchange(req, res, pipe.upstream, .{ .bytes = output.written() }, pipe.signal == .log);
    }

    fn execPipeBuffered(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        pipe: service_mod.PipeBuffered,
    ) !void {
        const ctx = self.ctx;
        const raw_body = switch (try inboundBody(req, ctx.limits)) {
            .bytes => |b| b,
            .lazy => |len| blk: {
                const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
                break :blk try bufferLazyBody(
                    ctx.io,
                    req,
                    try bufs.ensureBody(ctx.gpa, ctx.limits.max_body_size),
                    len,
                );
            },
        };

        // res.arena is httpz's per-request fallback allocator; safe for the
        // resize-heavy transform since 5f60277 (fallback resize fix).
        const processed: exec.BufferedResult = exec.processBuffered(ctx, pipe, res.arena, raw_body) catch |err| blk: {
            if (err == error.BodyTooLarge or err == error.DecodedBodyTooLarge) return err;
            log.warn("buffered transform failed open: {s}", .{@errorName(err)});
            break :blk .{ .body = raw_body, .all_dropped = false };
        };

        if (processed.all_dropped) {
            // Nothing left to forward: answer for the upstream.
            res.status = 200;
            res.header("content-type", "application/json");
            res.body = "{}";
            return;
        }

        try self.exchange(req, res, pipe.upstream, .{ .bytes = processed.body }, pipe.signal == .log);
    }

    fn execFetchFiltered(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        fetch: service_mod.FetchFiltered,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        var upstream_req = self.openUpstream(req, res.arena, fetch.upstream) catch {
            res.status = 502;
            res.body = "";
            return;
        };
        defer upstream_req.deinit();
        trackUpstream(ctx.io, bufs, upstream_req.connection);
        defer trackUpstream(ctx.io, bufs, null);
        // Scope eviction to the upstream send+head phase: a reused dead keep-alive
        // fails here, so evict it from the pool. Past receiveHead the response
        // streams straight to the client, so failures there are client-disconnect
        // or local filter errors — those must NOT mark a healthy upstream conn
        // closing and churn the pool. Genuine upstream receive-side failures during
        // the body are handled by std (it sets connection.closing on its own).
        var upstream_res = blk: {
            errdefer |err| self.evictUpstream(&upstream_req, req.url.path, err);
            try upstream_req.sendBodiless();
            break :blk try upstream_req.receiveHead(&.{});
        };
        var extra_headers: [64]std.http.Header = undefined;
        const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, res.arena, &extra_headers);
        res.status = @intFromEnum(upstream_res.head.status);
        for (relayed) |header| res.header(header.name, header.value);

        // Same scratch layout as the stdio frontend: 4K line + 2K metadata
        // + 8K writer staging out of the (otherwise idle on GET) record
        // scratch region.
        try growBuffer(ctx.gpa, &bufs.scratch, 14336);
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
};

fn errorStatus(err: anyerror) u16 {
    return switch (err) {
        error.DecodedBodyTooLarge, error.BodyTooLarge => 413,
        error.InboundBodyTimeout => 408,
        error.InvalidRequestBody => 400,
        error.UpstreamTimeout => 504,
        error.OutOfMemory, error.WriteFailed => 503,
        else => 502,
    };
}

/// Failures that mean "the peer's read side went away while we were writing"
/// — the only case where an early response can be waiting in the socket.
fn isSendSideFailure(err: anyerror) bool {
    return switch (err) {
        error.WriteFailed,
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        => true,
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

fn sendAndReceiveHead(
    request: *std.http.Client.Request,
    method: std.http.Method,
    body: BodySource,
    bufs: *ThreadBufs,
) !std.http.Client.Response {
    try sendBufferedBody(request, method, body, bufs);
    return request.receiveHead(&.{});
}

/// Force a failed upstream connection out of the shared client's pool.
///
/// std.http.Client only evicts on the *receive* side (receiveHead sets
/// connection.closing; deinit then destroys it). A *send*-side failure —
/// BrokenPipe/ConnectionReset writing to a keep-alive the remote idle-closed —
/// leaves connection.closing false, so deinit returns the dead connection to
/// the pool and every later request reuses it and fails too. That's the
/// still-unfixed half of ziglang/zig#30165 (the 0.16 fix only covered receive).
/// Marking it closing here makes Request.deinit destroy it instead of pooling
/// it. Callers do this before their deferred request teardown.
fn markUpstreamClosing(upstream_req: *std.http.Client.Request) void {
    if (upstream_req.connection) |conn| conn.closing = true;
}

/// Writes a fully-buffered request body upstream with an exact
/// content-length (chunked inbound bodies were already de-chunked by httpz).
fn sendBufferedBody(
    upstream_req: *std.http.Client.Request,
    method: std.http.Method,
    body: BodySource,
    bufs: *ThreadBufs,
) !void {
    if (method.requestHasBody()) {
        const len = switch (body) {
            .bytes => |b| b.len,
            .stream => |st| st.len,
        };
        upstream_req.transfer_encoding = .{ .content_length = len };
        const write_buf = switch (body) {
            .bytes => bufs.upstream,
            // Sized by exchange() before the send; see ensurePump.
            .stream => bufs.pump,
        };
        std.debug.assert(write_buf.len > 0);
        var body_writer = try upstream_req.sendBodyUnflushed(write_buf);
        switch (body) {
            .bytes => |b| try body_writer.writer.writeAll(b),
            // Client socket to upstream socket through the 20 KiB write
            // buffer; nothing body-sized is ever resident.
            .stream => |st| try st.reader.streamExact(&body_writer.writer, st.len),
        }
        try body_writer.end();
        try upstream_req.connection.?.flush();
    } else {
        try upstream_req.sendBodiless();
    }
}

fn serviceMethod(method: httpz.Method) service_mod.HttpMethod {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        .CONNECT, .OTHER => .OTHER,
    };
}

fn stdMethod(method: httpz.Method) ?std.http.Method {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        .CONNECT => .CONNECT,
        .OTHER => null,
    };
}

// ============================== Tests ==============================

const testing = std.testing;

test "httpz config derives from limits" {
    const limits: limits_mod.Limits = .resolve(.{ .max_body_size = 1024 * 1024 });

    const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
    try testing.expectEqual(@as(?usize, 1024 * 1024), config.request.max_body_size);
    try testing.expectEqual(@as(?usize, limits_mod.RECV_BUF_BYTES), config.request.buffer_size);
    // One event loop with the default handler pool.
    try testing.expectEqual(@as(?u16, 1), config.workers.count);
    try testing.expectEqual(@as(?u16, limits_mod.DEFAULT_HANDLER_THREADS), config.thread_pool.count);
    // The large-body pool must NOT ride httpz defaults (16 x max_body_size).
    try testing.expectEqual(@as(?u16, 8), config.workers.large_buffer_count);
    try testing.expectEqual(@as(?u32, limits_mod.LARGE_BODY_BUFFER_BYTES), config.workers.large_buffer_size);
    try testing.expectEqual(@as(u16, 8080), config.address.ip.ip4.port);
}

test "httpz config carries benchmark overrides" {
    const limits: limits_mod.Limits = .resolve(.{
        .max_body_size = 1024 * 1024,
        .worker_count = 2,
        .thread_pool_count = 8,
    });
    const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
    try testing.expectEqual(@as(?u16, 2), config.workers.count);
    try testing.expectEqual(@as(?u16, 8), config.thread_pool.count);
}

test "httpz worker count preserves the global connection cap" {
    for ([_]u16{ 1, 2, 3, 4 }) |workers| {
        const limits: limits_mod.Limits = .resolve(.{
            .max_body_size = 1024 * 1024,
            .max_connections = 256,
            .worker_count = workers,
        });
        const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
        const total = (config.workers.max_conn orelse 0) * config.workerCount();
        try testing.expect(total <= 256 and total > 256 - workers);
    }
}

test "more workers than connections cannot over-admit" {
    // httpz applies max_conn to every worker, so an unclamped worker count
    // would admit one connection per worker against a one-connection cap.
    const limits: limits_mod.Limits = .resolve(.{
        .max_body_size = 1024 * 1024,
        .max_connections = 1,
        .worker_count = 64,
    });
    try testing.expectEqual(@as(?u16, 1), limits.worker_count);

    const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
    try testing.expectEqual(@as(usize, 1), (config.workers.max_conn orelse 0) * config.workerCount());
}

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

test "httpz method maps onto service and std methods" {
    try testing.expectEqual(service_mod.HttpMethod.POST, serviceMethod(.POST));
    try testing.expectEqual(service_mod.HttpMethod.OTHER, serviceMethod(.CONNECT));
    try testing.expectEqual(@as(?std.http.Method, .GET), stdMethod(.GET));
    try testing.expectEqual(@as(?std.http.Method, null), stdMethod(.OTHER));
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
