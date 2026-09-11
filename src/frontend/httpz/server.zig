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
const BudgetAllocator = @import("../../core/budget_allocator.zig").BudgetAllocator;
const runtime_metrics = @import("../../runtime/runtime_metrics.zig");
const limits_mod = @import("../../core/limits.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const prom = @import("../../signals/prometheus/root.zig");

const log = std.log.scoped(.httpz_server);

// Named event payloads: the type name is the telemetry event name.
const UpstreamRetried = struct { path: []const u8, err: []const u8 };
/// A request threw out of dispatch (not a handled 4xx/5xx) — answered 502.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// A pooled upstream connection failed and was destroyed instead of re-pooled,
/// so the next request dials fresh (breaks the stale-keepalive poison loop).
/// Eligible log intakes replay the prepared payload once on a fresh connection.
const UpstreamConnectionEvicted = struct { path: []const u8, err: []const u8 };
/// Per-request trace, emitted at debug so it's off unless log_level=debug.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };

/// Derives the httpz tuning from limits.zig — no size constant may live
/// here (PLAN-FRONTEND-SWAP.md §5). Worker/thread-pool counts stay on httpz
/// defaults (1 event-loop worker, 32 pool threads), the master-proven shape.
pub fn configFromLimits(limits: limits_mod.Limits, address: [4]u8, port: u16) httpz.Config {
    return .{
        .address = .{ .ip = .{ .ip4 = .{ .bytes = address, .port = port } } },
        .request = .{
            .max_body_size = limits.max_body_size,
            .buffer_size = limits.recv_buf,
        },
        // null => httpz defaults (1 worker, 32 pool threads). thread_pool count
        // multiplies the per-thread pipeline-scratch floor (see ThreadBufs).
        // The large-buffer pool is eagerly allocated (count x size at startup)
        // and httpz's defaults are 16 x max_body_size; we bound it from limits.
        // Misses fall back to exact-size per-request arena allocs, so this is
        // a memory cap, not a body-size cap.
        .workers = .{
            .count = limits.worker_count,
            .max_conn = @intCast(limits.max_connections / (limits.worker_count orelse 1)),
            .min_conn = @intCast(@min(8, limits.max_connections / (limits.worker_count orelse 1))),
            .large_buffer_count = limits.large_body_buffer_count,
            .large_buffer_size = limits.large_body_buffer_size,
        },
        .thread_pool = .{
            .count = limits.thread_pool_count,
            .backlog = @intCast(@max(2, limits.max_connections / (limits.worker_count orelse 1))),
            .buffer_size = limits_mod.HANDLER_THREAD_BUF_BYTES,
        },
        .timeout = .{ .request = 30, .keepalive = 30 },
    };
}

/// Eager httpz pools plus one recv buffer and arena reserve per admitted
/// connection. Bodies, transforms and responses share the remaining budget.
/// ponytail: the per-connection term is an estimate; compare it against
/// edge_http_allocated_bytes at full load before trusting the headroom.
pub fn minimumViableBytes(limits: limits_mod.Limits, config: httpz.Config) !usize {
    const body_pool = try std.math.mul(
        usize,
        @as(usize, config.workers.large_buffer_count orelse 0),
        @as(usize, config.workers.large_buffer_size orelse 0),
    );
    const thread_bufs = try std.math.mul(usize, config.threadPoolCount(), config.thread_pool.buffer_size orelse 0);
    const per_worker = try std.math.add(usize, body_pool, thread_bufs);
    const per_conn = try std.math.add(usize, limits.recv_buf, limits.conn_arena_reserve);
    return std.math.add(
        usize,
        try std.math.mul(usize, config.workerCount(), per_worker),
        try std.math.mul(usize, limits.max_connections, per_conn),
    );
}

/// Only transport staging is allocated for passthrough. Codec and policy
/// workspaces grow on demand and are charged to the shared HTTP memory budget.
const ThreadBufs = struct {
    decode: []u8 = &.{},
    encode: []u8 = &.{},
    scratch: []u8 = &.{},
    chunk: []u8 = &.{},
    upstream: []u8,
    record: exec.RecordScratch,
    /// Guards connection/deadline between the owning handler and the watchdog.
    lock: std.Io.Mutex = .init,
    connection: ?*std.http.Client.Connection = null,
    deadline_ns: i128 = 0,
    expired: std.atomic.Value(bool) = .init(false),

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
    bufs_registry_mutex.lockUncancelable(io);
    defer bufs_registry_mutex.unlock(io);
    try bufs_registry.append(allocator, bufs);
    tl_bufs = bufs;
    return bufs;
}

fn trackConnection(io: std.Io, bufs: *ThreadBufs, connection: ?*std.http.Client.Connection, deadline_ns: i128) void {
    bufs.lock.lockUncancelable(io);
    defer bufs.lock.unlock(io);
    bufs.connection = connection;
    bufs.deadline_ns = deadline_ns;
    if (connection != null) bufs.expired.store(false, .monotonic);
}

/// Shutdown interrupts blocked reads/writes without closing/recycling the fd.
/// Detaching under the same lock precedes Request.deinit, so the watchdog can
/// never touch an already-destroyed connection or a reused descriptor.
fn expireConnections(ctx: *exec.SharedCtx) std.Io.Cancelable!void {
    while (true) {
        try ctx.io.sleep(.fromMilliseconds(50), .awake);
        const now = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
        bufs_registry_mutex.lockUncancelable(ctx.io);
        defer bufs_registry_mutex.unlock(ctx.io);
        for (bufs_registry.items) |bufs| {
            bufs.lock.lockUncancelable(ctx.io);
            defer bufs.lock.unlock(ctx.io);
            const conn = bufs.connection orelse continue;
            if (now < bufs.deadline_ns or bufs.expired.swap(true, .monotonic)) continue;
            conn.stream_reader.stream.shutdown(ctx.io, .both) catch |err| {
                log.debug("upstream deadline shutdown: {s}", .{@errorName(err)});
            };
        }
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
    memory: *BudgetAllocator,
    listen_done: std.Io.Event = .unset,

    pub fn init(
        ctx: *exec.SharedCtx,
        lifecycle: *lifecycle_mod.Lifecycle,
        listen_address: [4]u8,
        listen_port: u16,
    ) !HttpServer {
        const handler = try ctx.gpa.create(Handler);
        errdefer ctx.gpa.destroy(handler);
        const memory = try ctx.gpa.create(BudgetAllocator);
        errdefer ctx.gpa.destroy(memory);
        memory.* = .{ .parent = ctx.gpa, .limit = ctx.limits.max_buffered_bytes };
        handler.* = .{ .ctx = ctx, .allocator = memory.allocator(), .memory = memory };

        const config = configFromLimits(ctx.limits, listen_address, listen_port);
        const minimum = minimumViableBytes(ctx.limits, config) catch return error.InvalidLimits;
        const per_conn = ctx.limits.recv_buf + ctx.limits.conn_arena_reserve;
        if (minimum > memory.limit) {
            log.err(
                "max_buffered_bytes={d} is below the minimum viable {d} ({d} connections x {d} bytes + pools); " ++
                    "raise max_buffered_bytes or lower max_connections/thread_pool_count",
                .{ memory.limit, minimum, ctx.limits.max_connections, per_conn },
            );
            return error.InsufficientMemoryBudget;
        }
        const server = try httpz.Server(*Handler).init(ctx.io, memory.allocator(), config, handler);
        log.info(
            "httpz manifest: cap {d} bytes, minimum {d} ({d} connections, {d} handler threads), headroom {d} for " ++
                "bodies/transforms/responses; excludes TLS, policies and thread stacks",
            .{
                memory.limit,
                minimum,
                (config.workers.max_conn orelse 0) * config.workerCount(),
                config.threadPoolCount() * config.workerCount(),
                memory.limit - minimum,
            },
        );
        return .{
            .ctx = ctx,
            .lifecycle = lifecycle,
            .handler = handler,
            .server = server,
            .memory = memory,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        self.server.deinit();
        // Handler pool is joined by now; reclaim each thread's pipeline scratch.
        freeThreadBufs(self.ctx.io, self.memory.allocator());
        std.debug.assert(self.memory.used.load(.monotonic) == 0);
        self.ctx.gpa.destroy(self.memory);
        self.ctx.gpa.destroy(self.handler);
        self.* = undefined;
    }

    /// Blocks in httpz's accept/event loop until `stopAccepting`. Spawned
    /// into the lifecycle group like the stdio accept loop; cancellation
    /// can't interrupt the blocking listen, which is why Engine.stop calls
    /// stopAccepting() before Lifecycle.shutdown.
    pub fn run(self: *HttpServer) std.Io.Cancelable!void {
        defer self.listen_done.set(self.ctx.io);
        self.lifecycle.spawn(self.ctx.io, expireConnections, .{self.ctx}) catch {
            self.lifecycle.requestShutdown(self.ctx.io);
            return;
        };
        self.server.listen() catch |err| {
            log.err("httpz listen failed: {s} (HTTP allocations {d} of {d} bytes)", .{
                @errorName(err),
                self.memory.used.load(.monotonic),
                self.memory.limit,
            });
        };
        if (!self.handler.stopping.load(.acquire)) self.lifecycle.requestShutdown(self.ctx.io);
    }

    /// Stop producers, then join consumers. A timed-out drain exits without
    /// running destructors against memory still referenced by live threads.
    pub fn stopAccepting(self: *HttpServer) void {
        const io = self.ctx.io;
        var finished: std.Io.Event = .unset;
        const guard = std.Thread.spawn(.{}, shutdownGuard, .{ io, &finished }) catch {
            log.err("cannot start shutdown deadline guard", .{});
            std.process.exit(1);
        };
        defer {
            finished.set(io);
            guard.join();
        }
        self.handler.stopping.store(true, .release);
        // httpz's listen() deinits every worker, freeing its handler-pool
        // arena, as soon as the event loop exits, without joining the pool.
        // Join the pools while the loop still runs. Holding _mut guarantees
        // listen() has finished constructing the workers.
        {
            self.server._mut.lockUncancelable(io);
            defer self.server._mut.unlock(io);
            if (self.server._listener != null) {
                for (self.server._workers) |*worker| worker.thread_pool.stop();
            }
        }
        self.server.stop();
        self.listen_done.waitUncancelable(io);
    }

    fn shutdownGuard(io: std.Io, finished: *std.Io.Event) void {
        const timeout: std.Io.Timeout = .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } };
        const deadline = timeout.toDeadline(io);
        while (!finished.isSet()) {
            finished.waitTimeout(io, deadline) catch |err| switch (err) {
                error.Timeout => {
                    const now_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds();
                    if (now_ns < deadline.deadline.raw.toNanoseconds()) continue;
                    log.err("shutdown deadline exceeded; exiting without freeing live request state", .{});
                    std.process.exit(1);
                },
                error.Canceled => return,
            };
        }
    }
};

/// Upper bound on forwarded request headers (datadog/prom intakes stay well
/// under this). Excess returns error.TooManyHeaders rather than truncating.
const max_forward_headers = 64;

/// Collects forwardable (hop-by-hop-filtered) request headers into an
/// arena-owned array, with names/values duped into the same arena.
///
/// The array MUST outlive this call: std.http.Client.request stores
/// `extra_headers` by reference and only reads it later in `sendHead`. A
/// stack array would dangle by send time and corrupt the TLS write path
/// (segfault on a wild header.name). Hence the arena, not a local buffer.
/// `iter` is any iterator whose `next()` yields `.{ .key, .value }`.
fn collectForwardHeaders(arena: std.mem.Allocator, iter: anytype) ![]std.http.Header {
    const out = try arena.alloc(std.http.Header, max_forward_headers);
    var it = iter;
    var count: usize = 0;
    while (it.next()) |kv| {
        if (upstream_mod.shouldSkipRequestHeader(kv.key)) continue;
        if (count >= out.len) return error.TooManyHeaders;
        out[count] = .{
            .name = try arena.dupe(u8, kv.key),
            .value = try arena.dupe(u8, kv.value),
        };
        count += 1;
    }
    return out[0..count];
}

pub const Handler = struct {
    ctx: *exec.SharedCtx,
    allocator: std.mem.Allocator,
    memory: *BudgetAllocator,
    stopping: std.atomic.Value(bool) = .init(false),
    /// httpz entry point (takes precedence over httpz's router). Must not
    /// return errors; failures discard buffered headers and the partial
    /// response discarded.
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
            if (ctx.metrics) |metrics| {
                metrics.recordRequestError(known_path, .uncaught);
                if (err == error.UpstreamTimeout) metrics.recordUpstreamTimeout();
            }
        };

        // Lifecycle observability is emitted here, AFTER the catch applies the
        // final status, so the duration metric and completion event reflect what
        // the client actually got (a thrown request returns 502, not whatever
        // partial status dispatch had set before it errored).
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
                metrics.recordHttpMemory(self.memory.used.load(.monotonic), self.memory.limit);
                try metrics.writePrometheus(res.writer());
            }
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
        return self.exchange(req, res, fwd.upstream, req.body() orelse "", fwd.replayable);
    }

    /// Exactly one evaluation precedes this function. Only transport failure
    /// before a response head can replay; upstream HTTP statuses pass through.
    fn exchange(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        choice: service_mod.UpstreamChoice,
        body: []const u8,
        replayable: bool,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, self.allocator, ctx.limits);
        const headers = try collectForwardHeaders(res.arena, req.headers.iterator());
        const method = stdMethod(req.method) orelse return error.UnsupportedMethod;
        const deadline = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() +
            @as(i128, ctx.limits.upstream_timeout_ms) * std.time.ns_per_ms;
        const retry = (replayable and ctx.limits.retry_log_intake) or method == .GET or method == .HEAD;
        const attempts: usize = if (retry) 2 else 1;
        for (0..attempts) |attempt| {
            const client = if (attempt == 0) ctx.upstreams.getHttpClient() else &ctx.upstreams.retry_client;
            if (ctx.metrics) |metrics| metrics.recordUpstreamAttempt(attempt > 0);
            var upstream_req = try exec.openUpstreamWithClient(
                ctx,
                res.arena,
                method,
                req.url.raw,
                headers,
                choice,
                client,
            );
            defer upstream_req.deinit();
            if (std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() >= deadline) {
                markUpstreamClosing(&upstream_req);
                return error.UpstreamTimeout;
            }
            trackConnection(ctx.io, bufs, upstream_req.connection, deadline);
            defer trackConnection(ctx.io, bufs, null, 0);
            var upstream_res = sendAndReceiveHead(&upstream_req, req.method, body, bufs) catch |err| {
                self.evictUpstream(&upstream_req, req.url.path, err);
                if (bufs.expired.load(.monotonic)) return error.UpstreamTimeout;
                if (attempt + 1 == attempts or !retryableTransportError(err)) return error.UpstreamTransportFailed;
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                ctx.bus.info(UpstreamRetried{ .path = req.url.path, .err = @errorName(err) });
                continue;
            };
            const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(choice));
            self.relayResponse(res, &upstream_res, max_response, bufs) catch |err| {
                self.evictUpstream(&upstream_req, req.url.path, err);
                if (bufs.expired.load(.monotonic)) return error.UpstreamTimeout;
                if (err == error.BodyTooLarge) return error.UpstreamResponseTooLarge;
                return err;
            };
            return;
        }
        unreachable;
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
        const raw_body = req.body() orelse "";
        if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
            return self.exchange(req, res, pipe.upstream, raw_body, pipe.signal == .log);
        }
        const bufs = try threadBufs(ctx.io, self.allocator, ctx.limits);
        try bufs.prepare(self.allocator, ctx.limits, pipe.codec);
        var body_reader = std.Io.Reader.fixed(raw_body);
        const initial_capacity = @min(raw_body.len, limits_mod.LARGE_BODY_BUFFER_BYTES);
        var output: std.Io.Writer.Allocating = try .initCapacity(res.arena, initial_capacity);
        var sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format, &bufs.record);
        defer sink.deinit();
        const stats = pipeline_mod.run(.{
            .decode = pipe.codec,
            .format = pipe.format,
            .encode = pipe.codec,
            .max_decoded_bytes = ctx.limits.max_decoded_bytes,
            .zstd_window_len = ctx.limits.zstd_window_len,
        }, &body_reader, &output.writer, .{
            .decoder = bufs.decode,
            .encoder = bufs.encode,
            .scratch = bufs.scratch,
            .chunk = bufs.chunk,
        }, &sink) catch |err| switch (err) {
            error.ReadFailed => return error.InvalidRequestBody,
            else => return err,
        };
        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
        }
        try self.exchange(req, res, pipe.upstream, output.written(), pipe.signal == .log);
    }

    fn execPipeBuffered(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        pipe: service_mod.PipeBuffered,
    ) !void {
        const ctx = self.ctx;
        const raw_body = req.body() orelse "";

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

        try self.exchange(req, res, pipe.upstream, processed.body, pipe.signal == .log);
    }

    fn execFetchFiltered(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        fetch: service_mod.FetchFiltered,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, self.allocator, ctx.limits);
        var upstream_req = self.openUpstream(req, res.arena, fetch.upstream) catch {
            res.status = 502;
            res.body = "";
            return;
        };
        defer upstream_req.deinit();
        const deadline = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() +
            @as(i128, ctx.limits.upstream_timeout_ms) * std.time.ns_per_ms;
        trackConnection(ctx.io, bufs, upstream_req.connection, deadline);
        defer trackConnection(ctx.io, bufs, null, 0);

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
        try growBuffer(self.allocator, &bufs.scratch, 14336);
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
        error.InvalidRequestBody => 400,
        error.OutOfMemory, error.WriteFailed => 503,
        error.UpstreamTimeout => 504,
        else => 502,
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
        => true,
        else => false,
    };
}

fn sendAndReceiveHead(
    request: *std.http.Client.Request,
    method: httpz.Method,
    body: []const u8,
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
/// it, so the next request dials fresh. Pair with `errdefer` so it runs on any
/// error path before the request's own `defer ...deinit()`.
fn markUpstreamClosing(upstream_req: *std.http.Client.Request) void {
    if (upstream_req.connection) |conn| conn.closing = true;
}

/// Writes a fully-buffered request body upstream with an exact
/// content-length (chunked inbound bodies were already de-chunked by httpz).
fn sendBufferedBody(
    upstream_req: *std.http.Client.Request,
    method: httpz.Method,
    body: []const u8,
    bufs: *ThreadBufs,
) !void {
    const std_method = stdMethod(method) orelse return error.UnsupportedMethod;
    if (std_method.requestHasBody() and body.len > 0) {
        upstream_req.transfer_encoding = .{ .content_length = body.len };
        var body_writer = try upstream_req.sendBodyUnflushed(bufs.upstream);
        var fixed = std.Io.Reader.fixed(body);
        _ = try pipeline_mod.streamReaderToWriter(&fixed, &body_writer.writer, body.len);
        try body_writer.end();
        try upstream_req.connection.?.flush();
    } else if (std_method.requestHasBody()) {
        upstream_req.transfer_encoding = .{ .content_length = 0 };
        var body_writer = try upstream_req.sendBodyUnflushed(bufs.upstream);
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
    // Unset worker/thread-pool counts ride httpz defaults (null).
    try testing.expectEqual(@as(?u16, null), config.workers.count);
    try testing.expectEqual(@as(?u16, null), config.thread_pool.count);
    // The large-body pool must NOT ride httpz defaults (16 x max_body_size).
    try testing.expectEqual(@as(?u16, 8), config.workers.large_buffer_count);
    try testing.expectEqual(@as(?u32, limits_mod.LARGE_BODY_BUFFER_BYTES), config.workers.large_buffer_size);
    try testing.expectEqual(@as(u16, 8080), config.address.ip.ip4.port);
}

test "httpz config carries configured worker/thread-pool counts" {
    const limits: limits_mod.Limits = .resolve(.{
        .max_body_size = 1024 * 1024,
        .worker_count = 2,
        .thread_pool_count = 8,
    });
    const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
    try testing.expectEqual(@as(?u16, 2), config.workers.count);
    try testing.expectEqual(@as(?u16, 8), config.thread_pool.count);
}

test "httpz worker count cannot raise the global connection cap" {
    for ([_]u16{ 1, 2, 4 }) |workers| {
        const limits: limits_mod.Limits = .resolve(.{
            .max_body_size = 1024 * 1024,
            .max_connections = 256,
            .worker_count = workers,
        });
        const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
        try testing.expectEqual(@as(usize, 256), (config.workers.max_conn orelse 0) * config.workerCount());
    }
}

test "httpz minimum viable budget is checked arithmetic below the default cap" {
    const limits: limits_mod.Limits = .resolve(.{ .max_body_size = 1024 * 1024, .max_connections = 256 });
    const config = configFromLimits(limits, .{ 127, 0, 0, 1 }, 8080);
    const minimum = try minimumViableBytes(limits, config);
    const expected = 8 * @as(usize, limits_mod.LARGE_BODY_BUFFER_BYTES) + 32 * limits_mod.HANDLER_THREAD_BUF_BYTES +
        256 * (limits.recv_buf + limits.conn_arena_reserve);
    try testing.expectEqual(expected, minimum);
    try testing.expect(minimum < limits.max_buffered_bytes);

    var absurd = limits;
    absurd.max_connections = std.math.maxInt(usize);
    try testing.expectError(error.Overflow, minimumViableBytes(absurd, config));
}

test "httpz method maps onto service and std methods" {
    try testing.expectEqual(service_mod.HttpMethod.POST, serviceMethod(.POST));
    try testing.expectEqual(service_mod.HttpMethod.OTHER, serviceMethod(.CONNECT));
    try testing.expectEqual(@as(?std.http.Method, .GET), stdMethod(.GET));
    try testing.expectEqual(@as(?std.http.Method, null), stdMethod(.OTHER));
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

// Regression for the dangling-header segfault: std.http.Client.request stores
// extra_headers by reference and reads it later in sendHead, so the returned
// array must be arena-owned. A stack-local array (the original bug) would read
// garbage once the building frame is reused. We build in a child frame, clobber
// the dead stack, then assert the headers still read back intact.
test "collectForwardHeaders headers survive the building scope" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const headers = try buildAndReturnHeaders(arena.allocator());

    var scratch: [8192]u8 = undefined;
    for (&scratch, 0..) |*b, i| b.* = @truncate(i);
    std.mem.doNotOptimizeAway(&scratch);

    try testing.expectEqual(@as(usize, 1), headers.len);
    try testing.expectEqualStrings("x-tero", headers[0].name);
    try testing.expectEqualStrings("v", headers[0].value);
}

fn buildAndReturnHeaders(arena: std.mem.Allocator) ![]std.http.Header {
    // Sources live only in this frame; collectForwardHeaders must dupe them and
    // return an arena-owned array that outlives this return.
    var key_buf: [6]u8 = "x-tero".*;
    var val_buf: [1]u8 = "v".*;
    const pairs = [_]HeaderPair{.{ .key = &key_buf, .value = &val_buf }};
    const iter: FakeHeaderIter = .{ .pairs = &pairs };
    return collectForwardHeaders(arena, iter);
}
