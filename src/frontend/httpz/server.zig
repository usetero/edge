//! httpz frontend (PLAN-FRONTEND-SWAP.md §4): inbound HTTP rides httpz's
//! own kqueue/epoll event loop + worker thread pool instead of one
//! Io.Threaded task per connection. The process-wide `Io` keeps serving the
//! upstream client, policy loader, and lifecycle; httpz only needs it for
//! net types.
//!
//! Request bodies use httpz's lazy reader path: small bodies may already live
//! in httpz's request buffer, while larger bodies are read from the socket by
//! the route handler. All routing/planning/transform logic comes from
//! frontend/exec.zig, shared with the stdio frontend.
const std = @import("std");
const httpz = @import("httpz");

const exec = @import("../exec.zig");
const service_mod = @import("../../service/service.zig");
const upstream_mod = @import("../upstream.zig");
const pipeline_mod = @import("../../pipeline/pipeline.zig");
const limits_mod = @import("../../core/limits.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const prom = @import("../../signals/prometheus/root.zig");

const log = std.log.scoped(.httpz_server);

// Named event payloads: the type name is the telemetry event name.
const PipelineAborted = struct { err: []const u8 };
/// A request threw out of dispatch (not a handled 4xx/5xx) — answered 502.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// A pooled upstream connection failed and was destroyed instead of re-pooled,
/// so the next request dials fresh (breaks the stale-keepalive poison loop).
/// We do not retry in-process — the sender retries onto the fresh connection.
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
            .lazy_read_size = limits.chunk_buf,
        },
        // null => httpz defaults (1 worker, 32 pool threads). thread_pool count
        // multiplies the per-thread pipeline-scratch floor (see ThreadBufs).
        .workers = .{
            .count = limits.worker_count,
            // With lazy reads, large request bodies should not be parked in
            // httpz's buffer pool. Tiny bodies fit in the request buffer; rare
            // spillover can use the per-request arena instead of a process-wide
            // max_body_size pool.
            .large_buffer_count = 0,
            .large_buffer_size = @intCast(@max(@as(usize, 1), limits.chunk_buf)),
        },
        .thread_pool = .{ .count = limits.thread_pool_count },
    };
}

/// Per-worker-thread pipeline scratch, lazily allocated on first use and
/// retained for the thread's lifetime (httpz pool threads live as long as
/// the process, so this is bounded by thread_pool.count and intentionally
/// never freed). Replaces the stdio frontend's per-connection slab regions.
///
/// Deliberately excludes the decode window: it's the one big buffer (zstd
/// worst case ~2 MiB) and most requests don't need it (identity=0, gzip=32K).
/// Pinning it per thread cost thread_pool_count x 2 MiB of mostly-idle memory,
/// so it's allocated per request, sized to that request's codec, and freed
/// when the request ends — resident decode memory now tracks concurrent
/// *compressed* requests, not thread count. The rest here is small (<500 KiB
/// per thread total) and hot, so keeping it warm/threadlocal is worth it.
const ThreadBufs = struct {
    encode: []u8,
    scratch: []u8,
    chunk: []u8,
    upstream: []u8,
};

threadlocal var tl_bufs: ?ThreadBufs = null;

// httpz handler threads cache their pipeline scratch in tl_bufs and never free
// it themselves. We can't free a thread-local from another thread, so each set
// is also recorded here and swept once at shutdown — safe because the handler
// pool is joined first (see HttpServer.deinit -> httpz worker thread_pool.stop).
// one process-wide server, so module-global bookkeeping is fine.
var bufs_registry_mutex: std.Io.Mutex = .init;
var bufs_registry: std.ArrayList(ThreadBufs) = .empty;

fn threadBufs(io: std.Io, gpa: std.mem.Allocator, limits: limits_mod.Limits) !ThreadBufs {
    if (tl_bufs) |bufs| return bufs;
    const bufs: ThreadBufs = .{
        .encode = try gpa.alloc(u8, limits.encode_buf),
        .scratch = try gpa.alloc(u8, limits.record_scratch),
        .chunk = try gpa.alloc(u8, limits.chunk_buf),
        .upstream = try gpa.alloc(u8, limits.upstream_write_buf),
    };
    {
        bufs_registry_mutex.lockUncancelable(io);
        defer bufs_registry_mutex.unlock(io);
        try bufs_registry.append(gpa, bufs);
    }
    tl_bufs = bufs;
    return bufs;
}

/// Frees every thread's pipeline scratch. Call exactly once, after the httpz
/// handler pool has been joined (no handler thread may touch tl_bufs after).
fn freeThreadBufs(io: std.Io, gpa: std.mem.Allocator) void {
    bufs_registry_mutex.lockUncancelable(io);
    defer bufs_registry_mutex.unlock(io);
    for (bufs_registry.items) |bufs| {
        gpa.free(bufs.encode);
        gpa.free(bufs.scratch);
        gpa.free(bufs.chunk);
        gpa.free(bufs.upstream);
    }
    bufs_registry.deinit(gpa);
    bufs_registry = .empty;
    tl_bufs = null;
}

pub const HttpServer = struct {
    ctx: *exec.SharedCtx,
    lifecycle: *lifecycle_mod.Lifecycle,
    handler: *Handler,
    server: httpz.Server(*Handler),

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
            "httpz frontend: {d} pool threads x {d} bytes scratch/thread; decode buffer up to {d} bytes/request",
            .{
                config.threadPoolCount(),
                ctx.limits.encode_buf + ctx.limits.record_scratch +
                    ctx.limits.chunk_buf + ctx.limits.upstream_write_buf,
                ctx.limits.decode_buf,
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
        self.server.listen() catch |err| {
            log.err("httpz listen failed: {s}", .{@errorName(err)});
        };
    }

    /// Thread-safe: breaks `run` out of its event loop, closes the listener,
    /// then waits for in-flight handlers to finish before returning. The wait
    /// is essential: httpz's kqueue worker `stop()` only halts the event loop
    /// and `deinit` frees the handler thread pool WITHOUT joining it, so a
    /// handler still in `relayResponse` would otherwise race the io/upstream
    /// teardown that follows (Engine.stop -> lifecycle.shutdown; destroy ->
    /// upstreams.deinit) and segfault reading a freed response head. Bounded so
    /// a wedged handler can't block shutdown forever.
    pub fn stopAccepting(self: *HttpServer) void {
        self.server.stop();

        const io = self.ctx.io;
        const deadline_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds() +
            5 * std.time.ns_per_s;
        while (self.handler.in_flight.load(.acquire) > 0) {
            if (std.Io.Timestamp.now(io, .awake).toNanoseconds() >= deadline_ns) {
                log.warn("shutdown: {d} request(s) still in flight after 5s drain", .{
                    self.handler.in_flight.load(.acquire),
                });
                break;
            }
            io.sleep(.fromNanoseconds(2 * std.time.ns_per_ms), .awake) catch break;
        }
    }
};

/// Upper bound on forwarded request headers (datadog/prom intakes stay well
/// under this). Excess returns error.TooManyHeaders rather than truncating.
const max_forward_headers = 64;

/// Per-read timeout for httpz's lazy body reader. This protects handler threads
/// from slow clients after the request head has already been accepted.
const request_body_timeout_ms = 30 * std.time.ms_per_s;

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
    /// In-flight request count. httpz's kqueue worker stops its event loop on
    /// `stop()` but never joins its handler thread pool before `deinit` frees
    /// it, so an in-flight handler can race shutdown's io/upstream teardown
    /// (segfault reading a torn response head). Shutdown drains this to zero
    /// before tearing anything down — see `HttpServer.stopAccepting`.
    in_flight: std.atomic.Value(u32) = .init(0),

    /// httpz entry point (takes precedence over httpz's router). Must not
    /// return errors; failures collapse to a 502 with the buffered partial
    /// response discarded.
    pub fn handle(self: *Handler, req: *httpz.Request, res: *httpz.Response) void {
        _ = self.in_flight.fetchAdd(1, .acquire);
        defer _ = self.in_flight.fetchSub(1, .release);

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
            res.status = 502;
            res.body = "";
        };

        // Lifecycle observability is emitted here, AFTER the catch applies the
        // final status, so the duration metric and completion event reflect what
        // the client actually got (a thrown request returns 502, not whatever
        // partial status dispatch had set before it errored).
        const elapsed_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() - start_ns;
        const elapsed_s = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
        if (ctx.metrics) |metrics| metrics.recordRequestDuration(known_path, elapsed_s);
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

        // httpz skips its max_body_size rejection when lazy_read_size is set.
        // Keep the data-plane contract here and close without draining a body
        // we already know we will not process.
        if (req.body_len > ctx.limits.max_body_size) {
            res.status = 413;
            res.body = "";
            res.keepalive = false;
            return;
        }

        // Internal observability endpoint, checked before routing — parity
        // with the stdio driver's /_edge/metrics short-circuit.
        if (req.method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) {
            res.header("content-type", "text/plain; version=0.0.4");
            exec.refreshPolicyGauge(ctx);
            if (ctx.metrics) |metrics| try metrics.writePrometheus(res.writer());
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
        upstream_req: *std.http.Client.Request,
        max_response_body: usize,
        bufs: ThreadBufs,
    ) !void {
        _ = self;
        var upstream_res = try upstream_req.receiveHead(&.{});

        var extra_headers: [64]std.http.Header = undefined;
        const relayed = try exec.collectUpstreamResponseHeaders(&upstream_res, res.arena, &extra_headers);
        res.status = @intFromEnum(upstream_res.head.status);
        for (relayed) |header| res.header(header.name, header.value);

        const upstream_body = upstream_res.reader(bufs.upstream);
        _ = try pipeline_mod.streamReaderToWriter(upstream_body, res.writer(), max_response_body);
    }

    fn execForwardRaw(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        fwd: service_mod.Forward,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        var upstream_req = self.openUpstream(req, res.arena, fwd.upstream) catch {
            res.status = 502;
            res.body = "";
            closeIfUnread(req, res);
            return;
        };
        defer upstream_req.deinit();
        // On any upstream failure, evict the connection so it isn't re-pooled — the
        // next request dials fresh. We do NOT retry in-process: a replay could
        // duplicate a non-idempotent request, and the sender already retries 502s.
        errdefer |err| self.evictUpstream(&upstream_req, req.url.path, err);

        try sendRequestBody(&upstream_req, req, res, bufs);

        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(fwd.upstream));
        try self.relayResponse(res, &upstream_req, max_response, bufs);
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

    fn execPipeStream(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        pipe: service_mod.PipeStream,
    ) !void {
        const ctx = self.ctx;
        // No policy targets this signal: the pipe is an identity transform,
        // so skip the framer/codec/chunked overhead and relay the raw bytes
        // (master's prefilter "forward unchanged" decision).
        if (!exec.policiesActiveFor(ctx.registry, pipe.signal)) {
            return self.execForwardRaw(req, res, .{ .upstream = pipe.upstream });
        }
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        // Decode window sized to THIS request's codec, not pinned per thread:
        // identity => 0 (no alloc), gzip => 32 KiB, zstd => full window.
        // page_allocator (not gpa/malloc) so free() munmaps the window straight
        // back to the OS — resident decode memory tracks *current* concurrent
        // compressed requests and shrinks when a burst subsides, instead of
        // malloc caching the freed multi-MB blocks. The mmap+fault cost is
        // negligible against the decode itself and only touched on compressed
        // requests.
        const decode = try std.heap.page_allocator.alloc(u8, pipe.codec.decoderBufferLen(ctx.limits.zstd_window_len));
        defer std.heap.page_allocator.free(decode);
        var upstream_req = self.openUpstream(req, res.arena, pipe.upstream) catch {
            res.status = 502;
            res.body = "";
            closeIfUnread(req, res);
            return;
        };
        defer upstream_req.deinit();
        // Any failure (mid-stream send to a dead conn, or relay) evicts the conn —
        // a partially-sent chunked body makes it unreusable anyway. No retry.
        errdefer |err| self.evictUpstream(&upstream_req, req.url.path, err);

        var request_body = try HttpzBodyReader.init(req);
        defer request_body.deinit();
        if (request_body.restore_conn) {
            // httpz's lazy socket reader temporarily changes connection read
            // mode/timeouts. Close socket-backed request-body connections after
            // the response instead of reusing a connection with mutated state.
            res.keepalive = false;
        }

        // Filtering changes length: always chunked.
        upstream_req.transfer_encoding = .chunked;
        var body_writer = try upstream_req.sendBodyUnflushed(bufs.upstream);

        var sink = exec.RecordSink.init(ctx, pipe.signal, pipe.format);
        defer sink.deinit();

        const stats = pipeline_mod.run(.{
            .decode = pipe.codec,
            .format = pipe.format,
            .encode = pipe.codec,
            .max_decoded_bytes = ctx.limits.max_decoded_bytes,
            .zstd_window_len = ctx.limits.zstd_window_len,
        }, request_body.reader(), &body_writer.writer, .{
            .decoder = decode,
            .encoder = bufs.encode,
            .scratch = bufs.scratch,
            .chunk = bufs.chunk,
        }, &sink) catch |err| {
            // Mid-stream failure aborts the exchange: a partial chunked body is on
            // the wire, so evict the conn and answer 502 (close the client conn —
            // we can't complete a clean response). Handled here, so the errdefer
            // (which covers the trailing sends/relay) does not also fire.
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.err(PipelineAborted{ .err = @errorName(err) });
            self.evictUpstream(&upstream_req, req.url.path, err);
            res.status = 502;
            res.body = "";
            res.keepalive = false;
            return;
        };
        try body_writer.end();
        try upstream_req.connection.?.flush();

        if (ctx.metrics) |metrics| {
            metrics.recordPolicyBatch(exec.routeLabel(pipe.signal, pipe.format), stats.records, stats.dropped);
        }

        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
        try self.relayResponse(res, &upstream_req, max_response, bufs);
    }

    fn execPipeBuffered(
        self: *Handler,
        req: *httpz.Request,
        res: *httpz.Response,
        pipe: service_mod.PipeBuffered,
    ) !void {
        const ctx = self.ctx;
        const bufs = try threadBufs(ctx.io, ctx.gpa, ctx.limits);
        const raw_body = try readRequestBody(req, res, ctx.limits.max_body_size);

        // res.arena is httpz's per-request fallback allocator; safe for the
        // resize-heavy transform since 5f60277 (fallback resize fix).
        const processed: exec.BufferedResult = exec.processBuffered(ctx, pipe, res.arena, raw_body) catch |err| blk: {
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

        var upstream_req = self.openUpstream(req, res.arena, pipe.upstream) catch {
            res.status = 502;
            res.body = "";
            closeIfUnread(req, res);
            return;
        };
        defer upstream_req.deinit();
        errdefer |err| self.evictUpstream(&upstream_req, req.url.path, err); // don't re-pool; no retry

        try sendBufferedBody(&upstream_req, req.method, processed.body, bufs);

        const max_response = ctx.upstreams.getMaxResponseBody(ctx.upstream_ids.resolve(pipe.upstream));
        try self.relayResponse(res, &upstream_req, max_response, bufs);
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
            closeIfUnread(req, res);
            return;
        };
        defer upstream_req.deinit();

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

fn closeIfUnread(req: *httpz.Request, res: *httpz.Response) void {
    if (req.unread_body > 0) res.keepalive = false;
}

/// Adapts httpz's lazy body reader to std.Io EOF semantics. httpz's reader
/// returns 0 at EOF, while std.Io APIs such as readSliceShort keep polling
/// until the vtable reports error.EndOfStream.
const HttpzBodyReader = struct {
    req: *httpz.Request,
    inner: httpz.Request.Reader,
    remaining: usize,
    restore_conn: bool,
    buffer: [limits_mod.BODY_BUF_BYTES]u8 = undefined,
    interface: std.Io.Reader = .{
        .buffer = &.{},
        .end = 0,
        .seek = 0,
        .vtable = &.{ .stream = stream },
    },

    fn init(req: *httpz.Request) !HttpzBodyReader {
        const restore_conn = req.unread_body > 0;
        return .{
            .req = req,
            .inner = try req.reader(request_body_timeout_ms),
            .remaining = req.body_len,
            .restore_conn = restore_conn,
        };
    }

    fn deinit(self: *HttpzBodyReader) void {
        defer self.* = undefined;
        if (!self.restore_conn) return;

        const timeout: std.posix.timeval = .{ .sec = 0, .usec = 0 };
        const zero_timeout = std.mem.toBytes(timeout);
        std.posix.setsockopt(
            self.req.conn.stream.socket.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            &zero_timeout,
        ) catch |err| {
            log.debug("failed to clear httpz lazy body read timeout: {s}", .{@errorName(err)});
        };
        self.req.conn.nonblockingMode() catch |err| {
            log.debug("failed to restore httpz connection nonblocking mode: {s}", .{@errorName(err)});
        };
    }

    fn reader(self: *HttpzBodyReader) *std.Io.Reader {
        self.interface.buffer = &self.buffer;
        return &self.interface;
    }

    fn stream(
        io_r: *std.Io.Reader,
        writer: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *HttpzBodyReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (self.remaining == 0) return error.EndOfStream;

        const capped_limit: std.Io.Limit = .limited(limit.minInt(self.remaining));
        if (capped_limit == .nothing) return 0;

        const n = try self.inner.interface.stream(writer, capped_limit);
        if (n == 0) return error.EndOfStream;
        self.remaining -= n;
        return n;
    }
};

/// Captures a request body for routes that are intentionally batch-buffered.
/// Streaming routes should consume `HttpzBodyReader` directly.
fn readRequestBody(
    req: *httpz.Request,
    res: *httpz.Response,
    max_body_size: usize,
) ![]const u8 {
    var body_reader = try HttpzBodyReader.init(req);
    defer body_reader.deinit();
    if (body_reader.restore_conn) res.keepalive = false;
    var out: std.Io.Writer.Allocating = .init(res.arena);
    _ = try pipeline_mod.streamReaderToWriter(body_reader.reader(), &out.writer, max_body_size);
    return out.written();
}

/// Streams the inbound request body upstream with the original content length.
fn sendRequestBody(
    upstream_req: *std.http.Client.Request,
    req: *httpz.Request,
    res: *httpz.Response,
    bufs: ThreadBufs,
) !void {
    const std_method = stdMethod(req.method) orelse return error.UnsupportedMethod;
    if (std_method.requestHasBody() and req.body_len > 0) {
        upstream_req.transfer_encoding = .{ .content_length = req.body_len };
        var body_writer = try upstream_req.sendBodyUnflushed(bufs.upstream);
        var body_reader = try HttpzBodyReader.init(req);
        defer body_reader.deinit();
        if (body_reader.restore_conn) res.keepalive = false;
        _ = try pipeline_mod.streamReaderToWriter(body_reader.reader(), &body_writer.writer, req.body_len);
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

/// Writes a fully-buffered request body upstream with an exact
/// content-length (chunked inbound bodies were already de-chunked by httpz).
fn sendBufferedBody(
    upstream_req: *std.http.Client.Request,
    method: httpz.Method,
    body: []const u8,
    bufs: ThreadBufs,
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
    try testing.expectEqual(@as(?usize, limits_mod.CHUNK_BUF_BYTES), config.request.lazy_read_size);
    try testing.expectEqual(@as(?u16, 0), config.workers.large_buffer_count);
    // Unset worker/thread-pool counts ride httpz defaults (null).
    try testing.expectEqual(@as(?u16, null), config.workers.count);
    try testing.expectEqual(@as(?u16, null), config.thread_pool.count);
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
