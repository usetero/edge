//! httpz frontend: inbound HTTP rides httpz's own kqueue/epoll event loop
//! and handler thread pool. The process-wide `Io`
//! still serves the upstream client, policy loader, and lifecycle.
//!
//! This file is the shell: server lifecycle, httpz config derived from
//! limits, and the per-request `handle` → `dispatch` that turns a routed
//! outcome into a call on one of the sibling files.
//!
//!   ../paths.zig       the four request executors (raw forward, streamed
//!                   pipeline, buffered transform, filtered scrape)
//!   ../exchange.zig    the upstream leg: dial, send, receive, relay, retry
//!   ../thread_bufs.zig per-thread scratch and the upstream deadline watchdog
//!   ../endpoints.zig   /_edge/* observability endpoints
//!
//! Bodies at or above the 64 KiB pool buffer arrive unread and stream when
//! no policy needs them; smaller ones arrive buffered. Both cases are owned
//! by paths.zig. Routing and planning come from frontend/exec.zig, shared
//! with the stdio frontend.
const std = @import("std");
const httpz = @import("httpz");
const exec = @import("../exec.zig");
const limits_mod = @import("../../core/limits.zig");
const service_mod = @import("../../service/service.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const exchange = @import("../exchange.zig");
const paths = @import("../paths.zig");
const endpoints = @import("../endpoints.zig");
const thread_bufs = @import("../thread_bufs.zig");

const Inbound = exchange.Inbound;
const InboundBody = paths.InboundBody;

/// Per-read timeout for pulling a lazy body off the client socket. This is
/// SO_RCVTIMEO, so it bounds one read, not the transfer; `DeadlineReader`
/// bounds the transfer.
const lazy_read_timeout_ms: usize = limits_mod.REQUEST_TIMEOUT_SECONDS * 1000;

/// Whole-body deadline for a lazy inbound body.
const inbound_body_timeout_ns: i128 = @as(i128, limits_mod.REQUEST_TIMEOUT_SECONDS) * std.time.ns_per_s;

/// Absolute deadline over a lazy body read. `req.reader(ms)` sets
/// SO_RCVTIMEO, which restarts on every read. A client that sends one byte
/// inside each timeout holds its handler thread without limit, and a few
/// dozen such clients stop the server, health checks too. This reader fails
/// the transfer when the deadline passes.
pub const DeadlineReader = struct {
    interface: std.Io.Reader,
    inner: *std.Io.Reader,
    io: std.Io,
    deadline_ns: i128,
    /// Set when the deadline fired, so the handler closes the connection
    /// instead of leaving an undrained body on it.
    expired: bool = false,

    pub fn init(io: std.Io, inner: *std.Io.Reader) DeadlineReader {
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

/// The response side of the sink contract (exchange.zig) over an httpz
/// response. httpz commits status and headers when the handler returns, so
/// `end` has nothing to do.
pub const Sink = struct {
    res: *httpz.Response,
    pub fn begin(self: Sink, status: u16, headers: []const std.http.Header) !*std.Io.Writer {
        self.res.status = status;
        for (headers) |h| self.res.header(h.name, h.value);
        return self.res.writer();
    }
    pub fn end(_: Sink) !void {}
};

/// Lift the request into the frontend-neutral shape.
fn inboundOf(req: *httpz.Request, arena: std.mem.Allocator) !Inbound {
    return .{
        .method = stdMethod(req.method) orelse return error.UnsupportedMethod,
        .target = req.url.raw,
        .path = req.url.path,
        .headers = try exchange.collectForwardHeaders(arena, req.headers.iterator()),
        .arena = arena,
    };
}

/// Classify the body and enforce the cap httpz skips for lazy reads: with
/// lazy_read_size set, httpz does not check max_body_size (request.zig), and
/// `req.body()` on a lazy request holds only the prefix that arrived with the
/// headers. `lazy_reader` must outlive the returned body; it is only
/// initialized when the body is lazy.
fn inboundBodyOf(
    io: std.Io,
    req: *httpz.Request,
    limits: limits_mod.Limits,
    lazy_reader: *httpz.Request.Reader,
    bounded: *DeadlineReader,
) !InboundBody {
    if (req.unread_body == 0) return .{ .bytes = req.body() orelse "" };
    if (req.body_len > limits.max_body_size) return error.BodyTooLarge;
    lazy_reader.* = try req.reader(lazy_read_timeout_ms);
    bounded.* = .init(io, &lazy_reader.interface);
    return .{ .lazy = .{ .reader = &bounded.interface, .len = req.body_len } };
}

const log = std.log.scoped(.httpz_server);

// Named event payloads: the type name is the telemetry event name.
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// The listener stopped with an error. Nothing reaches the edge after this,
/// so it is the one line that explains a process that is up and deaf.
const ListenFailed = struct { err: []const u8 };
/// The upstream deadline watchdog could not start, so nothing would ever cut
/// off a hung upstream. The process shuts down instead of serving blind.
const WatchdogSpawnFailed = struct { err: []const u8 };

pub fn configFromLimits(limits: limits_mod.Limits, address: [4]u8, port: u16) httpz.Config {
    const requested_workers = limits.worker_count orelse 1;
    const worker_count: u16 = @intCast(@min(@as(usize, requested_workers), limits.max_connections));
    const per_worker: u16 = @intCast(@min(
        @max(1, limits.max_connections / worker_count),
        std.math.maxInt(u16),
    ));
    return .{
        .address = .{ .ip = .{ .ip4 = .{ .bytes = address, .port = port } } },
        .request = .{
            .max_body_size = limits.max_body_size,
            .buffer_size = limits.recv_buf,
            .lazy_read_size = limits.large_body_buffer_size,
            // Above our forward cap, so our cap refuses the request with
            // 431. At httpz's default of 32, httpz drops excess headers with
            // no error. Past this count httpz still truncates.
            .max_header_count = limits_mod.MAX_FORWARD_HEADERS + 32,
        },
        .workers = .{
            .count = worker_count,
            .max_conn = per_worker,
            .large_buffer_count = limits.large_body_buffer_count,
            .large_buffer_size = limits.large_body_buffer_size,
        },
        // Same reason as the request cap: at httpz's default of 16, httpz
        // drops excess response headers, such as `Retry-After` on a 429.
        .response = .{ .max_header_count = limits_mod.MAX_FORWARD_HEADERS + 32 },
        .thread_pool = .{ .count = limits.thread_pool_count },
        .timeout = .{
            .request = limits_mod.REQUEST_TIMEOUT_SECONDS,
            .keepalive = limits_mod.KEEPALIVE_TIMEOUT_SECONDS,
        },
    };
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
        thread_bufs.freeAll(self.ctx.io, self.ctx.gpa);
        self.ctx.gpa.destroy(self.handler);
        self.* = undefined;
    }

    pub fn run(self: *HttpServer) std.Io.Cancelable!void {
        self.lifecycle.spawn(self.ctx.io, watchUpstreamDeadlines, .{self}) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            self.ctx.bus.err(WatchdogSpawnFailed{ .err = @errorName(err) });
            self.listen_done.set(self.ctx.io);
            self.lifecycle.requestShutdown(self.ctx.io);
            return;
        };
        self.server.listen() catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            self.ctx.bus.err(ListenFailed{ .err = @errorName(err) });
        };
        const stopped = self.handler.stopping.load(.acquire);
        self.listen_done.set(self.ctx.io);
        if (!stopped) self.lifecycle.requestShutdown(self.ctx.io);
    }

    pub fn stopAccepting(self: *HttpServer) void {
        self.handler.stopping.store(true, .release);
        thread_bufs.expireTrackedUpstreams(self.ctx, true);
        if (!self.listen_done.isSet()) self.server.stop();
        self.listen_done.waitUncancelable(self.ctx.io);
    }
};

fn watchUpstreamDeadlines(server: *HttpServer) std.Io.Cancelable!void {
    while (!server.handler.stopping.load(.acquire)) {
        try server.ctx.io.sleep(.fromMilliseconds(thread_bufs.watchdog_interval_ms), .awake);
        thread_bufs.expireTrackedUpstreams(server.ctx, false);
    }
}

pub const Handler = struct {
    ctx: *exec.SharedCtx,
    stopping: std.atomic.Value(bool) = .init(false),
    pub fn handle(self: *Handler, req: *httpz.Request, res: *httpz.Response) void {
        if (self.stopping.load(.acquire)) {
            res.status = 503;
            res.keepalive = false;
            return;
        }
        const ctx = self.ctx;
        const start_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
        if (ctx.metrics) |metrics| metrics.recordInFlight(1);
        defer if (ctx.metrics) |metrics| metrics.recordInFlight(-1);
        const method = serviceMethod(req.method);
        const known_path = exec.classifyKnownPath(req.url.path, method);
        if (ctx.metrics) |metrics| {
            metrics.recordRequest(exec.methodLabel(method), known_path);
        }

        self.dispatch(req, res) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.err(RequestFailed{
                .method = @tagName(req.method),
                .path = req.url.path,
                .err = @errorName(err),
            });
            res.clearWriter();
            res.headers.reset();
            res.status = exchange.errorStatus(err);
            res.body = "";
            if (ctx.metrics) |metrics| {
                metrics.recordRequestError(known_path, .uncaught);
            }
        };

        paths.finishRequest(ctx, @tagName(req.method), req.url.path, known_path, res.status, start_ns);
    }

    fn dispatch(self: *Handler, req: *httpz.Request, res: *httpz.Response) !void {
        const ctx = self.ctx;
        const method = serviceMethod(req.method);
        const path = req.url.path;

        var sink: Sink = .{ .res = res };
        // Claim the whole namespace whatever the method; see the stdio note.
        if (std.mem.startsWith(u8, path, "/_edge/") and req.method != .GET) {
            res.status = 405;
            res.body = "";
            return;
        }
        if (std.mem.eql(u8, path, "/_edge/metrics")) {
            return endpoints.metrics(ctx, &sink, &httpz.writeMetrics);
        }
        if (std.mem.eql(u8, path, "/_edge/policies")) {
            const json = std.mem.eql(u8, (try req.query()).get("format") orelse "", "json");
            return endpoints.policies(ctx, &sink, json);
        }

        if (std.mem.startsWith(u8, path, "/_edge/tap/")) {
            const stage: exec.TapState.Stage = if (std.mem.eql(u8, path, "/_edge/tap/pre"))
                .pre
            else if (std.mem.eql(u8, path, "/_edge/tap/post"))
                .post
            else {
                res.status = 404;
                return;
            };
            const n: u32 = if ((try req.query()).get("n")) |raw| std.fmt.parseInt(u32, raw, 10) catch 50 else 50;
            return endpoints.recordTap(ctx, &sink, stage, n);
        }
        if (std.mem.startsWith(u8, path, "/_edge/")) {
            res.status = 404;
            res.body = "";
            return;
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
        if (outcome == .respond) {
            const static = outcome.respond;
            res.status = static.status;
            res.header("content-type", static.content_type);
            res.body = static.body;
            return;
        }
        const in = try inboundOf(req, res.arena);
        var lazy_reader: httpz.Request.Reader = undefined;
        var bounded: DeadlineReader = undefined;
        const body = try inboundBodyOf(ctx.io, req, ctx.limits, &lazy_reader, &bounded);
        const served = switch (outcome) {
            .respond => unreachable,
            .forward_raw => |fwd| paths.execForwardRaw(ctx, in, &sink, body, fwd),
            .pipe_stream => |pipe| paths.execPipeStream(ctx, in, &sink, body, pipe),
            .pipe_buffered => |pipe| paths.execPipeBuffered(ctx, in, &sink, body, pipe),
            .fetch_filtered => |fetch| paths.execFetchFiltered(ctx, in, &sink, body, fetch),
        };
        served catch |err| {
            // A stalled lazy read surfaces as a generic read failure. Only
            // this frontend knows the deadline fired, so name it here. Close
            // the connection: httpz drains a part-read body after the
            // handler, which is the same unbounded wait. `res.keepalive` only
            // sets the response header; httpz gates the drain on
            // `conn.handover`, so set that to `.close`.
            if (body == .lazy and bounded.expired) {
                req.conn.handover = .close;
                res.keepalive = false;
                return error.InboundBodyTimeout;
            }
            return err;
        };
    }
};

pub fn serviceMethod(method: httpz.Method) service_mod.HttpMethod {
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

test "httpz method maps onto service and std methods" {
    try testing.expectEqual(service_mod.HttpMethod.POST, serviceMethod(.POST));
    try testing.expectEqual(service_mod.HttpMethod.OTHER, serviceMethod(.CONNECT));
    try testing.expectEqual(@as(?std.http.Method, .GET), stdMethod(.GET));
    try testing.expectEqual(@as(?std.http.Method, null), stdMethod(.OTHER));
}
