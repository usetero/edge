//! httpz frontend (PLAN-FRONTEND-SWAP.md §4): inbound HTTP rides httpz's own
//! kqueue/epoll event loop and handler thread pool. The process-wide `Io`
//! still serves the upstream client, policy loader, and lifecycle.
//!
//! This file is the shell: server lifecycle, httpz config derived from
//! limits, and the per-request `handle` → `dispatch` that turns a routed
//! outcome into a call on one of the sibling files.
//!
//!   paths.zig       the four request executors (raw forward, streamed
//!                   pipeline, buffered transform, filtered scrape)
//!   exchange.zig    the upstream leg: dial, send, receive, relay, retry
//!   thread_bufs.zig per-thread scratch and the upstream deadline watchdog
//!   endpoints.zig   /_edge/* observability endpoints
//!
//! Bodies at or above the 64 KiB pool buffer arrive unread and stream when
//! no policy needs them; smaller ones arrive buffered. Both cases are owned
//! by paths.zig. Routing and planning come from frontend/exec.zig, shared
//! with the stdio frontend.
const std = @import("std");
const httpz = @import("httpz");
const exec = @import("../exec.zig");
const runtime_metrics = @import("../../runtime/runtime_metrics.zig");
const limits_mod = @import("../../core/limits.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const exchange = @import("exchange.zig");
const paths = @import("paths.zig");
const endpoints = @import("endpoints.zig");
const thread_bufs = @import("thread_bufs.zig");

const log = std.log.scoped(.httpz_server);

// Named event payloads: the type name is the telemetry event name.
/// A request threw out of dispatch and was mapped to a bounded error response.
const RequestFailed = struct { method: []const u8, path: []const u8, err: []const u8 };
/// Per-request trace at debug level.
const RequestCompleted = struct { method: []const u8, path: []const u8, status: u16, duration_ms: f64 };

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
        },
        .workers = .{
            .count = worker_count,
            .max_conn = per_worker,
            .large_buffer_count = limits.large_body_buffer_count,
            .large_buffer_size = limits.large_body_buffer_size,
        },
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
        const method = exchange.serviceMethod(req.method);
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
        const method = exchange.serviceMethod(req.method);
        const path = req.url.path;

        if (req.method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) return endpoints.metrics(ctx, res);

        if (req.method == .GET and std.mem.eql(u8, path, "/_edge/policies")) return endpoints.policies(ctx, req, res);

        if (req.method == .GET and std.mem.startsWith(u8, path, "/_edge/tap/")) {
            const stage: exec.TapState.Stage = if (std.mem.eql(u8, path, "/_edge/tap/pre"))
                .pre
            else if (std.mem.eql(u8, path, "/_edge/tap/post"))
                .post
            else {
                res.status = 404;
                return;
            };
            return endpoints.recordTap(ctx, req, res, stage);
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
            .forward_raw => |fwd| try paths.execForwardRaw(ctx, req, res, fwd),
            .pipe_stream => |pipe| try paths.execPipeStream(ctx, req, res, pipe),
            .pipe_buffered => |pipe| try paths.execPipeBuffered(ctx, req, res, pipe),
            .fetch_filtered => |fetch| try paths.execFetchFiltered(ctx, req, res, fetch),
        }
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
