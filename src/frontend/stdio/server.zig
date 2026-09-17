//! std.Io-native frontend: accept loop on std.Io.net (PLAN.md §9). One
//! concurrent task per connection via Lifecycle.spawn; the Io implementation
//! decides what "concurrent" means. Shutdown is structured:
//! Lifecycle.shutdown cancels the accept task and every connection task
//! together.
//!
//! Owns the frontend-specific per-connection state — the conn slab and the
//! arena pool (PLAN-FRONTEND-SWAP.md §2) — so composing a different frontend
//! never pays this one's memory reservation. Body-sized scratch and the
//! upstream deadline watchdog are shared with httpz (../thread_bufs.zig).
const std = @import("std");
const conn_mod = @import("conn.zig");
const exec = @import("../exec.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");
const conn_slab_mod = @import("../../core/conn_slab.zig");
const arena_pool_mod = @import("../../core/arena_pool.zig");
const thread_bufs = @import("../thread_bufs.zig");

const log = std.log.scoped(.http_server);

// Named event payloads: the type name is the telemetry event name.
/// A connection refused before it carried a request, with the status sent.
const ConnectionShed = struct { reason: []const u8, answered: u16 };

pub const HttpServer = struct {
    listener: std.Io.net.Server,
    ctx: *exec.SharedCtx,
    lifecycle: *lifecycle_mod.Lifecycle,
    slab: conn_slab_mod.ConnSlab,
    arenas: arena_pool_mod.ArenaPool,

    pub fn init(
        ctx: *exec.SharedCtx,
        lifecycle: *lifecycle_mod.Lifecycle,
        listen_address: [4]u8,
        listen_port: u16,
    ) !HttpServer {
        var slab: conn_slab_mod.ConnSlab = try .init(ctx.gpa, ctx.limits);
        errdefer slab.deinit(ctx.gpa);
        var arenas: arena_pool_mod.ArenaPool = try .init(ctx.gpa, ctx.limits);
        errdefer arenas.deinit(ctx.gpa);

        var addr_buf: [64]u8 = undefined;
        const addr_str = try std.fmt.bufPrint(&addr_buf, "{d}.{d}.{d}.{d}", .{
            listen_address[0], listen_address[1], listen_address[2], listen_address[3],
        });
        const address = try std.Io.net.IpAddress.parse(addr_str, listen_port);
        const listener = try address.listen(ctx.io, .{
            .reuse_address = true,
            // Default 128 overflows instantly when a load spike (or error
            // storm) makes many clients redial at once; connection refused
            // at the kernel turns one failure into a reconnect avalanche.
            .kernel_backlog = 1024,
        });
        return .{
            .listener = listener,
            .ctx = ctx,
            .lifecycle = lifecycle,
            .slab = slab,
            .arenas = arenas,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        self.listener.deinit(self.ctx.io);
        self.arenas.deinit(self.ctx.gpa);
        self.slab.deinit(self.ctx.gpa);
        thread_bufs.freeAll(self.ctx.io, self.ctx.gpa);
        self.* = undefined;
    }

    /// Lifecycle cancellation already unblocks the accept loop (accept()
    /// returns error.Canceled); this only cuts every in-flight upstream
    /// exchange so connection tasks stop promptly. The httpz frontend, whose
    /// listen loop is NOT Io-cancelable, does more here.
    pub fn stopAccepting(self: *HttpServer) void {
        thread_bufs.expireTrackedUpstreams(self.ctx, true);
        // Cancellation does not reach a connection task parked in a poll, so
        // without this a SIGTERM waited out the 30 s idle deadline while the
        // orchestrator counted down its kill timer.
        const interrupted = self.slab.shutdownAll(self.ctx.io);
        if (interrupted > 0) log.info("interrupted {d} inbound connection(s)", .{interrupted});
    }

    /// The accept loop; itself spawned into the lifecycle group, so
    /// cancellation lands here as error.Canceled out of accept().
    pub fn run(self: *HttpServer) std.Io.Cancelable!void {
        const io = self.ctx.io;
        self.lifecycle.spawn(io, watchUpstreamDeadlines, .{ self.ctx, self.lifecycle }) catch {
            self.lifecycle.requestShutdown(io);
            return;
        };
        while (!self.lifecycle.isShuttingDown()) {
            const stream = self.listener.accept(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => {
                    // Transient accept failures (fd exhaustion, aborted
                    // handshake) shouldn't kill the server.
                    log.warn("accept failed: {s}", .{@errorName(err)});
                    continue;
                },
            };
            if (self.ctx.metrics) |metrics| metrics.recordConnectionAccepted();
            self.lifecycle.spawn(io, conn_mod.serveConnection, .{
                self.ctx, &self.slab, &self.arenas, stream,
            }) catch |err| switch (err) {
                error.ConcurrencyUnavailable => {
                    // The Io implementation is at its task limit; the slab
                    // would also have shed. Tell the client to back off.
                    if (self.ctx.metrics) |metrics| metrics.recordConnectionShed(.concurrency);
                    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                    self.ctx.bus.warn(ConnectionShed{ .reason = "io_concurrency_unavailable", .answered = 503 });
                    shedConnection(io, stream);
                },
            };
        }
    }
};

fn watchUpstreamDeadlines(ctx: *exec.SharedCtx, lifecycle: *lifecycle_mod.Lifecycle) std.Io.Cancelable!void {
    while (!lifecycle.isShuttingDown()) {
        try ctx.io.sleep(.fromMilliseconds(thread_bufs.watchdog_interval_ms), .awake);
        thread_bufs.expireTrackedUpstreams(ctx, false);
    }
}

fn shedConnection(io: std.Io, stream: std.Io.net.Stream) void {
    defer stream.close(io);
    var buf: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, io, &buf);
    writer.interface.writeAll(
        conn_mod.shed_response,
    ) catch return;
    writer.interface.flush() catch return;
}
