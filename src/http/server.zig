//! Accept loop on std.Io.net (PLAN.md §9). One concurrent task per
//! connection via Lifecycle.spawn; the Io implementation decides what
//! "concurrent" means. Shutdown is structured: Lifecycle.shutdown cancels
//! the accept task and every connection task together.
const std = @import("std");
const conn_mod = @import("conn.zig");
const lifecycle_mod = @import("../core/lifecycle.zig");

const log = std.log.scoped(.http_server);

pub const HttpServer = struct {
    listener: std.Io.net.Server,
    ctx: *conn_mod.SharedCtx,
    lifecycle: *lifecycle_mod.Lifecycle,

    pub fn init(
        ctx: *conn_mod.SharedCtx,
        lifecycle: *lifecycle_mod.Lifecycle,
        listen_address: [4]u8,
        listen_port: u16,
    ) !HttpServer {
        var addr_buf: [64]u8 = undefined;
        const addr_str = try std.fmt.bufPrint(&addr_buf, "{d}.{d}.{d}.{d}", .{
            listen_address[0], listen_address[1], listen_address[2], listen_address[3],
        });
        const address = try std.Io.net.IpAddress.parse(addr_str, listen_port);
        const listener = try address.listen(ctx.io, .{
            .reuse_address = true,
        });
        return .{
            .listener = listener,
            .ctx = ctx,
            .lifecycle = lifecycle,
        };
    }

    pub fn deinit(self: *HttpServer) void {
        self.listener.deinit(self.ctx.io);
        self.* = undefined;
    }

    /// The accept loop; itself spawned into the lifecycle group, so
    /// cancellation lands here as error.Canceled out of accept().
    pub fn run(self: *HttpServer) std.Io.Cancelable!void {
        const io = self.ctx.io;
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
            self.lifecycle.spawn(io, conn_mod.serveConnection, .{ self.ctx, stream }) catch |err| switch (err) {
                error.ConcurrencyUnavailable => {
                    // The Io implementation is at its task limit; the slab
                    // would also have shed. Tell the client to back off.
                    shedConnection(io, stream);
                },
            };
        }
    }
};

fn shedConnection(io: std.Io, stream: std.Io.net.Stream) void {
    defer stream.close(io);
    var buf: [256]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(stream, io, &buf);
    writer.interface.writeAll(
        "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    ) catch return;
    writer.interface.flush() catch return;
}
