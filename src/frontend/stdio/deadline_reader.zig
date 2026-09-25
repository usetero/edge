//! Inbound socket reads with a deadline. `std.Io.net.Stream.Reader` never
//! times out, so a client that connects and sends nothing holds its slab slot
//! until the process exits. Reads use `net_receive` under `Io.operateTimeout`:
//! on POSIX, a non-blocking `recvmsg` and a `poll` with the deadline. That
//! costs no extra task and keeps `std.posix` out of the frontend.
//!
//! Two deadlines, so both stalls are bounded:
//!
//!   idle     caps one read while no request is in flight (keep-alive wait).
//!   request  caps the whole request once its first byte arrives.
//!
//! The second one is what httpz lacks. Its `SO_RCVTIMEO` restarts on every
//! read, so a client that dribbles one byte per 29 s holds a handler thread
//! for as long as it likes (see the DeadlineReader note in ../httpz/server.zig).
const std = @import("std");
const limits_mod = @import("../../core/limits.zig");

/// Which deadline a read hit.
pub const Phase = enum { idle, request };

pub const DeadlineReader = struct {
    interface: std.Io.Reader,
    io: std.Io,
    stream: std.Io.net.Stream,
    /// Cap for a single read while no request is in flight.
    idle: std.Io.Clock.Duration,
    /// Cap for a whole request, measured from its first byte.
    request: std.Io.Clock.Duration,
    /// Armed by the first byte of a request; cleared by `endRequest`.
    request_deadline: ?std.Io.Clock.Timestamp = null,
    /// The real error behind `error.ReadFailed`, which `Io.Reader` cannot
    /// carry. The connection driver reads it to tell a timeout from a peer
    /// that went away.
    err: ?anyerror = null,
    /// Which deadline expired, set with `err = error.Timeout`.
    expired: ?Phase = null,

    pub fn init(io: std.Io, stream: std.Io.net.Stream, buffer: []u8) DeadlineReader {
        return .{
            .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .io = io,
            .stream = stream,
            .idle = .{ .raw = .fromSeconds(limits_mod.KEEPALIVE_TIMEOUT_SECONDS), .clock = .awake },
            .request = .{ .raw = .fromSeconds(limits_mod.REQUEST_TIMEOUT_SECONDS), .clock = .awake },
        };
    }

    /// Call after every response. The next read waits for a new request, so
    /// the idle cap applies again.
    pub fn endRequest(self: *DeadlineReader) void {
        self.request_deadline = null;
        self.expired = null;
        self.err = null;
    }

    fn currentTimeout(self: *const DeadlineReader) std.Io.Timeout {
        if (self.request_deadline) |deadline| return .{ .deadline = deadline };
        return .{ .duration = self.idle };
    }

    fn streamImpl(
        io_r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *DeadlineReader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const phase: Phase = if (self.request_deadline == null) .idle else .request;

        var message: std.Io.net.IncomingMessage = .init;
        const result = self.io.operateTimeout(.{ .net_receive = .{
            .socket_handle = self.stream.socket.handle,
            .message_buffer = (&message)[0..1],
            .data_buffer = dest,
            .flags = .{},
        } }, self.currentTimeout()) catch |err| {
            self.err = err;
            if (err == error.Timeout) self.expired = phase;
            return error.ReadFailed;
        };

        const maybe_err, const count = result.net_receive;
        if (maybe_err) |err| {
            self.err = err;
            return error.ReadFailed;
        }
        // A stream socket reports a peer close as a zero-length message.
        if (count == 0 or message.data.len == 0) return error.EndOfStream;

        // The first byte starts the whole-request clock.
        if (self.request_deadline == null) {
            self.request_deadline = .fromNow(self.io, self.request);
        }
        w.advance(message.data.len);
        return message.data.len;
    }
};

// ============================== Tests ==============================

const testing = std.testing;

const Pair = struct {
    server: std.Io.net.Server,
    client: std.Io.net.Stream,
    accepted: std.Io.net.Stream,
};

/// Binds a loopback port, connects to it, and returns both ends. The same TCP
/// path the frontend serves; `socketpair` cannot make an AF_INET pair.
fn connectedPair(io: std.Io) !Pair {
    var port: u16 = 21080;
    while (port < 21280) : (port += 1) {
        const address = std.Io.net.IpAddress.parse("127.0.0.1", port) catch continue;
        var server = address.listen(io, .{ .reuse_address = true }) catch continue;
        errdefer server.deinit(io);
        const client = try address.connect(io, .{ .mode = .stream });
        errdefer client.close(io);
        const accepted = try server.accept(io);
        return .{ .server = server, .client = client, .accepted = accepted };
    }
    return error.NoFreePort;
}

test "an idle peer hits the idle deadline instead of blocking forever" {
    const io = testing.io;
    var pair = try connectedPair(io);
    defer pair.server.deinit(io);
    defer pair.client.close(io);
    defer pair.accepted.close(io);

    var buffer: [256]u8 = undefined;
    var reader: DeadlineReader = .init(io, pair.accepted, &buffer);
    // The production caps are 30 s; this test only needs to prove the read
    // returns at all.
    reader.idle = .{ .raw = .fromMilliseconds(50), .clock = .awake };

    // The client never writes.
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try testing.expectEqual(@as(?anyerror, error.Timeout), reader.err);
    try testing.expectEqual(@as(?Phase, .idle), reader.expired);
    try testing.expect(reader.expired != null);
}

test "a request that never finishes hits the request deadline" {
    const io = testing.io;
    var pair = try connectedPair(io);
    defer pair.server.deinit(io);
    defer pair.client.close(io);
    defer pair.accepted.close(io);

    var write_buffer: [64]u8 = undefined;
    var client_writer = std.Io.net.Stream.Writer.init(pair.client, io, &write_buffer);
    try client_writer.interface.writeAll("GET / HTTP/1.1\r\n");
    try client_writer.interface.flush();

    var buffer: [256]u8 = undefined;
    var reader: DeadlineReader = .init(io, pair.accepted, &buffer);
    reader.idle = .{ .raw = .fromMilliseconds(50), .clock = .awake };
    reader.request = .{ .raw = .fromMilliseconds(50), .clock = .awake };

    // The head arrives, so the request clock arms; the client then stalls.
    _ = try reader.interface.take(16);
    try testing.expect(reader.request_deadline != null);
    try testing.expectError(error.ReadFailed, reader.interface.takeByte());
    try testing.expectEqual(@as(?Phase, .request), reader.expired);

    // A finished response returns the reader to the idle cap.
    reader.endRequest();
    try testing.expect(reader.request_deadline == null);
}

test "a peer that closes reports end of stream, not a timeout" {
    const io = testing.io;
    var pair = try connectedPair(io);
    defer pair.server.deinit(io);
    defer pair.accepted.close(io);

    pair.client.close(io);

    var buffer: [256]u8 = undefined;
    var reader: DeadlineReader = .init(io, pair.accepted, &buffer);
    reader.idle = .{ .raw = .fromMilliseconds(500), .clock = .awake };

    try testing.expectError(error.EndOfStream, reader.interface.takeByte());
    try testing.expect(reader.expired == null);
}
