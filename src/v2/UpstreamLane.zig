//! One reusable upstream connection per worker; its buffers never change address.
const Self = @This();
const std = @import("std");
const Origin = @import("Origin.zig");
const tls = std.crypto.tls;

stream: ?std.Io.net.Stream = null,
origin: Origin = undefined,
reader: std.Io.net.Stream.Reader = undefined,
writer: std.Io.net.Stream.Writer = undefined,
secure: tls.Client = undefined,
read_buffer: [tls.Client.min_buffer_len]u8 = undefined,
write_buffer: [tls.Client.min_buffer_len]u8 = undefined,
tls_read: [tls.Client.min_buffer_len]u8 = undefined,
tls_write: [tls.Client.min_buffer_len]u8 = undefined,
last_used: std.Io.Timestamp = .{ .nanoseconds = 0 },

pub const Trust = struct {
    allocator: std.mem.Allocator,
    bundle: *std.crypto.Certificate.Bundle,
    lock: *std.Io.RwLock,
};

/// Acquire the stream before handshake, allowing the owner to arm its watchdog.
pub fn acquire(
    self: *Self,
    io: std.Io,
    origin: Origin,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
) !bool {
    if (self.stream != null) {
        if (self.origin.secure == origin.secure and std.mem.eql(u8, self.origin.authority, origin.authority) and
            std.mem.eql(u8, self.origin.host, origin.host) and
            std.meta.eql(self.origin.address, origin.address) and self.idleClean(io)) return false;
        self.close(io);
    }
    const stream = try origin.connect(io, deadline, stopped);
    self.stream = stream;
    self.origin = origin;
    self.reader = stream.reader(io, &self.read_buffer);
    self.writer = stream.writer(io, &self.write_buffer);
    return true;
}

pub fn handshake(self: *Self, io: std.Io, trust: ?Trust) !void {
    if (!self.origin.secure) return;
    const ca = trust orelse return error.MissingTlsConfiguration;
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    self.secure = try .init(&self.reader.interface, &self.writer.interface, .{
        .host = .{ .explicit = self.origin.host },
        .ca = .{ .bundle = .{ .gpa = ca.allocator, .io = io, .lock = ca.lock, .bundle = ca.bundle } },
        .read_buffer = &self.tls_read,
        .write_buffer = &self.tls_write,
        .entropy = &entropy,
        .realtime_now = .now(io, .real),
    });
}

pub fn close(self: *Self, io: std.Io) void {
    if (self.stream) |stream| stream.close(io);
    self.stream = null;
}

pub fn input(self: *Self) *std.Io.Reader {
    return if (self.origin.secure) &self.secure.reader else &self.reader.interface;
}

pub fn output(self: *Self) *std.Io.Writer {
    return if (self.origin.secure) &self.secure.writer else &self.writer.interface;
}

pub fn flush(self: *Self) !void {
    try self.output().flush();
    try self.writer.interface.flush();
}

/// Called only after the watchdog has disarmed and framing authorized reuse.
pub fn release(self: *Self, io: std.Io, reusable: bool) void {
    if (!reusable or self.input().buffered().len != 0 or self.reader.interface.buffered().len != 0) {
        return self.close(io);
    }
    self.last_used = .now(io, .awake);
}

fn idleClean(self: *Self, io: std.Io) bool {
    if (std.Io.Timestamp.now(io, .awake).nanoseconds - self.last_used.nanoseconds > 30_000_000_000) return false;
    // EOF, unread data and unsolicited TLS records all evict conservatively.
    // A peer can still race this check: never retry after request commitment.
    var byte: [1]u8 = undefined;
    const count = std.c.recv(self.stream.?.socket.handle, &byte, 1, std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT);
    return count < 0 and std.posix.errno(count) == .AGAIN;
}
