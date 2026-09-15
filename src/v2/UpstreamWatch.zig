//! Absolute upstream deadlines enforced by shutting down the watched socket.
//! The forwarder stays the only closer: it disarms under the slot lock before
//! close, so the watchdog can never touch a recycled descriptor.
const Self = @This();

const std = @import("std");

slots: []Slot,

pub const Slot = struct {
    lock: std.Io.Mutex = .init,
    stream: ?std.Io.net.Stream = null,
    deadline_ns: i96 = 0,
    expired: bool = false,
};

pub fn init(allocator: std.mem.Allocator, count: usize) !Self {
    const slots = try allocator.alloc(Slot, count);
    @memset(slots, .{});
    return .{ .slots = slots };
}

/// Every slot must be disarmed first; the watch never owns a stream.
pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
    for (self.slots) |slot| std.debug.assert(slot.stream == null);
    allocator.free(self.slots);
    self.* = undefined;
}

/// Arm before the first blocking transport call of an exchange.
pub fn arm(self: *Self, io: std.Io, index: usize, stream: std.Io.net.Stream, deadline: std.Io.Timestamp) void {
    const slot = &self.slots[index];
    slot.lock.lockUncancelable(io);
    defer slot.lock.unlock(io);
    std.debug.assert(slot.stream == null);
    slot.stream = stream;
    slot.deadline_ns = deadline.nanoseconds;
    slot.expired = false;
}

/// Disarm before closing the stream. Reports whether the deadline fired.
pub fn disarm(self: *Self, io: std.Io, index: usize) bool {
    const slot = &self.slots[index];
    slot.lock.lockUncancelable(io);
    defer slot.lock.unlock(io);
    slot.stream = null;
    return slot.expired;
}

/// One watchdog pass. Returns how many armed streams were shut down.
pub fn expire(self: *Self, io: std.Io, now: std.Io.Timestamp) usize {
    var count: usize = 0;
    for (self.slots) |*slot| {
        slot.lock.lockUncancelable(io);
        defer slot.lock.unlock(io);
        const stream = slot.stream orelse continue;
        if (slot.expired or now.nanoseconds < slot.deadline_ns) continue;
        slot.expired = true;
        count += 1;
        stream.shutdown(io, .both) catch |err| {
            std.log.warn("upstream deadline shutdown failed: {t}", .{err});
        };
    }
    return count;
}

const testing = std.testing;

const Peer = struct {
    listener: std.Io.net.Server,
    accepted: ?std.Io.net.Stream = null,

    fn init(io: std.Io) !Peer {
        const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        return .{ .listener = try address.listen(io, .{}) };
    }

    fn deinit(self: *Peer, io: std.Io) void {
        if (self.accepted) |stream| stream.close(io);
        self.listener.deinit(io);
        self.* = undefined;
    }

    fn connect(self: *Peer, io: std.Io) !std.Io.net.Stream {
        const stream = try self.listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        self.accepted = try self.listener.accept(io);
        return stream;
    }

    /// A trickling peer keeps the per-call clock moving without ever finishing.
    fn trickle(self: *Peer, io: std.Io, interval_ms: u16) !void {
        var buffer: [16]u8 = undefined;
        var writer = self.accepted.?.writer(io, &buffer);
        while (true) {
            try writer.interface.writeByte('.');
            try writer.interface.flush();
            try io.sleep(.fromMilliseconds(interval_ms), .awake);
        }
    }
};

const Read = struct {
    bytes: usize = 0,
    elapsed_ms: i64 = 0,
    err: ?anyerror = null,

    fn run(self: *Read, io: std.Io, stream: std.Io.net.Stream) void {
        const started: std.Io.Timestamp = .now(io, .awake);
        defer self.elapsed_ms = started.durationTo(.now(io, .awake)).toMilliseconds();
        var buffer: [64]u8 = undefined;
        var reader = stream.reader(io, &buffer);
        while (reader.interface.takeByte()) |_| {
            self.bytes += 1;
        } else |err| {
            self.err = reader.err orelse err;
        }
    }
};

fn watchUntilExpired(watch: *Self, io: std.Io) !void {
    for (0..1000) |_| {
        if (watch.expire(io, .now(io, .awake)) == 1) return;
        try io.sleep(.fromMilliseconds(5), .awake);
    }
    return error.TestDeadlineNeverFired;
}

fn deadlineIn(io: std.Io, ms: u16) std.Io.Timestamp {
    return std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(ms));
}

test "v2 upstream watch interrupts a read blocked on a silent peer at the deadline" {
    const io = testing.io;
    var peer: Peer = try .init(io);
    defer peer.deinit(io);
    const stream = try peer.connect(io);
    defer stream.close(io);
    var watch: Self = try .init(testing.allocator, 1);
    defer watch.deinit(testing.allocator);
    watch.arm(io, 0, stream, deadlineIn(io, 100));
    var read: Read = .{};
    var task = try io.concurrent(Read.run, .{ &read, io, stream });
    try watchUntilExpired(&watch, io);
    task.await(io);
    try testing.expect(watch.disarm(io, 0));
    try testing.expect(read.err != null);
    try testing.expectEqual(@as(usize, 0), read.bytes);
    try testing.expect(read.elapsed_ms >= 90);
    try testing.expect(read.elapsed_ms < 2000);
}

test "v2 upstream watch bounds a trickling peer that defeats per-call timeouts" {
    const io = testing.io;
    var peer: Peer = try .init(io);
    defer peer.deinit(io);
    const stream = try peer.connect(io);
    defer stream.close(io);
    var trickle = try io.concurrent(Peer.trickle, .{ &peer, io, 10 });
    // The peer ends with WriteFailed after the shutdown, or Canceled here.
    defer trickle.cancel(io) catch |err| switch (err) {
        error.Canceled, error.WriteFailed => {},
    };
    var watch: Self = try .init(testing.allocator, 1);
    defer watch.deinit(testing.allocator);
    watch.arm(io, 0, stream, deadlineIn(io, 150));
    var read: Read = .{};
    var task = try io.concurrent(Read.run, .{ &read, io, stream });
    try watchUntilExpired(&watch, io);
    task.await(io);
    try testing.expect(watch.disarm(io, 0));
    // Each byte arrived well inside any per-call receive timeout, yet the
    // absolute deadline still ended the exchange.
    try testing.expect(read.bytes >= 3);
    try testing.expect(read.elapsed_ms >= 140);
    try testing.expect(read.elapsed_ms < 2000);
}

test "v2 upstream watch interrupts a stalled TLS handshake" {
    const io = testing.io;
    var peer: Peer = try .init(io);
    defer peer.deinit(io);
    const stream = try peer.connect(io);
    defer stream.close(io);
    var watch: Self = try .init(testing.allocator, 1);
    defer watch.deinit(testing.allocator);
    watch.arm(io, 0, stream, deadlineIn(io, 100));
    var handshake: Handshake = .{};
    var task = try io.concurrent(Handshake.run, .{ &handshake, io, stream });
    try watchUntilExpired(&watch, io);
    task.await(io);
    try testing.expect(watch.disarm(io, 0));
    try testing.expect(handshake.err != null);
    try testing.expect(handshake.elapsed_ms < 2000);
}

const Handshake = struct {
    elapsed_ms: i64 = 0,
    err: ?anyerror = null,

    fn run(self: *Handshake, io: std.Io, stream: std.Io.net.Stream) void {
        const started: std.Io.Timestamp = .now(io, .awake);
        defer self.elapsed_ms = started.durationTo(.now(io, .awake)).toMilliseconds();
        const tls = std.crypto.tls;
        var read_buffer: [tls.Client.min_buffer_len]u8 = undefined;
        var write_buffer: [tls.Client.min_buffer_len]u8 = undefined;
        var tls_read: [tls.Client.min_buffer_len]u8 = undefined;
        var tls_write: [tls.Client.min_buffer_len]u8 = undefined;
        var reader = stream.reader(io, &read_buffer);
        var writer = stream.writer(io, &write_buffer);
        var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        // Probe only: verification is irrelevant because the peer never answers.
        _ = tls.Client.init(&reader.interface, &writer.interface, .{
            .host = .no_verification,
            .ca = .no_verification,
            .read_buffer = &tls_read,
            .write_buffer = &tls_write,
            .entropy = &entropy,
            .realtime_now = .now(io, .real),
        }) catch |err| {
            self.err = err;
        };
    }
};

test "v2 upstream watch never touches a descriptor reused after disarm" {
    const io = testing.io;
    var peer: Peer = try .init(io);
    defer peer.deinit(io);
    var watch: Self = try .init(testing.allocator, 1);
    defer watch.deinit(testing.allocator);
    const first = try peer.connect(io);
    const first_handle = first.socket.handle;
    watch.arm(io, 0, first, deadlineIn(io, 0));
    try testing.expect(!watch.disarm(io, 0));
    first.close(io);
    peer.accepted.?.close(io);
    peer.accepted = null;
    const second = try peer.connect(io);
    defer second.close(io);
    // A forced pass after disarm must not shut down the recycled descriptor.
    try testing.expectEqual(@as(usize, 0), watch.expire(io, deadlineIn(io, 1000)));
    var buffer: [8]u8 = undefined;
    var writer = second.writer(io, &buffer);
    try writer.interface.writeAll("ok");
    try writer.interface.flush();
    var receive: [2]u8 = undefined;
    var reader = peer.accepted.?.reader(io, &receive);
    try testing.expectEqualStrings("ok", try reader.interface.take(2));
    // Descriptor reuse is what makes stale shutdown dangerous; record whether it happened.
    if (second.socket.handle != first_handle) std.log.warn("v2 watch probe: descriptor not reused", .{});
}

test "v2 upstream watch: task cancellation also interrupts a blocked read" {
    // DNS lookups cannot be shut down through a socket we own; this is the
    // cancellation path a control-plane resolver would rely on instead.
    const io = testing.io;
    var peer: Peer = try .init(io);
    defer peer.deinit(io);
    const stream = try peer.connect(io);
    defer stream.close(io);
    var read: Read = .{};
    var task = try io.concurrent(Read.run, .{ &read, io, stream });
    try io.sleep(.fromMilliseconds(50), .awake);
    const started: std.Io.Timestamp = .now(io, .awake);
    task.cancel(io);
    try testing.expect(started.durationTo(.now(io, .awake)).toMilliseconds() < 2000);
    try testing.expectEqual(error.Canceled, read.err.?);
}
