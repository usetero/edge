//! Fixed-capacity connection slab: all per-connection state and buffers are
//! pre-allocated at startup and addressed by ConnId handles (index + ABA
//! generation). After init, claiming and releasing a connection performs zero
//! allocation, which is what makes the data-plane memory budget closed-form
//! (see limits.zig).
const std = @import("std");
const builtin = @import("builtin");
const limits_mod = @import("limits.zig");

const log = std.log.scoped(.conn_slab);

/// Handle = generation (high 16 bits) | slot index (low 16 bits). Packing the
/// generation into the handle makes stale-handle use detectable (ABA guard)
/// while keeping references at 32 bits per DoD guidelines.
pub const ConnId = enum(u32) {
    _,

    fn pack(slot: u16, gen: u16) ConnId {
        return @enumFromInt(@as(u32, gen) << 16 | slot);
    }

    pub fn index(self: ConnId) u16 {
        return @truncate(@intFromEnum(self));
    }

    pub fn generation(self: ConnId) u16 {
        return @truncate(@intFromEnum(self) >> 16);
    }
};

/// Hot data: touched on every claim and release. `claimed` lets claim and
/// release assert that a slot is not claimed twice or released twice.
const ConnHot = struct {
    claimed: bool,
    generation: u16,
};

pub const ConnSlab = struct {
    hot: std.MultiArrayList(ConnHot),
    /// Contiguous buffer arena sliced per slot; the only large allocation.
    /// Page-aligned so madvise can address individual connection slots.
    buffers: []align(std.heap.page_size_min) u8,
    /// Stack of free slot indexes; claim pops, release pushes.
    free_list: []u16,
    /// The socket each claimed slot is serving, so shutdown can interrupt a
    /// read that is waiting on its deadline. Cancellation does not reach a
    /// task parked in a poll, so without this a SIGTERM waited out the idle
    /// deadline: 30 s per deployment, against the orchestrator's kill timer.
    sockets: []?std.Io.net.Stream,
    free_count: usize,
    mutex: std.Io.Mutex,
    limits: limits_mod.Limits,
    /// Slots an ordinary connection may not take, so a health probe can still
    /// be read while the slab is full. See limits.CONTROL_RESERVE_SLOTS.
    reserve: usize,

    pub fn init(gpa: std.mem.Allocator, limits: limits_mod.Limits) !ConnSlab {
        // u16 slot indexes bound the slab; 65k concurrent connections is far
        // beyond this proxy's design envelope.
        std.debug.assert(limits.max_connections > 0);
        std.debug.assert(limits.connectionSlots() < std.math.maxInt(u16));
        // The control reserve is extra capacity, not a slice of the operator's
        // cap: `claim` must still yield `max_connections` ordinary slots, or a
        // deployment sized to its sender count sheds the last few senders.
        const n = limits.connectionSlots();

        var hot: std.MultiArrayList(ConnHot) = .empty;
        errdefer hot.deinit(gpa);
        try hot.resize(gpa, n);
        for (0..n) |i| hot.set(i, .{ .claimed = false, .generation = 0 });

        // The buffer region is page-granular and process-lifetime; going
        // through page_allocator keeps reserved-but-untouched pages out of
        // RSS (a debug gpa would memset the whole reservation). Alignment
        // must be at least page_size_min so madvise() can address any slot.
        const buffers = try std.heap.page_allocator.alignedAlloc(
            u8,
            .fromByteUnits(std.heap.page_size_min),
            n * limits.perConnBytes(),
        );
        errdefer std.heap.page_allocator.free(buffers);

        const free_list = try gpa.alloc(u16, n);
        errdefer gpa.free(free_list);

        const sockets = try gpa.alloc(?std.Io.net.Stream, n);
        errdefer gpa.free(sockets);
        @memset(sockets, null);
        // Pop order is LIFO: slot 0 first, keeping low slots (and their warm
        // cache lines) in rotation under light load.
        for (free_list, 0..) |*slot, i| slot.* = @intCast(n - 1 - i);

        return .{
            .hot = hot,
            .buffers = buffers,
            .free_list = free_list,
            .sockets = sockets,
            .free_count = n,
            .mutex = .init,
            .limits = limits,
            .reserve = limits_mod.CONTROL_RESERVE_SLOTS,
        };
    }

    pub fn deinit(self: *ConnSlab, gpa: std.mem.Allocator) void {
        self.hot.deinit(gpa);
        std.heap.page_allocator.free(self.buffers);
        gpa.free(self.free_list);
        gpa.free(self.sockets);
        self.* = undefined;
    }

    /// Claims a slot, or null when the slab is exhausted (caller load-sheds
    /// with 503). Never blocks beyond the mutex, never allocates.
    ///
    /// Leaves `reserve` slots untouched; `claimReserved` reaches those, and
    /// the caller must close such a connection after one request so the
    /// reserve recycles.
    pub fn claim(self: *ConnSlab, io: std.Io) ?ConnId {
        return self.claimInner(io, false);
    }

    /// Claims from the reserve. Only for a connection that will be answered
    /// and closed at once, so a control path can be served while the rest of
    /// the slab is full.
    pub fn claimReserved(self: *ConnSlab, io: std.Io) ?ConnId {
        return self.claimInner(io, true);
    }

    fn claimInner(self: *ConnSlab, io: std.Io, reserved: bool) ?ConnId {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const floor = if (reserved) 0 else self.reserve;
        if (self.free_count <= floor) return null;
        self.free_count -= 1;
        const slot = self.free_list[self.free_count];

        const entry = self.hot.get(slot);
        std.debug.assert(!entry.claimed);
        self.hot.set(slot, .{ .claimed = true, .generation = entry.generation });
        self.sockets[slot] = null;
        return ConnId.pack(slot, entry.generation);
    }

    /// Releases a slot back to the free list and bumps the generation, so a
    /// stale ConnId asserts instead of aliasing the new owner. Advises the OS
    /// to decommit the buffer pages, so idle RSS returns to near zero.
    ///
    /// The decommit runs under the mutex. The free list is LIFO, so the next
    /// `claim` returns this slot. A decommit after unlock would zero the pages
    /// of the new owner. The lock is held once per connection, so the cost is
    /// small.
    pub fn release(self: *ConnSlab, io: std.Io, id: ConnId) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const slot = self.checkedIndex(id);
        const entry = self.hot.get(slot);
        std.debug.assert(entry.claimed);
        self.hot.set(slot, .{ .claimed = false, .generation = entry.generation +% 1 });
        self.sockets[slot] = null;

        std.debug.assert(self.free_count < self.free_list.len);
        self.free_list[self.free_count] = slot;
        self.free_count += 1;

        // Decommit the slot's pages: DONTNEED on Linux, FREE_REUSABLE on
        // macOS. The next use faults in zeroed pages, with no allocation.
        // madvise needs page-aligned bounds; the guard skips a slot that is
        // not aligned.
        const page = std.heap.page_size_min;
        const base = @as(usize, slot) * self.limits.perConnBytes();
        const aligned_base = std.mem.alignForward(usize, base, page);
        const aligned_end = std.mem.alignBackward(usize, base + self.limits.perConnBytes(), page);
        if (aligned_end > aligned_base) {
            const advice: u32 = switch (builtin.os.tag) {
                .linux => std.c.MADV.DONTNEED,
                .macos, .ios => std.c.MADV.FREE_REUSABLE,
                else => return,
            };
            const ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(self.buffers[aligned_base..].ptr);
            std.posix.madvise(ptr, aligned_end - aligned_base, advice) catch |err| {
                // Advisory only: the slot stays usable, RSS just won't shrink.
                log.warn("madvise failed for slot {d}: {s}", .{ slot, @errorName(err) });
            };
        }
    }

    /// Records the socket a claimed slot is serving. Call once the stream is
    /// known, so `shutdownAll` can reach it.
    pub fn trackSocket(self: *ConnSlab, io: std.Io, id: ConnId, stream: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.sockets[self.checkedIndex(id)] = stream;
    }

    /// Interrupts every connection the slab is serving. A reader parked on
    /// its deadline returns at once, so shutdown does not wait out the idle
    /// timeout. Safe to call from another task: shutdown only, and the worst
    /// case is a read that was about to fail anyway.
    pub fn shutdownAll(self: *ConnSlab, io: std.Io) usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        var count: usize = 0;
        for (self.sockets) |maybe_stream| {
            const stream = maybe_stream orelse continue;
            stream.shutdown(io, .both) catch |err| {
                log.debug("failed to interrupt inbound socket: {s}", .{@errorName(err)});
                continue;
            };
            count += 1;
        }
        return count;
    }

    pub fn recvBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, 0, self.limits.recv_buf);
    }

    pub fn sendBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.limits.recv_buf, self.limits.send_buf);
    }

    /// Request-body reader buffer, then response BodyWriter staging; the two
    /// never overlap in time. Codec and record scratch are per thread
    /// (frontend/thread_bufs.zig), not per connection.
    pub fn bodyBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.limits.recv_buf + self.limits.send_buf, self.limits.body_buf);
    }

    pub fn inUse(self: *ConnSlab, io: std.Io) usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.free_list.len - self.free_count;
    }

    fn bufRegion(self: *ConnSlab, id: ConnId, offset: usize, len: usize) []u8 {
        const slot = self.checkedIndex(id);
        const base = @as(usize, slot) * self.limits.perConnBytes();
        return self.buffers[base + offset ..][0..len];
    }

    /// Validates the handle's generation against the slot — catches use of a
    /// ConnId that outlived its connection (the ABA bug class).
    fn checkedIndex(self: *ConnSlab, id: ConnId) u16 {
        const slot = id.index();
        std.debug.assert(slot < self.free_list.len);
        std.debug.assert(self.hot.items(.generation)[slot] == id.generation());
        return slot;
    }
};

const testing = std.testing;

const test_limits: limits_mod.Limits = .resolve(.{ .max_body_size = 128, .max_connections = 4 });

test "claim and release cycle slots without allocating" {
    var slab: ConnSlab = try .init(testing.allocator, test_limits);
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    const a = slab.claim(io).?;
    const b = slab.claim(io).?;
    try testing.expect(a != b);
    try testing.expectEqual(@as(usize, 2), slab.inUse(io));

    slab.release(io, a);
    slab.release(io, b);
    try testing.expectEqual(@as(usize, 0), slab.inUse(io));
}

test "exhausted slab returns null, recovers after release" {
    var slab: ConnSlab = try .init(testing.allocator, test_limits);
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    // An ordinary claim stops at the reserve, not at zero.
    const ordinary = slab.free_list.len - slab.reserve;
    var ids: [4]ConnId = undefined;
    for (ids[0..ordinary]) |*id| id.* = slab.claim(io).?;
    try testing.expectEqual(@as(?ConnId, null), slab.claim(io));

    slab.release(io, ids[2]);
    const again = slab.claim(io).?;
    try testing.expectEqual(ids[2].index(), again.index());
    // Same slot, new generation: the old handle is dead.
    try testing.expect(ids[2] != again);

    for (ids[0..ordinary], 0..) |id, i| if (i != 2) slab.release(io, id);
    slab.release(io, again);
}

test "the reserve is reachable only through claimReserved" {
    var slab: ConnSlab = try .init(testing.allocator, test_limits);
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    try testing.expect(slab.reserve > 0);
    // The promise: `claim` yields exactly `max_connections` slots, and the
    // reserve is extra.
    const ordinary = slab.free_list.len - slab.reserve;
    try testing.expectEqual(test_limits.max_connections, ordinary);

    var ids: [8]ConnId = undefined;
    for (ids[0..ordinary]) |*id| id.* = slab.claim(io).?;
    // The slab looks full to an ordinary connection...
    try testing.expectEqual(@as(?ConnId, null), slab.claim(io));
    // ...and a health probe still gets read.
    const probe = slab.claimReserved(io).?;
    slab.release(io, probe);

    for (ids[0..ordinary]) |id| slab.release(io, id);
}

test "buffer regions are disjoint per connection and per region" {
    var slab: ConnSlab = try .init(testing.allocator, test_limits);
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    const a = slab.claim(io).?;
    const b = slab.claim(io).?;
    defer slab.release(io, a);
    defer slab.release(io, b);

    @memset(slab.recvBuf(a), 0xAA);
    @memset(slab.sendBuf(a), 0xBB);
    @memset(slab.bodyBuf(a), 0xCC);
    @memset(slab.recvBuf(b), 0xDD);

    try testing.expectEqual(@as(u8, 0xAA), slab.recvBuf(a)[0]);
    try testing.expectEqual(@as(u8, 0xBB), slab.sendBuf(a)[0]);
    try testing.expectEqual(@as(u8, 0xCC), slab.bodyBuf(a)[0]);
    try testing.expectEqual(@as(u8, 0xDD), slab.recvBuf(b)[0]);
    try testing.expectEqual(limits_mod.RECV_BUF_BYTES, slab.recvBuf(a).len);
    try testing.expectEqual(limits_mod.SEND_BUF_BYTES, slab.sendBuf(a).len);
    try testing.expectEqual(limits_mod.BODY_BUF_BYTES, slab.bodyBuf(a).len);
}

test "release decommits page-aligned slot buffers and the slot stays usable" {
    // The slab must survive the in-lock decommit: a re-claimed slot is still
    // usable, and on Linux MADV_DONTNEED zeroed it. The race itself needs OS
    // threads; testing.io is single-threaded.
    var slab: ConnSlab = try .init(testing.allocator, test_limits);
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    const a = slab.claim(io).?;
    const a_recv = slab.recvBuf(a);
    @memset(a_recv, 0xAA);
    try testing.expectEqual(@as(u8, 0xAA), a_recv[0]);
    slab.release(io, a);

    // LIFO: the released slot is the next claim.
    const b = slab.claim(io).?;
    try testing.expectEqual(a.index(), b.index());
    const b_recv = slab.recvBuf(b);

    switch (builtin.os.tag) {
        // MADV_DONTNEED discards the page; the next read returns zeros.
        .linux => try testing.expectEqual(@as(u8, 0x00), b_recv[0]),
        // Elsewhere the decommit is advisory; only check the buffer stays usable.
        else => {},
    }
    @memset(b_recv, 0xBB);
    try testing.expectEqual(@as(u8, 0xBB), b_recv[0]);
    slab.release(io, b);
}
