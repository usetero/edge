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
    none = std.math.maxInt(u32),
    _,

    fn pack(slot: u16, gen: u16) ConnId {
        return @enumFromInt(@as(u32, gen) << 16 | slot);
    }

    pub fn index(self: ConnId) u16 {
        std.debug.assert(self != .none);
        return @truncate(@intFromEnum(self));
    }

    pub fn generation(self: ConnId) u16 {
        std.debug.assert(self != .none);
        return @truncate(@intFromEnum(self) >> 16);
    }
};

/// Connection lifecycle states; transitions are asserted in setState so a
/// driver bug surfaces as a crash in debug builds, not silent corruption.
pub const ConnState = enum(u8) {
    free,
    accepted,
    reading_head,
    piping,
    responding,
    closing,

    fn legalNext(self: ConnState, next: ConnState) bool {
        return switch (self) {
            .free => next == .accepted,
            .accepted => next == .reading_head or next == .closing,
            .reading_head => next == .piping or next == .responding or next == .closing,
            .piping => next == .responding or next == .closing,
            // keep-alive loops back to reading_head for the next request.
            .responding => next == .reading_head or next == .closing,
            .closing => next == .free,
        };
    }
};

/// Hot data: touched on every state transition. SoA via MultiArrayList keeps
/// the state bytes densely packed for scans.
const ConnHot = struct {
    state: ConnState,
    generation: u16,
};

pub const ConnSlab = struct {
    hot: std.MultiArrayList(ConnHot),
    /// Contiguous buffer arena sliced per slot; the only large allocation.
    /// Page-aligned so madvise can address individual connection slots.
    buffers: []align(std.heap.page_size_min) u8,
    /// Stack of free slot indexes; claim pops, release pushes.
    free_list: []u16,
    free_count: usize,
    mutex: std.Io.Mutex,
    limits: limits_mod.Limits,

    pub fn init(gpa: std.mem.Allocator, limits: limits_mod.Limits) !ConnSlab {
        // u16 slot indexes bound the slab; 65k concurrent connections is far
        // beyond this proxy's design envelope.
        std.debug.assert(limits.max_connections > 0);
        std.debug.assert(limits.max_connections < std.math.maxInt(u16));
        const n = limits.max_connections;

        var hot: std.MultiArrayList(ConnHot) = .empty;
        errdefer hot.deinit(gpa);
        try hot.resize(gpa, n);
        for (0..n) |i| hot.set(i, .{ .state = .free, .generation = 0 });

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
        // Pop order is LIFO: slot 0 first, keeping low slots (and their warm
        // cache lines) in rotation under light load.
        for (free_list, 0..) |*slot, i| slot.* = @intCast(n - 1 - i);

        return .{
            .hot = hot,
            .buffers = buffers,
            .free_list = free_list,
            .free_count = n,
            .mutex = .init,
            .limits = limits,
        };
    }

    pub fn deinit(self: *ConnSlab, gpa: std.mem.Allocator) void {
        self.hot.deinit(gpa);
        std.heap.page_allocator.free(self.buffers);
        gpa.free(self.free_list);
        self.* = undefined;
    }

    /// Claims a slot, or null when the slab is exhausted (caller load-sheds
    /// with 503). Never blocks beyond the mutex, never allocates.
    pub fn claim(self: *ConnSlab, io: std.Io) ?ConnId {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        if (self.free_count == 0) return null;
        self.free_count -= 1;
        const slot = self.free_list[self.free_count];

        const entry = self.hot.get(slot);
        std.debug.assert(entry.state == .free);
        self.hot.set(slot, .{ .state = .accepted, .generation = entry.generation });
        return ConnId.pack(slot, entry.generation);
    }

    /// Releases a slot back to the free list, bumping the generation so any
    /// stale ConnId held elsewhere asserts instead of aliasing the new owner.
    /// After releasing the lock, advises the OS to decommit the buffer pages
    /// so idle RSS returns to near zero between connections.
    pub fn release(self: *ConnSlab, io: std.Io, id: ConnId) void {
        const slot: u16 = blk: {
            self.mutex.lockUncancelable(io);
            defer self.mutex.unlock(io);

            const s = self.checkedIndex(id);
            const entry = self.hot.get(s);
            std.debug.assert(entry.state != .free);
            self.hot.set(s, .{ .state = .free, .generation = entry.generation +% 1 });

            std.debug.assert(self.free_count < self.free_list.len);
            self.free_list[self.free_count] = s;
            self.free_count += 1;
            break :blk s;
        };

        // One madvise per connection close: tell the OS these pages are no
        // longer needed. On Linux (DONTNEED) pages are immediately zeroed and
        // deducted from RSS. On macOS (FREE_REUSABLE) they're immediately
        // reclaimable and drop from the physical footprint. Pages are re-faulted
        // as zeroed on next use — the slab's zero-alloc hot path is preserved.
        //
        // madvise requires page-aligned address and length. In production all
        // buffer size constants are multiples of 4 KiB, so the slot region is
        // naturally aligned. Tests use tiny buffer sizes where it isn't; the
        // aligned_end ≤ aligned_base guard skips the call safely.
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

    pub fn setState(self: *ConnSlab, io: std.Io, id: ConnId, next: ConnState) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const slot = self.checkedIndex(id);
        const entry = self.hot.get(slot);
        std.debug.assert(entry.state.legalNext(next));
        self.hot.set(slot, .{ .state = next, .generation = entry.generation });
    }

    pub fn recvBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, 0, self.limits.recv_buf);
    }

    pub fn sendBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.limits.recv_buf, self.limits.send_buf);
    }

    pub fn upstreamBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.limits.recv_buf + self.limits.send_buf, self.limits.upstream_write_buf);
    }

    pub fn recordScratch(self: *ConnSlab, id: ConnId) []u8 {
        const offset = self.limits.recv_buf + self.limits.send_buf + self.limits.upstream_write_buf;
        return self.bufRegion(id, offset, self.limits.record_scratch);
    }

    pub fn decodeBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.offsetAfterScratch(), self.limits.decode_buf);
    }

    pub fn encodeBuf(self: *ConnSlab, id: ConnId) []u8 {
        return self.bufRegion(id, self.offsetAfterScratch() + self.limits.decode_buf, self.limits.encode_buf);
    }

    pub fn bodyBuf(self: *ConnSlab, id: ConnId) []u8 {
        const offset = self.offsetAfterScratch() + self.limits.decode_buf + self.limits.encode_buf;
        return self.bufRegion(id, offset, self.limits.body_buf);
    }

    pub fn chunkBuf(self: *ConnSlab, id: ConnId) []u8 {
        const offset = self.offsetAfterScratch() + self.limits.decode_buf +
            self.limits.encode_buf + self.limits.body_buf;
        return self.bufRegion(id, offset, self.limits.chunk_buf);
    }

    fn offsetAfterScratch(self: *const ConnSlab) usize {
        return self.limits.recv_buf + self.limits.send_buf +
            self.limits.upstream_write_buf + self.limits.record_scratch;
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

fn testLimits() limits_mod.Limits {
    return .{
        .max_connections = 4,
        .max_body_size = 1024,
        .record_scratch = 256,
        .recv_buf = 64,
        .send_buf = 64,
        .upstream_write_buf = 64,
        .decode_buf = 128,
        .encode_buf = 128,
        .body_buf = 32,
        .chunk_buf = 32,
        .zstd_window_len = 64,
        .conn_arena_reserve = 64,
    };
}

test "claim and release cycle slots without allocating" {
    var slab: ConnSlab = try .init(testing.allocator, testLimits());
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
    var slab: ConnSlab = try .init(testing.allocator, testLimits());
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    var ids: [4]ConnId = undefined;
    for (&ids) |*id| id.* = slab.claim(io).?;
    try testing.expectEqual(@as(?ConnId, null), slab.claim(io));

    slab.release(io, ids[2]);
    const again = slab.claim(io).?;
    try testing.expectEqual(ids[2].index(), again.index());
    // Same slot, new generation: the old handle is dead.
    try testing.expect(ids[2] != again);

    for (ids, 0..) |id, i| if (i != 2) slab.release(io, id);
    slab.release(io, again);
}

test "buffer regions are disjoint per connection and per region" {
    var slab: ConnSlab = try .init(testing.allocator, testLimits());
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    const a = slab.claim(io).?;
    const b = slab.claim(io).?;
    defer slab.release(io, a);
    defer slab.release(io, b);

    @memset(slab.recvBuf(a), 0xAA);
    @memset(slab.sendBuf(a), 0xBB);
    @memset(slab.recordScratch(a), 0xCC);
    @memset(slab.recvBuf(b), 0xDD);

    try testing.expectEqual(@as(u8, 0xAA), slab.recvBuf(a)[0]);
    try testing.expectEqual(@as(u8, 0xBB), slab.sendBuf(a)[0]);
    try testing.expectEqual(@as(u8, 0xCC), slab.recordScratch(a)[0]);
    try testing.expectEqual(@as(u8, 0xDD), slab.recvBuf(b)[0]);
    try testing.expectEqual(@as(usize, 64), slab.recvBuf(a).len);
    try testing.expectEqual(@as(usize, 256), slab.recordScratch(a).len);
}

test "state machine transitions are tracked" {
    var slab: ConnSlab = try .init(testing.allocator, testLimits());
    defer slab.deinit(testing.allocator);
    const io = testing.io;

    const id = slab.claim(io).?;
    slab.setState(io, id, .reading_head);
    slab.setState(io, id, .piping);
    slab.setState(io, id, .responding);
    slab.setState(io, id, .reading_head); // keep-alive
    slab.setState(io, id, .closing);
    slab.release(io, id);
}
