//! Pool of per-connection arenas for cold-path allocations (header copies,
//! upstream URL strings, error bodies). Arenas are claimed alongside a slab
//! slot and reset with retained capacity on release, so after warm-up the
//! pool performs no heap traffic. Hot-path data NEVER comes from here — it
//! lives in the conn slab's fixed buffers.
const std = @import("std");
const limits_mod = @import("limits.zig");

const log = std.log.scoped(.arena_pool);

pub const ArenaPool = struct {
    arenas: []std.heap.ArenaAllocator,
    free_list: []u16,
    free_count: usize,
    mutex: std.Io.Mutex,
    reserve: usize,

    pub fn init(gpa: std.mem.Allocator, limits: limits_mod.Limits) !ArenaPool {
        const n = limits.max_connections;
        std.debug.assert(n > 0);
        std.debug.assert(n < std.math.maxInt(u16));

        const arenas = try gpa.alloc(std.heap.ArenaAllocator, n);
        errdefer gpa.free(arenas);
        for (arenas) |*arena| arena.* = .init(gpa);

        const free_list = try gpa.alloc(u16, n);
        errdefer gpa.free(free_list);
        for (free_list, 0..) |*slot, i| slot.* = @intCast(n - 1 - i);

        return .{
            .arenas = arenas,
            .free_list = free_list,
            .free_count = n,
            .mutex = .init,
            .reserve = limits.conn_arena_reserve,
        };
    }

    pub fn deinit(self: *ArenaPool, gpa: std.mem.Allocator) void {
        for (self.arenas) |*arena| arena.deinit();
        gpa.free(self.arenas);
        gpa.free(self.free_list);
        self.* = undefined;
    }

    /// Pairs with a successful ConnSlab.claim; the slab is the capacity
    /// gate, so exhaustion here means the two pools fell out of lockstep.
    pub fn claim(self: *ArenaPool, io: std.Io) u16 {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.free_count > 0);
        self.free_count -= 1;
        return self.free_list[self.free_count];
    }

    pub fn allocator(self: *ArenaPool, slot: u16) std.mem.Allocator {
        std.debug.assert(slot < self.arenas.len);
        return self.arenas[slot].allocator();
    }

    /// Resets a held slot between keep-alive requests without returning it
    /// to the pool. Same retain-capacity semantics as release.
    pub fn reset(self: *ArenaPool, slot: u16) void {
        std.debug.assert(slot < self.arenas.len);
        if (!self.arenas[slot].reset(.retain_capacity)) {
            log.warn("arena reset failed for slot {d}", .{slot});
        }
    }

    /// Reset-don't-free: retained capacity makes steady-state claims
    /// allocation-free. A connection that out-grows the reserve is a cold-path
    /// budget leak — warn so it shows up in logs before it shows up in RSS.
    pub fn release(self: *ArenaPool, io: std.Io, slot: u16) void {
        std.debug.assert(slot < self.arenas.len);
        const capacity = self.arenas[slot].queryCapacity();
        if (capacity > self.reserve) {
            log.warn("conn arena grew to {d} bytes (reserve {d}); check cold paths", .{
                capacity, self.reserve,
            });
        }
        if (!self.arenas[slot].reset(.retain_capacity)) {
            // Failed resets leave the arena valid but unpooled-capacity; safe
            // to continue, worth counting if it ever happens.
            log.warn("arena reset failed for slot {d}", .{slot});
        }

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.free_count < self.free_list.len);
        self.free_list[self.free_count] = slot;
        self.free_count += 1;
    }
};

const testing = std.testing;

fn testLimits() limits_mod.Limits {
    return .{
        .max_connections = 2,
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
        .large_body_buffer_count = 1,
        .large_body_buffer_size = 1024,
        .conn_arena_reserve = 4096,
    };
}

test "claim, allocate, release retains capacity and leaks nothing" {
    var pool: ArenaPool = try .init(testing.allocator, testLimits());
    defer pool.deinit(testing.allocator);
    const io = testing.io;

    const slot = pool.claim(io);
    const first = try pool.allocator(slot).dupe(u8, "hello upstream url");
    try testing.expectEqualStrings("hello upstream url", first);
    pool.release(io, slot);

    // Reclaim: capacity was retained, content is gone.
    const again = pool.claim(io);
    try testing.expectEqual(slot, again);
    const second = try pool.allocator(again).alloc(u8, 8);
    try testing.expectEqual(@as(usize, 8), second.len);
    pool.release(io, again);
}

test "slots are independent" {
    var pool: ArenaPool = try .init(testing.allocator, testLimits());
    defer pool.deinit(testing.allocator);
    const io = testing.io;

    const a = pool.claim(io);
    const b = pool.claim(io);
    try testing.expect(a != b);
    _ = try pool.allocator(a).alloc(u8, 16);
    _ = try pool.allocator(b).alloc(u8, 16);
    pool.release(io, a);
    pool.release(io, b);
}
