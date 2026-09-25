//! A bounded pool of encoders, shared by every handler thread.
//!
//! A zstd compression context holds about 3.5 MiB at level 3, so the edge
//! cannot keep one per handler thread. A released encoder keeps its library
//! state for the next body. When every slot is full, a released encoder is
//! freed, so idle memory stays at most `cap` encoders.
const std = @import("std");
const Encoder = @import("encoder.zig").Encoder;

pub const EncoderPool = struct {
    /// Atomic slots, not a mutex: acquire and release are one swap or
    /// compare-and-swap for each slot they scan, from any thread.
    slots: [cap]std.atomic.Value(?*Pooled) = @splat(.init(null)),

    pub const cap = 8;

    /// An encoder and its staging buffer. On the heap, so the writer's
    /// buffer pointer stays valid.
    pub const Pooled = struct {
        encoder: Encoder,
        staging: [4096]u8,
    };

    pub fn acquire(self: *EncoderPool, allocator: std.mem.Allocator) std.mem.Allocator.Error!*Pooled {
        for (&self.slots) |*slot| {
            if (slot.swap(null, .acquire)) |pooled| return pooled;
        }
        const pooled = try allocator.create(Pooled);
        errdefer allocator.destroy(pooled);
        pooled.encoder = try .init(allocator, &pooled.staging);
        return pooled;
    }

    /// `allocator` must be the one that `acquire` used.
    pub fn release(self: *EncoderPool, allocator: std.mem.Allocator, pooled: *Pooled) void {
        for (&self.slots) |*slot| {
            if (slot.cmpxchgStrong(null, pooled, .release, .monotonic) == null) return;
        }
        destroy(allocator, pooled);
    }

    /// Frees every idle encoder. Call it once no thread uses the pool. The
    /// pool stays valid and empty.
    pub fn freeIdle(self: *EncoderPool, allocator: std.mem.Allocator) void {
        for (&self.slots) |*slot| {
            if (slot.swap(null, .acquire)) |pooled| destroy(allocator, pooled);
        }
    }

    fn destroy(allocator: std.mem.Allocator, pooled: *Pooled) void {
        pooled.encoder.deinit(allocator);
        allocator.destroy(pooled);
    }
};

test "the pool reuses an encoder and frees the ones it cannot hold" {
    const gpa = std.testing.allocator;
    var pool: EncoderPool = .{};
    defer pool.freeIdle(gpa);
    var held: [EncoderPool.cap + 2]*EncoderPool.Pooled = undefined;
    for (&held) |*slot| slot.* = try pool.acquire(gpa);
    for (held) |pooled| pool.release(gpa, pooled);
    const again = try pool.acquire(gpa);
    var found = false;
    for (held[0..EncoderPool.cap]) |pooled| found = found or pooled == again;
    try std.testing.expect(found);
    pool.release(gpa, again);
}
