//! Bounded Allocator
//!
//! A memory allocator with a fixed budget that pre-allocates its entire
//! memory region at initialization. Implements the `std.mem.Allocator`
//! interface for compatibility with any code expecting an allocator.
//!
//! Use cases:
//! - Prometheus scrape processing (bounded per-module memory)
//! - Request processing with memory limits
//! - Any subsystem requiring predictable memory bounds
//!

const std = @import("std");

/// A bounded memory allocator with stats tracking.
/// Pre-allocates a fixed memory region and tracks allocation statistics
/// using atomic counters for thread safety.
pub const BoundedAllocator = struct {
    /// Pre-allocated memory block
    backing_memory: []u8,

    /// Underlying fixed buffer allocator
    fba: std.heap.FixedBufferAllocator,

    /// Number of active allocations (for leak detection)
    active_allocations: std.atomic.Value(usize),

    /// Current bytes allocated
    bytes_allocated: std.atomic.Value(usize),

    /// The memory budget (for reporting)
    budget: usize,

    /// Initialize a bounded allocator with the given budget.
    /// Pre-allocates the entire budget from the page allocator.
    pub fn init(budget: usize) !BoundedAllocator {
        const backing = try std.heap.page_allocator.alloc(u8, budget);

        return .{
            .backing_memory = backing,
            .fba = std.heap.FixedBufferAllocator.init(backing),
            .active_allocations = std.atomic.Value(usize).init(0),
            .bytes_allocated = std.atomic.Value(usize).init(0),
            .budget = budget,
        };
    }

    /// Free the pre-allocated memory region.
    pub fn deinit(self: *BoundedAllocator) void {
        std.heap.page_allocator.free(self.backing_memory);
    }

    /// Reset the allocator, freeing all allocations.
    /// This resets the fixed buffer allocator and clears stats.
    pub fn reset(self: *BoundedAllocator) void {
        self.fba.reset();
        self.active_allocations.store(0, .monotonic);
        self.bytes_allocated.store(0, .monotonic);
    }

    /// Returns a std.mem.Allocator interface.
    /// This allocator can be passed to any code expecting an Allocator.
    /// Returns error.OutOfMemory when budget is exhausted.
    pub fn allocator(self: *BoundedAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        const result = self.fba.allocator().rawAlloc(len, ptr_align, ret_addr);
        if (result != null) {
            _ = self.active_allocations.fetchAdd(1, .monotonic);
            _ = self.bytes_allocated.fetchAdd(len, .monotonic);
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        const old_len = buf.len;
        const success = self.fba.allocator().rawResize(buf, buf_align, new_len, ret_addr);
        if (success) {
            if (new_len > old_len) {
                _ = self.bytes_allocated.fetchAdd(new_len - old_len, .monotonic);
            } else {
                _ = self.bytes_allocated.fetchSub(old_len - new_len, .monotonic);
            }
        }
        return success;
    }

    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        const old_len = buf.len;
        const result = self.fba.allocator().rawRemap(buf, buf_align, new_len, ret_addr);
        if (result != null) {
            if (new_len > old_len) {
                _ = self.bytes_allocated.fetchAdd(new_len - old_len, .monotonic);
            } else {
                _ = self.bytes_allocated.fetchSub(old_len - new_len, .monotonic);
            }
        }
        return result;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        self.fba.allocator().rawFree(buf, buf_align, ret_addr);
        _ = self.active_allocations.fetchSub(1, .monotonic);
        _ = self.bytes_allocated.fetchSub(buf.len, .monotonic);
    }

    /// Stats for observability
    pub const Stats = struct {
        /// Total memory budget
        budget: usize,
        /// Currently allocated bytes
        bytes_allocated: usize,
        /// Available bytes
        bytes_available: usize,
        /// Number of active allocations
        active_allocations: usize,
    };

    /// Get current allocation statistics
    pub fn getStats(self: *const BoundedAllocator) Stats {
        const allocated = self.bytes_allocated.load(.monotonic);
        return .{
            .budget = self.budget,
            .bytes_allocated = allocated,
            .bytes_available = self.budget -| allocated,
            .active_allocations = self.active_allocations.load(.monotonic),
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "BoundedAllocator - basic allocation" {
    var bounded = try BoundedAllocator.init(4096);
    defer bounded.deinit();

    const alloc = bounded.allocator();

    // Allocate some memory
    const buf = try alloc.alloc(u8, 100);
    defer alloc.free(buf);

    try std.testing.expectEqual(@as(usize, 100), buf.len);

    const stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 4096), stats.budget);
    try std.testing.expectEqual(@as(usize, 1), stats.active_allocations);
    try std.testing.expect(stats.bytes_allocated >= 100);
}

test "BoundedAllocator - multiple allocations" {
    var bounded = try BoundedAllocator.init(4096);
    defer bounded.deinit();

    const alloc = bounded.allocator();

    const buf1 = try alloc.alloc(u8, 100);
    const buf2 = try alloc.alloc(u8, 200);
    const buf3 = try alloc.alloc(u8, 300);

    var stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 3), stats.active_allocations);

    alloc.free(buf2);
    stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.active_allocations);

    alloc.free(buf1);
    alloc.free(buf3);
    stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.active_allocations);
}

test "BoundedAllocator - out of memory" {
    var bounded = try BoundedAllocator.init(100);
    defer bounded.deinit();

    const alloc = bounded.allocator();

    // This should fail - requesting more than budget
    const result = alloc.alloc(u8, 200);
    try std.testing.expectError(error.OutOfMemory, result);
}

test "BoundedAllocator - reset" {
    var bounded = try BoundedAllocator.init(4096);
    defer bounded.deinit();

    const alloc = bounded.allocator();

    // Allocate some memory
    _ = try alloc.alloc(u8, 100);
    _ = try alloc.alloc(u8, 200);

    var stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 2), stats.active_allocations);

    // Reset
    bounded.reset();

    stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.active_allocations);
    try std.testing.expectEqual(@as(usize, 0), stats.bytes_allocated);

    // Should be able to allocate again
    const buf = try alloc.alloc(u8, 500);
    try std.testing.expectEqual(@as(usize, 500), buf.len);
}

test "BoundedAllocator - stats tracking" {
    var bounded = try BoundedAllocator.init(4096);
    defer bounded.deinit();

    const alloc = bounded.allocator();

    var stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 4096), stats.budget);
    try std.testing.expectEqual(@as(usize, 4096), stats.bytes_available);
    try std.testing.expectEqual(@as(usize, 0), stats.bytes_allocated);

    const buf = try alloc.alloc(u8, 1000);

    stats = bounded.getStats();
    try std.testing.expect(stats.bytes_allocated >= 1000);
    try std.testing.expect(stats.bytes_available <= 4096 - 1000);

    alloc.free(buf);

    stats = bounded.getStats();
    try std.testing.expectEqual(@as(usize, 0), stats.active_allocations);
}
