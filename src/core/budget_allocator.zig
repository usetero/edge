//! Charges retained allocations before allocating, including concurrent growth.
const std = @import("std");

pub const BudgetAllocator = struct {
    parent: std.mem.Allocator,
    limit: usize,
    used: std.atomic.Value(usize) = .init(0),

    /// The owner must remain pinned until every allocation has been freed.
    pub fn allocator(self: *BudgetAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    /// One atomic add on the hot path; an over-reservation is undone at once.
    fn reserve(self: *BudgetAllocator, bytes: usize) bool {
        if (bytes > self.limit) return false;
        const previous = self.used.fetchAdd(bytes, .monotonic);
        if (previous > self.limit - bytes) {
            self.release(bytes);
            return false;
        }
        return true;
    }

    fn release(self: *BudgetAllocator, bytes: usize) void {
        const previous = self.used.fetchSub(bytes, .monotonic);
        std.debug.assert(previous >= bytes);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        if (!self.reserve(len)) return null;
        return self.parent.rawAlloc(len, alignment, ret_addr) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        const growth = new_len -| memory.len;
        if (!self.reserve(growth)) return false;
        if (!self.parent.rawResize(memory, alignment, new_len, ret_addr)) {
            self.release(growth);
            return false;
        }
        self.release(memory.len -| new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        const growth = new_len -| memory.len;
        if (!self.reserve(growth)) return null;
        const result = self.parent.rawRemap(memory, alignment, new_len, ret_addr) orelse {
            self.release(growth);
            return null;
        };
        self.release(memory.len -| new_len);
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *BudgetAllocator = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
        self.release(memory.len);
    }
};

test "budget exhaustion, growth, shrink and release conserve credits" {
    var storage: [256]u8 = undefined;
    var parent: std.heap.FixedBufferAllocator = .init(&storage);
    var budget: BudgetAllocator = .{ .parent = parent.allocator(), .limit = 100 };
    const allocator = budget.allocator();
    const first = try allocator.alloc(u8, 60);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 41));
    try std.testing.expect(!allocator.resize(first, 101));
    const second = try allocator.alloc(u8, 40);
    allocator.free(second);
    const grown = try allocator.realloc(first, 80);
    try std.testing.expectEqual(@as(usize, 80), budget.used.load(.monotonic));
    const shrunk = try allocator.realloc(grown, 20);
    allocator.free(shrunk);
    try std.testing.expectEqual(@as(usize, 0), budget.used.load(.monotonic));
}
