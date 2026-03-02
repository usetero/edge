const std = @import("std");

pub const BoundedAllocator = struct {
    allocator: std.mem.Allocator,
    max_bytes: usize,
    used_bytes: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_bytes: usize) BoundedAllocator {
        return .{
            .allocator = allocator,
            .max_bytes = max_bytes,
        };
    }

    pub fn canReserve(self: *const BoundedAllocator, size: usize) bool {
        return self.used_bytes + size <= self.max_bytes;
    }

    pub fn reserve(self: *BoundedAllocator, size: usize) !void {
        if (!self.canReserve(size)) return error.OutOfMemory;
        self.used_bytes += size;
    }

    pub fn release(self: *BoundedAllocator, size: usize) void {
        self.used_bytes = if (size > self.used_bytes) 0 else self.used_bytes - size;
    }
};
