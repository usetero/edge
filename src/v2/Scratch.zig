//! Fixed scratch with sticky allocation failure, including errors codecs suppress.
const Self = @This();
const std = @import("std");

buffer: std.heap.FixedBufferAllocator,
denied: bool = false,
peak: usize = 0,

pub fn init(bytes: []u8) Self {
    return .{ .buffer = .init(bytes) };
}

/// Reset only after all results from the previous record have been consumed.
pub fn reset(self: *Self) void {
    self.buffer.reset();
    self.denied = false;
}

pub fn allocator(self: *Self) std.mem.Allocator {
    return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
}

fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
    const self: *Self = @ptrCast(@alignCast(ctx));
    const result = self.buffer.allocator().rawAlloc(len, alignment, address) orelse {
        self.denied = true;
        return null;
    };
    self.peak = @max(self.peak, self.buffer.end_index);
    return result;
}

fn resize(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, address: usize) bool {
    const self: *Self = @ptrCast(@alignCast(ctx));
    const result = self.buffer.allocator().rawResize(bytes, alignment, len, address);
    self.peak = @max(self.peak, self.buffer.end_index);
    return result;
}

fn remap(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, address: usize) ?[*]u8 {
    const self: *Self = @ptrCast(@alignCast(ctx));
    const result = self.buffer.allocator().rawRemap(bytes, alignment, len, address);
    self.peak = @max(self.peak, self.buffer.end_index);
    return result;
}

fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
    const self: *Self = @ptrCast(@alignCast(ctx));
    self.buffer.allocator().rawFree(bytes, alignment, address);
}

test "v2 scratch remembers suppressed OOM until the owner resets it" {
    var bytes: [64]u8 = undefined;
    var scratch: Self = .init(&bytes);
    const allocator_value = scratch.allocator();
    _ = allocator_value.alloc(u8, 65) catch null;
    _ = try allocator_value.alloc(u8, 8);
    try std.testing.expect(scratch.denied);
    try std.testing.expectEqual(8, scratch.peak);
    scratch.reset();
    try std.testing.expect(!scratch.denied);
    _ = try allocator_value.alloc(u8, 64);
    try std.testing.expectEqual(64, scratch.peak);
}
