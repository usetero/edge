const std = @import("std");
const checkpoint_types = @import("types.zig");

pub const UpdateQueue = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    buf: []checkpoint_types.Update,
    head: usize = 0,
    len: usize = 0,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !UpdateQueue {
        return .{
            .allocator = allocator,
            .capacity = capacity,
            .buf = try allocator.alloc(checkpoint_types.Update, capacity),
        };
    }

    pub fn deinit(self: *UpdateQueue) void {
        self.allocator.free(self.buf);
    }

    pub fn push(self: *UpdateQueue, update: checkpoint_types.Update) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len >= self.capacity) return false;

        const tail = (self.head + self.len) % self.capacity;
        self.buf[tail] = update;
        self.len += 1;
        return true;
    }

    pub fn pop(self: *UpdateQueue) ?checkpoint_types.Update {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.len == 0) return null;

        const update = self.buf[self.head];
        self.head = (self.head + 1) % self.capacity;
        self.len -= 1;
        return update;
    }

    pub fn isEmpty(self: *UpdateQueue) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.len == 0;
    }
};

const testing = std.testing;
const tail_types = @import("../types.zig");

test "checkpoint/queue: push/pop is bounded" {
    var q = try UpdateQueue.init(testing.allocator, 1);
    defer q.deinit();

    const id = tail_types.FileIdentity{ .dev = 1, .inode = 1, .fingerprint = 1 };
    try testing.expect(q.push(.{ .identity = id, .byte_offset = 1, .last_seen_size = 1, .last_seen_ns = 1 }));
    try testing.expect(!q.push(.{ .identity = id, .byte_offset = 2, .last_seen_size = 2, .last_seen_ns = 2 }));

    const first = q.pop().?;
    try testing.expectEqual(@as(u64, 1), first.byte_offset);
    try testing.expectEqual(@as(?checkpoint_types.Update, null), q.pop());
}
