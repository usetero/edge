const std = @import("std");

pub const Entry = struct {
    identity_hash: u64,
    last_seen_ns: i64,
    slot_idx: u16,
};

pub const TtlStore = struct {
    allocator: std.mem.Allocator,
    map: std.AutoHashMap(u64, Entry),

    pub fn init(allocator: std.mem.Allocator) TtlStore {
        return .{ .allocator = allocator, .map = std.AutoHashMap(u64, Entry).init(allocator) };
    }

    pub fn deinit(self: *TtlStore) void {
        self.map.deinit();
    }

    pub fn touch(self: *TtlStore, identity_hash: u64, now_ns: i64, slot_idx: u16) !void {
        try self.map.put(identity_hash, .{
            .identity_hash = identity_hash,
            .last_seen_ns = now_ns,
            .slot_idx = slot_idx,
        });
    }

    pub fn evictExpired(self: *TtlStore, now_ns: i64, ttl_ns: i64, out: *std.ArrayList(Entry)) !void {
        var it = self.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.last_seen_ns >= now_ns - ttl_ns) continue;
            try out.append(self.allocator, kv.value_ptr.*);
        }
        for (out.items) |entry| {
            _ = self.map.remove(entry.identity_hash);
        }
    }
};

const testing = std.testing;

test "TtlStore public API: touch and evictExpired" {
    var ttl = TtlStore.init(testing.allocator);
    defer ttl.deinit();

    try ttl.touch(1, 100, 0);
    try ttl.touch(2, 200, 1);

    var out: std.ArrayList(Entry) = .{};
    defer out.deinit(testing.allocator);

    try ttl.evictExpired(250, 60, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(@as(u64, 1), out.items[0].identity_hash);
}
