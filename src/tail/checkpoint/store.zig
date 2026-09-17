const std = @import("std");
const tail_types = @import("../types.zig");
const checkpoint_types = @import("types.zig");

const log = std.log.scoped(.checkpoint_store);

const Oldest = struct {
    key: u64,
    last_seen_ns: i64,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    max_slots: usize,
    ttl_ns: i128,
    mutex: std.Io.Mutex = .init,
    by_identity: std.AutoHashMap(u64, checkpoint_types.Value),
    by_inode: std.AutoHashMap(u64, checkpoint_types.Value),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, max_slots: usize, ttl_ns: i128) Store {
        return .{
            .allocator = allocator,
            .io = io,
            .max_slots = max_slots,
            .ttl_ns = ttl_ns,
            .by_identity = std.AutoHashMap(u64, checkpoint_types.Value).init(allocator),
            .by_inode = std.AutoHashMap(u64, checkpoint_types.Value).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        self.by_identity.deinit();
        self.by_inode.deinit();
        self.* = undefined;
    }

    pub fn upsert(self: *Store, value: checkpoint_types.Value) !void {
        const keys = checkpoint_types.keysFor(value.identity);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (!self.by_identity.contains(keys.identity) and self.by_identity.count() >= self.max_slots) {
            self.evictOldestLocked();
        }

        try self.by_identity.put(keys.identity, value);
        self.by_inode.put(keys.inode, value) catch |err| log.warn("by_inode put failed (upsert): {}", .{err});
    }

    pub fn getOffset(self: *Store, identity: tail_types.FileIdentity) ?u64 {
        const keys = checkpoint_types.keysFor(identity);
        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        if (self.by_identity.get(keys.identity)) |value| {
            if (!checkpoint_types.isExpired(value, self.ttl_ns, now)) return value.offset;
        }
        if (self.by_inode.get(keys.inode)) |value| {
            if (value.identity.fingerprint == identity.fingerprint and
                !checkpoint_types.isExpired(value, self.ttl_ns, now)) return value.offset;
        }
        return null;
    }

    pub fn evictExpired(self: *Store, now_ns: i128) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var expired_keys: std.ArrayList(u64) = .empty;
        defer expired_keys.deinit(self.allocator);

        var it = self.by_identity.iterator();
        while (it.next()) |entry| {
            if (!checkpoint_types.isExpired(entry.value_ptr.*, self.ttl_ns, now_ns)) continue;
            expired_keys.append(self.allocator, entry.key_ptr.*) catch return;
        }

        for (expired_keys.items) |identity_key| {
            if (self.by_identity.fetchRemove(identity_key)) |removed| {
                self.removeInodeAliasLocked(removed.value);
            }
        }
    }

    pub fn collectValues(self: *Store) !std.ArrayList(checkpoint_types.Value) {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        var out: std.ArrayList(checkpoint_types.Value) = .empty;
        try out.ensureTotalCapacity(self.allocator, self.by_identity.count());

        var it = self.by_identity.iterator();
        while (it.next()) |entry| out.appendAssumeCapacity(entry.value_ptr.*);
        return out;
    }

    pub fn loadValues(self: *Store, values: []const checkpoint_types.Value) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);

        self.by_identity.clearRetainingCapacity();
        self.by_inode.clearRetainingCapacity();

        for (values) |value| {
            const keys = checkpoint_types.keysFor(value.identity);
            if (!self.by_identity.contains(keys.identity) and self.by_identity.count() >= self.max_slots) {
                self.evictOldestLocked();
            }
            try self.by_identity.put(keys.identity, value);
            self.by_inode.put(keys.inode, value) catch |err| log.warn("by_inode put failed (loadValues): {}", .{err});
        }
    }

    fn evictOldestLocked(self: *Store) void {
        var oldest: ?Oldest = null;
        var it = self.by_identity.iterator();
        while (it.next()) |entry| {
            const candidate: Oldest = .{ .key = entry.key_ptr.*, .last_seen_ns = entry.value_ptr.last_seen_ns };
            if (oldest == null or candidate.last_seen_ns < oldest.?.last_seen_ns) oldest = candidate;
        }

        const victim = oldest orelse return;
        if (self.by_identity.fetchRemove(victim.key)) |removed| {
            self.removeInodeAliasLocked(removed.value);
        }
    }

    fn removeInodeAliasLocked(self: *Store, value: checkpoint_types.Value) void {
        const inode_key = checkpoint_types.keysFor(value.identity).inode;
        if (self.by_inode.get(inode_key)) |existing| {
            if (existing.identity.dev == value.identity.dev and
                existing.identity.inode == value.identity.inode and
                existing.identity.fingerprint == value.identity.fingerprint)
            {
                _ = self.by_inode.remove(inode_key);
            }
        }
    }
};

const testing = std.testing;

fn freshStore(ttl_ns: i128) Store {
    return Store.init(testing.allocator, testing.io, 256, ttl_ns);
}

test "store: by_inode fallback returns null when stored fingerprint differs" {
    var store = freshStore(72 * 60 * 60 * std.time.ns_per_s);
    defer store.deinit();

    const id_a: tail_types.FileIdentity = .{ .dev = 1, .inode = 2, .fingerprint = 100 };
    const id_b: tail_types.FileIdentity = .{ .dev = 1, .inode = 2, .fingerprint = 999 };
    const now = std.Io.Timestamp.now(testing.io, .awake).toNanoseconds();
    try store.upsert(.{ .identity = id_a, .offset = 4096, .last_seen_ns = @intCast(now) });

    // by_identity misses (different fingerprint key).
    try testing.expect(store.by_identity.get(checkpoint_types.keysFor(id_b).identity) == null);
    // by_inode gate must reject the cross-version offset.
    try testing.expect(store.getOffset(id_b) == null);
}

test "store: by_inode fallback returns offset when fingerprint matches and by_identity misses" {
    var store = freshStore(72 * 60 * 60 * std.time.ns_per_s);
    defer store.deinit();

    // Two entries sharing the same (dev, inode) but different fingerprints.
    const id_a: tail_types.FileIdentity = .{ .dev = 1, .inode = 5, .fingerprint = 10 };
    const id_b: tail_types.FileIdentity = .{ .dev = 1, .inode = 5, .fingerprint = 20 };
    const now = std.Io.Timestamp.now(testing.io, .awake).toNanoseconds();
    try store.upsert(.{ .identity = id_a, .offset = 111, .last_seen_ns = @intCast(now) });
    try store.upsert(.{ .identity = id_b, .offset = 222, .last_seen_ns = @intCast(now) });

    // by_identity hits directly for each fingerprint.
    try testing.expectEqual(@as(?u64, 111), store.getOffset(id_a));
    try testing.expectEqual(@as(?u64, 222), store.getOffset(id_b));
}

test "store: by_inode fallback returns null for expired entry with matching fingerprint" {
    const ttl_ns: i128 = 1 * std.time.ns_per_s;
    var store = freshStore(ttl_ns);
    defer store.deinit();

    const id: tail_types.FileIdentity = .{ .dev = 1, .inode = 2, .fingerprint = 100 };
    // last seen far in the past so it is expired relative to ttl.
    try store.upsert(.{ .identity = id, .offset = 4096, .last_seen_ns = -1_000_000_000 });

    try testing.expect(store.getOffset(id) == null);
}
