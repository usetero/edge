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
            if (!checkpoint_types.isExpired(value, self.ttl_ns, now)) return value.offset;
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
