const std = @import("std");
const t = @import("types.zig");
const map_mod = @import("map.zig");
const wal_mod = @import("wal.zig");
const ttl_mod = @import("ttl.zig");

pub const Update = struct {
    identity: t.FileIdentity,
    byte_offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
};

pub const Options = struct {
    state_dir: []const u8,
    max_slots: usize = 256,
    checkpoint_interval_ms: u64 = 5000,
    checkpoint_ttl_ms: u64 = 72 * 60 * 60 * 1000,
    queue_capacity: usize = 2048,
};

pub const CheckpointStore = struct {
    allocator: std.mem.Allocator,
    opts: Options,
    map_store: map_mod.MapStore,
    wal_store: wal_mod.WalStore,
    ttl_store: ttl_mod.TtlStore,

    slot_by_hash: std.AutoHashMap(u64, u16),
    offset_by_hash: std.AutoHashMap(u64, u64),
    slot_used: []bool,

    queue: std.ArrayList(Update),
    queue_mutex: std.Thread.Mutex = .{},
    data_mutex: std.Thread.Mutex = .{},
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    worker: ?std.Thread = null,

    pub fn init(allocator: std.mem.Allocator, opts: Options) !CheckpointStore {
        var store = CheckpointStore{
            .allocator = allocator,
            .opts = opts,
            .map_store = try map_mod.MapStore.init(allocator, opts.state_dir, opts.max_slots),
            .wal_store = try wal_mod.WalStore.init(allocator, opts.state_dir),
            .ttl_store = ttl_mod.TtlStore.init(allocator),
            .slot_by_hash = std.AutoHashMap(u64, u16).init(allocator),
            .offset_by_hash = std.AutoHashMap(u64, u64).init(allocator),
            .slot_used = try allocator.alloc(bool, opts.max_slots),
            .queue = .{},
        };
        errdefer store.deinit();

        @memset(store.slot_used, false);
        try store.recover();
        return store;
    }

    pub fn start(self: *CheckpointStore) !void {
        if (self.worker != null) return;
        self.worker = try std.Thread.spawn(.{}, workerMain, .{self});
    }

    pub fn deinit(self: *CheckpointStore) void {
        if (self.worker) |thread| {
            self.stop.store(true, .release);
            thread.join();
            self.worker = null;
        }

        self.queue.deinit(self.allocator);
        self.offset_by_hash.deinit();
        self.slot_by_hash.deinit();
        self.ttl_store.deinit();
        self.wal_store.deinit();
        self.map_store.deinit();
        self.allocator.free(self.slot_used);
    }

    /// Returns false when queue is full; caller should continue without blocking.
    pub fn enqueue(self: *CheckpointStore, update: Update) !bool {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();

        if (self.queue.items.len >= self.opts.queue_capacity) return false;
        try self.queue.append(self.allocator, update);
        return true;
    }

    pub fn getOffset(self: *CheckpointStore, identity: t.FileIdentity) ?u64 {
        const key = t.identityHash(identity);
        self.data_mutex.lock();
        defer self.data_mutex.unlock();
        return self.offset_by_hash.get(key);
    }

    pub fn compactNow(self: *CheckpointStore) !void {
        self.data_mutex.lock();
        defer self.data_mutex.unlock();

        var evicted: std.ArrayList(ttl_mod.Entry) = .{};
        defer evicted.deinit(self.allocator);

        const now: i64 = @intCast(std.time.nanoTimestamp());
        const ttl_ns: i64 = @intCast(self.opts.checkpoint_ttl_ms * std.time.ns_per_ms);
        try self.ttl_store.evictExpired(now, ttl_ns, &evicted);

        for (evicted.items) |entry| {
            _ = self.slot_by_hash.remove(entry.identity_hash);
            _ = self.offset_by_hash.remove(entry.identity_hash);
            self.slot_used[entry.slot_idx] = false;
            try self.map_store.clearSlot(entry.slot_idx);
        }

        try self.map_store.sync();
        try self.wal_store.truncate();
    }

    fn workerMain(self: *CheckpointStore) void {
        const interval_ns = self.opts.checkpoint_interval_ms * std.time.ns_per_ms;
        var next_compact_ns = std.time.nanoTimestamp() + @as(i128, @intCast(interval_ns));

        while (true) {
            if (self.stop.load(.acquire)) {
                if (!self.flushOneFromQueue()) break;
                continue;
            }

            if (!self.flushOneFromQueue()) {
                std.Thread.sleep(@min(interval_ns, 10 * std.time.ns_per_ms));
            }

            if (std.time.nanoTimestamp() >= next_compact_ns) {
                self.compactNow() catch {};
                next_compact_ns = std.time.nanoTimestamp() + @as(i128, @intCast(interval_ns));
            }
        }

        // Drain remaining queue on shutdown.
        while (self.flushOneFromQueue()) {}
    }

    fn flushOneFromQueue(self: *CheckpointStore) bool {
        self.queue_mutex.lock();
        if (self.queue.items.len == 0) {
            self.queue_mutex.unlock();
            return false;
        }
        const update = self.queue.orderedRemove(0);
        self.queue_mutex.unlock();

        self.persistUpdate(update) catch {};
        return true;
    }

    fn persistUpdate(self: *CheckpointStore, update: Update) !void {
        const key = t.identityHash(update.identity);

        self.data_mutex.lock();
        defer self.data_mutex.unlock();

        const slot_idx: u16 = if (self.slot_by_hash.get(key)) |idx|
            idx
        else blk: {
            const free_idx = self.findFreeSlot() orelse return error.NoCheckpointSlots;
            self.slot_used[free_idx] = true;
            const idx: u16 = @intCast(free_idx);
            try self.slot_by_hash.put(key, idx);
            break :blk idx;
        };

        var wal_entry = std.mem.zeroInit(t.WalEntry, .{});
        wal_entry.timestamp_ns = update.last_seen_ns;
        wal_entry.identity_hash = key;
        wal_entry.identity = update.identity;
        wal_entry.slot_idx = slot_idx;
        wal_entry.byte_offset = update.byte_offset;
        wal_entry.last_seen_size = update.last_seen_size;
        wal_entry = try self.wal_store.append(wal_entry);

        const old_slot = try self.map_store.readSlot(slot_idx);
        var next_seq: u64 = 2;
        if (old_slot.sequence > 0 and old_slot.sequence % 2 == 0) {
            next_seq = old_slot.sequence + 2;
        }

        var slot = std.mem.zeroInit(t.Slot, .{});
        slot.sequence = next_seq;
        slot.identity = update.identity;
        slot.byte_offset = update.byte_offset;
        slot.last_seen_size = update.last_seen_size;
        slot.last_seen_ns = update.last_seen_ns;
        slot.lsn = wal_entry.lsn;
        slot.checksum = t.slotChecksum(slot);

        try self.map_store.writeSlot(slot_idx, slot);
        try self.map_store.sync();

        try self.offset_by_hash.put(key, update.byte_offset);
        try self.ttl_store.touch(key, update.last_seen_ns, slot_idx);
    }

    fn findFreeSlot(self: *CheckpointStore) ?usize {
        var i: usize = 0;
        while (i < self.slot_used.len) : (i += 1) {
            if (!self.slot_used[i]) return i;
        }
        return null;
    }

    fn recover(self: *CheckpointStore) !void {
        // 1) Load valid map slots.
        var i: usize = 0;
        while (i < self.opts.max_slots) : (i += 1) {
            const slot = try self.map_store.readSlot(i);
            if (!isSlotValid(slot)) continue;

            const key = t.identityHash(slot.identity);
            self.slot_used[i] = true;
            try self.slot_by_hash.put(key, @intCast(i));
            try self.offset_by_hash.put(key, slot.byte_offset);
            try self.ttl_store.touch(key, @intCast(slot.last_seen_ns), @intCast(i));
        }

        // 2) Replay WAL on top of map state.
        const Ctx = struct {
            store: *CheckpointStore,
            fn apply(ctx: *@This(), e: t.WalEntry) !void {
                const idx: usize = e.slot_idx;
                if (idx >= ctx.store.opts.max_slots) return;

                var slot = try ctx.store.map_store.readSlot(idx);
                const existing_valid = isSlotValid(slot);
                if (existing_valid and slot.lsn >= e.lsn) {
                    // Map already has same or newer state.
                    return;
                }

                const next_seq: u64 = if (existing_valid and slot.sequence % 2 == 0) slot.sequence + 2 else 2;
                slot.sequence = next_seq;
                slot.identity = e.identity;
                slot.byte_offset = e.byte_offset;
                slot.last_seen_size = e.last_seen_size;
                slot.last_seen_ns = e.timestamp_ns;
                slot.lsn = e.lsn;
                slot.checksum = t.slotChecksum(slot);
                try ctx.store.map_store.writeSlot(idx, slot);

                ctx.store.slot_used[idx] = true;
                try ctx.store.slot_by_hash.put(e.identity_hash, @intCast(idx));
                try ctx.store.offset_by_hash.put(e.identity_hash, e.byte_offset);
                try ctx.store.ttl_store.touch(e.identity_hash, @intCast(e.timestamp_ns), @intCast(idx));
            }
        };

        var ctx = Ctx{ .store = self };
        try self.wal_store.forEach(&ctx, Ctx.apply);
    }
};

fn isSlotValid(slot: t.Slot) bool {
    if (slot.sequence == 0) return false;
    if (slot.sequence % 2 != 0) return false;
    return slot.checksum == t.slotChecksum(slot);
}

const testing = std.testing;

test "CheckpointStore public API: enqueue/getOffset persists through worker" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var store = try CheckpointStore.init(testing.allocator, .{
        .state_dir = state_dir,
        .max_slots = 16,
        .checkpoint_interval_ms = 10,
        .checkpoint_ttl_ms = 10_000,
        .queue_capacity = 64,
    });
    defer store.deinit();
    try store.start();

    const id = t.FileIdentity{ .dev = 1, .inode = 2, .fingerprint = 3 };
    const ok = try store.enqueue(.{
        .identity = id,
        .byte_offset = 123,
        .last_seen_size = 123,
        .last_seen_ns = @intCast(std.time.nanoTimestamp()),
    });
    try testing.expect(ok);

    var tries: usize = 0;
    while (tries < 50 and store.getOffset(id) == null) : (tries += 1) {
        std.Thread.sleep(5 * std.time.ns_per_ms);
    }

    try testing.expectEqual(@as(?u64, 123), store.getOffset(id));
}

test "CheckpointStore public API: queue full returns false" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var store = try CheckpointStore.init(testing.allocator, .{
        .state_dir = state_dir,
        .max_slots = 4,
        .checkpoint_interval_ms = 1000,
        .checkpoint_ttl_ms = 10_000,
        .queue_capacity = 1,
    });
    defer store.deinit();
    try store.start();

    const id = t.FileIdentity{ .dev = 4, .inode = 5, .fingerprint = 6 };
    const a = try store.enqueue(.{ .identity = id, .byte_offset = 1, .last_seen_size = 1, .last_seen_ns = 1 });
    const b = try store.enqueue(.{ .identity = id, .byte_offset = 2, .last_seen_size = 2, .last_seen_ns = 2 });

    try testing.expect(a);
    try testing.expect(!b);
}

test "CheckpointStore crash-safety: odd sequence slot is recovered from WAL" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = t.FileIdentity{ .dev = 11, .inode = 22, .fingerprint = 33 };

    {
        var store = try CheckpointStore.init(testing.allocator, .{
            .state_dir = state_dir,
            .max_slots = 16,
            .checkpoint_interval_ms = 10_000,
            .checkpoint_ttl_ms = 60_000,
            .queue_capacity = 64,
        });
        defer store.deinit();
        try store.start();

        _ = try store.enqueue(.{
            .identity = id,
            .byte_offset = 500,
            .last_seen_size = 500,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });

        var tries: usize = 0;
        while (tries < 100 and store.getOffset(id) == null) : (tries += 1) {
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }

    // Corrupt slot by setting odd sequence and bad checksum.
    var map_store = try map_mod.MapStore.init(testing.allocator, state_dir, 16);
    defer map_store.deinit();
    var slot = try map_store.readSlot(0);
    slot.sequence = 3;
    slot.checksum = 0;
    try map_store.writeSlot(0, slot);
    try map_store.sync();

    var recovered = try CheckpointStore.init(testing.allocator, .{
        .state_dir = state_dir,
        .max_slots = 16,
        .checkpoint_interval_ms = 10_000,
        .checkpoint_ttl_ms = 60_000,
        .queue_capacity = 64,
    });
    defer recovered.deinit();

    try testing.expectEqual(@as(?u64, 500), recovered.getOffset(id));
}

test "CheckpointStore crash-safety: map slot loss recovers from WAL identity payload" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = t.FileIdentity{ .dev = 101, .inode = 202, .fingerprint = 303 };

    {
        var store = try CheckpointStore.init(testing.allocator, .{
            .state_dir = state_dir,
            .max_slots = 8,
            .checkpoint_interval_ms = 10_000,
            .checkpoint_ttl_ms = 60_000,
            .queue_capacity = 64,
        });
        defer store.deinit();
        try store.start();
        _ = try store.enqueue(.{
            .identity = id,
            .byte_offset = 777,
            .last_seen_size = 777,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        var tries: usize = 0;
        while (tries < 100 and store.getOffset(id) == null) : (tries += 1) {
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }

    // Simulate map loss while WAL still contains records.
    var map_store = try map_mod.MapStore.init(testing.allocator, state_dir, 8);
    defer map_store.deinit();
    try map_store.clearSlot(0);
    try map_store.sync();

    var recovered = try CheckpointStore.init(testing.allocator, .{
        .state_dir = state_dir,
        .max_slots = 8,
        .checkpoint_interval_ms = 10_000,
        .checkpoint_ttl_ms = 60_000,
        .queue_capacity = 64,
    });
    defer recovered.deinit();

    try testing.expectEqual(@as(?u64, 777), recovered.getOffset(id));
}

test "CheckpointStore crash-safety: recovery keeps highest LSN offset" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = t.FileIdentity{ .dev = 42, .inode = 43, .fingerprint = 44 };

    {
        var store = try CheckpointStore.init(testing.allocator, .{
            .state_dir = state_dir,
            .max_slots = 8,
            .checkpoint_interval_ms = 10_000,
            .checkpoint_ttl_ms = 60_000,
            .queue_capacity = 64,
        });
        defer store.deinit();
        try store.start();

        _ = try store.enqueue(.{
            .identity = id,
            .byte_offset = 10,
            .last_seen_size = 10,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        _ = try store.enqueue(.{
            .identity = id,
            .byte_offset = 20,
            .last_seen_size = 20,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });

        var tries: usize = 0;
        while (tries < 100 and store.getOffset(id) != 20) : (tries += 1) {
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }

    var recovered = try CheckpointStore.init(testing.allocator, .{
        .state_dir = state_dir,
        .max_slots = 8,
        .checkpoint_interval_ms = 10_000,
        .checkpoint_ttl_ms = 60_000,
        .queue_capacity = 64,
    });
    defer recovered.deinit();

    try testing.expectEqual(@as(?u64, 20), recovered.getOffset(id));
}
