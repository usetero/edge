const std = @import("std");
const types = @import("types.zig");

pub const Update = struct {
    identity: types.FileIdentity,
    byte_offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
};

/// Asynchronous checkpoint lane for file-tail offsets.
///
/// How it works:
/// 1. Hot path calls `enqueue()` with `{identity, offset, last_seen}`; this is
///    bounded and non-blocking apart from a short queue mutex section.
/// 2. A background worker drains the queue and persists each update in strict
///    order: append WAL entry -> `fdatasync()` WAL -> update mmap slot with a
///    seqlock -> `msync(MS_ASYNC)` map.
/// 3. In-memory indexes (`by_identity`, inode fallback) are updated alongside
///    persistence so `getOffset()` remains O(1).
///
/// Durability/integrity model:
/// - WAL (`checkpoint.wal`) is the durable source of truth for the latest
///   checkpointed LSN.
/// - mmap map (`checkpoint.map`) is a fast lookup cache of fixed-size slots.
/// - Each slot uses a seqlock sequence (odd during write, even when stable) to
///   prevent torn multi-field reads.
/// - Slot and WAL checksums protect against partial/corrupt records.
///
/// Startup recovery:
/// - Load valid mmap slots (best-effort).
/// - Replay valid WAL entries (authoritative) in LSN order.
/// - Rewrite the mmap slots from recovered memory state.
/// - Compact WAL to one live record per identity.
///
/// Expiry/GC:
/// - Entries older than TTL are evicted from in-memory indexes and map slots.
/// - Slot ownership is tracked with a fixed slot table up to `max_slots`.
pub const Lane = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    max_slots: usize,
    queue_buf: []Update,
    queue_head: usize = 0,
    queue_len: usize = 0,
    queue_mutex: std.Thread.Mutex = .{},
    data_mutex: std.Thread.Mutex = .{},
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    worker: ?std.Thread = null,
    interval_ns: u64,
    ttl_ns: i128,
    by_identity: std.AutoHashMap(u64, CheckpointValue),
    by_inode: std.AutoHashMap(u64, CheckpointValue),
    slot_owner: []?u64,
    wal_file: std.fs.File,
    wal_path: []u8,
    wal_tmp_path: []u8,
    wal_write_offset: u64 = 0,
    map_file: std.fs.File,
    map_path: []u8,
    map_region: []align(std.heap.page_size_min) u8,
    next_lsn: u64 = 1,
    writes_since_compact: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        state_dir: []const u8,
        capacity: usize,
        max_slots: usize,
        interval_ms: u64,
        ttl_ms: u64,
    ) !Lane {
        if (max_slots == 0) return error.InvalidCheckpointSlots;

        try std.fs.cwd().makePath(state_dir);
        const wal_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.wal" });
        errdefer allocator.free(wal_path);
        const wal_tmp_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.wal.tmp" });
        errdefer allocator.free(wal_tmp_path);
        const map_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.map" });
        errdefer allocator.free(map_path);

        const wal_file = std.fs.cwd().openFile(wal_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(wal_path, .{ .read = true, .truncate = false }),
            else => return err,
        };
        errdefer wal_file.close();

        const map_file = std.fs.cwd().openFile(map_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(map_path, .{ .read = true, .truncate = false }),
            else => return err,
        };
        errdefer map_file.close();

        var lane = Lane{
            .allocator = allocator,
            .capacity = capacity,
            .max_slots = max_slots,
            .queue_buf = try allocator.alloc(Update, capacity),
            .interval_ns = interval_ms * std.time.ns_per_ms,
            .ttl_ns = @as(i128, @intCast(ttl_ms)) * std.time.ns_per_ms,
            .by_identity = std.AutoHashMap(u64, CheckpointValue).init(allocator),
            .by_inode = std.AutoHashMap(u64, CheckpointValue).init(allocator),
            .slot_owner = try allocator.alloc(?u64, max_slots),
            .wal_file = wal_file,
            .wal_path = wal_path,
            .wal_tmp_path = wal_tmp_path,
            .map_file = map_file,
            .map_path = map_path,
            .map_region = &.{},
        };
        errdefer allocator.free(lane.queue_buf);
        errdefer allocator.free(lane.slot_owner);

        @memset(lane.slot_owner, null);
        try lane.initMap();
        errdefer lane.deinitMap();

        lane.wal_write_offset = try lane.wal_file.getEndPos();
        try lane.recover();
        return lane;
    }

    pub fn deinit(self: *Lane) void {
        self.stopWorker();
        self.deinitMap();
        self.allocator.free(self.queue_buf);
        self.allocator.free(self.slot_owner);
        self.by_identity.deinit();
        self.by_inode.deinit();
        self.wal_file.close();
        self.map_file.close();
        self.allocator.free(self.wal_path);
        self.allocator.free(self.wal_tmp_path);
        self.allocator.free(self.map_path);
    }

    pub fn start(self: *Lane) !void {
        if (self.worker != null) return;
        self.worker = try std.Thread.spawn(.{}, workerMain, .{self});
    }

    pub fn stopWorker(self: *Lane) void {
        if (self.worker) |thread| {
            self.stop.store(true, .release);
            thread.join();
            self.worker = null;
        }
    }

    pub fn enqueue(self: *Lane, update: Update) !bool {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();
        if (self.queue_len >= self.capacity) return false;

        const tail = (self.queue_head + self.queue_len) % self.capacity;
        self.queue_buf[tail] = update;
        self.queue_len += 1;
        return true;
    }

    pub fn getOffset(self: *Lane, identity: types.FileIdentity) ?u64 {
        const keys = checkpointKeys(identity);
        const now = std.time.nanoTimestamp();

        self.data_mutex.lock();
        defer self.data_mutex.unlock();

        self.evictExpiredLocked(now);

        if (self.by_identity.get(keys.identity)) |v| return v.offset;
        if (self.by_inode.get(keys.inode)) |v| return v.offset;
        return null;
    }

    fn workerMain(self: *Lane) void {
        while (true) {
            if (self.stop.load(.acquire)) {
                while (self.flushOne()) {}
                break;
            }
            if (!self.flushOne()) {
                std.Thread.sleep(@min(self.interval_ns, 10 * std.time.ns_per_ms));
            }
        }
    }

    fn flushOne(self: *Lane) bool {
        const update = self.popQueuedUpdate() orelse return false;

        self.data_mutex.lock();
        defer self.data_mutex.unlock();

        self.applyUpdateLocked(update) catch return true;
        return true;
    }

    fn popQueuedUpdate(self: *Lane) ?Update {
        self.queue_mutex.lock();
        defer self.queue_mutex.unlock();
        if (self.queue_len == 0) return null;
        const update = self.queue_buf[self.queue_head];
        self.queue_head = (self.queue_head + 1) % self.capacity;
        self.queue_len -= 1;
        return update;
    }

    fn applyUpdateLocked(self: *Lane, update: Update) !void {
        const now = std.time.nanoTimestamp();
        const keys = checkpointKeys(update.identity);

        self.evictExpiredLocked(now);
        const slot_idx = try self.allocateSlotLocked(keys.identity);
        const lsn = self.nextLsn();
        const value = CheckpointValue{
            .identity = update.identity,
            .offset = update.byte_offset,
            .last_seen_ns = update.last_seen_ns,
            .slot_idx = slot_idx,
            .lsn = lsn,
        };

        try self.upsertValueLocked(keys, value);
        try self.appendWalDurable(value);
        try self.writeMapSlot(slot_idx, value);
        self.maybeCompactWalLocked();
    }

    fn nextLsn(self: *Lane) u64 {
        const lsn = self.next_lsn;
        self.next_lsn += 1;
        return lsn;
    }

    fn upsertValueLocked(self: *Lane, keys: CheckpointKeys, value: CheckpointValue) !void {
        try self.by_identity.put(keys.identity, value);
        self.by_inode.put(keys.inode, value) catch {};
    }

    fn maybeCompactWalLocked(self: *Lane) void {
        self.writes_since_compact += 1;
        if (self.writes_since_compact < @as(u64, @intCast(@max(self.max_slots, 64)))) return;
        self.compactWalLocked() catch {};
        self.writes_since_compact = 0;
    }

    fn initMap(self: *Lane) !void {
        const expected_len = MAP_HEADER_SIZE + self.max_slots * SLOT_SIZE;
        try self.map_file.setEndPos(expected_len);

        self.map_region = try std.posix.mmap(
            null,
            expected_len,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            .{ .TYPE = .SHARED },
            self.map_file.handle,
            0,
        );

        const header = self.mapHeader();
        if (header.magic != MAP_MAGIC or header.version != MAP_VERSION or header.slot_count != self.max_slots) {
            @memset(self.map_region, 0);
            header.magic = MAP_MAGIC;
            header.version = MAP_VERSION;
            header.slot_count = @intCast(self.max_slots);
            try std.posix.msync(self.map_region, std.posix.MSF.SYNC);
        }
    }

    fn deinitMap(self: *Lane) void {
        if (self.map_region.len == 0) return;
        std.posix.munmap(self.map_region);
        self.map_region = &.{};
    }

    fn recover(self: *Lane) !void {
        self.recoverFromMapBestEffort();
        try self.replayWalAuthoritative();
        try self.rewriteMapFromMemory();
        try self.compactWalLocked();
        self.writes_since_compact = 0;
    }

    fn recoverFromMapBestEffort(self: *Lane) void {
        var idx: usize = 0;
        while (idx < self.max_slots) : (idx += 1) {
            const slot = self.slotPtr(@intCast(idx));
            const snap = self.readSlotSnapshot(slot) orelse continue;
            const value = CheckpointValue{
                .identity = .{
                    .dev = snap.dev,
                    .inode = snap.inode,
                    .fingerprint = snap.fingerprint,
                },
                .offset = snap.offset,
                .last_seen_ns = snap.last_seen_ns,
                .slot_idx = @intCast(idx),
                .lsn = 0,
            };
            self.slot_owner[idx] = types.identityHash(value.identity);
            self.upsertValueLocked(checkpointKeys(value.identity), value) catch {};
        }
    }

    fn replayWalAuthoritative(self: *Lane) !void {
        const end = try self.wal_file.getEndPos();
        self.wal_write_offset = end;
        const rec_size = @sizeOf(WalEntry);
        var off: u64 = 0;
        while (off + rec_size <= end) : (off += rec_size) {
            var rec: WalEntry = undefined;
            const n = try std.posix.pread(self.wal_file.handle, std.mem.asBytes(&rec), off);
            if (n != rec_size) break;
            const value = walRecordToValue(rec, self.max_slots) orelse continue;
            const keys = checkpointKeys(value.identity);
            self.slot_owner[value.slot_idx] = keys.identity;
            try self.upsertValueLocked(keys, value);
            if (self.next_lsn <= value.lsn) self.next_lsn = value.lsn + 1;
        }
    }

    fn compactWalLocked(self: *Lane) !void {
        var tmp = try std.fs.cwd().createFile(self.wal_tmp_path, .{ .read = true, .truncate = true });
        defer tmp.close();

        var values: std.ArrayList(CheckpointValue) = .{};
        defer values.deinit(self.allocator);
        try values.ensureTotalCapacity(self.allocator, self.by_identity.count());

        var it = self.by_identity.iterator();
        while (it.next()) |entry| values.appendAssumeCapacity(entry.value_ptr.*);

        std.mem.sort(CheckpointValue, values.items, {}, lessByLsn);

        var off: u64 = 0;
        for (values.items) |value| {
            var rec = std.mem.zeroInit(WalEntry, .{});
            rec.magic = WAL_MAGIC;
            rec.version = WAL_VERSION;
            rec.lsn = value.lsn;
            rec.timestamp_ns = value.last_seen_ns;
            rec.identity_hash = types.identityHash(value.identity);
            rec.dev = value.identity.dev;
            rec.inode = value.identity.inode;
            rec.fingerprint = value.identity.fingerprint;
            rec.slot_idx = value.slot_idx;
            rec.offset = value.offset;
            rec.checksum = walChecksum(rec);
            try pwriteAll(tmp, std.mem.asBytes(&rec), off);
            off += @sizeOf(WalEntry);
        }

        try tmp.sync();
        self.wal_file.close();
        try std.fs.cwd().rename(self.wal_tmp_path, self.wal_path);
        self.wal_file = try std.fs.cwd().openFile(self.wal_path, .{ .mode = .read_write });
        self.wal_write_offset = try self.wal_file.getEndPos();
    }

    fn evictExpiredLocked(self: *Lane, now: i128) void {
        var to_remove: std.ArrayList(u64) = .{};
        defer to_remove.deinit(self.allocator);

        var it = self.by_identity.iterator();
        while (it.next()) |entry| {
            if (@as(i128, entry.value_ptr.last_seen_ns) + self.ttl_ns >= now) continue;
            to_remove.append(self.allocator, entry.key_ptr.*) catch return;
        }

        for (to_remove.items) |identity_key| {
            if (self.by_identity.fetchRemove(identity_key)) |kv| {
                self.removeInodeAliasForValue(kv.value);
                self.freeSlot(kv.value.slot_idx);
            }
        }
    }

    fn removeInodeAliasForValue(self: *Lane, value: CheckpointValue) void {
        const inode_key = types.inodeIdentityHash(value.identity);
        if (self.by_inode.get(inode_key)) |v| {
            if (v.slot_idx == value.slot_idx) {
                _ = self.by_inode.remove(inode_key);
            }
        }
    }

    fn freeSlot(self: *Lane, slot_idx: u16) void {
        const idx: usize = slot_idx;
        if (idx >= self.slot_owner.len) return;
        if (self.slot_owner[idx] == null) return;
        self.slot_owner[idx] = null;
        self.clearMapSlot(slot_idx) catch {};
    }

    fn allocateSlotLocked(self: *Lane, identity_key: u64) !u16 {
        if (self.by_identity.get(identity_key)) |v| return v.slot_idx;

        var i: usize = 0;
        while (i < self.slot_owner.len) : (i += 1) {
            if (self.slot_owner[i] == null) {
                self.slot_owner[i] = identity_key;
                return @intCast(i);
            }
        }

        const victim = self.oldestValue() orelse return error.NoCheckpointSlots;
        const removed = self.by_identity.fetchRemove(victim.key).?;
        self.removeInodeAliasForValue(removed.value);
        self.slot_owner[removed.value.slot_idx] = identity_key;
        return removed.value.slot_idx;
    }

    fn oldestValue(self: *Lane) ?OldestValue {
        var oldest: ?OldestValue = null;
        var it = self.by_identity.iterator();
        while (it.next()) |entry| {
            const current = OldestValue{
                .key = entry.key_ptr.*,
                .last_seen_ns = entry.value_ptr.last_seen_ns,
            };
            if (oldest == null or current.last_seen_ns < oldest.?.last_seen_ns) oldest = current;
        }
        return oldest;
    }

    fn appendWalDurable(self: *Lane, value: CheckpointValue) !void {
        var rec = std.mem.zeroInit(WalEntry, .{});
        rec.magic = WAL_MAGIC;
        rec.version = WAL_VERSION;
        rec.lsn = value.lsn;
        rec.timestamp_ns = value.last_seen_ns;
        rec.identity_hash = types.identityHash(value.identity);
        rec.dev = value.identity.dev;
        rec.inode = value.identity.inode;
        rec.fingerprint = value.identity.fingerprint;
        rec.slot_idx = value.slot_idx;
        rec.offset = value.offset;
        rec.checksum = walChecksum(rec);

        try pwriteAll(self.wal_file, std.mem.asBytes(&rec), self.wal_write_offset);
        self.wal_write_offset += @sizeOf(WalEntry);
        try std.posix.fdatasync(self.wal_file.handle);
    }

    fn mapHeader(self: *Lane) *align(@alignOf(MappedHeader)) MappedHeader {
        return @ptrCast(self.map_region.ptr);
    }

    fn slotPtr(self: *Lane, idx: u16) *align(@alignOf(MappedSlot)) MappedSlot {
        const offset = MAP_HEADER_SIZE + @as(usize, idx) * SLOT_SIZE;
        return @ptrCast(@alignCast(self.map_region.ptr + offset));
    }

    fn clearAllSlots(self: *Lane) void {
        var idx: usize = 0;
        while (idx < self.max_slots) : (idx += 1) {
            self.clearMapSlot(@intCast(idx)) catch {};
        }
    }

    fn clearMapSlot(self: *Lane, idx: u16) !void {
        const slot = self.slotPtr(idx);
        self.writeSlotValue(slot, .{
            .dev = 0,
            .inode = 0,
            .fingerprint = 0,
            .offset = 0,
            .last_seen_ns = 0,
        });
        try self.syncMapAsync();
    }

    fn writeMapSlot(self: *Lane, idx: u16, value: CheckpointValue) !void {
        const slot = self.slotPtr(idx);
        self.writeSlotValue(slot, .{
            .dev = value.identity.dev,
            .inode = value.identity.inode,
            .fingerprint = value.identity.fingerprint,
            .offset = value.offset,
            .last_seen_ns = value.last_seen_ns,
        });
        try self.syncMapAsync();
    }

    fn writeSlotValue(self: *Lane, slot: *align(@alignOf(MappedSlot)) MappedSlot, snapshot: SlotSnapshotNoChecksum) void {
        _ = self;
        beginWrite(slot);
        slot.dev = snapshot.dev;
        slot.inode = snapshot.inode;
        slot.fingerprint = snapshot.fingerprint;
        slot.offset = snapshot.offset;
        slot.last_seen_ns = snapshot.last_seen_ns;
        slot.checksum = slotChecksum(slot.*);
        endWrite(slot);
    }

    fn syncMapAsync(self: *Lane) !void {
        try std.posix.msync(self.map_region, std.posix.MSF.ASYNC);
    }

    fn rewriteMapFromMemory(self: *Lane) !void {
        self.clearAllSlots();
        var it = self.by_identity.iterator();
        while (it.next()) |entry| {
            try self.writeMapSlot(entry.value_ptr.slot_idx, entry.value_ptr.*);
        }
        try std.posix.msync(self.map_region, std.posix.MSF.SYNC);
    }

    fn readSlotSnapshot(_: *Lane, slot: *align(@alignOf(MappedSlot)) const MappedSlot) ?SlotSnapshot {
        var tries: usize = 0;
        while (tries < 64) : (tries += 1) {
            const s1 = readSequence(slot);
            if ((s1 & 1) == 1) {
                std.atomic.spinLoopHint();
                continue;
            }

            const snap = SlotSnapshot{
                .dev = slot.dev,
                .inode = slot.inode,
                .fingerprint = slot.fingerprint,
                .offset = slot.offset,
                .last_seen_ns = slot.last_seen_ns,
                .checksum = slot.checksum,
            };

            if (!validateSequence(slot, s1)) continue;
            if (snap.dev == 0 and snap.inode == 0) return null;
            if (snap.checksum != slotChecksumFromSnapshot(snap)) return null;
            return snap;
        }
        return null;
    }
};

const CheckpointValue = struct {
    identity: types.FileIdentity,
    offset: u64,
    last_seen_ns: i64,
    slot_idx: u16,
    lsn: u64,
};

const CheckpointKeys = struct {
    identity: u64,
    inode: u64,
};

const OldestValue = struct {
    key: u64,
    last_seen_ns: i64,
};

const SlotSnapshotNoChecksum = struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,
    offset: u64,
    last_seen_ns: i64,
};

const MAP_MAGIC: u32 = 0x544C4157; // "WALT"
const MAP_VERSION: u16 = 1;
const MAP_HEADER_SIZE = 64;
const SLOT_SIZE = 128;
const WAL_MAGIC: u32 = 0x334C4157; // "WAL3"
const WAL_VERSION: u16 = 1;

const MappedHeader = extern struct {
    magic: u32,
    version: u16,
    slot_count: u16,
    _pad: [56]u8 = [_]u8{0} ** 56,
};

const MappedSlot = extern struct {
    sequence: u64,
    _sequence_pad: [56]u8 = [_]u8{0} ** 56,
    dev: u64,
    inode: u64,
    fingerprint: u32,
    _pad0: u32 = 0,
    offset: u64,
    last_seen_ns: i64,
    checksum: u32,
    _pad1: [20]u8 = [_]u8{0} ** 20,
};

const SlotSnapshot = struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,
    offset: u64,
    last_seen_ns: i64,
    checksum: u32,
};

const WalEntry = extern struct {
    magic: u32,
    version: u16,
    _pad0: u16 = 0,
    lsn: u64,
    timestamp_ns: i64,
    identity_hash: u64,
    dev: u64,
    inode: u64,
    fingerprint: u32,
    slot_idx: u16,
    _pad1: u16 = 0,
    offset: u64,
    checksum: u32,
    _pad2: u32 = 0,
};

comptime {
    std.debug.assert(@sizeOf(MappedHeader) == MAP_HEADER_SIZE);
    std.debug.assert(@sizeOf(MappedSlot) == SLOT_SIZE);
}

fn lessByLsn(_: void, a: CheckpointValue, b: CheckpointValue) bool {
    return a.lsn < b.lsn;
}

fn checkpointKeys(identity: types.FileIdentity) CheckpointKeys {
    return .{
        .identity = types.identityHash(identity),
        .inode = types.inodeIdentityHash(identity),
    };
}

fn walRecordToValue(rec: WalEntry, max_slots: usize) ?CheckpointValue {
    if (rec.magic != WAL_MAGIC or rec.version != WAL_VERSION) return null;
    if (rec.checksum != walChecksum(rec)) return null;
    if (rec.slot_idx >= max_slots) return null;

    const identity = types.FileIdentity{
        .dev = rec.dev,
        .inode = rec.inode,
        .fingerprint = rec.fingerprint,
    };
    if (types.identityHash(identity) != rec.identity_hash) return null;

    return .{
        .identity = identity,
        .offset = rec.offset,
        .last_seen_ns = rec.timestamp_ns,
        .slot_idx = @intCast(rec.slot_idx),
        .lsn = rec.lsn,
    };
}

fn beginWrite(slot: *align(@alignOf(MappedSlot)) MappedSlot) void {
    while (true) {
        const cur = @atomicLoad(u64, &slot.sequence, .acquire);
        if ((cur & 1) == 1) {
            _ = @cmpxchgWeak(u64, &slot.sequence, cur, cur + 1, .acq_rel, .acquire);
            std.atomic.spinLoopHint();
            continue;
        }
        if (@cmpxchgWeak(u64, &slot.sequence, cur, cur + 1, .acq_rel, .acquire) == null) return;
        std.atomic.spinLoopHint();
    }
}

fn endWrite(slot: *align(@alignOf(MappedSlot)) MappedSlot) void {
    _ = @atomicRmw(u64, &slot.sequence, .Add, 1, .release);
}

fn readSequence(slot: *align(@alignOf(MappedSlot)) const MappedSlot) u64 {
    return @atomicLoad(u64, &slot.sequence, .acquire);
}

fn validateSequence(slot: *align(@alignOf(MappedSlot)) const MappedSlot, s: u64) bool {
    return @atomicLoad(u64, &slot.sequence, .acquire) == s;
}

fn slotChecksum(slot: MappedSlot) u32 {
    var hasher = std.hash.Crc32.init();
    hasher.update(std.mem.asBytes(&slot.dev));
    hasher.update(std.mem.asBytes(&slot.inode));
    hasher.update(std.mem.asBytes(&slot.fingerprint));
    hasher.update(std.mem.asBytes(&slot.offset));
    hasher.update(std.mem.asBytes(&slot.last_seen_ns));
    return hasher.final();
}

fn slotChecksumFromSnapshot(snap: SlotSnapshot) u32 {
    var hasher = std.hash.Crc32.init();
    hasher.update(std.mem.asBytes(&snap.dev));
    hasher.update(std.mem.asBytes(&snap.inode));
    hasher.update(std.mem.asBytes(&snap.fingerprint));
    hasher.update(std.mem.asBytes(&snap.offset));
    hasher.update(std.mem.asBytes(&snap.last_seen_ns));
    return hasher.final();
}

fn walChecksum(entry: WalEntry) u32 {
    var tmp = entry;
    tmp.checksum = 0;
    return std.hash.Crc32.hash(std.mem.asBytes(&tmp));
}

fn pwriteAll(file: std.fs.File, bytes: []const u8, offset: u64) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try std.posix.pwrite(file.handle, bytes[written..], offset + written);
        if (n == 0) return error.Unexpected;
        written += n;
    }
}

const testing = std.testing;

/// waitForOffset waits for the given offset to be observed by the lane, or fails the test if it does not appear within max_tries attempts.
fn waitForOffset(lane: *Lane, id: types.FileIdentity, expected: ?u64, max_tries: usize) !void {
    var tries: usize = 0;
    while (tries < max_tries and lane.getOffset(id) != expected) : (tries += 1) {
        std.Thread.sleep(2 * std.time.ns_per_ms);
    }
    try testing.expectEqual(expected, lane.getOffset(id));
}

fn corruptByte(path: []const u8, at: u64) !void {
    var f = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer f.close();
    var b: [1]u8 = undefined;
    const n = try std.posix.pread(f.handle, &b, at);
    if (n != 1) return error.Unexpected;
    b[0] ^= 0x5a;
    try pwriteAll(f, &b, at);
    try f.sync();
}

test "checkpoint lane public API: enqueue and observe offset" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000);
    defer lane.deinit();
    try lane.start();

    const id = types.FileIdentity{ .dev = 1, .inode = 2, .fingerprint = 3 };
    const ok = try lane.enqueue(.{
        .identity = id,
        .byte_offset = 99,
        .last_seen_size = 99,
        .last_seen_ns = @intCast(std.time.nanoTimestamp()),
    });
    try testing.expect(ok);

    try waitForOffset(&lane, id, 99, 100);
}

test "checkpoint lane public API: recovers offset from WAL and map" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = types.FileIdentity{ .dev = 7, .inode = 8, .fingerprint = 9 };
    {
        var lane = try Lane.init(testing.allocator, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000);
        defer lane.deinit();
        try lane.start();
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 1234,
            .last_seen_size = 1234,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        try waitForOffset(&lane, id, 1234, 100);
    }

    var recovered = try Lane.init(testing.allocator, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 1234), recovered.getOffset(id));
}

test "checkpoint lane: queue is bounded and returns false when full" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, state_dir, 1, 8, 5, 72 * 60 * 60 * 1000);
    defer lane.deinit();

    const id = types.FileIdentity{ .dev = 1, .inode = 1, .fingerprint = 1 };
    try testing.expect(try lane.enqueue(.{
        .identity = id,
        .byte_offset = 1,
        .last_seen_size = 1,
        .last_seen_ns = @intCast(std.time.nanoTimestamp()),
    }));
    try testing.expect(!(try lane.enqueue(.{
        .identity = id,
        .byte_offset = 2,
        .last_seen_size = 2,
        .last_seen_ns = @intCast(std.time.nanoTimestamp()),
    })));
}

test "checkpoint lane: expired entries are evicted on lookup" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, state_dir, 16, 16, 5, 1);
    defer lane.deinit();
    try lane.start();

    const id = types.FileIdentity{ .dev = 2, .inode = 2, .fingerprint = 2 };
    const stale_ns: i64 = @intCast(std.time.nanoTimestamp() - (10 * std.time.ns_per_ms));
    _ = try lane.enqueue(.{
        .identity = id,
        .byte_offset = 44,
        .last_seen_size = 44,
        .last_seen_ns = stale_ns,
    });
    std.Thread.sleep(20 * std.time.ns_per_ms);
    try testing.expectEqual(@as(?u64, null), lane.getOffset(id));
}

test "checkpoint lane: max slots evicts least recently seen entry" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, state_dir, 32, 2, 5, 72 * 60 * 60 * 1000);
    defer lane.deinit();
    try lane.start();

    const base_ns: i64 = @intCast(std.time.nanoTimestamp());
    const id1 = types.FileIdentity{ .dev = 10, .inode = 10, .fingerprint = 10 };
    const id2 = types.FileIdentity{ .dev = 10, .inode = 11, .fingerprint = 11 };
    const id3 = types.FileIdentity{ .dev = 10, .inode = 12, .fingerprint = 12 };

    _ = try lane.enqueue(.{ .identity = id1, .byte_offset = 100, .last_seen_size = 100, .last_seen_ns = base_ns });
    _ = try lane.enqueue(.{ .identity = id2, .byte_offset = 200, .last_seen_size = 200, .last_seen_ns = base_ns + 1 });
    _ = try lane.enqueue(.{ .identity = id3, .byte_offset = 300, .last_seen_size = 300, .last_seen_ns = base_ns + 2 });

    try waitForOffset(&lane, id3, 300, 200);
    try testing.expectEqual(@as(?u64, null), lane.getOffset(id1));
    try testing.expectEqual(@as(?u64, 200), lane.getOffset(id2));
    try testing.expectEqual(@as(?u64, 300), lane.getOffset(id3));
}

test "checkpoint lane: recovers from corrupted WAL using map snapshot" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = types.FileIdentity{ .dev = 21, .inode = 22, .fingerprint = 23 };
    {
        var lane = try Lane.init(testing.allocator, state_dir, 16, 16, 5, 72 * 60 * 60 * 1000);
        defer lane.deinit();
        try lane.start();
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 9001,
            .last_seen_size = 9001,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        try waitForOffset(&lane, id, 9001, 100);
    }

    const wal_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.wal" });
    defer testing.allocator.free(wal_path);
    try corruptByte(wal_path, @offsetOf(WalEntry, "checksum"));

    var recovered = try Lane.init(testing.allocator, state_dir, 16, 16, 5, 72 * 60 * 60 * 1000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 9001), recovered.getOffset(id));
}

test "checkpoint lane: recovers from corrupted map using WAL replay" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = types.FileIdentity{ .dev = 31, .inode = 32, .fingerprint = 33 };
    {
        var lane = try Lane.init(testing.allocator, state_dir, 16, 16, 5, 72 * 60 * 60 * 1000);
        defer lane.deinit();
        try lane.start();
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 4242,
            .last_seen_size = 4242,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        try waitForOffset(&lane, id, 4242, 100);
    }

    const map_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.map" });
    defer testing.allocator.free(map_path);
    try corruptByte(map_path, MAP_HEADER_SIZE + @offsetOf(MappedSlot, "checksum"));

    var recovered = try Lane.init(testing.allocator, state_dir, 16, 16, 5, 72 * 60 * 60 * 1000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 4242), recovered.getOffset(id));
}

test "checkpoint lane: tolerates odd seqlock value in persisted map slot" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    {
        var lane = try Lane.init(testing.allocator, state_dir, 16, 8, 5, 72 * 60 * 60 * 1000);
        defer lane.deinit();
    }

    const map_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.map" });
    defer testing.allocator.free(map_path);
    var map_file = try std.fs.cwd().openFile(map_path, .{ .mode = .read_write });
    defer map_file.close();
    var odd: u64 = 1;
    try pwriteAll(map_file, std.mem.asBytes(&odd), MAP_HEADER_SIZE + @offsetOf(MappedSlot, "sequence"));
    try map_file.sync();

    var recovered = try Lane.init(testing.allocator, state_dir, 16, 8, 5, 72 * 60 * 60 * 1000);
    defer recovered.deinit();
    try testing.expect(true);
}

test "checkpoint lane: initializes cleanly when state files are missing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const wal_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.wal" });
    defer testing.allocator.free(wal_path);
    const map_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.map" });
    defer testing.allocator.free(map_path);

    var lane = try Lane.init(testing.allocator, state_dir, 8, 8, 5, 72 * 60 * 60 * 1000);
    lane.deinit();
    std.fs.cwd().deleteFile(wal_path) catch {};
    std.fs.cwd().deleteFile(map_path) catch {};

    var recreated = try Lane.init(testing.allocator, state_dir, 8, 8, 5, 72 * 60 * 60 * 1000);
    defer recreated.deinit();
}
