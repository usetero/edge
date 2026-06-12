const std = @import("std");
const tail_types = @import("../types.zig");
const checkpoint_types = @import("types.zig");
const queue_mod = @import("queue.zig");
const store_mod = @import("store.zig");
const wal_mod = @import("wal.zig");
const snapshot_mod = @import("snapshot.zig");
const lifecycle_mod = @import("../../core/lifecycle.zig");

const log = std.log.scoped(.checkpoint_lane);

pub const Update = checkpoint_types.Update;

pub const Lane = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    queue: queue_mod.UpdateQueue,
    store: store_mod.Store,
    wal: wal_mod.Wal,
    snapshot: snapshot_mod.Snapshot,
    started: bool = false,

    interval_ns: u64,
    ttl_ns: i128,
    sync_batch: u32,
    next_lsn: u64 = 1,
    pending_unsynced: u32 = 0,
    last_sync_ns: i128 = 0,

    gc_interval_ns: i128,
    next_gc_ns: i128,
    snapshot_interval_ns: i128,
    next_snapshot_ns: i128,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        state_dir: []const u8,
        capacity: usize,
        max_slots: usize,
        interval_ms: u64,
        ttl_ms: u64,
        sync_batch: u32,
        snapshot_interval_ms: u64,
    ) !Lane {
        if (max_slots == 0) return error.InvalidCheckpointSlots;
        if (sync_batch == 0) return error.InvalidCheckpointSyncBatch;
        if (snapshot_interval_ms == 0) return error.InvalidCheckpointSnapshotInterval;

        try std.Io.Dir.cwd().createDirPath(io, state_dir);

        const interval_ns = interval_ms * std.time.ns_per_ms;
        const ttl_ns = @as(i128, @intCast(ttl_ms)) * std.time.ns_per_ms;

        var lane: Lane = .{
            .allocator = allocator,
            .io = io,
            .queue = try queue_mod.UpdateQueue.init(allocator, io, capacity),
            .store = store_mod.Store.init(allocator, io, max_slots, ttl_ns),
            .wal = try wal_mod.Wal.init(allocator, io, state_dir),
            .snapshot = try snapshot_mod.Snapshot.init(allocator, io, state_dir),
            .interval_ns = interval_ns,
            .ttl_ns = ttl_ns,
            .sync_batch = sync_batch,
            .gc_interval_ns = @max(@as(i128, interval_ns), 500 * std.time.ns_per_ms),
            .next_gc_ns = 0,
            .snapshot_interval_ns = @as(i128, @intCast(snapshot_interval_ms)) * std.time.ns_per_ms,
            .next_snapshot_ns = 0,
            .pending_unsynced = 0,
        };
        errdefer lane.queue.deinit();
        errdefer lane.store.deinit();
        errdefer lane.wal.deinit();
        errdefer lane.snapshot.deinit();

        try lane.recover();
        const now = std.Io.Timestamp.now(io, .awake).toNanoseconds();
        lane.last_sync_ns = now;
        lane.next_gc_ns = now + lane.gc_interval_ns;
        lane.next_snapshot_ns = now + lane.snapshot_interval_ns;

        return lane;
    }

    /// Resource teardown only. When `start` was used, the owning runtime
    /// MUST run `Lifecycle.shutdown` (joining the worker task) and then
    /// `finalize` before calling this.
    pub fn deinit(self: *Lane) void {
        self.snapshot.deinit();
        self.wal.deinit();
        self.store.deinit();
        self.queue.deinit();
        self.* = undefined;
    }

    /// Spawns the worker as a concurrent task in the caller's lifecycle
    /// group (PLAN.md §9 Phase 6): shutdown is the group's collective
    /// cancel, not a Lane-owned thread join.
    pub fn start(self: *Lane, lifecycle: *lifecycle_mod.Lifecycle) !void {
        if (self.started) return;
        try lifecycle.spawn(self.io, workerMain, .{self});
        self.started = true;
    }

    /// Post-shutdown drain, called by the owner AFTER Lifecycle.shutdown has
    /// joined the worker task (the canceled task can't reliably run final
    /// file IO itself). Applies whatever the poll loop enqueued last, then
    /// syncs the WAL and rewrites the snapshot so recovery sees everything.
    pub fn finalize(self: *Lane) void {
        while (self.queue.pop()) |update| self.applyUpdate(update) catch |err|
            log.warn("applyUpdate (drain) failed: {}", .{err});
        self.runMaintenance(true) catch |err| log.warn("runMaintenance (final) failed: {}", .{err});
    }

    pub fn enqueue(self: *Lane, update: Update) !bool {
        return self.queue.push(update);
    }

    pub fn getOffset(self: *Lane, identity: tail_types.FileIdentity) ?u64 {
        return self.store.getOffset(identity);
    }

    fn recover(self: *Lane) !void {
        var snapshot_values = try self.snapshot.load(self.allocator);
        defer snapshot_values.deinit(self.allocator);
        try self.store.loadValues(snapshot_values.items);

        var replay = try self.wal.replay(self.allocator);
        defer replay.deinit(self.allocator);
        for (replay.entries.items) |entry| {
            try self.store.upsert(entry.value);
        }
        self.next_lsn = replay.next_lsn;

        try self.persistSnapshotAndResetWal();
    }

    /// Concurrent task in the runtime's lifecycle group. Cancellation lands
    /// here as error.Canceled out of the cadence sleep; the final drain runs
    /// in `finalize` on the shutdown thread, where file IO is not canceled.
    fn workerMain(self: *Lane) std.Io.Cancelable!void {
        while (true) {
            if (self.queue.pop()) |update| {
                self.applyUpdate(update) catch |err| log.warn("applyUpdate failed: {}", .{err});
                self.runMaintenance(false) catch |err| log.warn("runMaintenance failed: {}", .{err});
                continue;
            }

            self.runMaintenance(false) catch |err| log.warn("runMaintenance failed: {}", .{err});
            const sleep_ns = @min(self.interval_ns, 10 * std.time.ns_per_ms);
            try self.io.sleep(.fromNanoseconds(@intCast(sleep_ns)), .awake);
        }
    }

    fn applyUpdate(self: *Lane, update: Update) !void {
        const value = checkpoint_types.valueFromUpdate(update);
        try self.store.upsert(value);
        try self.wal.append(self.next_lsn, value);
        self.next_lsn += 1;
        self.pending_unsynced += 1;
    }

    fn runMaintenance(self: *Lane, force: bool) !void {
        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();

        if (force or self.pending_unsynced >= self.sync_batch or (now - self.last_sync_ns) >= self.interval_ns) {
            if (self.pending_unsynced > 0) {
                try self.wal.sync();
                self.pending_unsynced = 0;
            }
            self.last_sync_ns = now;
        }

        if (force or now >= self.next_gc_ns) {
            self.store.evictExpired(now);
            self.next_gc_ns = now + self.gc_interval_ns;
        }

        if (force or now >= self.next_snapshot_ns) {
            try self.persistSnapshotAndResetWal();
            self.next_snapshot_ns = now + self.snapshot_interval_ns;
        }
    }

    fn persistSnapshotAndResetWal(self: *Lane) !void {
        var values = try self.store.collectValues();
        defer values.deinit(self.allocator);

        try self.snapshot.write(values.items);
        if (self.pending_unsynced > 0) {
            try self.wal.sync();
            self.pending_unsynced = 0;
        }
        try self.wal.reset();
    }
};

const testing = std.testing;

fn waitForOffset(lane: *Lane, id: tail_types.FileIdentity, expected: ?u64, max_tries: usize) !void {
    var tries: usize = 0;
    while (tries < max_tries and lane.getOffset(id) != expected) : (tries += 1) {
        try testing.io.sleep(.fromNanoseconds(2 * std.time.ns_per_ms), .awake);
    }
    try testing.expectEqual(expected, lane.getOffset(id));
}

/// Started lanes need the lifecycle drained then the final persist before
/// deinit — same contract the runtime follows.
fn shutdownLane(lane: *Lane, lifecycle: *lifecycle_mod.Lifecycle, io: std.Io) void {
    lifecycle.requestShutdown(io);
    lifecycle.shutdown(io);
    lane.finalize();
}

fn corruptByte(io: std.Io, path: []const u8, at: u64) !void {
    const f = try std.Io.Dir.openFileAbsolute(io, path, .{ .mode = .read_write });
    defer f.close(io);

    var b: [1]u8 = undefined;
    const n = try f.readPositionalAll(io, &b, at);
    if (n != 1) return error.Unexpected;

    b[0] ^= 0x5a;
    try f.writePositionalAll(io, &b, at);
    try f.sync(io);
}

test "checkpoint/lane: enqueue and observe offset" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    var lifecycle: lifecycle_mod.Lifecycle = .init;
    var lane = try Lane.init(testing.allocator, io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer lane.deinit();
    try lane.start(&lifecycle);
    defer shutdownLane(&lane, &lifecycle, io);

    const id: tail_types.FileIdentity = .{ .dev = 1, .inode = 2, .fingerprint = 3 };
    try testing.expect(try lane.enqueue(.{
        .identity = id,
        .byte_offset = 99,
        .last_seen_size = 99,
        .last_seen_ns = @intCast(std.Io.Timestamp.now(testing.io, .awake).toNanoseconds()),
    }));
    try waitForOffset(&lane, id, 99, 100);
}

test "checkpoint/lane: queue is bounded" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, testing.io, state_dir, 1, 8, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer lane.deinit();

    const id: tail_types.FileIdentity = .{ .dev = 1, .inode = 1, .fingerprint = 1 };
    try testing.expect(try lane.enqueue(.{ .identity = id, .byte_offset = 1, .last_seen_size = 1, .last_seen_ns = 1 }));
    try testing.expect(!(try lane.enqueue(.{
        .identity = id,
        .byte_offset = 2,
        .last_seen_size = 2,
        .last_seen_ns = 2,
    })));
}

test "checkpoint/lane: recovers from wal and snapshot" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const id: tail_types.FileIdentity = .{ .dev = 7, .inode = 8, .fingerprint = 9 };
    {
        const io = testing.io;
        var lifecycle: lifecycle_mod.Lifecycle = .init;
        var lane = try Lane.init(testing.allocator, io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
        defer lane.deinit();
        try lane.start(&lifecycle);
        defer shutdownLane(&lane, &lifecycle, io);
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 1234,
            .last_seen_size = 1234,
            .last_seen_ns = @intCast(std.Io.Timestamp.now(testing.io, .awake).toNanoseconds()),
        });
        try waitForOffset(&lane, id, 1234, 100);
    }

    var recovered = try Lane.init(testing.allocator, testing.io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 1234), recovered.getOffset(id));
}

test "checkpoint/lane: corrupted wal is tolerated" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const id: tail_types.FileIdentity = .{ .dev = 10, .inode = 11, .fingerprint = 12 };
    {
        const io = testing.io;
        var lifecycle: lifecycle_mod.Lifecycle = .init;
        var lane = try Lane.init(testing.allocator, io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
        defer lane.deinit();
        try lane.start(&lifecycle);
        defer shutdownLane(&lane, &lifecycle, io);
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 55,
            .last_seen_size = 55,
            .last_seen_ns = @intCast(std.Io.Timestamp.now(testing.io, .awake).toNanoseconds()),
        });
        try waitForOffset(&lane, id, 55, 100);
    }

    const wal_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.wal" });
    defer testing.allocator.free(wal_path);

    const wal_file = try std.Io.Dir.openFileAbsolute(testing.io, wal_path, .{ .mode = .read_write });
    defer wal_file.close(testing.io);
    const junk: [3]u8 = .{ 0xaa, 0xbb, 0xcc };
    try wal_file.writePositionalAll(testing.io, &junk, 0);
    try wal_file.sync(testing.io);

    var recovered = try Lane.init(testing.allocator, testing.io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 55), recovered.getOffset(id));
}

test "checkpoint/lane: corrupted snapshot falls back to wal replay" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const id: tail_types.FileIdentity = .{ .dev = 20, .inode = 21, .fingerprint = 22 };
    const value: checkpoint_types.Value = .{
        .identity = id,
        .offset = 777,
        .last_seen_ns = @intCast(std.Io.Timestamp.now(testing.io, .awake).toNanoseconds()),
    };

    var snap = try snapshot_mod.Snapshot.init(testing.allocator, testing.io, state_dir);
    defer snap.deinit();
    var vals: [1]checkpoint_types.Value = .{value};
    try snap.write(vals[0..]);

    const snap_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.snap" });
    defer testing.allocator.free(snap_path);
    try corruptByte(testing.io, snap_path, 0);

    var wal = try wal_mod.Wal.init(testing.allocator, testing.io, state_dir);
    defer wal.deinit();
    try wal.append(1, value);
    try wal.sync();

    var recovered = try Lane.init(testing.allocator, testing.io, state_dir, 16, 64, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 777), recovered.getOffset(id));
}

test "checkpoint/lane: missing state files initialize cleanly" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realPathFileAlloc(testing.io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const wal_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.wal" });
    defer testing.allocator.free(wal_path);
    const snap_path = try std.fs.path.join(testing.allocator, &.{ state_dir, "checkpoint.snap" });
    defer testing.allocator.free(snap_path);

    var lane = try Lane.init(testing.allocator, testing.io, state_dir, 8, 8, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    lane.deinit();

    std.Io.Dir.deleteFileAbsolute(testing.io, wal_path) catch |err| log.warn("deleteFile wal failed: {}", .{err});
    std.Io.Dir.deleteFileAbsolute(testing.io, snap_path) catch |err| log.warn("deleteFile snap failed: {}", .{err});

    var recreated = try Lane.init(testing.allocator, testing.io, state_dir, 8, 8, 5, 72 * 60 * 60 * 1000, 64, 60_000);
    defer recreated.deinit();
}
