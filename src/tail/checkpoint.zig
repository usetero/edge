const std = @import("std");
const types = @import("types.zig");

pub const Update = struct {
    identity: types.FileIdentity,
    byte_offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
};

/// Background checkpoint lane for tail runtime.
///
/// This is intentionally lightweight: a bounded queue feeds a worker thread
/// that batches state updates into memory. Disk-backed persistence will replace
/// this worker internals while preserving the non-blocking enqueue contract.
pub const Lane = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    state_dir: []const u8,
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
    wal_file: std.fs.File,
    wal_path: []u8,
    pending_wal_sync: u32 = 0,
    last_sync_ns: i128 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        state_dir: []const u8,
        capacity: usize,
        interval_ms: u64,
        ttl_ms: u64,
    ) !Lane {
        try std.fs.cwd().makePath(state_dir);
        const wal_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.wal" });
        errdefer allocator.free(wal_path);
        const wal_file = std.fs.cwd().openFile(wal_path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(wal_path, .{ .read = true, .truncate = false }),
            else => return err,
        };
        errdefer wal_file.close();

        var lane = Lane{
            .allocator = allocator,
            .capacity = capacity,
            .state_dir = state_dir,
            .queue_buf = try allocator.alloc(Update, capacity),
            .interval_ns = interval_ms * std.time.ns_per_ms,
            .ttl_ns = @as(i128, @intCast(ttl_ms)) * std.time.ns_per_ms,
            .by_identity = std.AutoHashMap(u64, CheckpointValue).init(allocator),
            .by_inode = std.AutoHashMap(u64, CheckpointValue).init(allocator),
            .wal_file = wal_file,
            .wal_path = wal_path,
            .last_sync_ns = std.time.nanoTimestamp(),
        };
        errdefer allocator.free(lane.queue_buf);
        try lane.recover();
        return lane;
    }

    pub fn deinit(self: *Lane) void {
        self.stopWorker();
        self.allocator.free(self.queue_buf);
        self.by_identity.deinit();
        self.by_inode.deinit();
        self.wal_file.close();
        self.allocator.free(self.wal_path);
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

    /// Non-blocking hot path enqueue. Returns false when queue is full.
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
        const key = types.identityHash(identity);
        const inode_key = types.inodeIdentityHash(identity);
        const now = std.time.nanoTimestamp();
        self.data_mutex.lock();
        defer self.data_mutex.unlock();
        if (self.by_identity.get(key)) |v| {
            if (@as(i128, v.last_seen_ns) + self.ttl_ns >= now) return v.offset;
            _ = self.by_identity.remove(key);
        }
        if (self.by_inode.get(inode_key)) |v| {
            if (@as(i128, v.last_seen_ns) + self.ttl_ns >= now) return v.offset;
            _ = self.by_inode.remove(inode_key);
        }
        return null;
    }

    fn workerMain(self: *Lane) void {
        while (true) {
            if (self.stop.load(.acquire)) {
                while (self.flushOne()) {}
                if (self.pending_wal_sync > 0) {
                    self.wal_file.sync() catch {};
                    self.pending_wal_sync = 0;
                }
                break;
            }

            if (!self.flushOne()) {
                std.Thread.sleep(@min(self.interval_ns, 10 * std.time.ns_per_ms));
            }
        }
    }

    fn flushOne(self: *Lane) bool {
        self.queue_mutex.lock();
        if (self.queue_len == 0) {
            self.queue_mutex.unlock();
            return false;
        }
        const update = self.queue_buf[self.queue_head];
        self.queue_head = (self.queue_head + 1) % self.capacity;
        self.queue_len -= 1;
        self.queue_mutex.unlock();

        const key = types.identityHash(update.identity);
        const inode_key = types.inodeIdentityHash(update.identity);
        self.data_mutex.lock();
        const v = CheckpointValue{
            .offset = update.byte_offset,
            .last_seen_ns = update.last_seen_ns,
        };
        self.by_identity.put(key, v) catch {};
        self.by_inode.put(inode_key, v) catch {};
        self.data_mutex.unlock();
        self.appendWal(update) catch {};

        const now = std.time.nanoTimestamp();
        if (self.pending_wal_sync >= 64 or (now - self.last_sync_ns) >= @as(i128, @intCast(self.interval_ns))) {
            self.wal_file.sync() catch {};
            self.pending_wal_sync = 0;
            self.last_sync_ns = now;
        }
        return true;
    }

    fn appendWal(self: *Lane, update: Update) !void {
        var rec = std.mem.zeroInit(WalRecord, .{});
        rec.magic = WAL_MAGIC;
        rec.version = WAL_VERSION;
        rec.dev = update.identity.dev;
        rec.inode = update.identity.inode;
        rec.fingerprint = update.identity.fingerprint;
        rec.offset = update.byte_offset;
        rec.last_seen_size = update.last_seen_size;
        rec.last_seen_ns = update.last_seen_ns;
        rec.checksum = recordChecksum(rec);

        const end = try self.wal_file.getEndPos();
        try pwriteAll(self.wal_file, std.mem.asBytes(&rec), end);
        self.pending_wal_sync += 1;
    }

    fn recover(self: *Lane) !void {
        const end = try self.wal_file.getEndPos();
        var off: u64 = 0;
        const rec_size = @sizeOf(WalRecord);
        while (off + rec_size <= end) : (off += rec_size) {
            var rec: WalRecord = undefined;
            const n = try std.posix.pread(self.wal_file.handle, std.mem.asBytes(&rec), off);
            if (n != rec_size) break;
            if (rec.magic != WAL_MAGIC or rec.version != WAL_VERSION) continue;
            if (rec.checksum != recordChecksum(rec)) continue;
            const id = types.FileIdentity{
                .dev = rec.dev,
                .inode = rec.inode,
                .fingerprint = rec.fingerprint,
            };
            const v = CheckpointValue{
                .offset = rec.offset,
                .last_seen_ns = rec.last_seen_ns,
            };
            try self.by_identity.put(types.identityHash(id), v);
            try self.by_inode.put(types.inodeIdentityHash(id), v);
        }
    }
};

const CheckpointValue = struct {
    offset: u64,
    last_seen_ns: i64,
};

const WAL_MAGIC: u32 = 0x3250434b; // "KCP2"
const WAL_VERSION: u16 = 1;

const WalRecord = extern struct {
    magic: u32,
    version: u16,
    _pad0: u16 = 0,
    dev: u64,
    inode: u64,
    fingerprint: u32,
    _pad1: u32 = 0,
    offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
    checksum: u32,
    _pad2: u32 = 0,
};

fn recordChecksum(record: WalRecord) u32 {
    var tmp = record;
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

test "checkpoint lane public API: enqueue and observe offset" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var lane = try Lane.init(testing.allocator, state_dir, 16, 5, 72 * 60 * 60 * 1000);
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

    var tries: usize = 0;
    while (tries < 50 and lane.getOffset(id) == null) : (tries += 1) {
        std.Thread.sleep(2 * std.time.ns_per_ms);
    }
    try testing.expectEqual(@as(?u64, 99), lane.getOffset(id));
}

test "checkpoint lane public API: recovers offset from WAL" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    const id = types.FileIdentity{ .dev = 7, .inode = 8, .fingerprint = 9 };
    {
        var lane = try Lane.init(testing.allocator, state_dir, 16, 5, 72 * 60 * 60 * 1000);
        defer lane.deinit();
        try lane.start();
        _ = try lane.enqueue(.{
            .identity = id,
            .byte_offset = 1234,
            .last_seen_size = 1234,
            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
        });
        var tries: usize = 0;
        while (tries < 50 and lane.getOffset(id) == null) : (tries += 1) {
            std.Thread.sleep(2 * std.time.ns_per_ms);
        }
    }

    var recovered = try Lane.init(testing.allocator, state_dir, 16, 5, 72 * 60 * 60 * 1000);
    defer recovered.deinit();
    try testing.expectEqual(@as(?u64, 1234), recovered.getOffset(id));
}
