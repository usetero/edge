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
    offsets: std.AutoHashMap(u64, u64),
    last_seen: std.AutoHashMap(u64, i64),
    offsets_inode: std.AutoHashMap(u64, u64),
    last_seen_inode: std.AutoHashMap(u64, i64),
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
        const wal_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.v2.wal" });
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
            .offsets = std.AutoHashMap(u64, u64).init(allocator),
            .last_seen = std.AutoHashMap(u64, i64).init(allocator),
            .offsets_inode = std.AutoHashMap(u64, u64).init(allocator),
            .last_seen_inode = std.AutoHashMap(u64, i64).init(allocator),
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
        self.offsets.deinit();
        self.last_seen.deinit();
        self.offsets_inode.deinit();
        self.last_seen_inode.deinit();
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
        const key = identityHash(identity);
        const inode_key = inodeIdentityHash(identity);
        const now = std.time.nanoTimestamp();
        self.data_mutex.lock();
        defer self.data_mutex.unlock();
        if (self.offsets.get(key)) |off| {
            const seen = self.last_seen.get(key) orelse 0;
            if (@as(i128, seen) + self.ttl_ns >= now) return off;
            _ = self.offsets.remove(key);
            _ = self.last_seen.remove(key);
        }
        if (self.offsets_inode.get(inode_key)) |off| {
            const seen = self.last_seen_inode.get(inode_key) orelse 0;
            if (@as(i128, seen) + self.ttl_ns >= now) return off;
            _ = self.offsets_inode.remove(inode_key);
            _ = self.last_seen_inode.remove(inode_key);
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

        const key = identityHash(update.identity);
        const inode_key = inodeIdentityHash(update.identity);
        self.data_mutex.lock();
        self.offsets.put(key, update.byte_offset) catch {};
        self.last_seen.put(key, update.last_seen_ns) catch {};
        self.offsets_inode.put(inode_key, update.byte_offset) catch {};
        self.last_seen_inode.put(inode_key, update.last_seen_ns) catch {};
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
            try self.offsets.put(identityHash(id), rec.offset);
            try self.last_seen.put(identityHash(id), rec.last_seen_ns);
            try self.offsets_inode.put(inodeIdentityHash(id), rec.offset);
            try self.last_seen_inode.put(inodeIdentityHash(id), rec.last_seen_ns);
        }
    }
};

fn identityHash(identity: types.FileIdentity) u64 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(std.mem.asBytes(&identity.dev));
    hasher.update(std.mem.asBytes(&identity.inode));
    hasher.update(std.mem.asBytes(&identity.fingerprint));
    return hasher.final();
}

fn inodeIdentityHash(identity: types.FileIdentity) u64 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(std.mem.asBytes(&identity.dev));
    hasher.update(std.mem.asBytes(&identity.inode));
    return hasher.final();
}

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
