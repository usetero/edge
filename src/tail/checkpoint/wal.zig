const std = @import("std");
const t = @import("types.zig");

pub const WalStore = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    next_lsn: u64,

    pub fn init(allocator: std.mem.Allocator, state_dir: []const u8) !WalStore {
        try std.fs.cwd().makePath(state_dir);

        const path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.wal" });
        defer allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
        errdefer file.close();

        const header_size = @sizeOf(t.WalHeader);
        const cur_size = try file.getEndPos();
        if (cur_size < header_size) {
            const hdr = t.WalHeader{ .magic = t.WAL_MAGIC, .version = t.VERSION };
            try pwriteAll(file, std.mem.asBytes(&hdr), 0);
            try file.sync();
            return .{ .allocator = allocator, .file = file, .next_lsn = 1 };
        }

        var hdr: t.WalHeader = undefined;
        _ = try std.posix.pread(file.handle, std.mem.asBytes(&hdr), 0);
        if (hdr.magic != t.WAL_MAGIC) return error.InvalidWalMagic;
        if (hdr.version != t.VERSION) return error.UnsupportedWalVersion;

        const entry_size = @sizeOf(t.WalEntry);
        const entries = (cur_size - header_size) / entry_size;
        return .{ .allocator = allocator, .file = file, .next_lsn = @intCast(entries + 1) };
    }

    pub fn deinit(self: *WalStore) void {
        self.file.close();
    }

    pub fn append(self: *WalStore, entry_in: t.WalEntry) !t.WalEntry {
        var entry = entry_in;
        entry.lsn = self.next_lsn;
        entry.checksum = t.walChecksum(entry);

        const off = try self.file.getEndPos();
        try pwriteAll(self.file, std.mem.asBytes(&entry), off);
        try self.file.sync();

        self.next_lsn += 1;
        return entry;
    }

    pub fn forEach(self: *WalStore, ctx: anytype, callback: fn (@TypeOf(ctx), t.WalEntry) anyerror!void) !void {
        const header_size = @sizeOf(t.WalHeader);
        const entry_size = @sizeOf(t.WalEntry);
        const end = try self.file.getEndPos();

        var off: u64 = header_size;
        while (off + entry_size <= end) : (off += entry_size) {
            var entry: t.WalEntry = undefined;
            const n = try std.posix.pread(self.file.handle, std.mem.asBytes(&entry), off);
            if (n != entry_size) return error.ShortRead;
            if (entry.checksum != t.walChecksum(entry)) continue;
            try callback(ctx, entry);
        }
    }

    pub fn truncate(self: *WalStore) !void {
        try self.file.setEndPos(@sizeOf(t.WalHeader));
        try self.file.sync();
        self.next_lsn = 1;
    }
};

fn pwriteAll(file: std.fs.File, bytes: []const u8, offset: u64) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const n = try std.posix.pwrite(file.handle, bytes[written..], offset + written);
        if (n == 0) return error.Unexpected;
        written += n;
    }
}

const testing = std.testing;

test "WalStore public API: append/iterate/truncate" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var wal = try WalStore.init(testing.allocator, state_dir);
    defer wal.deinit();

    var e = std.mem.zeroInit(t.WalEntry, .{});
    e.timestamp_ns = 1;
    e.identity_hash = 2;
    e.identity = .{ .dev = 10, .inode = 20, .fingerprint = 30 };
    e.slot_idx = 3;
    e.byte_offset = 4;
    e.last_seen_size = 5;

    _ = try wal.append(e);
    _ = try wal.append(e);

    const Ctx = struct { count: usize = 0 };
    var ctx = Ctx{};

    try wal.forEach(&ctx, struct {
        fn cb(c: *Ctx, _: t.WalEntry) !void {
            c.count += 1;
        }
    }.cb);

    try testing.expectEqual(@as(usize, 2), ctx.count);

    try wal.truncate();
    ctx.count = 0;
    try wal.forEach(&ctx, struct {
        fn cb(c: *Ctx, _: t.WalEntry) !void {
            c.count += 1;
        }
    }.cb);
    try testing.expectEqual(@as(usize, 0), ctx.count);
}

test "WalStore public API: forEach skips corrupted checksum entries" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var wal = try WalStore.init(testing.allocator, state_dir);
    defer wal.deinit();

    var e = std.mem.zeroInit(t.WalEntry, .{});
    e.timestamp_ns = 1;
    e.identity_hash = 2;
    e.identity = .{ .dev = 1, .inode = 2, .fingerprint = 3 };
    e.slot_idx = 0;
    e.byte_offset = 100;
    e.last_seen_size = 100;
    _ = try wal.append(e);
    _ = try wal.append(e);

    // Corrupt second entry checksum.
    const off_second = @sizeOf(t.WalHeader) + @sizeOf(t.WalEntry);
    var second: t.WalEntry = undefined;
    _ = try std.posix.pread(wal.file.handle, std.mem.asBytes(&second), off_second);
    second.checksum +%= 1;
    try pwriteAll(wal.file, std.mem.asBytes(&second), off_second);
    try wal.file.sync();

    const Ctx = struct { count: usize = 0 };
    var ctx = Ctx{};
    try wal.forEach(&ctx, struct {
        fn cb(c: *Ctx, _: t.WalEntry) !void {
            c.count += 1;
        }
    }.cb);
    try testing.expectEqual(@as(usize, 1), ctx.count);
}
