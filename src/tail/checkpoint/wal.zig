const std = @import("std");
const checkpoint_types = @import("types.zig");

const WAL_MAGIC: u32 = 0x4C415757; // "WAWL"
const WAL_VERSION: u16 = 1;

const WalRecord = extern struct {
    magic: u32,
    version: u16,
    _pad0: u16 = 0,
    lsn: u64,
    dev: u64,
    inode: u64,
    fingerprint: u32,
    _pad1: u32 = 0,
    offset: u64,
    last_seen_ns: i64,
    checksum: u32,
    _pad2: u32 = 0,
};

pub const ReplayEntry = struct {
    lsn: u64,
    value: checkpoint_types.Value,
};

pub const ReplayResult = struct {
    entries: std.ArrayList(ReplayEntry),
    next_lsn: u64,

    pub fn deinit(self: *ReplayResult, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }
};

pub const Wal = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    path: []u8,
    write_offset: u64,

    pub fn init(allocator: std.mem.Allocator, state_dir: []const u8) !Wal {
        const path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.wal" });
        errdefer allocator.free(path);

        const file = std.fs.cwd().openFile(path, .{ .mode = .read_write }) catch |err| switch (err) {
            error.FileNotFound => try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false }),
            else => return err,
        };
        errdefer file.close();

        return .{
            .allocator = allocator,
            .file = file,
            .path = path,
            .write_offset = try file.getEndPos(),
        };
    }

    pub fn deinit(self: *Wal) void {
        self.file.close();
        self.allocator.free(self.path);
    }

    pub fn append(self: *Wal, lsn: u64, value: checkpoint_types.Value) !void {
        var rec = std.mem.zeroInit(WalRecord, .{});
        rec.magic = WAL_MAGIC;
        rec.version = WAL_VERSION;
        rec.lsn = lsn;
        rec.dev = value.identity.dev;
        rec.inode = value.identity.inode;
        rec.fingerprint = value.identity.fingerprint;
        rec.offset = value.offset;
        rec.last_seen_ns = value.last_seen_ns;
        rec.checksum = recordChecksum(rec);

        try pwriteAll(self.file, std.mem.asBytes(&rec), self.write_offset);
        self.write_offset += @sizeOf(WalRecord);
    }

    pub fn sync(self: *Wal) !void {
        try std.posix.fdatasync(self.file.handle);
    }

    pub fn replay(self: *Wal, allocator: std.mem.Allocator) !ReplayResult {
        const end = try self.file.getEndPos();
        const rec_size = @sizeOf(WalRecord);

        var out = ReplayResult{
            .entries = .{},
            .next_lsn = 1,
        };
        errdefer out.deinit(allocator);

        var off: u64 = 0;
        while (off + rec_size <= end) : (off += rec_size) {
            var rec: WalRecord = undefined;
            const n = try std.posix.pread(self.file.handle, std.mem.asBytes(&rec), off);
            if (n != rec_size) break;
            if (rec.magic != WAL_MAGIC or rec.version != WAL_VERSION) continue;
            if (rec.checksum != recordChecksum(rec)) continue;

            try out.entries.append(allocator, .{
                .lsn = rec.lsn,
                .value = .{
                    .identity = .{
                        .dev = rec.dev,
                        .inode = rec.inode,
                        .fingerprint = rec.fingerprint,
                    },
                    .offset = rec.offset,
                    .last_seen_ns = rec.last_seen_ns,
                },
            });
            if (out.next_lsn <= rec.lsn) out.next_lsn = rec.lsn + 1;
        }

        self.write_offset = end;
        return out;
    }

    pub fn reset(self: *Wal) !void {
        try self.file.setEndPos(0);
        self.write_offset = 0;
        try self.sync();
    }
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
