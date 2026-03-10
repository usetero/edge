const std = @import("std");
const checkpoint_types = @import("types.zig");

const SNAP_MAGIC: u32 = 0x534B5043; // "CPKS"
const SNAP_VERSION: u16 = 1;

const SnapshotHeader = extern struct {
    magic: u32,
    version: u16,
    _pad: u16 = 0,
    count: u64,
};

const SnapshotEntry = extern struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,
    _pad0: u32 = 0,
    offset: u64,
    last_seen_ns: i64,
    checksum: u32,
    _pad1: u32 = 0,
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    path: []u8,
    tmp_path: []u8,

    pub fn init(allocator: std.mem.Allocator, state_dir: []const u8) !Snapshot {
        const path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.snap" });
        errdefer allocator.free(path);
        const tmp_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.snap.tmp" });
        errdefer allocator.free(tmp_path);

        return .{
            .allocator = allocator,
            .path = path,
            .tmp_path = tmp_path,
        };
    }

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.path);
        self.allocator.free(self.tmp_path);
    }

    pub fn load(self: *Snapshot, allocator: std.mem.Allocator) !std.ArrayList(checkpoint_types.Value) {
        var out: std.ArrayList(checkpoint_types.Value) = .{};

        const file = std.fs.cwd().openFile(self.path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return out,
            else => return err,
        };
        defer file.close();

        var header: SnapshotHeader = undefined;
        const got_header = try std.posix.pread(file.handle, std.mem.asBytes(&header), 0);
        if (got_header != @sizeOf(SnapshotHeader)) return out;
        if (header.magic != SNAP_MAGIC or header.version != SNAP_VERSION) return out;

        try out.ensureTotalCapacity(allocator, @intCast(header.count));

        var off: u64 = @sizeOf(SnapshotHeader);
        var i: u64 = 0;
        while (i < header.count) : (i += 1) {
            var entry: SnapshotEntry = undefined;
            const n = try std.posix.pread(file.handle, std.mem.asBytes(&entry), off);
            if (n != @sizeOf(SnapshotEntry)) break;
            off += @sizeOf(SnapshotEntry);

            if (entry.checksum != entryChecksum(entry)) continue;
            try out.append(allocator, .{
                .identity = .{
                    .dev = entry.dev,
                    .inode = entry.inode,
                    .fingerprint = entry.fingerprint,
                },
                .offset = entry.offset,
                .last_seen_ns = entry.last_seen_ns,
            });
        }

        return out;
    }

    pub fn write(self: *Snapshot, values: []const checkpoint_types.Value) !void {
        var file = try std.fs.cwd().createFile(self.tmp_path, .{ .read = true, .truncate = true });
        defer file.close();

        var header = std.mem.zeroInit(SnapshotHeader, .{});
        header.magic = SNAP_MAGIC;
        header.version = SNAP_VERSION;
        header.count = values.len;

        var off: u64 = 0;
        try pwriteAll(file, std.mem.asBytes(&header), off);
        off += @sizeOf(SnapshotHeader);

        for (values) |value| {
            var entry = std.mem.zeroInit(SnapshotEntry, .{});
            entry.dev = value.identity.dev;
            entry.inode = value.identity.inode;
            entry.fingerprint = value.identity.fingerprint;
            entry.offset = value.offset;
            entry.last_seen_ns = value.last_seen_ns;
            entry.checksum = entryChecksum(entry);
            try pwriteAll(file, std.mem.asBytes(&entry), off);
            off += @sizeOf(SnapshotEntry);
        }

        try file.sync();
        try std.fs.cwd().rename(self.tmp_path, self.path);
    }
};

fn entryChecksum(entry: SnapshotEntry) u32 {
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
