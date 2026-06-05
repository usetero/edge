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
    io: std.Io,
    path: []u8,
    tmp_path: []u8,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, state_dir: []const u8) !Snapshot {
        const path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.snap" });
        errdefer allocator.free(path);
        const tmp_path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.snap.tmp" });
        errdefer allocator.free(tmp_path);

        return .{
            .allocator = allocator,
            .io = io,
            .path = path,
            .tmp_path = tmp_path,
        };
    }

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.path);
        self.allocator.free(self.tmp_path);
    }

    pub fn load(self: *Snapshot, allocator: std.mem.Allocator) !std.ArrayList(checkpoint_types.Value) {
        var out: std.ArrayList(checkpoint_types.Value) = .empty;

        const file = std.Io.Dir.cwd().openFile(self.io, self.path, .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return out,
            else => return err,
        };
        defer file.close(self.io);

        var header: SnapshotHeader = undefined;
        const got_header = try file.readPositionalAll(self.io, std.mem.asBytes(&header), 0);
        if (got_header != @sizeOf(SnapshotHeader)) return out;
        if (header.magic != SNAP_MAGIC or header.version != SNAP_VERSION) return out;

        try out.ensureTotalCapacity(allocator, @intCast(header.count));

        var off: u64 = @sizeOf(SnapshotHeader);
        var i: u64 = 0;
        while (i < header.count) : (i += 1) {
            var entry: SnapshotEntry = undefined;
            const n = try file.readPositionalAll(self.io, std.mem.asBytes(&entry), off);
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
        var file = try std.Io.Dir.cwd().createFile(self.io, self.tmp_path, .{ .read = true, .truncate = true });
        defer file.close(self.io);

        var header = std.mem.zeroInit(SnapshotHeader, .{});
        header.magic = SNAP_MAGIC;
        header.version = SNAP_VERSION;
        header.count = values.len;

        var off: u64 = 0;
        try file.writePositionalAll(self.io, std.mem.asBytes(&header), off);
        off += @sizeOf(SnapshotHeader);

        for (values) |value| {
            var entry = std.mem.zeroInit(SnapshotEntry, .{});
            entry.dev = value.identity.dev;
            entry.inode = value.identity.inode;
            entry.fingerprint = value.identity.fingerprint;
            entry.offset = value.offset;
            entry.last_seen_ns = value.last_seen_ns;
            entry.checksum = entryChecksum(entry);
            try file.writePositionalAll(self.io, std.mem.asBytes(&entry), off);
            off += @sizeOf(SnapshotEntry);
        }

        try file.sync(self.io);
        try std.Io.Dir.cwd().rename(self.tmp_path, std.Io.Dir.cwd(), self.path, self.io);
    }
};

fn entryChecksum(entry: SnapshotEntry) u32 {
    var tmp = entry;
    tmp.checksum = 0;
    return std.hash.Crc32.hash(std.mem.asBytes(&tmp));
}
