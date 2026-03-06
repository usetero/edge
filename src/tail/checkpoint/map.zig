const std = @import("std");
const t = @import("types.zig");

pub const MapStore = struct {
    allocator: std.mem.Allocator,
    file: std.fs.File,
    slot_count: usize,

    pub fn init(allocator: std.mem.Allocator, state_dir: []const u8, slot_count: usize) !MapStore {
        try std.fs.cwd().makePath(state_dir);

        const path = try std.fs.path.join(allocator, &.{ state_dir, "checkpoint.map" });
        defer allocator.free(path);

        const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
        errdefer file.close();

        const header_size = @sizeOf(t.MapHeader);
        const slot_size = @sizeOf(t.Slot);
        const expected_size: u64 = header_size + slot_size * slot_count;
        const cur_size = try file.getEndPos();

        if (cur_size < header_size) {
            const header = t.MapHeader{
                .magic = t.MAP_MAGIC,
                .version = t.VERSION,
                .slot_count = @intCast(slot_count),
            };
            try pwriteAll(file, std.mem.asBytes(&header), 0);
            var zero_slot: t.Slot = std.mem.zeroInit(t.Slot, .{});
            var i: usize = 0;
            while (i < slot_count) : (i += 1) {
                try pwriteAll(file, std.mem.asBytes(&zero_slot), header_size + i * slot_size);
            }
            try file.sync();
        } else {
            var header: t.MapHeader = undefined;
            _ = try std.posix.pread(file.handle, std.mem.asBytes(&header), 0);
            if (header.magic != t.MAP_MAGIC) return error.InvalidMapMagic;
            if (header.version != t.VERSION) return error.UnsupportedMapVersion;
        }

        if (cur_size != expected_size) {
            try file.setEndPos(expected_size);
        }

        return .{
            .allocator = allocator,
            .file = file,
            .slot_count = slot_count,
        };
    }

    pub fn deinit(self: *MapStore) void {
        self.file.close();
    }

    pub fn readSlot(self: *MapStore, idx: usize) !t.Slot {
        if (idx >= self.slot_count) return error.SlotOutOfRange;
        var slot: t.Slot = undefined;
        const off = @sizeOf(t.MapHeader) + idx * @sizeOf(t.Slot);
        const n = try std.posix.pread(self.file.handle, std.mem.asBytes(&slot), off);
        if (n != @sizeOf(t.Slot)) return error.ShortRead;
        return slot;
    }

    pub fn writeSlot(self: *MapStore, idx: usize, slot: t.Slot) !void {
        if (idx >= self.slot_count) return error.SlotOutOfRange;
        const off = @sizeOf(t.MapHeader) + idx * @sizeOf(t.Slot);
        try pwriteAll(self.file, std.mem.asBytes(&slot), off);
    }

    pub fn sync(self: *MapStore) !void {
        try self.file.sync();
    }

    pub fn clearSlot(self: *MapStore, idx: usize) !void {
        const zero: t.Slot = std.mem.zeroInit(t.Slot, .{});
        try self.writeSlot(idx, zero);
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

test "MapStore public API: init/write/read/clear" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const state_dir = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(state_dir);

    var store = try MapStore.init(testing.allocator, state_dir, 8);
    defer store.deinit();

    var slot = std.mem.zeroInit(t.Slot, .{});
    slot.sequence = 2;
    slot.identity = .{ .dev = 1, .inode = 2, .fingerprint = 3 };
    slot.byte_offset = 42;
    slot.last_seen_size = 42;
    slot.last_seen_ns = 123;
    slot.lsn = 7;
    slot.checksum = t.slotChecksum(slot);

    try store.writeSlot(0, slot);
    const got = try store.readSlot(0);
    try testing.expectEqual(@as(u64, 42), got.byte_offset);

    try store.clearSlot(0);
    const cleared = try store.readSlot(0);
    try testing.expectEqual(@as(u64, 0), cleared.byte_offset);
}
