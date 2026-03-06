const std = @import("std");

pub const MAP_MAGIC: u32 = 0x54414d43; // "CMAT"
pub const WAL_MAGIC: u32 = 0x4c415754; // "TWAL"
pub const VERSION: u16 = 1;

pub const FileIdentity = extern struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,
    fingerprint_offset: u32 = 0,
};

pub const MapHeader = extern struct {
    magic: u32,
    version: u16,
    slot_count: u16,
    _pad: [56]u8 = [_]u8{0} ** 56,
};

pub const Slot = extern struct {
    sequence: u64,
    identity: FileIdentity,
    byte_offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
    lsn: u64,
    checksum: u32,
    _pad: [76]u8 = [_]u8{0} ** 76,
};

pub const WalHeader = extern struct {
    magic: u32,
    version: u16,
    _pad: [58]u8 = [_]u8{0} ** 58,
};

pub const WalEntry = extern struct {
    lsn: u64,
    timestamp_ns: i64,
    identity_hash: u64,
    identity: FileIdentity,
    slot_idx: u16,
    _pad0: [6]u8 = [_]u8{0} ** 6,
    byte_offset: u64,
    last_seen_size: u64,
    checksum: u32,
    _pad1: [4]u8 = [_]u8{0} ** 4,
};

pub fn identityHash(identity: FileIdentity) u64 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(std.mem.asBytes(&identity.dev));
    hasher.update(std.mem.asBytes(&identity.inode));
    hasher.update(std.mem.asBytes(&identity.fingerprint));
    hasher.update(std.mem.asBytes(&identity.fingerprint_offset));
    return hasher.final();
}

pub fn slotChecksum(slot: Slot) u32 {
    var tmp = slot;
    tmp.checksum = 0;
    return std.hash.Crc32.hash(std.mem.asBytes(&tmp));
}

pub fn walChecksum(entry: WalEntry) u32 {
    var tmp = entry;
    tmp.checksum = 0;
    return std.hash.Crc32.hash(std.mem.asBytes(&tmp));
}

const testing = std.testing;

test "types public API: identityHash stable" {
    const id = FileIdentity{ .dev = 1, .inode = 2, .fingerprint = 3 };
    try testing.expectEqual(identityHash(id), identityHash(id));
}

test "types public API: checksum helpers change with payload" {
    var slot = Slot{
        .sequence = 2,
        .identity = .{ .dev = 1, .inode = 2, .fingerprint = 3 },
        .byte_offset = 10,
        .last_seen_size = 10,
        .last_seen_ns = 11,
        .lsn = 1,
        .checksum = 0,
    };
    const c1 = slotChecksum(slot);
    slot.byte_offset = 20;
    const c2 = slotChecksum(slot);
    try testing.expect(c1 != c2);

    var e = WalEntry{
        .lsn = 1,
        .timestamp_ns = 5,
        .identity_hash = 7,
        .identity = .{ .dev = 1, .inode = 2, .fingerprint = 3 },
        .slot_idx = 1,
        .byte_offset = 10,
        .last_seen_size = 12,
        .checksum = 0,
    };
    const w1 = walChecksum(e);
    e.byte_offset = 11;
    const w2 = walChecksum(e);
    try testing.expect(w1 != w2);
}
