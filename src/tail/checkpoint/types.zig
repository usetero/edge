const std = @import("std");
const tail_types = @import("../types.zig");

pub const Update = struct {
    identity: tail_types.FileIdentity,
    byte_offset: u64,
    last_seen_size: u64,
    last_seen_ns: i64,
};

pub const Value = struct {
    identity: tail_types.FileIdentity,
    offset: u64,
    last_seen_ns: i64,
};

pub fn valueFromUpdate(update: Update) Value {
    return .{
        .identity = update.identity,
        .offset = update.byte_offset,
        .last_seen_ns = update.last_seen_ns,
    };
}

pub const Keys = struct {
    identity: u64,
    inode: u64,
};

pub fn keysFor(identity: tail_types.FileIdentity) Keys {
    return .{
        .identity = tail_types.identityHash(identity),
        .inode = tail_types.inodeIdentityHash(identity),
    };
}

pub fn isExpired(value: Value, ttl_ns: i128, now_ns: i128) bool {
    return @as(i128, value.last_seen_ns) + ttl_ns < now_ns;
}

const testing = std.testing;

test "checkpoint/types: valueFromUpdate copies checkpoint fields" {
    const id = tail_types.FileIdentity{ .dev = 1, .inode = 2, .fingerprint = 3 };
    const update = Update{ .identity = id, .byte_offset = 99, .last_seen_size = 123, .last_seen_ns = 456 };
    const value = valueFromUpdate(update);

    try testing.expectEqual(id.dev, value.identity.dev);
    try testing.expectEqual(@as(u64, 99), value.offset);
    try testing.expectEqual(@as(i64, 456), value.last_seen_ns);
}
