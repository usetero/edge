const tail_types = @import("../types.zig");

pub const Value = struct {
    identity: tail_types.FileIdentity,
    offset: u64,
    last_seen_ns: i64,
};

pub fn isExpired(value: Value, ttl_ns: i128, now_ns: i128) bool {
    return @as(i128, value.last_seen_ns) + ttl_ns < now_ns;
}
