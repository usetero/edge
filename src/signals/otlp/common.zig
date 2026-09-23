//! Types and helpers that the OTLP logs, metrics, and traces modules share.

/// Wire format of an OTLP request body.
pub const Format = enum { json, protobuf };

/// Counts from one OTLP batch.
pub const StreamProcessResult = struct {
    was_transformed: bool = false,
    dropped_count: usize,
    original_count: usize,

    pub fn wasModified(self: StreamProcessResult) bool {
        return self.dropped_count > 0 or self.was_transformed;
    }

    pub fn allDropped(self: StreamProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Test output: the bytes written and the counts.
pub const TestRun = struct {
    data: []u8,
    result: StreamProcessResult,
};

/// Remove each item of `list` whose `child` list is empty. Keep the order
/// of the other items.
pub fn pruneEmpty(list: anytype, comptime child: []const u8) void {
    var write_idx: usize = 0;
    for (list.items) |item| {
        if (@field(item, child).items.len > 0) {
            list.items[write_idx] = item;
            write_idx += 1;
        }
    }
    list.shrinkRetainingCapacity(write_idx);
}
