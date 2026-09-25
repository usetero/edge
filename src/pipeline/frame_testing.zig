//! Test helpers for the framers. Only tests import this file.
const std = @import("std");
const framer_mod = @import("framer.zig");

const testing = std.testing;

/// Records every record it sees. A record that contains "drop" is dropped.
/// A record that contains "swap" is replaced with `replacement`.
pub const TestSink = struct {
    seen: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,
    replacement: []const u8,

    pub fn deinit(self: *TestSink) void {
        for (self.seen.items) |record| self.allocator.free(record);
        self.seen.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn onRecord(self: *TestSink, bytes: []const u8) !framer_mod.Decision {
        try self.seen.append(self.allocator, try self.allocator.dupe(u8, bytes));
        if (std.mem.indexOf(u8, bytes, "drop") != null) return .drop;
        if (std.mem.indexOf(u8, bytes, "swap") != null) return .{ .replace = self.replacement };
        return .keep;
    }
};

/// Feeds `input` to a framer of type `F` in chunks of `chunk_len` bytes.
/// Returns the framed output. The caller owns the result.
pub fn runChunked(
    comptime F: type,
    input: []const u8,
    chunk_len: usize,
    scratch_len: usize,
    sink: *TestSink,
) ![]u8 {
    const scratch = try testing.allocator.alloc(u8, scratch_len);
    defer testing.allocator.free(scratch);
    var framer: F = .init(scratch);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();

    var offset: usize = 0;
    while (offset < input.len) {
        const end = @min(offset + chunk_len, input.len);
        try framer.ingest(input[offset..end], &out.writer, sink);
        offset = end;
    }
    try framer.finish(&out.writer, sink);
    return out.toOwnedSlice();
}
