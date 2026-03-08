const std = @import("std");
const types = @import("types.zig");

/// Incremental newline framer used by edge-tail.
///
/// This module is intentionally IO-interface based so it can be reused for:
/// - stdin streaming
/// - file chunk streaming
/// - tests with in-memory writers
pub const LineFramer = struct {
    allocator: std.mem.Allocator,
    read_buf: []u8,
    remainder: std.ArrayList(u8),
    max_line: usize,
    remainder_truncated: bool,

    pub fn init(allocator: std.mem.Allocator, read_buf_size: usize, max_line: usize) !LineFramer {
        return .{
            .allocator = allocator,
            .read_buf = try allocator.alloc(u8, read_buf_size),
            .remainder = .{},
            .max_line = max_line,
            .remainder_truncated = false,
        };
    }

    pub fn deinit(self: *LineFramer) void {
        self.allocator.free(self.read_buf);
        self.remainder.deinit(self.allocator);
    }

    pub const LineFilterFn = fn (ctx: *anyopaque, line: []const u8, meta: types.LineMeta) anyerror!bool;

    /// Ingests a byte chunk and emits complete newline-delimited segments.
    ///
    /// Fast path uses SIMD blocks (16-byte vectors): compare each lane to `'\n'`,
    /// bit-cast the boolean vector to a bitmask, then walk set bits via `ctz`.
    /// Each set bit yields one newline index. We then route each segment through
    /// `emitSegment`, which keeps all existing truncation/remainder semantics.
    ///
    /// Tail bytes that do not end with a newline are appended to `remainder` and
    /// will be completed by a later chunk or `finish()`.
    pub fn ingestChunk(
        self: *LineFramer,
        chunk: []const u8,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        var start: usize = 0;
        var i: usize = 0;
        const Lanes = 16;
        const V = @Vector(Lanes, u8);
        const M = @Vector(Lanes, bool);
        const Bits = std.meta.Int(.unsigned, Lanes);
        const needle: V = @splat('\n');

        while (i + Lanes <= chunk.len) : (i += Lanes) {
            const vec_ptr: *align(1) const V = @ptrCast(chunk[i .. i + Lanes].ptr);
            const mask: M = vec_ptr.* == needle;
            var bits: Bits = @bitCast(mask);
            while (bits != 0) {
                const rel: usize = @intCast(@ctz(bits));
                const newline_idx = i + rel;
                try self.emitSegment(chunk[start..newline_idx], writer, filter_ctx, filter_fn);
                start = newline_idx + 1;
                bits &= bits - 1;
            }
        }

        while (i < chunk.len) : (i += 1) {
            if (chunk[i] != '\n') continue;
            try self.emitSegment(chunk[start..i], writer, filter_ctx, filter_fn);
            start = i + 1;
        }

        if (start < chunk.len) {
            try self.appendCapped(chunk[start..]);
        }
    }

    pub fn finish(
        self: *LineFramer,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        if (self.remainder.items.len == 0 and !self.remainder_truncated) return;
        try emitLine(writer, self.remainder.items, .{ .truncated = self.remainder_truncated }, filter_ctx, filter_fn);
        self.remainder.clearRetainingCapacity();
        self.remainder_truncated = false;
    }

    /// Pumps from any Reader endpoint into this framer with no per-iteration
    /// allocations by reading directly into the reusable `read_buf`.
    pub fn pump(
        self: *LineFramer,
        allocator: std.mem.Allocator,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        read_limit: usize,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        _ = allocator;
        const max_chunk = @min(read_limit, self.read_buf.len);
        while (true) {
            const n = try reader.readSliceShort(self.read_buf[0..max_chunk]);
            if (n == 0) break;
            try self.ingestChunk(self.read_buf[0..n], writer, filter_ctx, filter_fn);
        }

        try self.finish(writer, filter_ctx, filter_fn);
    }

    /// Reads `[start_offset, end_offset)` from `file` using pread and frames
    /// newline-delimited lines to the writer.
    pub fn readRange(
        self: *LineFramer,
        file: *const std.fs.File,
        start_offset: u64,
        end_offset: u64,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        var offset = start_offset;
        while (offset < end_offset) {
            const remaining = end_offset - offset;
            const to_read: usize = @intCast(@min(remaining, self.read_buf.len));
            const n = try std.posix.pread(file.handle, self.read_buf[0..to_read], @intCast(offset));
            if (n == 0) break;

            try self.ingestChunk(self.read_buf[0..n], writer, filter_ctx, filter_fn);
            offset += n;
        }
    }

    fn appendCapped(self: *LineFramer, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        if (self.remainder.items.len >= self.max_line) {
            self.remainder_truncated = true;
            return;
        }

        const remaining = self.max_line - self.remainder.items.len;
        const copy_len = @min(remaining, bytes.len);
        try self.remainder.appendSlice(self.allocator, bytes[0..copy_len]);
        if (copy_len < bytes.len) self.remainder_truncated = true;
    }

    fn emitSegment(
        self: *LineFramer,
        segment: []const u8,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        if (self.remainder.items.len > 0 or self.remainder_truncated) {
            try self.appendCapped(segment);
            try emitLine(writer, self.remainder.items, .{ .truncated = self.remainder_truncated }, filter_ctx, filter_fn);
            self.remainder.clearRetainingCapacity();
            self.remainder_truncated = false;
            return;
        }
        if (segment.len > self.max_line) {
            try emitLine(writer, segment[0..self.max_line], .{ .truncated = true }, filter_ctx, filter_fn);
            return;
        }
        try emitLine(writer, segment, .{}, filter_ctx, filter_fn);
    }

    fn emitLine(
        writer: *std.Io.Writer,
        line: []const u8,
        meta: types.LineMeta,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        const keep = try filter_fn(filter_ctx, line, meta);
        if (!keep) return;
        try writer.writeAll(line);
        try writer.writeByte('\n');
    }
};

const testing = std.testing;

fn keepAll(_: *anyopaque, _: []const u8, _: types.LineMeta) !bool {
    return true;
}

test "framer public API: frames lines across chunk boundaries" {
    var framer = try LineFramer.init(testing.allocator, 8, 1024);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.ingestChunk("a\nb", &out.writer, &ctx, keepAll);
    try framer.ingestChunk("c\n", &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("a\nbc\n", out.written());
}

test "framer public API: enforces max line cap" {
    var framer = try LineFramer.init(testing.allocator, 8, 4);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.ingestChunk("123456\nok\n", &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("1234\nok\n", out.written());
}

test "framer public API: simd scanner handles multiple newlines in one vector" {
    var framer = try LineFramer.init(testing.allocator, 64, 1024);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.ingestChunk("a\nb\nc\nd\ne\nf\ng\nh\n", &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("a\nb\nc\nd\ne\nf\ng\nh\n", out.written());
}

test "framer public API: readRange emits file bytes as lines" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("in.log", .{});
        defer f.close();
        try f.writeAll("x\ny\n");
    }

    const in_path = try tmp.dir.realpathAlloc(testing.allocator, "in.log");
    defer testing.allocator.free(in_path);

    const file = try std.fs.openFileAbsolute(in_path, .{ .mode = .read_only });
    defer file.close();
    const size = (try file.stat()).size;

    var framer = try LineFramer.init(testing.allocator, 8, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.readRange(&file, 0, size, &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);
    try testing.expectEqualStrings("x\ny\n", out.written());
}
