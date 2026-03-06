const std = @import("std");

/// Incremental line framer for byte streams.
///
/// The reader accepts arbitrary chunks, emits newline-delimited records, and
/// carries partial trailing bytes (`remainder`) into the next chunk.
pub const LineReader = struct {
    allocator: std.mem.Allocator,
    read_buf: []u8,
    remainder: std.ArrayList(u8),
    max_line: usize,
    remainder_truncated: bool,

    /// Allocates the reusable read buffer and initializes carry-over state.
    pub fn init(allocator: std.mem.Allocator, read_buf_size: usize, max_line: usize) !LineReader {
        return .{
            .allocator = allocator,
            .read_buf = try allocator.alloc(u8, read_buf_size),
            .remainder = .{},
            .max_line = max_line,
            .remainder_truncated = false,
        };
    }

    pub fn deinit(self: *LineReader) void {
        self.allocator.free(self.read_buf);
        self.remainder.deinit(self.allocator);
    }

    /// Reads `[start_offset, end_offset)` from `file` via pread and emits lines
    /// to `writer`. This keeps offset tracking outside the reader.
    pub fn readRange(self: *LineReader, file: *const std.fs.File, start_offset: u64, end_offset: u64, writer: *std.Io.Writer) !void {
        var offset = start_offset;
        while (offset < end_offset) {
            const remaining = end_offset - offset;
            const to_read: usize = @intCast(@min(remaining, self.read_buf.len));
            const n = try std.posix.pread(file.handle, self.read_buf[0..to_read], @intCast(offset));
            if (n == 0) break;

            try self.ingestChunk(self.read_buf[0..n], writer);
            offset += n;
        }
    }

    /// Ingests one arbitrary chunk and emits all complete lines.
    ///
    /// Incomplete trailing bytes are stored in `remainder` and will be emitted
    /// only once a future chunk provides a newline (or `finish` is called).
    pub fn ingestChunk(self: *LineReader, chunk: []const u8, writer: *std.Io.Writer) !void {
        var start: usize = 0;
        while (std.mem.indexOfScalarPos(u8, chunk, start, '\n')) |newline_idx| {
            const segment = chunk[start..newline_idx];

            if (self.remainder.items.len > 0 or self.remainder_truncated) {
                // Complete a line that started in a previous chunk.
                try self.appendCapped(segment);
                try writeLine(writer, self.remainder.items, self.remainder_truncated);
                self.remainder.clearRetainingCapacity();
                self.remainder_truncated = false;
            } else if (segment.len > self.max_line) {
                // Guard against unbounded line growth.
                try writeLine(writer, segment[0..self.max_line], true);
            } else {
                try writeLine(writer, segment, false);
            }

            start = newline_idx + 1;
        }

        if (start < chunk.len) {
            // Save trailing partial line bytes for the next chunk.
            try self.appendCapped(chunk[start..]);
        }
    }

    /// Flushes a final unterminated line at end-of-stream.
    pub fn finish(self: *LineReader, writer: *std.Io.Writer) !void {
        if (self.remainder.items.len == 0 and !self.remainder_truncated) return;
        try writeLine(writer, self.remainder.items, self.remainder_truncated);
        self.remainder.clearRetainingCapacity();
        self.remainder_truncated = false;
    }

    /// Appends bytes into the carry-over buffer, capping at `max_line`.
    fn appendCapped(self: *LineReader, bytes: []const u8) !void {
        if (bytes.len == 0) return;

        if (self.remainder.items.len >= self.max_line) {
            self.remainder_truncated = true;
            return;
        }

        const remaining = self.max_line - self.remainder.items.len;
        const copy_len = @min(remaining, bytes.len);
        try self.remainder.appendSlice(self.allocator, bytes[0..copy_len]);

        if (copy_len < bytes.len) {
            self.remainder_truncated = true;
        }
    }

    /// Writes one logical line plus newline terminator.
    /// `truncated` is currently informational; call sites may use it later.
    fn writeLine(writer: *std.Io.Writer, line: []const u8, truncated: bool) !void {
        _ = truncated;
        try writer.writeAll(line);
        try writer.writeByte('\n');
    }
};

const testing = std.testing;

test "LineReader public API: ingestChunk + finish frames across chunk boundaries" {
    var reader = try LineReader.init(testing.allocator, 8, 1024);
    defer reader.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    try reader.ingestChunk("a\nb", &out.writer);
    try reader.ingestChunk("c\n", &out.writer);
    try reader.finish(&out.writer);

    try testing.expectEqualStrings("a\nbc\n", out.written());
}

test "LineReader public API: ingestChunk enforces max_line cap" {
    var reader = try LineReader.init(testing.allocator, 32, 4);
    defer reader.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    try reader.ingestChunk("123456\nok\n", &out.writer);
    try reader.finish(&out.writer);

    try testing.expectEqualStrings("1234\nok\n", out.written());
}

test "LineReader public API: readRange emits lines from file range" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    {
        const file = try tmp_dir.dir.createFile("input.log", .{});
        defer file.close();
        try file.writeAll("hello\nworld\n");
    }

    const file = try tmp_dir.dir.openFile("input.log", .{ .mode = .read_only });
    defer file.close();

    const size = (try file.stat()).size;
    var reader = try LineReader.init(testing.allocator, 5, 1024);
    defer reader.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    try reader.readRange(&file, 0, size, &out.writer);
    try reader.finish(&out.writer);

    try testing.expectEqualStrings("hello\nworld\n", out.written());
}
