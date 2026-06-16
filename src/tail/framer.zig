//! Line framing for edge-tail, implemented on the pipeline's SIMD newline
//! framer (PLAN.md §9 Phase 6): `pipeline/frame_ndjson.zig` is the one line
//! scanner in the tree; this file is a thin adapter that keeps the tail
//! call-sites' boolean keep/drop filter shape.
//!
//! Convergence semantics (changed from the retired tail-local scanner, see
//! .rewrite/test-exceptions.md):
//! - Lines longer than `max_line` FAIL OPEN: forwarded verbatim, unevaluated
//!   (PLAN §6.5.3). The old scanner truncated them — mutating log data — and
//!   nothing ever consumed the `LineMeta.truncated` flag it set.
//! - A trailing line without a newline is emitted without one (byte
//!   fidelity); the old scanner appended a newline.
const std = @import("std");
const types = @import("types.zig");
const pipeline_framer = @import("../pipeline/framer.zig");
const frame_ndjson = @import("../pipeline/frame_ndjson.zig");

pub const LineFramer = struct {
    allocator: std.mem.Allocator,
    /// Reusable read staging for pump/readRange and the read schedulers
    /// (they size positional reads off `read_buf.len`).
    read_buf: []u8,
    /// Scratch for chunk-spanning lines, sized to the eval bound: a line must
    /// fit here to be evaluated, otherwise it fails open.
    scratch: []u8,
    inner: frame_ndjson.NdjsonFramer,

    pub fn init(allocator: std.mem.Allocator, read_buf_size: usize, max_line: usize) !LineFramer {
        const read_buf = try allocator.alloc(u8, read_buf_size);
        errdefer allocator.free(read_buf);
        const scratch = try allocator.alloc(u8, max_line);
        return .{
            .allocator = allocator,
            .read_buf = read_buf,
            .scratch = scratch,
            .inner = .init(scratch),
        };
    }

    pub fn deinit(self: *LineFramer) void {
        self.allocator.free(self.read_buf);
        self.allocator.free(self.scratch);
        self.* = undefined;
    }

    pub const LineFilterFn = fn (ctx: *anyopaque, line: []const u8, meta: types.LineMeta) anyerror!bool;

    /// Bridges the tail boolean filter onto the pipeline sink contract.
    const FilterSink = struct {
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,

        pub fn onRecord(self: *const FilterSink, bytes: []const u8) !pipeline_framer.Decision {
            const keep = try self.filter_fn(self.filter_ctx, bytes, .{});
            return if (keep) .keep else .drop;
        }
    };

    /// Ingests a byte chunk and emits complete newline-delimited lines that
    /// pass the filter. Partial tail bytes buffer in scratch until a later
    /// chunk or `finish()` completes them.
    pub fn ingestChunk(
        self: *LineFramer,
        chunk: []const u8,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        const sink: FilterSink = .{ .filter_ctx = filter_ctx, .filter_fn = filter_fn };
        try self.inner.ingest(chunk, writer, &sink);
    }

    pub fn finish(
        self: *LineFramer,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        const sink: FilterSink = .{ .filter_ctx = filter_ctx, .filter_fn = filter_fn };
        try self.inner.finish(writer, &sink);
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

    /// Reads `[start_offset, end_offset)` from `file` using positional reads
    /// and frames newline-delimited lines to the writer.
    pub fn readRange(
        self: *LineFramer,
        io: std.Io,
        file: *const std.Io.File,
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
            const n = try file.readPositionalAll(io, self.read_buf[0..to_read], offset);
            if (n == 0) break;

            try self.ingestChunk(self.read_buf[0..n], writer, filter_ctx, filter_fn);
            offset += n;
        }
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
    // Lines over the cap fail OPEN: forwarded verbatim and never evaluated
    // (PLAN §6.5.3 — the retired tail scanner truncated them instead; see
    // .rewrite/test-exceptions.md).
    var framer = try LineFramer.init(testing.allocator, 8, 4);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    const DropAll = struct {
        fn filter(_: *anyopaque, _: []const u8, _: types.LineMeta) !bool {
            return false;
        }
    };
    var ctx: u8 = 0;
    try framer.ingestChunk("123456\nok\n", &out.writer, &ctx, DropAll.filter);
    try framer.finish(&out.writer, &ctx, DropAll.filter);

    // The oversized line passes through unevaluated; the in-bound line was
    // evaluated and dropped.
    try testing.expectEqualStrings("123456\n", out.written());
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

    const io = std.Options.debug_io;
    {
        const f = try tmp.dir.createFile(io, "in.log", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "x\ny\n");
    }

    const in_path = try tmp.dir.realPathFileAlloc(io, "in.log", testing.allocator);
    defer testing.allocator.free(in_path);

    const file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .read_only });
    defer file.close(io);
    const size = (try file.stat(io)).size;

    var framer = try LineFramer.init(testing.allocator, 8, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.readRange(io, &file, 0, size, &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);
    try testing.expectEqualStrings("x\ny\n", out.written());
}

test "framer public API: trailing line without newline is preserved byte-exactly" {
    var framer = try LineFramer.init(testing.allocator, 8, 1024);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.ingestChunk("done\npart", &out.writer, &ctx, keepAll);
    try framer.finish(&out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("done\npart", out.written());
}
