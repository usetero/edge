//! Line framing for edge-tail: a thin adapter over `pipeline/frame_ndjson.zig`
//! that keeps the tail keep/drop filter.
//! - A line longer than `max_line` fails open: it is forwarded unchanged and
//!   not evaluated.
//! - A last line without a newline is emitted without one.
const std = @import("std");
const pipeline_framer = @import("../pipeline/framer.zig");
const frame_ndjson = @import("../pipeline/frame_ndjson.zig");

pub const LineFramer = struct {
    allocator: std.mem.Allocator,
    /// Reusable read staging for pumpFileStreaming, readRange and the read
    /// schedulers (they size positional reads off `read_buf.len`).
    read_buf: []u8,
    /// Scratch for chunk-spanning lines, sized to the eval bound: a line must
    /// fit here to be evaluated, otherwise it fails open. Shared by every
    /// stream: only the *active* stream's partial line lives here at a time;
    /// `selectStream` swaps partials in/out when switching files.
    scratch: []u8,
    inner: frame_ndjson.NdjsonFramer,
    /// Saved partial lines of inactive streams, keyed by `eventKey`. One batch
    /// holds events for many files, so each file keeps its own partial line.
    /// The map lives across batches, so a line split across batches stays one
    /// record.
    streams: std.AutoHashMapUnmanaged(u64, StreamState) = .{},
    /// Key of the stream whose partial line is in `inner.scratch`. Null before
    /// the first `selectStream`.
    active_key: ?u64 = null,

    /// Saved partial-line state for one inactive stream.
    const StreamState = struct {
        /// Owned buffer holding `bytes[0..len]`. Grown only when a larger
        /// partial arrives; freed when the state is loaded back into `inner`,
        /// evicted (the file completed its line), or on `deinit`.
        bytes: ?[]u8 = null,
        /// Number of valid partial bytes in `bytes`. Always `<= scratch.len`
        /// because `NdjsonFramer` never buffers more than the scratch bound.
        len: usize = 0,
        /// True when the stream is mid-record in fail-open streaming. No bytes
        /// are held then (`len == 0`) but the flag must survive switching files
        /// so the file's next chunk continues verbatim until its closing
        /// newline instead of being evaluated as a fresh record.
        overflowed: bool = false,
    };

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
        var it = self.streams.iterator();
        while (it.next()) |entry| if (entry.value_ptr.bytes) |b| self.allocator.free(b);
        self.streams.deinit(self.allocator);
        self.* = undefined;
    }

    /// Switches the active stream so a partial line buffered for one file is
    /// never completed with bytes from another. Saves the currently active
    /// stream's partial (if any) under its key, then loads the named stream's
    /// saved partial (if any) into `inner`. Idempotent when `key` is already
    /// active. Callers that feed the framer from one stream at a time
    /// (`pumpFileStreaming`, or `readRange` for a single file) need not call
    /// this.
    pub fn selectStream(self: *LineFramer, key: u64) !void {
        if (self.active_key) |old_key| {
            if (old_key == key) return;
            try self.saveStream(old_key);
        }
        try self.loadStream(key);
        self.active_key = key;
    }

    /// Discards any saved (parked) partial-line state for `key` without loading
    /// it. Use cases:
    /// - **Truncation/rewrite**: call before `selectStream` when the watcher
    ///   resets a file's read offset to zero, so stale pre-rewrite bytes are
    ///   not concatenated onto the new contents.
    /// - **Rotation/removal**: call when the watcher evicts a tracked path so
    ///   the `streams` map does not hold the file's partial buffer indefinitely.
    ///   Without this, repeated log rotation grows the map without bound.
    pub fn resetStream(self: *LineFramer, key: u64) void {
        if (self.streams.fetchRemove(key)) |kv| if (kv.value.bytes) |b| self.allocator.free(b);
        // If this key is currently active, clear inner state too.
        if (self.active_key) |ak| {
            if (ak == key) {
                self.inner.scratch_len = 0;
                self.inner.overflowed = false;
                self.active_key = null;
            }
        }
    }

    /// Parks the active stream's partial state in `streams[key]`.
    fn saveStream(self: *LineFramer, key: u64) !void {
        const len = self.inner.scratch_len;
        const overflowed = self.inner.overflowed;
        // The stream completed cleanly: drop any stale entry so the file's
        // next event starts fresh rather than reviving an obsolete partial.
        if (len == 0 and !overflowed) {
            if (self.streams.fetchRemove(key)) |kv| if (kv.value.bytes) |b| self.allocator.free(b);
            return;
        }
        const gop = try self.streams.getOrPut(self.allocator, key);
        if (!gop.found_existing) gop.value_ptr.* = .{}; // getOrPut leaves new slots undefined
        const cap = if (gop.value_ptr.bytes) |b| b.len else 0;
        if (cap < len) {
            const new_bytes = try self.allocator.alloc(u8, len);
            if (gop.value_ptr.bytes) |b| self.allocator.free(b);
            gop.value_ptr.bytes = new_bytes;
        }
        if (len > 0) @memcpy(gop.value_ptr.bytes.?[0..len], self.inner.scratch[0..len]);
        gop.value_ptr.len = len;
        gop.value_ptr.overflowed = overflowed;
    }

    /// Loads `streams[key]` into `inner` and frees its owned buffer (the state
    /// now lives in the shared scratch). Resets `inner` when the stream has no
    /// saved state, which is the common case for a file seen for the first
    /// time in this run.
    fn loadStream(self: *LineFramer, key: u64) !void {
        self.inner.scratch_len = 0;
        self.inner.overflowed = false;
        if (self.streams.fetchRemove(key)) |kv| {
            if (kv.value.bytes) |b| {
                if (kv.value.len > 0) {
                    @memcpy(self.inner.scratch[0..kv.value.len], b[0..kv.value.len]);
                    self.inner.scratch_len = kv.value.len;
                }
                self.allocator.free(b);
            }
            self.inner.overflowed = kv.value.overflowed;
        }
    }

    pub const LineFilterFn = fn (ctx: *anyopaque, line: []const u8) anyerror!bool;

    /// Bridges the tail boolean filter onto the pipeline sink contract.
    const FilterSink = struct {
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,

        pub fn onRecord(self: *const FilterSink, bytes: []const u8) !pipeline_framer.Decision {
            const keep = try self.filter_fn(self.filter_ctx, bytes);
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

    /// Flushes all streams — the active one and every parked stream — emitting
    /// any unterminated trailing line from each file. When a multi-file batch
    /// ends, the active stream holds the last file's partial, while earlier
    /// files' partials are parked in `streams`; both must be drained here so
    /// no unterminated final line is silently dropped.
    pub fn finish(
        self: *LineFramer,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        const sink: FilterSink = .{ .filter_ctx = filter_ctx, .filter_fn = filter_fn };
        // Flush the active stream first.
        try self.inner.finish(writer, &sink);
        // Drain every parked stream: load it into `inner`, flush, then discard.
        // We collect the keys up front because draining empties the map.
        var keys: std.ArrayList(u64) = .empty;
        defer keys.deinit(self.allocator);
        {
            var it = self.streams.iterator();
            while (it.next()) |entry| try keys.append(self.allocator, entry.key_ptr.*);
        }
        for (keys.items) |k| {
            try self.loadStream(k);
            try self.inner.finish(writer, &sink);
        }
        self.active_key = null;
    }

    /// Pump a streaming file (stdin) with one short `readStreaming` per
    /// iteration. A cancel stops the read as error.Canceled, and no prefetched
    /// bytes are lost. The caller flushes the writer after the join.
    pub fn pumpFileStreaming(
        self: *LineFramer,
        io: std.Io,
        file: std.Io.File,
        writer: *std.Io.Writer,
        filter_ctx: *anyopaque,
        filter_fn: *const LineFilterFn,
    ) !void {
        while (true) {
            const n = file.readStreaming(io, &.{self.read_buf}) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err, // includes error.Canceled on cooperative shutdown
            };
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

fn keepAll(_: *anyopaque, _: []const u8) !bool {
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
    // Lines over the cap fail open: forwarded unchanged and not evaluated.
    var framer = try LineFramer.init(testing.allocator, 8, 4);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    const DropAll = struct {
        fn filter(_: *anyopaque, _: []const u8) !bool {
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
    try tmp.dir.writeFile(io, .{ .sub_path = "in.log", .data = "x\ny\n" });

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

test "framer public API: pumpFileStreaming frames bytes across short reads to EOF" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "in.log", .data = "a\nbc\ndef\n" });

    const in_path = try tmp.dir.realPathFileAlloc(io, "in.log", testing.allocator);
    defer testing.allocator.free(in_path);

    const file = try std.Io.Dir.cwd().openFile(io, in_path, .{ .mode = .read_only });
    defer file.close(io);

    // Small read_buf forces several short readv iterations across line
    // boundaries, exercising the same chunk-spanning path the stdin pump uses.
    var framer = try LineFramer.init(testing.allocator, 4, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.pumpFileStreaming(io, file, &out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("a\nbc\ndef\n", out.written());
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

test "framer public API: selectStream isolates per-file partial lines" {
    // A single framer fed by multiple files must keep each file's partial
    // line isolated: file A's trailing "partial" cannot be completed with
    // file B's first bytes. Switching back to A restores its buffered partial
    // so the logical line is still emitted as one record.
    var framer = try LineFramer.init(testing.allocator, 8, 64);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.selectStream(111);
    try framer.ingestChunk("line1\npartial", &out.writer, &ctx, keepAll);
    try framer.selectStream(222);
    try framer.ingestChunk("hello\nworld\n", &out.writer, &ctx, keepAll);
    try framer.selectStream(111);
    try framer.ingestChunk("rest\n", &out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("line1\nhello\nworld\npartialrest\n", out.written());
    try testing.expect(std.mem.indexOf(u8, out.written(), "partialhello") == null);
}

test "framer public API: selectStream no-ops for the active key" {
    // Re-selecting the active key keeps the buffered partial.
    var framer = try LineFramer.init(testing.allocator, 8, 64);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var ctx: u8 = 0;
    try framer.selectStream(111);
    try framer.ingestChunk("foo\nbar", &out.writer, &ctx, keepAll);
    try framer.selectStream(111);
    try framer.ingestChunk("baz\n", &out.writer, &ctx, keepAll);

    try testing.expectEqualStrings("foo\nbarbaz\n", out.written());
}

test "framer public API: selectStream isolates fail-open overflow per file" {
    // File A overflows without a newline. File B's record must still be
    // evaluated alone. The overflow flag must not carry across files.
    const Seen = struct {
        const Self = @This();
        seen: std.ArrayList([]u8) = .empty,
        allocator: std.mem.Allocator,
        fn deinit(self: *Self) void {
            for (self.seen.items) |s| self.allocator.free(s);
            self.seen.deinit(self.allocator);
            self.* = undefined;
        }
        fn filter(ctx: *anyopaque, line: []const u8) !bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            try self.seen.append(self.allocator, try self.allocator.dupe(u8, line));
            return true;
        }
    };

    var framer = try LineFramer.init(testing.allocator, 64, 32);
    defer framer.deinit();

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var seen: Seen = .{ .allocator = testing.allocator };
    defer seen.deinit();

    const partial_a = "Q" ** 40 ++ "PARTIAL"; // 47 bytes, no newline, > max_line
    try framer.selectStream(111);
    try framer.ingestChunk(partial_a, &out.writer, &seen, Seen.filter);
    try framer.selectStream(222);
    try framer.ingestChunk("hello\n", &out.writer, &seen, Seen.filter);

    try testing.expectEqual(@as(usize, 1), seen.seen.items.len);
    try testing.expectEqualStrings("hello", seen.seen.items[0]);
    try testing.expect(std.mem.indexOf(u8, out.written(), "PARTIAL") != null);
}
