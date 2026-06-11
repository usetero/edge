//! Newline-delimited record framer (NDJSON, plain log lines, Prometheus text).
//!
//! The newline scan is the SIMD pattern proven in tail/framer.zig: 16-lane
//! vector compare against '\n', bitcast the bool vector to a mask, walk set
//! bits with @ctz. Records fully contained in one chunk are sliced zero-copy;
//! only chunk-spanning records touch the fixed scratch buffer. Records that
//! exceed scratch are streamed through verbatim (fail-open, PLAN.md §6.5.3).
const std = @import("std");
const framer_mod = @import("framer.zig");

pub const NdjsonFramer = struct {
    scratch: []u8,
    scratch_len: usize = 0,
    /// Current record outgrew scratch: its bytes stream to `out` unevaluated
    /// until the closing newline.
    overflowed: bool = false,
    stats: framer_mod.Stats = .{},

    pub fn init(scratch: []u8) NdjsonFramer {
        return .{ .scratch = scratch };
    }

    pub fn ingest(self: *NdjsonFramer, chunk: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        var start: usize = 0;
        var i: usize = 0;
        const LANES = 16;
        const V = @Vector(LANES, u8);
        const M = @Vector(LANES, bool);
        const Bits = @Int(.unsigned, LANES);
        const needle: V = @splat('\n');

        while (i + LANES <= chunk.len) : (i += LANES) {
            const vec_ptr: *align(1) const V = @ptrCast(chunk[i .. i + LANES].ptr);
            const mask: M = vec_ptr.* == needle;
            var bits: Bits = @bitCast(mask);
            while (bits != 0) {
                const rel: usize = @intCast(@ctz(bits));
                const newline_idx = i + rel;
                try self.completeRecord(chunk[start..newline_idx], out, sink);
                start = newline_idx + 1;
                bits &= bits - 1;
            }
        }
        while (i < chunk.len) : (i += 1) {
            if (chunk[i] != '\n') continue;
            try self.completeRecord(chunk[start..i], out, sink);
            start = i + 1;
        }

        if (start < chunk.len) try self.bufferPartial(chunk[start..], out);
    }

    pub fn finish(self: *NdjsonFramer, out: *std.Io.Writer, sink: anytype) !void {
        if (self.overflowed) {
            // Overflow bytes were already streamed; the input had no trailing
            // newline, so neither does the output.
            self.overflowed = false;
            self.stats.failed_open += 1;
            return;
        }
        if (self.scratch_len == 0) return;
        // Final record without a trailing newline: emit without one.
        try self.emit(self.scratch[0..self.scratch_len], out, sink, false);
        self.scratch_len = 0;
    }

    /// `rest` completes the record whose prefix (possibly empty) is buffered.
    fn completeRecord(self: *NdjsonFramer, rest: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        if (self.overflowed) {
            try out.writeAll(rest);
            try out.writeByte('\n');
            self.overflowed = false;
            self.stats.failed_open += 1;
            return;
        }
        if (self.scratch_len == 0) {
            if (rest.len > self.scratch.len) {
                // The eval bound applies even when the record never touches
                // scratch — otherwise the same record would be evaluated or
                // not depending on where chunk boundaries fell.
                try out.writeAll(rest);
                try out.writeByte('\n');
                self.stats.failed_open += 1;
                return;
            }
            // Fast path: record fully inside this chunk, zero copies.
            return self.emit(rest, out, sink, true);
        }
        if (self.scratch_len + rest.len > self.scratch.len) {
            // Completes but never fit: fail the whole record open.
            try out.writeAll(self.scratch[0..self.scratch_len]);
            try out.writeAll(rest);
            try out.writeByte('\n');
            self.scratch_len = 0;
            self.stats.failed_open += 1;
            return;
        }
        @memcpy(self.scratch[self.scratch_len..][0..rest.len], rest);
        const record = self.scratch[0 .. self.scratch_len + rest.len];
        self.scratch_len = 0;
        try self.emit(record, out, sink, true);
    }

    fn bufferPartial(self: *NdjsonFramer, bytes: []const u8, out: *std.Io.Writer) !void {
        if (self.overflowed) {
            try out.writeAll(bytes);
            return;
        }
        if (self.scratch_len + bytes.len > self.scratch.len) {
            // Enter fail-open streaming: everything buffered so far plus the
            // rest of this record goes through verbatim, unevaluated.
            try out.writeAll(self.scratch[0..self.scratch_len]);
            try out.writeAll(bytes);
            self.scratch_len = 0;
            self.overflowed = true;
            return;
        }
        @memcpy(self.scratch[self.scratch_len..][0..bytes.len], bytes);
        self.scratch_len += bytes.len;
    }

    fn emit(
        self: *NdjsonFramer,
        record: []const u8,
        out: *std.Io.Writer,
        sink: anytype,
        with_newline: bool,
    ) !void {
        self.stats.records += 1;
        switch (try sink.onRecord(record)) {
            .keep => {
                self.stats.kept += 1;
                try out.writeAll(record);
                if (with_newline) try out.writeByte('\n');
            },
            .drop => self.stats.dropped += 1,
            .replace => |bytes| {
                self.stats.replaced += 1;
                try out.writeAll(bytes);
                if (with_newline) try out.writeByte('\n');
            },
        }
    }
};

// ============================== Tests ==============================

const testing = std.testing;

const TestSink = struct {
    seen: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,
    replacement: []const u8 = "SWAPPED",

    fn deinit(self: *TestSink) void {
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

fn runChunked(input: []const u8, chunk_len: usize, scratch_len: usize, sink: *TestSink) ![]u8 {
    const scratch = try testing.allocator.alloc(u8, scratch_len);
    defer testing.allocator.free(scratch);
    var framer: NdjsonFramer = .init(scratch);

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

test "keep-all reproduces input across chunk sizes" {
    const input = "{\"a\":1}\n{\"b\":2}\n\n{\"c\":3}\n";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(input, got);
        try testing.expectEqual(@as(usize, 4), sink.seen.items.len);
    }
}

test "trailing record without newline is preserved without newline" {
    const input = "first\nlast-no-newline";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(input, got);
    }
}

test "drop removes the record and its newline" {
    const input = "keep1\nplease drop me\nkeep2\n";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("keep1\nkeep2\n", got);
    }
}

test "replace substitutes record bytes" {
    const input = "one\nswap this\nthree\n";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings("one\nSWAPPED\nthree\n", got);
    }
}

test "oversized record fails open: forwarded verbatim, never evaluated" {
    // Record of 100 bytes vs 16-byte scratch; contains "drop" but MUST pass
    // through because fail-open bytes bypass the sink (PLAN §6.5.3).
    const big = "x" ** 40 ++ "drop" ++ "y" ** 56;
    const input = "small\n" ++ big ++ "\nsmall2\n";
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 16, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(input, got);
        // Sink saw only the two small records.
        try testing.expectEqual(@as(usize, 2), sink.seen.items.len);
    }
}

test "oversized trailing record without newline fails open" {
    const big = "z" ** 64;
    const input = "ok\n" ++ big; // no trailing newline
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 7, 16, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(input, got);
}

test "stats are accounted" {
    const input = "keep\ndrop it\nswap it\n" ++ ("w" ** 64) ++ "\n";
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();

    const scratch = try testing.allocator.alloc(u8, 16);
    defer testing.allocator.free(scratch);
    var framer: NdjsonFramer = .init(scratch);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try framer.ingest(input, &out.writer, &sink);
    try framer.finish(&out.writer, &sink);

    try testing.expectEqual(@as(u64, 3), framer.stats.records);
    try testing.expectEqual(@as(u64, 1), framer.stats.kept);
    try testing.expectEqual(@as(u64, 1), framer.stats.dropped);
    try testing.expectEqual(@as(u64, 1), framer.stats.replaced);
    try testing.expectEqual(@as(u64, 1), framer.stats.failed_open);
}
