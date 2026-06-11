//! Protobuf top-level field framer for OTLP request bodies.
//!
//! OTLP export requests are a single message whose top-level fields are
//! repeated LEN-delimited submessages (ResourceLogs / ResourceMetrics /
//! ResourceSpans). Framing only needs tag and length varints — payloads are
//! never parsed here — so each LEN payload becomes one record, and the other
//! wire types (VARINT, I32, I64) are copied through verbatim. Kept records
//! re-emit their original tag+length header bytes, so a keep-all sink
//! reproduces the input byte-for-byte.
//!
//! Failure semantics (PLAN.md §6.5): a payload longer than scratch streams
//! through verbatim without evaluation (fail-open); malformed wire data
//! (group wire types, runaway varints) desyncs to verbatim copy-through.
const std = @import("std");
const framer_mod = @import("framer.zig");

/// Tag varint + length varint, 10 bytes max each (64-bit varint ceiling).
const HEADER_MAX = 20;

pub const ProtobufFramer = struct {
    scratch: []u8,
    /// Bytes of the current record payload buffered so far.
    filled: usize = 0,
    /// Original header bytes (tag varint, then length varint) for the field
    /// being parsed; re-emitted verbatim for kept records.
    header: [HEADER_MAX]u8 = undefined,
    header_len: usize = 0,
    /// Length of the tag varint within `header` (replace re-encodes only the
    /// length varint, the tag bytes are reused).
    tag_len: usize = 0,
    /// Incremental varint decode state.
    varint: u64 = 0,
    varint_shift: u6 = 0,
    field_len: usize = 0,
    remaining: usize = 0,
    state: State = .tag,
    stats: framer_mod.Stats = .{},

    const State = enum {
        tag,
        len,
        /// Record payload accumulating in scratch.
        payload_buffer,
        /// Oversized record payload streaming straight to the output.
        payload_stream,
        /// Non-record field value streaming through (length in `remaining`).
        fixed_copy,
        /// Non-record VARINT value streaming through (ends on clear msb).
        varint_copy,
        desync,
    };

    pub fn init(scratch: []u8) ProtobufFramer {
        return .{ .scratch = scratch };
    }

    pub fn ingest(self: *ProtobufFramer, chunk: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        var i: usize = 0;
        while (i < chunk.len) {
            switch (self.state) {
                .tag => {
                    const byte = chunk[i];
                    i += 1;
                    if (!try self.pushHeaderByte(byte, out, chunk[i..])) return;
                    if (byte & 0x80 != 0) continue;
                    // Tag varint complete.
                    const tag = self.varint;
                    self.tag_len = self.header_len;
                    self.resetVarint();
                    switch (@as(u3, @truncate(tag))) {
                        2 => self.state = .len,
                        0 => {
                            try out.writeAll(self.header[0..self.header_len]);
                            self.header_len = 0;
                            self.state = .varint_copy;
                        },
                        5, 1 => |wire| {
                            try out.writeAll(self.header[0..self.header_len]);
                            self.header_len = 0;
                            self.remaining = if (wire == 5) 4 else 8;
                            self.state = .fixed_copy;
                        },
                        else => {
                            // Group wire types (3, 4) are pre-proto3 relics;
                            // anything else is corrupt. Flush the consumed
                            // tag bytes, then copy everything through.
                            try out.writeAll(self.header[0..self.header_len]);
                            self.header_len = 0;
                            try self.enterDesync(out, chunk[i..]);
                            return;
                        },
                    }
                },
                .len => {
                    const byte = chunk[i];
                    i += 1;
                    if (!try self.pushHeaderByte(byte, out, chunk[i..])) return;
                    if (byte & 0x80 != 0) continue;
                    // Length varint complete.
                    if (self.varint > std.math.maxInt(usize)) {
                        try out.writeAll(self.header[0..self.header_len]);
                        self.header_len = 0;
                        try self.enterDesync(out, chunk[i..]);
                        return;
                    }
                    self.field_len = @intCast(self.varint);
                    self.resetVarint();
                    self.remaining = self.field_len;
                    self.filled = 0;
                    if (self.field_len > self.scratch.len) {
                        // Fail open: header out now, payload streams behind it.
                        try out.writeAll(self.header[0..self.header_len]);
                        self.header_len = 0;
                        self.state = .payload_stream;
                    } else if (self.field_len == 0) {
                        try self.emitRecord(&.{}, out, sink);
                    } else {
                        self.state = .payload_buffer;
                    }
                },
                .payload_buffer => {
                    const take = @min(self.remaining, chunk.len - i);
                    @memcpy(self.scratch[self.filled..][0..take], chunk[i..][0..take]);
                    self.filled += take;
                    self.remaining -= take;
                    i += take;
                    if (self.remaining == 0) {
                        try self.emitRecord(self.scratch[0..self.field_len], out, sink);
                    }
                },
                .payload_stream => {
                    const take = @min(self.remaining, chunk.len - i);
                    try out.writeAll(chunk[i..][0..take]);
                    self.remaining -= take;
                    i += take;
                    if (self.remaining == 0) {
                        self.stats.failed_open += 1;
                        self.state = .tag;
                    }
                },
                .fixed_copy => {
                    const take = @min(self.remaining, chunk.len - i);
                    try out.writeAll(chunk[i..][0..take]);
                    self.remaining -= take;
                    i += take;
                    if (self.remaining == 0) self.state = .tag;
                },
                .varint_copy => {
                    const byte = chunk[i];
                    i += 1;
                    try out.writeByte(byte);
                    if (byte & 0x80 == 0) self.state = .tag;
                },
                .desync => {
                    try out.writeAll(chunk[i..]);
                    return;
                },
            }
        }
    }

    pub fn finish(self: *ProtobufFramer, out: *std.Io.Writer, sink: anytype) !void {
        _ = sink;
        switch (self.state) {
            .tag => {
                if (self.header_len > 0) {
                    // Truncated mid-tag: flush the partial varint.
                    try out.writeAll(self.header[0..self.header_len]);
                    self.header_len = 0;
                    self.stats.desynced = true;
                }
            },
            .len, .payload_buffer => {
                // Truncated mid-field: flush header and partial payload so no
                // bytes are lost; the truncation itself is upstream's problem.
                try out.writeAll(self.header[0..self.header_len]);
                self.header_len = 0;
                if (self.filled > 0) {
                    try out.writeAll(self.scratch[0..self.filled]);
                    self.filled = 0;
                }
                self.stats.desynced = true;
            },
            .payload_stream, .fixed_copy, .varint_copy => {
                // Streamed bytes are already out; just record the truncation.
                self.stats.desynced = true;
            },
            .desync => {},
        }
    }

    /// Accumulates one header varint byte. Returns false when the framer
    /// desynced (runaway varint or oversized header) and ingest must stop.
    fn pushHeaderByte(self: *ProtobufFramer, byte: u8, out: *std.Io.Writer, rest: []const u8) !bool {
        if (self.header_len == HEADER_MAX or self.varint_shift >= 63) {
            try out.writeAll(self.header[0..self.header_len]);
            self.header_len = 0;
            try out.writeByte(byte);
            try self.enterDesync(out, rest);
            return false;
        }
        self.header[self.header_len] = byte;
        self.header_len += 1;
        self.varint |= @as(u64, byte & 0x7f) << self.varint_shift;
        self.varint_shift += 7;
        return true;
    }

    fn emitRecord(self: *ProtobufFramer, payload: []const u8, out: *std.Io.Writer, sink: anytype) !void {
        self.stats.records += 1;
        switch (try sink.onRecord(payload)) {
            .keep => {
                self.stats.kept += 1;
                try out.writeAll(self.header[0..self.header_len]);
                try out.writeAll(payload);
            },
            .drop => self.stats.dropped += 1,
            .replace => |bytes| {
                self.stats.replaced += 1;
                try out.writeAll(self.header[0..self.tag_len]);
                try writeVarint(out, bytes.len);
                try out.writeAll(bytes);
            },
        }
        self.header_len = 0;
        self.filled = 0;
        self.state = .tag;
    }

    fn enterDesync(self: *ProtobufFramer, out: *std.Io.Writer, rest: []const u8) !void {
        // Header/scratch bytes for desync triggers are flushed by callers
        // before getting here, except the buffered-payload path.
        if (self.filled > 0) {
            try out.writeAll(self.scratch[0..self.filled]);
            self.filled = 0;
        }
        try out.writeAll(rest);
        self.state = .desync;
        self.stats.desynced = true;
    }

    fn resetVarint(self: *ProtobufFramer) void {
        self.varint = 0;
        self.varint_shift = 0;
    }

    fn writeVarint(out: *std.Io.Writer, value: usize) !void {
        var v: u64 = value;
        while (v >= 0x80) {
            try out.writeByte(@intCast((v & 0x7f) | 0x80));
            v >>= 7;
        }
        try out.writeByte(@intCast(v));
    }
};

// ============================== Tests ==============================

const testing = std.testing;

const TestSink = struct {
    seen: std.ArrayList([]u8) = .empty,
    allocator: std.mem.Allocator,
    replacement: []const u8 = "REPLACED-PAYLOAD",

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
    var framer: ProtobufFramer = .init(scratch);

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

/// field 1, wire type LEN: tag byte 0x0A. Comptime-only fixture builder.
fn lenRecord(comptime payload: []const u8) []const u8 {
    comptime std.debug.assert(payload.len < 128); // single-byte length varint
    const bytes = comptime [_]u8{ 0x0A, @intCast(payload.len) } ++ payload[0..payload.len].*;
    return &bytes;
}

test "keep-all reproduces input byte-for-byte across chunk sizes" {
    const input: []const u8 = comptime (lenRecord("first-resource") ++
        lenRecord("second-resource") ++
        lenRecord(""));
    for ([_]usize{ 1, 3, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, input, got);
        try testing.expectEqual(@as(usize, 3), sink.seen.items.len);
    }
}

test "non-LEN top-level fields copy through verbatim" {
    // field 2 VARINT (0x10), multi-byte value; field 3 I32 (0x1D);
    // field 4 I64 (0x21); interleaved with LEN records.
    const input: []const u8 = comptime (lenRecord("a") ++
        &[_]u8{ 0x10, 0xAC, 0x02 } ++ // varint 300
        &[_]u8{ 0x1D, 1, 2, 3, 4 } ++
        &[_]u8{ 0x21, 1, 2, 3, 4, 5, 6, 7, 8 } ++
        lenRecord("b"));
    for ([_]usize{ 1, 3, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, input, got);
        try testing.expectEqual(@as(usize, 2), sink.seen.items.len);
    }
}

test "drop removes header and payload" {
    const input: []const u8 = comptime (lenRecord("keep-me") ++ lenRecord("drop-me") ++ lenRecord("also-keep"));
    const expected: []const u8 = comptime (lenRecord("keep-me") ++ lenRecord("also-keep"));
    for ([_]usize{ 1, 3, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 64, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, expected, got);
    }
}

test "replace re-encodes length and keeps original tag" {
    const input: []const u8 = comptime lenRecord("swap-me");
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 3, 64, &sink);
    defer testing.allocator.free(got);
    const expected: []const u8 = comptime (&[_]u8{ 0x0A, 16 } ++ "REPLACED-PAYLOAD");
    try testing.expectEqualSlices(u8, expected, got);
}

test "multi-byte length varint round-trips" {
    // 200-byte payload: length varint is 2 bytes (0xC8 0x01).
    const input: []const u8 = comptime (&[_]u8{ 0x0A, 0xC8, 0x01 } ++ ("p" ** 200));
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 256, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, input, got);
    }
}

test "oversized payload fails open without evaluation" {
    // Payload contains "drop" but exceeds scratch: must pass through.
    const payload = "x" ** 30 ++ "drop" ++ "y" ** 30;
    const input: []const u8 = comptime (lenRecord("small") ++ lenRecord(payload) ++ lenRecord("tail"));
    for ([_]usize{ 1, 7, 4096 }) |chunk| {
        var sink: TestSink = .{ .allocator = testing.allocator };
        defer sink.deinit();
        const got = try runChunked(input, chunk, 16, &sink);
        defer testing.allocator.free(got);
        try testing.expectEqualSlices(u8, input, got);
        try testing.expectEqual(@as(usize, 2), sink.seen.items.len);
    }
}

test "invalid wire type desyncs to verbatim copy" {
    // Wire type 3 (start group) at top level.
    const input: []const u8 = comptime (&[_]u8{0x0B} ++ "whatever follows, even drop");
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 5, 64, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, input, got);
    try testing.expectEqual(@as(usize, 0), sink.seen.items.len);
}

test "truncated payload flushes buffered bytes at finish" {
    // Trailing field declares 32 payload bytes but only 9 arrive.
    const input: []const u8 = comptime (lenRecord("complete") ++
        &[_]u8{ 0x0A, 0x20 } ++ "only-part");
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const got = try runChunked(input, 4, 64, &sink);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, input, got);
}

test "stats are accounted" {
    const big = "b" ** 64;
    const input: []const u8 = comptime (lenRecord("keep") ++ lenRecord("drop") ++ lenRecord("swap") ++ lenRecord(big));
    var sink: TestSink = .{ .allocator = testing.allocator };
    defer sink.deinit();
    const scratch = try testing.allocator.alloc(u8, 32);
    defer testing.allocator.free(scratch);
    var framer: ProtobufFramer = .init(scratch);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try framer.ingest(input, &out.writer, &sink);
    try framer.finish(&out.writer, &sink);

    try testing.expectEqual(@as(u64, 3), framer.stats.records);
    try testing.expectEqual(@as(u64, 1), framer.stats.kept);
    try testing.expectEqual(@as(u64, 1), framer.stats.dropped);
    try testing.expectEqual(@as(u64, 1), framer.stats.replaced);
    try testing.expectEqual(@as(u64, 1), framer.stats.failed_open);
    try testing.expectEqual(false, framer.stats.desynced);
}
