//! Microbenchmark for the JSON-array framer (`pipeline/frame_json_array.zig`).
//!
//! Isolates the framing work — element-boundary scanning + copying records to
//! the sink — from policy evaluation and codec cost, using a trivial keep-all
//! sink and a fixed (non-allocating) output buffer. This is the code the
//! zero-copy rewrite targeted: single-chunk elements are handed to the sink as
//! direct chunk slices, cross-chunk elements bulk-copied one run per boundary.
//!
//! Run with: `zig build json-framer-bench`.
const std = @import("std");
const zbench = @import("zbench");
const edge = @import("edge");

const JsonArrayFramer = edge.pipeline_framer.frame_json_array.JsonArrayFramer;
const Decision = edge.pipeline_framer.Decision;
const CHUNK_BUF_BYTES = edge.core_limits.CHUNK_BUF_BYTES;
const RECORD_SCRATCH_BYTES = edge.core_limits.RECORD_SCRATCH_BYTES;

// A plain, high-volume-shaped log (~105 bytes) — fits well within one 4 KiB
// chunk, so the framer hands it to the sink zero-copy in the common case.
const small_log =
    \\{"message":"GET /healthz 200 1ms","status":"info","service":"api","hostname":"web-01","ddsource":"nginx"}
;

// Record counts sized so each body lands around a few hundred KiB (a realistic
// intake batch) regardless of per-record size.
const small_count = 4000;
const large_count = 40;

// Globals: zbench's BenchFunc is `fn(Allocator) void` with no context pointer,
// so payloads and reusable buffers live here.
var g_body_small: []const u8 = undefined;
var g_body_large: []const u8 = undefined;
var g_scratch: []u8 = undefined;
var g_out_buf: []u8 = undefined;

/// Keep-all, zero-work sink: measures pure framing, not policy evaluation.
const KeepAllSink = struct {
    records: u64 = 0,
    kept_bytes: u64 = 0,

    pub fn onRecord(self: *KeepAllSink, bytes: []const u8) !Decision {
        self.records += 1;
        self.kept_bytes += bytes.len;
        return .keep;
    }
};

fn runFramer(body: []const u8, chunk_size: usize) void {
    var framer: JsonArrayFramer = .init(g_scratch);
    var out = std.Io.Writer.fixed(g_out_buf);
    var sink: KeepAllSink = .{};

    var off: usize = 0;
    while (off < body.len) {
        const end = @min(off + chunk_size, body.len);
        framer.ingest(body[off..end], &out, &sink) catch |e|
            std.debug.panic("ingest failed: {t}", .{e});
        off = end;
    }
    framer.finish(&out, &sink) catch |e| std.debug.panic("finish failed: {t}", .{e});

    // Defeat dead-code elimination on the framing work.
    std.mem.doNotOptimizeAway(sink.records);
    std.mem.doNotOptimizeAway(sink.kept_bytes);
    std.mem.doNotOptimizeAway(out.end);
}

fn benchSmall4k(_: std.mem.Allocator) void {
    runFramer(g_body_small, CHUNK_BUF_BYTES);
}

fn benchSmallWhole(_: std.mem.Allocator) void {
    runFramer(g_body_small, g_body_small.len);
}

fn benchLarge4k(_: std.mem.Allocator) void {
    runFramer(g_body_large, CHUNK_BUF_BYTES);
}

/// Build "[obj,obj,...]" from a single JSON object, `count` copies.
fn buildBatch(allocator: std.mem.Allocator, obj: []const u8, count: usize) ![]const u8 {
    const trimmed = std.mem.trim(u8, obj, " \t\r\n");
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeByte('[');
    for (0..count) |i| {
        if (i != 0) try out.writer.writeByte(',');
        try out.writer.writeAll(trimmed);
    }
    try out.writer.writeByte(']');
    return out.toOwnedSlice();
}

/// A single log whose `message` is a ~8 KiB string, so each record straddles
/// several 4 KiB chunks and exercises the cross-chunk bulk-copy path.
fn buildLargeLog(allocator: std.mem.Allocator) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeAll("{\"service\":\"api\",\"status\":\"info\",\"message\":\"");
    // 8 KiB of body text with a few escapes to keep the string state machine honest.
    for (0..8192) |i| {
        try out.writer.writeByte(switch (i % 32) {
            7 => '\\', // followed by the next char -> escape pair
            0 => ' ',
            else => 'a' + @as(u8, @intCast(i % 26)),
        });
    }
    try out.writer.writeAll("\"}");
    return out.toOwnedSlice();
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    g_body_small = try buildBatch(gpa, small_log, small_count);
    defer gpa.free(g_body_small);

    const large_log = try buildLargeLog(gpa);
    defer gpa.free(large_log);
    g_body_large = try buildBatch(gpa, large_log, large_count);
    defer gpa.free(g_body_large);

    g_scratch = try gpa.alloc(u8, RECORD_SCRATCH_BYTES);
    defer gpa.free(g_scratch);

    // Keep-all re-emit is <= body length (whitespace dropped); size to the max.
    const out_len = @max(g_body_small.len, g_body_large.len) + 16;
    g_out_buf = try gpa.alloc(u8, out_len);
    defer gpa.free(g_out_buf);

    var bench = zbench.Benchmark.init(gpa, .{});
    defer bench.deinit();

    try bench.add("small logs, 4KiB chunks", benchSmall4k, .{});
    try bench.add("small logs, whole body", benchSmallWhole, .{});
    try bench.add("large logs (8KiB msg), 4KiB chunks", benchLarge4k, .{});

    const stdout: std.Io.File = .stdout();
    try bench.run(init.io, stdout);
}
