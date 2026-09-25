//! Compresses into another `std.Io.Writer`, as gzip or zstd.
//!
//! Bytes written to `writer` are compressed straight into the free space of
//! `output`, so the encoder copies nothing twice. `finish` ends the stream.
const std = @import("std");
const root = @import("root.zig");
const c = @import("c.zig").c;

const Codec = root.Codec;
const Writer = std.Io.Writer;

const log = std.log.scoped(.codec);

pub const Encoder = struct {
    /// Write the bytes to compress here.
    writer: Writer,
    output: *Writer = undefined,
    codec: Codec = .gzip,
    /// zlib deflate state. On the heap, because zlib keeps a pointer back to
    /// its stream, and the `Encoder` itself may move.
    z: *c.z_stream,
    z_ready: bool = false,
    cctx: ?*c.ZSTD_CCtx = null,

    pub const InitError = error{ OutOfMemory, CompressionInitFailed };

    /// `buffer` stages writes before they are compressed. Any size works,
    /// and a larger one means fewer library calls.
    pub fn init(allocator: std.mem.Allocator, buffer: []u8) std.mem.Allocator.Error!Encoder {
        const z = try allocator.create(c.z_stream);
        z.* = std.mem.zeroes(c.z_stream);
        return .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer }, .z = z };
    }

    pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
        if (self.z_ready) {
            // Z_DATA_ERROR only says an unfinished stream was freed.
            const rc = c.deflateEnd(self.z);
            if (rc != c.Z_OK and rc != c.Z_DATA_ERROR) log.warn("deflateEnd failed", .{});
        }
        if (self.cctx) |cctx| {
            if (c.ZSTD_isError(c.ZSTD_freeCCtx(cctx)) != 0) log.warn("ZSTD_freeCCtx failed", .{});
        }
        allocator.destroy(self.z);
        self.* = undefined;
    }

    /// Starts a new stream into `output`. The encoder keeps its library
    /// state from the last stream and resets it.
    pub fn begin(self: *Encoder, codec: Codec, output: *Writer) InitError!void {
        switch (codec) {
            .gzip => {
                const rc = if (self.z_ready)
                    c.deflateReset(self.z)
                else
                    // 15 + 16: the largest window, with a gzip header and
                    // trailer. Level 6 and memLevel 8 are the zlib defaults.
                    c.deflateInit2(self.z, c.Z_DEFAULT_COMPRESSION, c.Z_DEFLATED, 15 + 16, 8, c.Z_DEFAULT_STRATEGY);
                if (rc == c.Z_MEM_ERROR) return error.OutOfMemory;
                if (rc != c.Z_OK) return error.CompressionInitFailed;
                self.z_ready = true;
            },
            .zstd => {
                const cctx = self.cctx orelse c.ZSTD_createCCtx() orelse return error.OutOfMemory;
                self.cctx = cctx;
                if (c.ZSTD_isError(c.ZSTD_CCtx_reset(cctx, c.ZSTD_reset_session_and_parameters)) != 0) {
                    return error.CompressionInitFailed;
                }
                const level = c.ZSTD_CCtx_setParameter(cctx, c.ZSTD_c_compressionLevel, c.ZSTD_CLEVEL_DEFAULT);
                if (c.ZSTD_isError(level) != 0) return error.CompressionInitFailed;
            },
        }
        self.codec = codec;
        self.output = output;
        self.writer.end = 0;
    }

    /// Compresses what is staged, ends the stream, and flushes `output`.
    pub fn finish(self: *Encoder) Writer.Error!void {
        try self.writer.flush();
        var none: []const u8 = &.{};
        while (true) {
            const progress = try self.stepInto(&none, .finish);
            if (progress.finished) break;
            if (progress.produced == 0) return error.WriteFailed;
        }
        try self.output.flush();
    }

    fn drain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *Encoder = @alignCast(@fieldParentPtr("writer", w));
        try self.compress(w.buffer[0..w.end]);
        w.end = 0;
        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            try self.compress(slice);
            consumed += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try self.compress(last);
            consumed += last.len;
        }
        return consumed;
    }

    fn compress(self: *Encoder, bytes: []const u8) Writer.Error!void {
        var rest = bytes;
        while (rest.len != 0) {
            const before = rest.len;
            const progress = try self.stepInto(&rest, .run);
            // With input left and free space in `output`, a library call
            // always takes input or writes output.
            if (rest.len == before and progress.produced == 0) return error.WriteFailed;
        }
    }

    const Mode = enum { run, finish };
    const Progress = struct { produced: usize, finished: bool };

    /// One library call, from `rest.*` into the free space of `output`.
    /// Takes the consumed bytes off `rest.*`. `finished` is true once a
    /// `.finish` step has written the whole stream.
    fn stepInto(self: *Encoder, rest: *[]const u8, mode: Mode) Writer.Error!Progress {
        const dest = try self.output.writableSliceGreedy(1);
        var consumed: usize = 0;
        var produced: usize = 0;
        var finished = false;
        switch (self.codec) {
            .gzip => {
                const in_len: c_uint = @intCast(@min(rest.len, std.math.maxInt(c_uint)));
                const out_len: c_uint = @intCast(@min(dest.len, std.math.maxInt(c_uint)));
                self.z.next_in = @constCast(rest.ptr);
                self.z.avail_in = in_len;
                self.z.next_out = dest.ptr;
                self.z.avail_out = out_len;
                const rc = c.deflate(self.z, if (mode == .finish) c.Z_FINISH else c.Z_NO_FLUSH);
                if (rc == c.Z_STREAM_ERROR) return error.WriteFailed;
                consumed = in_len - self.z.avail_in;
                produced = out_len - self.z.avail_out;
                finished = rc == c.Z_STREAM_END;
            },
            .zstd => {
                var in_buffer: c.ZSTD_inBuffer = .{ .src = rest.ptr, .size = rest.len, .pos = 0 };
                var out_buffer: c.ZSTD_outBuffer = .{ .dst = dest.ptr, .size = dest.len, .pos = 0 };
                const directive: c.ZSTD_EndDirective = if (mode == .finish) c.ZSTD_e_end else c.ZSTD_e_continue;
                const remaining = c.ZSTD_compressStream2(self.cctx, &out_buffer, &in_buffer, directive);
                if (c.ZSTD_isError(remaining) != 0) {
                    log.warn("zstd compression failed: {s}", .{c.ZSTD_getErrorName(remaining)});
                    return error.WriteFailed;
                }
                consumed = in_buffer.pos;
                produced = out_buffer.pos;
                finished = mode == .finish and remaining == 0;
            },
        }
        self.output.advance(produced);
        rest.* = rest.*[consumed..];
        return .{ .produced = produced, .finished = finished };
    }
};

test "an encoder writes one gzip and one zstd stream, then another of each" {
    const gpa = std.testing.allocator;
    var staging: [16]u8 = undefined;
    var encoder: Encoder = try .init(gpa, &staging);
    defer encoder.deinit(gpa);
    for (0..2) |_| {
        inline for (.{ Codec.gzip, Codec.zstd }) |codec| {
            var out: Writer.Allocating = .init(gpa);
            defer out.deinit();
            try encoder.begin(codec, &out.writer);
            try encoder.writer.writeAll("hello ");
            try encoder.writer.writeAll("world");
            try encoder.finish();
            try std.testing.expect(out.written().len > 0);
        }
    }
}
