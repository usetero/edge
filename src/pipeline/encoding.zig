//! Streaming Content-Encoding codecs for the record pipeline.
//!
//! Decoders wrap the request/response body reader; encoders wrap the upstream
//! writer. Both operate on caller-provided fixed buffers so the pipeline
//! itself never allocates (PLAN.md §6.2). gzip rides on std.compress.flate
//! (Compress and Decompress are both native std.Io adapters in 0.16); zstd
//! decode rides on std.compress.zstd; zstd encode is the one codec std lacks,
//! so it wraps libzstd's ZSTD_compressStream2 behind a std.Io.Writer.
const std = @import("std");
const flate = std.compress.flate;
const zstd = std.compress.zstd;

const c = @cImport({
    @cInclude("zstd.h");
});

const log = std.log.scoped(.encoding);

pub const ContentEncoding = enum {
    identity,
    gzip,
    zstd,

    /// Maps a Content-Encoding header value; null means unsupported (caller
    /// treats the body as opaque and passes it through unfiltered).
    pub fn fromHeader(value: []const u8) ?ContentEncoding {
        if (value.len == 0) return .identity;
        if (std.ascii.eqlIgnoreCase(value, "identity")) return .identity;
        if (std.ascii.eqlIgnoreCase(value, "gzip")) return .gzip;
        if (std.ascii.eqlIgnoreCase(value, "x-gzip")) return .gzip;
        if (std.ascii.eqlIgnoreCase(value, "zstd")) return .zstd;
        return null;
    }

    pub fn headerValue(self: ContentEncoding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }

    /// Minimum decoder buffer for this encoding given the zstd window cap.
    /// flate's window is fixed by the format; zstd's is config-bounded
    /// (frames declaring a larger window fail open per PLAN.md §6.5).
    pub fn decoderBufferLen(self: ContentEncoding, zstd_window_len: usize) usize {
        return switch (self) {
            .identity => 0,
            .gzip => flate.max_window_len,
            .zstd => zstd_window_len + zstd.block_size_max,
        };
    }

    pub fn encoderBufferLen(self: ContentEncoding) usize {
        return switch (self) {
            .identity => 0,
            .gzip => flate.max_window_len,
            // Staging for compressed output between drain calls; one zstd
            // block bound keeps ZSTD_compressStream2 from stalling.
            .zstd => zstd.block_size_max,
        };
    }
};

/// Largest buffer any decoder/encoder pair needs for a given zstd window cap;
/// limits.zig uses this to size the per-connection codec region.
pub fn maxCodecBufferLen(zstd_window_len: usize) usize {
    var result: usize = 0;
    inline for (@typeInfo(ContentEncoding).@"enum".fields) |field| {
        const enc: ContentEncoding = @enumFromInt(field.value);
        result = @max(result, enc.decoderBufferLen(zstd_window_len));
        result = @max(result, enc.encoderBufferLen());
    }
    return result;
}

pub const Decoder = union(ContentEncoding) {
    identity: *std.Io.Reader,
    gzip: flate.Decompress,
    zstd: zstd.Decompress,

    /// `buffer` must be at least `encoding.decoderBufferLen(zstd_window_len)`
    /// bytes; it backs the decompression window and stays borrowed until the
    /// decoder is dropped.
    pub fn init(
        encoding: ContentEncoding,
        inner: *std.Io.Reader,
        buffer: []u8,
        zstd_window_len: usize,
    ) Decoder {
        std.debug.assert(buffer.len >= encoding.decoderBufferLen(zstd_window_len));
        return switch (encoding) {
            .identity => .{ .identity = inner },
            .gzip => .{ .gzip = flate.Decompress.init(inner, .gzip, buffer[0..flate.max_window_len]) },
            .zstd => .{ .zstd = zstd.Decompress.init(
                inner,
                buffer[0 .. zstd_window_len + zstd.block_size_max],
                .{ .window_len = @intCast(zstd_window_len) },
            ) },
        };
    }

    /// The decoded-bytes reader. Identity hands back the inner reader: zero
    /// added indirection on the passthrough path.
    pub fn reader(self: *Decoder) *std.Io.Reader {
        return switch (self.*) {
            .identity => |inner| inner,
            .gzip => |*d| &d.reader,
            .zstd => |*d| &d.reader,
        };
    }
};

pub const Encoder = union(ContentEncoding) {
    identity: *std.Io.Writer,
    gzip: flate.Compress,
    zstd: ZstdCompressor,

    pub const InitError = error{ WriteFailed, CompressionInitFailed };

    /// `buffer` must be at least `encoding.encoderBufferLen()` bytes, and
    /// `inner` must be a buffered writer (flate asserts > 8 bytes capacity).
    /// zstd allocates its compression context inside libzstd (bounded,
    /// freed in deinit); gzip and identity allocate nothing.
    pub fn init(
        encoding: ContentEncoding,
        inner: *std.Io.Writer,
        buffer: []u8,
    ) InitError!Encoder {
        std.debug.assert(buffer.len >= encoding.encoderBufferLen());
        return switch (encoding) {
            .identity => .{ .identity = inner },
            .gzip => .{ .gzip = try flate.Compress.init(inner, buffer[0..flate.max_window_len], .gzip, .default) },
            .zstd => .{ .zstd = try ZstdCompressor.init(inner, buffer[0..zstd.block_size_max]) },
        };
    }

    pub fn deinit(self: *Encoder) void {
        switch (self.*) {
            .identity, .gzip => {},
            .zstd => |*z| z.deinit(),
        }
        self.* = undefined;
    }

    pub fn writer(self: *Encoder) *std.Io.Writer {
        return switch (self.*) {
            .identity => |inner| inner,
            .gzip => |*e| &e.writer,
            .zstd => |*e| &e.writer,
        };
    }

    /// Terminates the compressed stream (gzip trailer / zstd frame epilogue)
    /// and flushes everything to the inner writer. Identity flushes only.
    pub fn finish(self: *Encoder) std.Io.Writer.Error!void {
        switch (self.*) {
            .identity => |inner| try inner.flush(),
            .gzip => |*e| try e.finish(),
            .zstd => |*e| try e.finish(),
        }
    }
};

/// std.Io.Writer adapter over libzstd streaming compression. Bytes written to
/// `writer` are compressed and drained to `output`; `finish` emits the frame
/// epilogue. The compression context lives in libzstd-owned memory (bounded
/// by level-3 defaults, ~1-2 MiB) — counted as a shared pool in the budget
/// notes, not the per-connection slab.
pub const ZstdCompressor = struct {
    writer: std.Io.Writer,
    output: *std.Io.Writer,
    cctx: *c.ZSTD_CCtx,

    pub fn init(output: *std.Io.Writer, buffer: []u8) error{CompressionInitFailed}!ZstdCompressor {
        const cctx = c.ZSTD_createCCtx() orelse return error.CompressionInitFailed;
        if (c.ZSTD_isError(c.ZSTD_CCtx_setParameter(cctx, c.ZSTD_c_compressionLevel, c.ZSTD_CLEVEL_DEFAULT)) != 0) {
            _ = c.ZSTD_freeCCtx(cctx);
            return error.CompressionInitFailed;
        }
        return .{
            .writer = .{ .vtable = &.{ .drain = drain }, .buffer = buffer },
            .output = output,
            .cctx = cctx,
        };
    }

    pub fn deinit(self: *ZstdCompressor) void {
        _ = c.ZSTD_freeCCtx(self.cctx);
        self.* = undefined;
    }

    pub fn finish(self: *ZstdCompressor) std.Io.Writer.Error!void {
        try self.writer.flush();
        var in_buffer: c.ZSTD_inBuffer = .{ .src = null, .size = 0, .pos = 0 };
        while (true) {
            if (try self.runStream(&in_buffer, c.ZSTD_e_end) == 0) break;
        }
        try self.output.flush();
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *ZstdCompressor = @fieldParentPtr("writer", w);

        try self.compressSlice(w.buffer[0..w.end]);
        w.end = 0;

        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            try self.compressSlice(slice);
            consumed += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try self.compressSlice(last);
            consumed += last.len;
        }
        return consumed;
    }

    fn compressSlice(self: *ZstdCompressor, slice: []const u8) std.Io.Writer.Error!void {
        if (slice.len == 0) return;
        var in_buffer: c.ZSTD_inBuffer = .{ .src = slice.ptr, .size = slice.len, .pos = 0 };
        while (in_buffer.pos < in_buffer.size) {
            _ = try self.runStream(&in_buffer, c.ZSTD_e_continue);
        }
    }

    /// One ZSTD_compressStream2 call; drains produced bytes to `output`.
    /// Returns libzstd's remaining-work hint (0 = done for ZSTD_e_end).
    fn runStream(
        self: *ZstdCompressor,
        in_buffer: *c.ZSTD_inBuffer,
        end_op: c.ZSTD_EndDirective,
    ) std.Io.Writer.Error!usize {
        var out_scratch: [4096]u8 = undefined;
        var out_buffer: c.ZSTD_outBuffer = .{ .dst = &out_scratch, .size = out_scratch.len, .pos = 0 };
        const remaining = c.ZSTD_compressStream2(self.cctx, &out_buffer, in_buffer, end_op);
        if (c.ZSTD_isError(remaining) != 0) {
            log.warn("zstd compression failed: {s}", .{c.ZSTD_getErrorName(remaining)});
            return error.WriteFailed;
        }
        if (out_buffer.pos > 0) try self.output.writeAll(out_scratch[0..out_buffer.pos]);
        return remaining;
    }
};

// ============================== Tests ==============================
// Streaming codecs are verified against the buffered oracle in
// compress_buffered.zig: every fixture must round-trip both directions.

const testing = std.testing;
const buffered = @import("compress_buffered.zig");

const TEST_ZSTD_WINDOW: usize = 256 * 1024;

const FIXTURES = [_][]const u8{
    "Test log message",
    \\ [
    \\   {
    \\     "ddsource": "nginx",
    \\     "ddtags": "env:staging,version:5.1",
    \\     "hostname": "i-012345678",
    \\     "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello World",
    \\     "service": "payment"
    \\   }
    \\ ]
    ,
    "a" ** 10_000,
    "", // empty body still produces a valid frame
};

fn decodeAll(
    encoding: ContentEncoding,
    compressed: []const u8,
    chunk_limit: usize,
) ![]u8 {
    var in: std.Io.Reader = .fixed(compressed);
    const buf = try testing.allocator.alloc(u8, encoding.decoderBufferLen(TEST_ZSTD_WINDOW));
    defer testing.allocator.free(buf);
    var decoder: Decoder = .init(encoding, &in, buf, TEST_ZSTD_WINDOW);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    const decoded = decoder.reader();
    while (true) {
        // Tiny limits force many vtable stream calls: chunk-boundary coverage.
        // A zero return does NOT mean end of stream (Reader.VTable contract);
        // only error.EndOfStream terminates.
        _ = decoded.stream(&out.writer, .limited(chunk_limit)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
    }
    return out.toOwnedSlice();
}

fn encodeAll(
    encoding: ContentEncoding,
    plain: []const u8,
    chunk_len: usize,
) ![]u8 {
    // flate.Compress.init asserts the inner writer is buffered (> 8 bytes);
    // the real pipeline's upstream writer always is.
    var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 4096);
    errdefer out.deinit();

    const buf = try testing.allocator.alloc(u8, encoding.encoderBufferLen());
    defer testing.allocator.free(buf);
    var encoder: Encoder = try .init(encoding, &out.writer, buf);
    defer encoder.deinit();

    var offset: usize = 0;
    while (offset < plain.len) {
        const end = @min(offset + chunk_len, plain.len);
        try encoder.writer().writeAll(plain[offset..end]);
        offset = end;
    }
    try encoder.finish();
    return out.toOwnedSlice();
}

test "streaming gzip decode matches buffered oracle across chunk sizes" {
    for (FIXTURES) |fixture| {
        const compressed = try buffered.compressGzip(testing.allocator, fixture);
        defer testing.allocator.free(compressed);
        for ([_]usize{ 1, 7, 4096 }) |chunk| {
            const decoded = try decodeAll(.gzip, compressed, chunk);
            defer testing.allocator.free(decoded);
            try testing.expectEqualStrings(fixture, decoded);
        }
    }
}

test "streaming gzip encode is decodable by buffered oracle" {
    for (FIXTURES) |fixture| {
        for ([_]usize{ 1, 7, 4096 }) |chunk| {
            const encoded = try encodeAll(.gzip, fixture, chunk);
            defer testing.allocator.free(encoded);
            const decoded = try buffered.decompressGzip(testing.allocator, encoded, 0);
            defer testing.allocator.free(decoded);
            try testing.expectEqualStrings(fixture, decoded);
        }
    }
}

test "streaming zstd decode matches buffered oracle across chunk sizes" {
    for (FIXTURES) |fixture| {
        const compressed = try buffered.compressZstd(testing.allocator, fixture);
        defer testing.allocator.free(compressed);
        for ([_]usize{ 1, 7, 4096 }) |chunk| {
            const decoded = try decodeAll(.zstd, compressed, chunk);
            defer testing.allocator.free(decoded);
            try testing.expectEqualStrings(fixture, decoded);
        }
    }
}

test "streaming zstd encode is decodable by buffered oracle" {
    for (FIXTURES) |fixture| {
        for ([_]usize{ 1, 7, 4096 }) |chunk| {
            const encoded = try encodeAll(.zstd, fixture, chunk);
            defer testing.allocator.free(encoded);
            const decoded = try buffered.decompressZstd(testing.allocator, encoded, 0);
            defer testing.allocator.free(decoded);
            try testing.expectEqualStrings(fixture, decoded);
        }
    }
}

test "identity passes bytes through untouched" {
    const fixture = FIXTURES[1];
    const encoded = try encodeAll(.identity, fixture, 7);
    defer testing.allocator.free(encoded);
    try testing.expectEqualStrings(fixture, encoded);

    const decoded = try decodeAll(.identity, fixture, 7);
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings(fixture, decoded);
}

test "ContentEncoding.fromHeader" {
    try testing.expectEqual(ContentEncoding.identity, ContentEncoding.fromHeader("").?);
    try testing.expectEqual(ContentEncoding.identity, ContentEncoding.fromHeader("identity").?);
    try testing.expectEqual(ContentEncoding.gzip, ContentEncoding.fromHeader("gzip").?);
    try testing.expectEqual(ContentEncoding.gzip, ContentEncoding.fromHeader("GZIP").?);
    try testing.expectEqual(ContentEncoding.gzip, ContentEncoding.fromHeader("x-gzip").?);
    try testing.expectEqual(ContentEncoding.zstd, ContentEncoding.fromHeader("zstd").?);
    try testing.expectEqual(@as(?ContentEncoding, null), ContentEncoding.fromHeader("br"));
    try testing.expectEqual(@as(?ContentEncoding, null), ContentEncoding.fromHeader("gzip, deflate"));
}
