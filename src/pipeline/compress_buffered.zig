//! Buffered (whole-payload) compression codecs over zlib/zstd C bindings.
//! Cold paths only: the §6.5 fallback, tail policy files, and the test
//! oracle that the streaming codecs in encoding.zig are verified against.
//! Ported verbatim from proxy/compress.zig (PLAN.md §4); the old copy is
//! removed with the proxy folder in Phase 5.
const std = @import("std");
const c = @cImport({
    @cInclude("zlib.h");
    @cInclude("zstd.h");
});

const log = std.log.scoped(.compress_buffered);

// Define these constants manually to avoid the overflow issue
const ZSTD_CONTENTSIZE_ERROR: u64 = @bitCast(@as(i64, -2));
const ZSTD_CONTENTSIZE_UNKNOWN: u64 = @bitCast(@as(i64, -1));

/// Default maximum decompressed size (100MB) to prevent compression bombs
pub const default_max_decompressed_size: usize = 100 * 1024 * 1024;

/// Compress data using zlib's gzip compression (actual gzip format)
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return compressGzipLevel(allocator, data, c.Z_DEFAULT_COMPRESSION);
}

/// `compressGzip` at a zlib level: 0 (stored blocks) to 9.
pub fn compressGzipLevel(allocator: std.mem.Allocator, data: []const u8, level: c_int) ![]u8 {

    // Calculate maximum compressed size
    const max_compressed_size = c.deflateBound(null, @intCast(data.len)) + 18; // Add extra for gzip headers
    const compressed = try allocator.alloc(u8, max_compressed_size);
    errdefer allocator.free(compressed);

    var stream: c.z_stream = undefined;
    stream.zalloc = null;
    stream.zfree = null;
    stream.@"opaque" = null;

    // Initialize for gzip compression
    // The key is using (15 + 16) for windowBits to get gzip format
    var result = c.deflateInit2(
        &stream,
        level,
        c.Z_DEFLATED,
        15 + 16, // 15 is default window size, +16 tells zlib to use gzip format
        8,
        c.Z_DEFAULT_STRATEGY,
    );

    if (result != c.Z_OK) {
        return error.CompressionInitFailed;
    }
    defer _ = c.deflateEnd(&stream);

    stream.next_in = @constCast(data.ptr);
    stream.avail_in = @intCast(data.len);
    stream.next_out = compressed.ptr;
    stream.avail_out = @intCast(max_compressed_size);

    result = c.deflate(&stream, c.Z_FINISH);
    if (result != c.Z_STREAM_END) {
        return error.CompressionFailed;
    }

    const compressed_len = stream.total_out;

    // Resize to actual compressed size
    const final = try allocator.realloc(compressed, compressed_len);

    return final;
}

/// Decompress gzip data using zlib
/// max_size: Maximum allowed decompressed size to prevent compression bombs.
///           Use 0 for default_max_decompressed_size.
pub fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8, max_size: usize) ![]u8 {
    const max_decompressed = if (max_size == 0) default_max_decompressed_size else max_size;

    // Start with a reasonable buffer size, but cap at max
    var decompressed_size: usize = @min(compressed.len * 10, max_decompressed);
    var decompressed = try allocator.alloc(u8, decompressed_size);
    errdefer allocator.free(decompressed);

    var stream: c.z_stream = undefined;
    stream.zalloc = null;
    stream.zfree = null;
    stream.@"opaque" = null;
    stream.next_in = @constCast(compressed.ptr);
    stream.avail_in = @intCast(compressed.len);

    // Initialize for gzip decompression
    // The key is using (15 + 16) for windowBits to handle gzip format
    var result = c.inflateInit2(&stream, 15 + 16);
    if (result != c.Z_OK) {
        return error.DecompressionInitFailed;
    }
    defer _ = c.inflateEnd(&stream);

    var total_out: usize = 0;

    while (true) {
        stream.next_out = decompressed.ptr + total_out;
        stream.avail_out = @intCast(decompressed_size - total_out);

        result = c.inflate(&stream, c.Z_NO_FLUSH);

        if (result != c.Z_STREAM_END and result != c.Z_OK and result != c.Z_BUF_ERROR) {
            return error.DecompressionFailed;
        }
        // Track cumulative output after EVERY inflate call. The proxy-era
        // version only did this on Z_BUF_ERROR, so a Z_OK return with a full
        // output buffer (normal for multi-block streams produced by a
        // streaming compressor) rewound next_out to offset 0 on the next
        // iteration and silently overwrote earlier output.
        total_out = stream.total_out;

        if (result == c.Z_STREAM_END) {
            // Final check: ensure decompressed size doesn't exceed limit
            if (total_out > max_decompressed) {
                return error.DecompressedSizeTooLarge;
            }
            break;
        }

        if (total_out == decompressed_size) {
            // Output buffer is full: grow it, bounded by the bomb limit.
            const new_size = @max(decompressed_size * 2, 64);

            // Check against max size limit to prevent compression bombs
            if (new_size > max_decompressed) {
                return error.DecompressedSizeTooLarge;
            }

            decompressed_size = new_size;
            decompressed = try allocator.realloc(decompressed, decompressed_size);
        } else if (result == c.Z_BUF_ERROR) {
            // No progress possible and output space remains: truncated input.
            return error.DecompressionFailed;
        }
    }

    // Resize to actual size
    const final = try allocator.realloc(decompressed, total_out);

    return final;
}

/// Compress data using zstd compression
pub fn compressZstd(allocator: std.mem.Allocator, data: []const u8) ![]u8 {

    // Get the maximum compressed size bound
    const max_compressed_size = c.ZSTD_compressBound(data.len);
    const compressed = try allocator.alloc(u8, max_compressed_size);
    errdefer allocator.free(compressed);

    // Perform compression with default compression level (3)
    const compressed_size = c.ZSTD_compress(
        compressed.ptr,
        max_compressed_size,
        data.ptr,
        data.len,
        c.ZSTD_CLEVEL_DEFAULT, // Default compression level (3)
    );

    // Check for errors
    if (c.ZSTD_isError(compressed_size) != 0) {
        const error_name = c.ZSTD_getErrorName(compressed_size);
        std.log.err("ZSTD compression failed: {s}", .{error_name});
        return error.CompressionFailed;
    }

    // Resize to actual compressed size
    const final = try allocator.realloc(compressed, compressed_size);

    return final;
}

/// Decompress every zstd frame in `compressed`, in order.
///
/// Safe on untrusted input: libzstd returns an error for each malformed
/// frame, and input that ends inside a frame fails with `DecompressionFailed`.
/// The edge decodes zstd here and not with `std.compress.zstd`, which in Zig
/// 0.16.0 reaches `unreachable` on some corrupt frames.
///
/// `max_size` bounds the output (0 = default_max_decompressed_size).
/// `window_len` bounds the window a frame may declare, which is the memory
/// libzstd allocates (0 = the libzstd limit). A frame that declares its size
/// and fits the output decodes into the output, needs no window, and skips
/// that check; `max_size` still bounds it.
pub fn decompressZstd(allocator: std.mem.Allocator, compressed: []const u8, max_size: usize, window_len: usize) ![]u8 {
    const max_decompressed = if (max_size == 0) default_max_decompressed_size else max_size;

    const dctx = c.ZSTD_createDCtx() orelse return error.DecompressionInitFailed;
    defer if (c.ZSTD_isError(c.ZSTD_freeDCtx(dctx)) != 0) log.warn("ZSTD_freeDCtx failed", .{});
    if (window_len != 0) {
        const log_max: c_int = std.math.log2_int_ceil(usize, window_len);
        if (c.ZSTD_isError(c.ZSTD_DCtx_setParameter(dctx, c.ZSTD_d_windowLogMax, log_max)) != 0) {
            return error.DecompressionInitFailed;
        }
    }

    // A declared content size only sets the first allocation. The frame can
    // lie, so the cap below still applies to what it actually produces.
    const declared = c.ZSTD_getFrameContentSize(compressed.ptr, compressed.len);
    if (declared == ZSTD_CONTENTSIZE_ERROR) return error.InvalidCompressedData;
    const first: usize = if (declared == ZSTD_CONTENTSIZE_UNKNOWN)
        compressed.len *| 4
    else
        @intCast(@min(declared, max_decompressed));
    var out: std.ArrayList(u8) = try .initCapacity(allocator, @max(@min(first, max_decompressed), 64));
    errdefer out.deinit(allocator);

    var in_buffer: c.ZSTD_inBuffer = .{ .src = compressed.ptr, .size = compressed.len, .pos = 0 };
    while (true) {
        if (out.items.len == out.capacity) {
            if (out.capacity >= max_decompressed) return error.DecompressedSizeTooLarge;
            try out.ensureTotalCapacityPrecise(allocator, @min(out.capacity *| 2, max_decompressed));
        }
        const spare = out.unusedCapacitySlice();
        var out_buffer: c.ZSTD_outBuffer = .{ .dst = spare.ptr, .size = spare.len, .pos = 0 };
        const in_before = in_buffer.pos;
        const result = c.ZSTD_decompressStream(dctx, &out_buffer, &in_buffer);
        if (c.ZSTD_isError(result) != 0) return error.DecompressionFailed;
        out.items.len += out_buffer.pos;

        const input_done = in_buffer.pos == in_buffer.size;
        // 0: the frame is complete and flushed. More input is another frame.
        if (result == 0 and input_done) break;
        // Room was left and no input remains, so the last frame is open:
        // the input ended early. A step with no progress is also malformed.
        if (input_done and out_buffer.pos < out_buffer.size) return error.DecompressionFailed;
        const stuck = out_buffer.pos == 0 and in_buffer.pos == in_before;
        if (stuck and out_buffer.size != 0) return error.DecompressionFailed;
    }
    return out.toOwnedSlice(allocator);
}

/// Options for `compressZstdWith`, for tests that need a specific frame.
pub const ZstdFrameOptions = struct {
    level: c_int = c.ZSTD_CLEVEL_DEFAULT,
    checksum: bool = false,
    /// 0 keeps the libzstd default.
    window_log: c_int = 0,
    /// False leaves the content size out of the frame header.
    content_size: bool = true,
};

fn setZstdParameter(cctx: *c.ZSTD_CCtx, parameter: c.ZSTD_cParameter, value: c_int) error{CompressionInitFailed}!void {
    if (c.ZSTD_isError(c.ZSTD_CCtx_setParameter(cctx, parameter, value)) != 0) return error.CompressionInitFailed;
}

/// Compress with explicit frame parameters.
pub fn compressZstdWith(allocator: std.mem.Allocator, data: []const u8, options: ZstdFrameOptions) ![]u8 {
    const cctx = c.ZSTD_createCCtx() orelse return error.CompressionInitFailed;
    defer if (c.ZSTD_isError(c.ZSTD_freeCCtx(cctx)) != 0) log.warn("ZSTD_freeCCtx failed", .{});
    try setZstdParameter(cctx, c.ZSTD_c_compressionLevel, options.level);
    try setZstdParameter(cctx, c.ZSTD_c_checksumFlag, @intFromBool(options.checksum));
    try setZstdParameter(cctx, c.ZSTD_c_contentSizeFlag, @intFromBool(options.content_size));
    if (options.window_log != 0) try setZstdParameter(cctx, c.ZSTD_c_windowLog, options.window_log);
    const bound = c.ZSTD_compressBound(data.len);
    const compressed = try allocator.alloc(u8, bound);
    errdefer allocator.free(compressed);
    const n = c.ZSTD_compress2(cctx, compressed.ptr, bound, data.ptr, data.len);
    if (c.ZSTD_isError(n) != 0) return error.CompressionFailed;
    return allocator.realloc(compressed, n);
}

// ========== Tests ==========

test "compressZstd and decompressZstd" {
    const allocator = std.testing.allocator;

    const originalData = "Test log message";

    // Compress the test data
    const compressed = try compressZstd(allocator, originalData);
    defer allocator.free(compressed);

    // Check for zstd magic number (0xFD2FB528 in little-endian)
    try std.testing.expect(compressed.len >= 4);
    try std.testing.expect(compressed[0] == 0x28);
    try std.testing.expect(compressed[1] == 0xB5);
    try std.testing.expect(compressed[2] == 0x2F);
    try std.testing.expect(compressed[3] == 0xFD);

    // Decompress to verify (0 = use default max size)
    const decompressed = try decompressZstd(allocator, compressed, 0, 0);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}

test "zstd compress and decompress JSON payload" {
    const allocator = std.testing.allocator;

    const originalData =
        \\ [
        \\   {
        \\     "ddsource": "nginx",
        \\     "ddtags": "env:staging,version:5.1",
        \\     "hostname": "i-012345678",
        \\     "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello World",
        \\     "service": "payment"
        \\   }
        \\ ]
    ;

    // Compress the test data
    const compressed = try compressZstd(allocator, originalData);
    defer allocator.free(compressed);

    // Compression ratio should be good for JSON
    try std.testing.expect(compressed.len < originalData.len);

    // Decompress to verify (0 = use default max size)
    const decompressed = try decompressZstd(allocator, compressed, 0, 0);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}

test "zstd vs gzip compression comparison" {
    const allocator = std.testing.allocator;

    const testData = "a" ** 1000; // Highly compressible data

    // Compress with gzip
    const gzip_compressed = try compressGzip(allocator, testData);
    defer allocator.free(gzip_compressed);

    // Compress with zstd
    const zstd_compressed = try compressZstd(allocator, testData);
    defer allocator.free(zstd_compressed);

    // Both should compress well
    try std.testing.expect(gzip_compressed.len < 50);
    try std.testing.expect(zstd_compressed.len < 50);
}

test "compressGzip and decompressGzip" {
    const allocator = std.testing.allocator;

    const originalData = "Test log message";

    // Compress the test data
    const compressed = try compressGzip(allocator, originalData);
    defer allocator.free(compressed);

    // Check for gzip magic number
    try std.testing.expect(compressed.len >= 10);
    try std.testing.expect(compressed[0] == 0x1f);
    try std.testing.expect(compressed[1] == 0x8b);

    // Decompress to verify (0 = use default max size)
    const decompressed = try decompressGzip(allocator, compressed, 0);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}

test "decompress json payload" {
    const allocator = std.testing.allocator;

    const originalData =
        \\ [
        \\   {
        \\     "ddsource": "nginx",
        \\     "ddtags": "env:staging,version:5.1",
        \\     "hostname": "i-012345678",
        \\     "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello World",
        \\     "service": "payment"
        \\   }
        \\ ]
    ;

    // Compress the test data
    const compressed = try compressGzip(allocator, originalData);
    defer allocator.free(compressed);

    // Check for gzip magic number
    try std.testing.expect(compressed.len >= 10);
    try std.testing.expect(compressed[0] == 0x1f);
    try std.testing.expect(compressed[1] == 0x8b);

    // Decompress to verify (0 = use default max size)
    const decompressed = try decompressGzip(allocator, compressed, 0);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}

test "decompress actual gzip command output" {
    const allocator = std.testing.allocator;

    // This is a real gzip compressed "Hello World\n" for testing
    // Generated with: echo "Hello World" | gzip | xxd -i
    const gzip_data = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0xb4, 0x6a, 0x1f, 0x69,
        0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57,
        0x08, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00,
        0xe3, 0xe5, 0x95, 0xb0, 0x0c, 0x00, 0x00, 0x00,
    };

    const decompressed = try decompressGzip(allocator, &gzip_data, 0);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings("Hello World\n", decompressed);
}

test "decompressGzip rejects data exceeding max size" {
    const allocator = std.testing.allocator;

    // Create highly compressible data (10000 'a' characters)
    // This compresses very small but decompresses large
    const original = "a" ** 10000;
    const compressed = try compressGzip(allocator, original);
    defer allocator.free(compressed);

    // Compressed size will be ~30 bytes, initial buffer = 30 * 10 = 300
    // We need 10000 bytes, so buffer will try to grow: 300 -> 600 -> 1200 -> 2400 -> 4800 -> 9600 -> 19200
    // With max_size=500, it should fail when trying to grow to 600
    const result = decompressGzip(allocator, compressed, 500);
    try std.testing.expectError(error.DecompressedSizeTooLarge, result);
}

test "decompressZstd rejects data exceeding max size" {
    const allocator = std.testing.allocator;

    // Create highly compressible data (10000 'a' characters)
    const original = "a" ** 10000;
    const compressed = try compressZstd(allocator, original);
    defer allocator.free(compressed);

    // ZSTD stores the decompressed size in the header, so it checks upfront
    const result = decompressZstd(allocator, compressed, 500, 0);
    try std.testing.expectError(error.DecompressedSizeTooLarge, result);
}

test "decompressZstd rejects truncated frame with known content size" {
    const allocator = std.testing.allocator;

    // The one-shot compressZstd embeds the content size in the frame header, so
    // decompressZstd routes through the known-size branch (ZSTD_decompress),
    // not decompressZstdStreaming. That branch already rejected truncated
    // input from day one — this test documents the safe subpath the streaming
    // branch is contrasted against. It truncates the frame to an *incomplete
    // header* (fewer than the minimum 6-byte zstd1 frame header), which makes
    // ZSTD_getFrameContentSize return ZSTD_CONTENTSIZE_ERROR, surfaced as
    // error.InvalidCompressedData before any ZSTD_decompress call. (Body
    // truncation of a known-size frame reaches the one-shot ZSTD_decompress
    // error path and would also be rejected, but that path logs via
    // std.log.err; the header-truncated subpath is the log-free rejection
    // this test exercises.)
    const payload_len: usize = 300_000;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    for (payload, 0..) |*b, i| b.* = @intCast(i % 251);

    const compressed = try compressZstd(allocator, payload);
    defer allocator.free(compressed);

    // Known content size => the non-streaming branch.
    try std.testing.expect(c.ZSTD_getFrameContentSize(compressed.ptr, compressed.len) == @as(u64, payload_len));

    // Sanity: a complete frame round-trips.
    {
        const decoded = try decompressZstd(allocator, compressed, 0, 0);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, payload, decoded);
    }

    // Truncate to an incomplete header at several lengths (keep < the minimum
    // 6-byte zstd1 frame header); each must be rejected with
    // error.InvalidCompressedData, never a silent partial plaintext.
    for ([_]usize{ 0, 3, 4 }) |keep| {
        const truncated = compressed[0..@min(keep, compressed.len)];
        try std.testing.expectError(error.InvalidCompressedData, decompressZstd(allocator, truncated, 0, 0));
    }
}
