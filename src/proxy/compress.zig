const std = @import("std");
const c = @cImport({
    @cInclude("zlib.h");
    @cInclude("zstd.h");
});

// Define these constants manually to avoid the overflow issue
const ZSTD_CONTENTSIZE_ERROR: u64 = @bitCast(@as(i64, -2));
const ZSTD_CONTENTSIZE_UNKNOWN: u64 = @bitCast(@as(i64, -1));

/// Compress data using zlib's gzip compression (actual gzip format)
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {

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
        c.Z_DEFAULT_COMPRESSION,
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
pub fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {

    // Start with a reasonable buffer size
    var decompressed_size: usize = compressed.len * 10; // Start with 10x the compressed size
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

        if (result == c.Z_STREAM_END) {
            total_out = stream.total_out;
            break;
        } else if (result == c.Z_BUF_ERROR) {
            // Need more output space
            total_out = stream.total_out;
            decompressed_size *= 2;
            decompressed = try allocator.realloc(decompressed, decompressed_size);
        } else if (result != c.Z_OK) {
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

/// Decompress zstd data
pub fn decompressZstd(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {

    // Get the decompressed size from the frame header
    const decompressed_size = c.ZSTD_getFrameContentSize(compressed.ptr, compressed.len);

    // Use our manually defined constants instead of c.ZSTD_CONTENTSIZE_*
    if (decompressed_size == ZSTD_CONTENTSIZE_ERROR) {
        return error.InvalidCompressedData;
    }

    if (decompressed_size == ZSTD_CONTENTSIZE_UNKNOWN) {
        // If size is unknown, we need to use streaming decompression
        return decompressZstdStreaming(allocator, compressed);
    }

    // Allocate exact size needed
    const decompressed = try allocator.alloc(u8, decompressed_size);
    errdefer allocator.free(decompressed);

    // Perform decompression
    const actual_size = c.ZSTD_decompress(
        decompressed.ptr,
        decompressed_size,
        compressed.ptr,
        compressed.len,
    );

    // Check for errors
    if (c.ZSTD_isError(actual_size) != 0) {
        const error_name = c.ZSTD_getErrorName(actual_size);
        std.log.err("ZSTD decompression failed: {s}", .{error_name});
        return error.DecompressionFailed;
    }

    if (actual_size != decompressed_size) {
        // Resize if needed (shouldn't happen with known size)
        const final = try allocator.realloc(decompressed, actual_size);
        return final;
    }

    return decompressed;
}

/// Streaming decompression for when content size is unknown
fn decompressZstdStreaming(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {

    // Create a decompression context
    const dctx = c.ZSTD_createDCtx();
    if (dctx == null) {
        return error.DecompressionInitFailed;
    }
    defer _ = c.ZSTD_freeDCtx(dctx);

    // Start with a reasonable buffer
    var decompressed_capacity: usize = compressed.len * 10;
    var decompressed = try allocator.alloc(u8, decompressed_capacity);
    errdefer allocator.free(decompressed);

    var in_buffer = c.ZSTD_inBuffer{
        .src = compressed.ptr,
        .size = compressed.len,
        .pos = 0,
    };

    var out_buffer = c.ZSTD_outBuffer{
        .dst = decompressed.ptr,
        .size = decompressed_capacity,
        .pos = 0,
    };

    while (in_buffer.pos < in_buffer.size) {
        // Check if we need more output space
        if (out_buffer.pos == out_buffer.size) {
            decompressed_capacity *= 2;
            decompressed = try allocator.realloc(decompressed, decompressed_capacity);
            out_buffer.dst = decompressed.ptr;
            out_buffer.size = decompressed_capacity;
        }

        const result = c.ZSTD_decompressStream(dctx, &out_buffer, &in_buffer);

        if (c.ZSTD_isError(result) != 0) {
            const error_name = c.ZSTD_getErrorName(result);
            std.log.err("ZSTD decompression failed: {s}", .{error_name});
            return error.DecompressionFailed;
        }

        // result == 0 means frame is completely decoded
        if (result == 0) {
            break;
        }
    }

    // Resize to actual size
    const final = try allocator.realloc(decompressed, out_buffer.pos);

    return final;
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

    // Decompress to verify
    const decompressed = try decompressZstd(allocator, compressed);
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

    // Decompress to verify
    const decompressed = try decompressZstd(allocator, compressed);
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

    // Decompress to verify
    const decompressed = try decompressGzip(allocator, compressed);
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

    // Decompress to verify
    const decompressed = try decompressGzip(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}

test "decompress actual gzip command output" {
    const allocator = std.testing.allocator;

    // This is a real gzip compressed "Hello World\n" for testing
    // Generated with: echo "Hello World" | gzip | xxd -i
    const gzip_data = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0xb4, 0x6a, 0x1f, 0x69, 0x00, 0x03, 0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x08, 0xcf, 0x2f, 0xca, 0x49, 0xe1, 0x02, 0x00, 0xe3, 0xe5, 0x95, 0xb0, 0x0c, 0x00, 0x00, 0x00 };

    const decompressed = try decompressGzip(allocator, &gzip_data);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings("Hello World\n", decompressed);
}
