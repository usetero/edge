const std = @import("std");
const c = @cImport({
    @cInclude("zlib.h");
});

/// Compress data using zlib's gzip compression (actual gzip format)
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    std.debug.print("Compressing with zlib (gzip format)...\n", .{});

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

    std.debug.print("Compressed {d} bytes to {d} bytes\n", .{ data.len, compressed_len });

    return final;
}

/// Decompress gzip data using zlib
pub fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    std.debug.print("Decompressing with zlib (gzip format)...\n", .{});

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

    std.debug.print("Decompressed {d} bytes to {d} bytes\n", .{ compressed.len, total_out });

    return final;
}

test "compressGzip and decompressGzip" {
    const allocator = std.testing.allocator;

    const originalData = "Test log message";

    // Compress the test data
    std.debug.print("Compressing data...\n", .{});
    const compressed = try compressGzip(allocator, originalData);
    std.debug.print("Successfully compressed data...\n", .{});
    defer allocator.free(compressed);

    std.debug.print("Compressed data length: {}\n", .{compressed.len});

    // Check for gzip magic number
    try std.testing.expect(compressed.len >= 10);
    try std.testing.expect(compressed[0] == 0x1f);
    try std.testing.expect(compressed[1] == 0x8b);

    // Decompress to verify
    std.debug.print("Decompressing data...\n", .{});
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
    std.debug.print("Compressing data...\n", .{});
    const compressed = try compressGzip(allocator, originalData);
    std.debug.print("Successfully compressed data...\n", .{});
    defer allocator.free(compressed);

    std.debug.print("Compressed data length: {}\n", .{compressed.len});

    // Check for gzip magic number
    try std.testing.expect(compressed.len >= 10);
    try std.testing.expect(compressed[0] == 0x1f);
    try std.testing.expect(compressed[1] == 0x8b);

    // Decompress to verify
    std.debug.print("Decompressing data...\n", .{});
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
