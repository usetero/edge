const std = @import("std");
const c = @cImport({
    @cInclude("zlib.h");
});

/// Compress data using zlib's gzip compression
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    std.debug.print("Compressing with zlib...\n", .{});

    // Calculate maximum compressed size
    const max_compressed_size = c.compressBound(@intCast(data.len));
    const compressed = try allocator.alloc(u8, max_compressed_size);
    errdefer allocator.free(compressed);

    var compressed_len: c.uLongf = max_compressed_size;

    // Use compress2 for gzip-compatible compression
    const result = c.compress2(
        compressed.ptr,
        &compressed_len,
        data.ptr,
        @intCast(data.len),
        c.Z_DEFAULT_COMPRESSION,
    );

    if (result != c.Z_OK) {
        return error.CompressionFailed;
    }

    // Resize to actual compressed size
    const final = try allocator.realloc(compressed, compressed_len);

    std.debug.print("Compressed {d} bytes to {d} bytes\n", .{ data.len, compressed_len });

    return final;
}

/// Decompress gzip data using zlib
pub fn decompressGzip(allocator: std.mem.Allocator, compressed: []const u8) ![]u8 {
    std.debug.print("Decompressing with zlib...\n", .{});

    // Start with a reasonable buffer size
    var decompressed_size: usize = compressed.len * 4;
    var decompressed = try allocator.alloc(u8, decompressed_size);
    errdefer allocator.free(decompressed);

    var dest_len: c.uLongf = decompressed_size;

    const result = c.uncompress(
        decompressed.ptr,
        &dest_len,
        compressed.ptr,
        @intCast(compressed.len),
    );

    if (result != c.Z_OK) {
        if (result == c.Z_BUF_ERROR) {
            // Buffer too small, try again with larger buffer
            allocator.free(decompressed);
            decompressed_size *= 2;
            decompressed = try allocator.alloc(u8, decompressed_size);
            dest_len = decompressed_size;

            const retry = c.uncompress(
                decompressed.ptr,
                &dest_len,
                compressed.ptr,
                @intCast(compressed.len),
            );

            if (retry != c.Z_OK) {
                return error.DecompressionFailed;
            }
        } else {
            return error.DecompressionFailed;
        }
    }

    // Resize to actual size
    const final = try allocator.realloc(decompressed, dest_len);

    std.debug.print("Decompressed {d} bytes to {d} bytes\n", .{ compressed.len, dest_len });

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

    try std.testing.expect(compressed.len > 0 and compressed.len != 8);

    // Decompress to verify
    std.debug.print("Decompressing data...\n", .{});
    const decompressed = try decompressGzip(allocator, compressed);
    defer allocator.free(decompressed);

    try std.testing.expectEqualStrings(originalData, decompressed);
}
