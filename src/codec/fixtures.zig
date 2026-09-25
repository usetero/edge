//! Compressors with explicit parameters: zlib at any level, and libzstd with
//! chosen frame options. Tests and benchmarks use them to make inputs the
//! edge's own `Encoder` does not write. The request path does not call them.
const std = @import("std");
const c = @import("c.zig").c;

const log = std.log.scoped(.codec_fixtures);

/// gzip at the zlib default level.
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    return compressGzipLevel(allocator, data, c.Z_DEFAULT_COMPRESSION);
}

/// gzip at a zlib level: 0 (stored blocks) to 9.
pub fn compressGzipLevel(allocator: std.mem.Allocator, data: []const u8, level: c_int) ![]u8 {
    var stream = std.mem.zeroes(c.z_stream);
    // 15 + 16: the largest window, with a gzip header and trailer.
    if (c.deflateInit2(&stream, level, c.Z_DEFLATED, 15 + 16, 8, c.Z_DEFAULT_STRATEGY) != c.Z_OK) {
        return error.CompressionInitFailed;
    }
    defer if (c.deflateEnd(&stream) != c.Z_OK) log.warn("deflateEnd failed", .{});
    const bound = c.deflateBound(&stream, @intCast(data.len));
    const compressed = try allocator.alloc(u8, bound);
    errdefer allocator.free(compressed);
    stream.next_in = @constCast(data.ptr);
    stream.avail_in = @intCast(data.len);
    stream.next_out = compressed.ptr;
    stream.avail_out = @intCast(bound);
    if (c.deflate(&stream, c.Z_FINISH) != c.Z_STREAM_END) return error.CompressionFailed;
    return allocator.realloc(compressed, stream.total_out);
}

/// Frame parameters for `compressZstdWith`.
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
