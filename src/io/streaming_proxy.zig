const std = @import("std");

pub const ContentEncoding = enum {
    identity,
    gzip,
    zstd,
};

pub const Transform = enum {
    passthrough,
    uppercase_ascii,
};

pub const FallbackReason = enum {
    needs_materialization,
    body_too_large,
    codec_limit,
};

pub const StreamOptions = struct {
    max_materialized_bytes: usize = 8 * 1024 * 1024,
    require_materialization: bool = false,
    content_encoding: ContentEncoding = .identity,
    transform: Transform = .passthrough,
};

pub const TransferStats = struct {
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    used_materialization: bool = false,
    fallback_reason: ?FallbackReason = null,
};

pub const StreamError = error{
    BodyTooLarge,
    UnsupportedCompressedMutation,
};

pub fn streamRequestBody(
    reader: *const std.Io.Reader,
    upstream_writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    options: StreamOptions,
) !TransferStats {
    return streamBody(reader, upstream_writer, allocator, options);
}

pub fn streamResponseBody(
    reader: *const std.Io.Reader,
    client_writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    options: StreamOptions,
) !TransferStats {
    return streamBody(reader, client_writer, allocator, options);
}

fn streamBody(
    reader: *const std.Io.Reader,
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    options: StreamOptions,
) !TransferStats {
    var r = reader.*;
    var stats = TransferStats{};

    if (options.content_encoding != .identity and options.transform != .passthrough) {
        stats.fallback_reason = .codec_limit;
        return StreamError.UnsupportedCompressedMutation;
    }

    if (options.require_materialization) {
        stats.used_materialization = true;
        stats.fallback_reason = .needs_materialization;

        var materialized = std.Io.Writer.Allocating.init(allocator);
        defer materialized.deinit();

        while (true) {
            const n = r.stream(&materialized.writer, .limited(4096)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return error.ReadFailed,
                error.WriteFailed => return error.WriteFailed,
            };
            if (n == 0) break;
            stats.bytes_in += n;
            if (stats.bytes_in > options.max_materialized_bytes) {
                stats.fallback_reason = .body_too_large;
                return StreamError.BodyTooLarge;
            }
        }

        const body = materialized.written();
        stats.bytes_out += try writeChunk(writer, allocator, body, options.transform);
        return stats;
    }

    if (options.transform == .passthrough) {
        while (true) {
            const n = r.stream(writer, .limited(64 * 1024)) catch |err| switch (err) {
                error.EndOfStream => break,
                else => |e| return e,
            };
            if (n == 0) break;
            stats.bytes_in += n;
            stats.bytes_out += n;
        }
        return stats;
    }

    var transform_buf: [4096]u8 = undefined;
    while (true) {
        var temp_writer = std.Io.Writer.fixed(&transform_buf);
        const n = r.stream(&temp_writer, .limited(transform_buf.len)) catch |err| switch (err) {
            error.EndOfStream => break,
            error.ReadFailed => return error.ReadFailed,
            error.WriteFailed => unreachable,
        };
        if (n == 0) break;
        const chunk = transform_buf[0..n];
        stats.bytes_in += n;
        stats.bytes_out += try writeChunk(writer, allocator, chunk, options.transform);
    }
    return stats;
}

fn writeChunk(
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    chunk: []const u8,
    transform: Transform,
) !u64 {
    switch (transform) {
        .passthrough => {
            try writer.writeAll(chunk);
            return chunk.len;
        },
        .uppercase_ascii => {
            const out = try allocator.alloc(u8, chunk.len);
            defer allocator.free(out);
            for (chunk, 0..) |b, i| out[i] = std.ascii.toUpper(b);
            try writer.writeAll(out);
            return out.len;
        },
    }
}

test "stream request passthrough with chunked reader" {
    var source = std.Io.Reader.fixed("hello streamed world");
    var out_buf: [128]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out_buf);
    const stats = try streamRequestBody(
        &source,
        &sink,
        std.testing.allocator,
        .{},
    );
    try std.testing.expectEqual(@as(u64, 20), stats.bytes_in);
    try std.testing.expectEqual(@as(u64, 20), stats.bytes_out);
    try std.testing.expectEqualStrings("hello streamed world", sink.buffered());
}

test "stream request transform uppercase" {
    var source = std.Io.Reader.fixed("abc-123");
    var out_buf: [128]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out_buf);
    const stats = try streamRequestBody(
        &source,
        &sink,
        std.testing.allocator,
        .{ .transform = .uppercase_ascii },
    );
    try std.testing.expectEqual(@as(u64, 7), stats.bytes_in);
    try std.testing.expectEqual(@as(u64, 7), stats.bytes_out);
    try std.testing.expectEqualStrings("ABC-123", sink.buffered());
}

test "materialization enforces max bytes" {
    var source = std.Io.Reader.fixed("1234567890");
    var out_buf: [128]u8 = undefined;
    var sink = std.Io.Writer.fixed(&out_buf);
    try std.testing.expectError(
        StreamError.BodyTooLarge,
        streamRequestBody(
            &source,
            &sink,
            std.testing.allocator,
            .{
                .require_materialization = true,
                .max_materialized_bytes = 4,
            },
        ),
    );
}

test "compressed passthrough allowed but compressed mutation blocked" {
    var source1 = std.Io.Reader.fixed("abc");
    var out_buf1: [16]u8 = undefined;
    var sink1 = std.Io.Writer.fixed(&out_buf1);
    _ = try streamRequestBody(
        &source1,
        &sink1,
        std.testing.allocator,
        .{ .content_encoding = .gzip, .transform = .passthrough },
    );
    try std.testing.expectEqualStrings("abc", sink1.buffered());

    var source2 = std.Io.Reader.fixed("abc");
    var out_buf2: [16]u8 = undefined;
    var sink2 = std.Io.Writer.fixed(&out_buf2);
    try std.testing.expectError(
        StreamError.UnsupportedCompressedMutation,
        streamRequestBody(
            &source2,
            &sink2,
            std.testing.allocator,
            .{ .content_encoding = .gzip, .transform = .uppercase_ascii },
        ),
    );
}
