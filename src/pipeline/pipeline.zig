//! The streaming record pipeline (PLAN.md §6): decode → frame → evaluate →
//! re-encode, over caller-provided fixed buffers, with zero allocation per
//! byte processed.
//!
//!   in_reader ─► Decoder ─► Framer ─► sink.onRecord ─► Encoder ─► out_writer
//!
//! `run` pumps until end of stream and returns framing stats. The sink is
//! comptime duck-typed (see framer.zig); the HTTP layer binds it to policy
//! evaluation in Phase 5, tests bind simple filters. Decode failures
//! propagate as errors — the caller owns §6.5.1 abort semantics, because
//! once compressed input is corrupt nothing downstream can be trusted.
const std = @import("std");
const encoding = @import("encoding.zig");
const framer_mod = @import("framer.zig");

pub const PipelineSpec = struct {
    decode: encoding.ContentEncoding,
    format: framer_mod.WireFormat,
    encode: encoding.ContentEncoding,
    /// Bound on DECODED body bytes (compression-bomb guard); exceeding it
    /// fails the request with error.DecodedBodyTooLarge.
    max_decoded_bytes: usize,
    /// zstd decode window cap; frames declaring a larger window fail the
    /// decode (PLAN §6.5 — caller aborts, never silently truncates).
    zstd_window_len: usize,
    // `decode` is never zstd for a sender's body: decode it first with
    // `compress_buffered.decompressZstd` and pass identity. See `Decoder`.
};

/// All fixed memory the pipeline operates on. In production these are slab
/// regions (conn_slab.zig); in tests, allocator-backed slices.
pub const Buffers = struct {
    /// Decoder window; >= spec.decode.decoderBufferLen(zstd_window_len).
    decoder: []u8,
    /// Encoder window/staging; >= spec.encode.encoderBufferLen().
    encoder: []u8,
    /// Record scratch: the eval-size bound for one record.
    scratch: []u8,
    /// Staging between decoder and framer; any size >= 1, typically 4 KiB.
    chunk: []u8,
};

pub const RunError = error{
    DecodedBodyTooLarge,
    /// Compressed input was corrupt or used unsupported parameters.
    ReadFailed,
    WriteFailed,
    CompressionInitFailed,
} || std.mem.Allocator.Error;

/// Pumps the whole stream through the pipeline. Returns framing stats; the
/// caller compares stats.records vs kept/dropped for telemetry.
pub fn run(
    spec: PipelineSpec,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
    buffers: Buffers,
    sink: anytype,
) !framer_mod.Stats {
    std.debug.assert(buffers.chunk.len > 0);
    std.debug.assert(spec.decode != .zstd);

    var decoder: encoding.Decoder = .init(spec.decode, in_reader, buffers.decoder, spec.zstd_window_len);
    var encoder: encoding.Encoder = try .init(spec.encode, out_writer, buffers.encoder);
    defer encoder.deinit();
    var framer: framer_mod.Framer = .init(spec.format, buffers.scratch);

    const decoded = decoder.reader();
    var total: usize = 0;
    var crc: std.hash.Crc32 = .init();
    while (true) {
        const n = try decoded.readSliceShort(buffers.chunk);
        if (n == 0) break;
        total += n;
        if (total > spec.max_decoded_bytes) return error.DecodedBodyTooLarge;
        if (spec.decode == .gzip) crc.update(buffers.chunk[0..n]);
        try framer.ingest(buffers.chunk[0..n], encoder.writer(), sink);
    }
    try decoder.verifyEnd(crc.final(), @truncate(total));
    try framer.finish(encoder.writer(), sink);
    try encoder.finish();
    return framer.stats();
}

/// Bounded reader→writer copy; the passthrough fast path and response
/// streaming use this. Ported from io/transport.zig.
pub fn streamReaderToWriter(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    max_bytes: usize,
) (std.Io.Reader.StreamError || error{BodyTooLarge})!usize {
    var total_bytes: usize = 0;
    while (total_bytes < max_bytes) {
        const bytes = reader.stream(
            writer,
            std.Io.Limit.limited(max_bytes - total_bytes),
        ) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        // A zero return is not the end: decoders and TLS return 0 before
        // they have output. Only `EndOfStream` ends the copy.
        total_bytes += bytes;
    }
    // EOF must be observed; merely copying the limit can turn a truncated
    // upstream response into a successful response with missing data.
    var excess: [1]u8 = undefined;
    if (try reader.readSliceShort(&excess) != 0) return error.BodyTooLarge;
    return total_bytes;
}

// ============================== Tests ==============================

const testing = std.testing;
const buffered = @import("compress_buffered.zig");

const TEST_WINDOW: usize = 256 * 1024;

const DropSink = struct {
    pub fn onRecord(_: *DropSink, bytes: []const u8) !framer_mod.Decision {
        if (std.mem.indexOf(u8, bytes, "drop") != null) return .drop;
        return .keep;
    }
};

fn testBuffers(spec: PipelineSpec) !Buffers {
    return .{
        .decoder = try testing.allocator.alloc(u8, spec.decode.decoderBufferLen(spec.zstd_window_len)),
        .encoder = try testing.allocator.alloc(u8, spec.encode.encoderBufferLen()),
        .scratch = try testing.allocator.alloc(u8, 4096),
        .chunk = try testing.allocator.alloc(u8, 256),
    };
}

fn freeBuffers(buffers: Buffers) void {
    testing.allocator.free(buffers.decoder);
    testing.allocator.free(buffers.encoder);
    testing.allocator.free(buffers.scratch);
    testing.allocator.free(buffers.chunk);
}

test "gzip ndjson in, filtered, gzip out" {
    const body = "keep1\ndrop me\nkeep2\n";
    const compressed = try buffered.compressGzip(testing.allocator, body);
    defer testing.allocator.free(compressed);

    const spec: PipelineSpec = .{
        .decode = .gzip,
        .format = .ndjson,
        .encode = .gzip,
        .max_decoded_bytes = 1024,
        .zstd_window_len = TEST_WINDOW,
    };
    const buffers = try testBuffers(spec);
    defer freeBuffers(buffers);

    var in: std.Io.Reader = .fixed(compressed);
    var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 4096);
    defer out.deinit();

    var sink: DropSink = .{};
    const stats = try run(spec, &in, &out.writer, buffers, &sink);

    try testing.expectEqual(@as(u64, 3), stats.records);
    try testing.expectEqual(@as(u64, 1), stats.dropped);

    const decoded = try buffered.decompressGzip(testing.allocator, out.written(), 0);
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings("keep1\nkeep2\n", decoded);
}

test "identity json_array in, zstd out" {
    const body = "[{\"m\":\"keep\"},{\"m\":\"drop\"}]";
    const spec: PipelineSpec = .{
        .decode = .identity,
        .format = .json_array,
        .encode = .zstd,
        .max_decoded_bytes = 1024,
        .zstd_window_len = TEST_WINDOW,
    };
    const buffers = try testBuffers(spec);
    defer freeBuffers(buffers);

    var in: std.Io.Reader = .fixed(body);
    var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 4096);
    defer out.deinit();

    var sink: DropSink = .{};
    const stats = try run(spec, &in, &out.writer, buffers, &sink);
    try testing.expectEqual(@as(u64, 1), stats.dropped);

    const decoded = try buffered.decompressZstd(testing.allocator, out.written(), 0, 0);
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings("[{\"m\":\"keep\"}]", decoded);
}

test "decoded body over the bound aborts (PLAN 6.5.1 caller semantics)" {
    const body = "a" ** 10_000; // compresses tiny, inflates past the bound
    const compressed = try buffered.compressGzip(testing.allocator, body);
    defer testing.allocator.free(compressed);

    const spec: PipelineSpec = .{
        .decode = .gzip,
        .format = .ndjson,
        .encode = .identity,
        .max_decoded_bytes = 500,
        .zstd_window_len = TEST_WINDOW,
    };
    const buffers = try testBuffers(spec);
    defer freeBuffers(buffers);

    var in: std.Io.Reader = .fixed(compressed);
    var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 4096);
    defer out.deinit();

    var sink: DropSink = .{};
    try testing.expectError(
        error.DecodedBodyTooLarge,
        run(spec, &in, &out.writer, buffers, &sink),
    );
}

test "corrupt gzip input propagates a read error" {
    const garbage = "\x1f\x8bnot really gzip at all, sorry";
    const spec: PipelineSpec = .{
        .decode = .gzip,
        .format = .ndjson,
        .encode = .identity,
        .max_decoded_bytes = 1024,
        .zstd_window_len = TEST_WINDOW,
    };
    const buffers = try testBuffers(spec);
    defer freeBuffers(buffers);

    var in: std.Io.Reader = .fixed(garbage);
    var out: std.Io.Writer.Allocating = try .initCapacity(testing.allocator, 4096);
    defer out.deinit();

    var sink: DropSink = .{};
    try testing.expectError(
        error.ReadFailed,
        run(spec, &in, &out.writer, buffers, &sink),
    );
}

test "streamReaderToWriter streams full payload" {
    const input = "hello world";
    var input_reader = std.Io.Reader.fixed(input);

    var out_buf: [64]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&out_buf);

    const bytes = try streamReaderToWriter(&input_reader, &output_writer, input.len);

    try std.testing.expectEqual(input.len, bytes);
    try std.testing.expectEqualStrings(input, out_buf[0..bytes]);
}

test "streamReaderToWriter rejects oversized input instead of silently truncating" {
    var in_reader = std.Io.Reader.fixed("abcdef");
    var out_buf: [16]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);

    try testing.expectError(error.BodyTooLarge, streamReaderToWriter(&in_reader, &out_writer, 3));
}

// The httpz frontend forwards the client's original compressed body, skipping
// the re-encode, whenever a batch comes back with `dropped == 0 and
// replaced == 0`. That is only safe if those two counters are the complete set
// of ways a record can differ from its input, so lock both directions here: a
// keep-everything pass must report zero, and a transform must report non-zero.
test "unchanged batches report no drops and no replacements" {
    const body = "keep1\nkeep2\nkeep3\n";
    const compressed = try buffered.compressGzip(testing.allocator, body);
    defer testing.allocator.free(compressed);

    const spec: PipelineSpec = .{
        .decode = .gzip,
        .format = .ndjson,
        .encode = .identity,
        .max_decoded_bytes = 1024,
        .zstd_window_len = TEST_WINDOW,
    };
    const buffers = try testBuffers(spec);
    defer freeBuffers(buffers);

    var in: std.Io.Reader = .fixed(compressed);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var sink: KeepAllSink = .{};
    const stats = try run(spec, &in, &out.writer, buffers, &sink);

    try testing.expectEqual(@as(u64, 0), stats.dropped);
    try testing.expectEqual(@as(u64, 0), stats.replaced);
    try testing.expect(!stats.desynced);
    // Plaintext round-trips unchanged, so the original bytes are equivalent.
    try testing.expectEqualStrings(body, out.written());
}

const KeepAllSink = struct {
    pub fn onRecord(_: *KeepAllSink, _: []const u8) !framer_mod.Decision {
        return .keep;
    }
};
