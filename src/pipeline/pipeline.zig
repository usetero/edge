//! The record pipeline (PLAN.md §6): decode, frame, evaluate, re-encode,
//! over caller-provided fixed buffers, with no allocation per byte.
//!
//!   body ─► codec.Decoder ─► Framer ─► sink.onRecord ─► codec.Encoder ─► out_writer
//!
//! `run` takes the complete body. A decoder never sees part of a body, so a
//! stream that ends early is always a fault in the body, never a sender that
//! has not finished. The sink is comptime duck-typed (see framer.zig). Decode
//! failures return as errors, and the caller fails open: once compressed
//! input is bad, nothing decoded from it can be trusted.
const std = @import("std");
const codec = @import("../codec/root.zig");
const framer_mod = @import("framer.zig");

pub const PipelineSpec = struct {
    decode: codec.ContentEncoding,
    format: framer_mod.WireFormat,
    encode: codec.ContentEncoding,
    /// Bound on decoded body bytes, the compression-bomb guard. Passing it
    /// fails the request with error.DecodedBodyTooLarge.
    max_decoded_bytes: usize,
    /// The largest window a zstd frame may ask for (PLAN §6.5).
    zstd_window_len: usize,
};

/// All fixed memory the pipeline operates on.
pub const Buffers = struct {
    /// Record scratch: the eval-size bound for one record.
    scratch: []u8,
    /// Staging between decoder and framer; any size >= 1, typically 4 KiB.
    chunk: []u8,
};

/// The library state `run` uses. The caller owns both and may reuse them.
pub const Codecs = struct {
    /// Used when `spec.decode` is gzip or zstd.
    decoder: *codec.Decoder,
    /// Used when `spec.encode` is gzip or zstd; null is fine for identity.
    encoder: ?*codec.Encoder,
};

/// Runs the whole of `body`, which must be complete, through the pipeline.
/// Returns framing stats; the caller compares stats.records against kept
/// and dropped for telemetry.
pub fn run(
    spec: PipelineSpec,
    body: []const u8,
    out_writer: *std.Io.Writer,
    buffers: Buffers,
    codecs: Codecs,
    sink: anytype,
) !framer_mod.Stats {
    std.debug.assert(buffers.chunk.len > 0);
    var framer: framer_mod.Framer = .init(spec.format, buffers.scratch);

    const encoder: ?*codec.Encoder = if (spec.encode.codec()) |which| blk: {
        const encoder = codecs.encoder.?;
        try encoder.begin(which, out_writer);
        break :blk encoder;
    } else null;
    const out = if (encoder) |e| &e.writer else out_writer;

    if (spec.decode.codec()) |which| {
        const decoder = codecs.decoder;
        try decoder.begin(which, body, .{ .max_output = spec.max_decoded_bytes, .window_len = spec.zstd_window_len });
        while (true) {
            const n = decoder.read(buffers.chunk) catch |err| return switch (err) {
                error.OutputTooLarge => error.DecodedBodyTooLarge,
                else => |e| e,
            };
            if (n == 0) break;
            try framer.ingest(buffers.chunk[0..n], out, sink);
        }
    } else {
        if (body.len > spec.max_decoded_bytes) return error.DecodedBodyTooLarge;
        // The body is the decoded stream. Feed it in chunk-sized slices.
        var rest = body;
        while (rest.len != 0) {
            const n = @min(rest.len, buffers.chunk.len);
            try framer.ingest(rest[0..n], out, sink);
            rest = rest[n..];
        }
    }
    try framer.finish(out, sink);
    if (encoder) |e| try e.finish() else try out_writer.flush();
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
const fixtures = codec.fixtures;

const TEST_WINDOW: usize = 256 * 1024;

const DropSink = struct {
    pub fn onRecord(_: *DropSink, bytes: []const u8) !framer_mod.Decision {
        if (std.mem.indexOf(u8, bytes, "drop") != null) return .drop;
        return .keep;
    }
};

const KeepAllSink = struct {
    pub fn onRecord(_: *KeepAllSink, _: []const u8) !framer_mod.Decision {
        return .keep;
    }
};

/// Buffers and codecs for one test, freed by `deinit`.
const Harness = struct {
    scratch: [4096]u8 = undefined,
    chunk: [256]u8 = undefined,
    decoder: codec.Decoder,
    encoder: codec.Encoder,
    staging: [512]u8 = undefined,

    fn init(self: *Harness) !void {
        self.decoder = try .init(testing.allocator);
        errdefer self.decoder.deinit(testing.allocator);
        self.encoder = try .init(testing.allocator, &self.staging);
    }

    fn deinit(self: *Harness) void {
        self.decoder.deinit(testing.allocator);
        self.encoder.deinit(testing.allocator);
        self.* = undefined;
    }

    fn buffers(self: *Harness) Buffers {
        return .{ .scratch = &self.scratch, .chunk = &self.chunk };
    }

    fn codecs(self: *Harness) Codecs {
        return .{ .decoder = &self.decoder, .encoder = &self.encoder };
    }

    fn decode(self: *Harness, which: codec.Codec, raw: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(testing.allocator);
        // The edge's encoder does not know the output size, so a zstd frame
        // asks for its level's full window (2 MiB at level 3).
        try self.decoder.begin(which, raw, .{ .max_output = 1 << 20, .window_len = 8 << 20 });
        try self.decoder.readAll(testing.allocator, &out);
        return out.toOwnedSlice(testing.allocator);
    }
};

fn testSpec(decode: codec.ContentEncoding, format: framer_mod.WireFormat, encode: codec.ContentEncoding) PipelineSpec {
    return .{
        .decode = decode,
        .format = format,
        .encode = encode,
        .max_decoded_bytes = 1024,
        .zstd_window_len = TEST_WINDOW,
    };
}

test "gzip ndjson in, filtered, gzip out" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    const compressed = try fixtures.compressGzip(testing.allocator, "keep1\ndrop me\nkeep2\n");
    defer testing.allocator.free(compressed);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var sink: DropSink = .{};
    const stats = try run(testSpec(.gzip, .ndjson, .gzip), compressed, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqual(@as(u64, 3), stats.records);
    try testing.expectEqual(@as(u64, 1), stats.dropped);

    const decoded = try h.decode(.gzip, out.written());
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings("keep1\nkeep2\n", decoded);
}

test "identity json_array in, zstd out" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var sink: DropSink = .{};
    const body = "[{\"m\":\"keep\"},{\"m\":\"drop\"}]";
    const stats = try run(testSpec(.identity, .json_array, .zstd), body, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqual(@as(u64, 1), stats.dropped);

    const decoded = try h.decode(.zstd, out.written());
    defer testing.allocator.free(decoded);
    try testing.expectEqualStrings("[{\"m\":\"keep\"}]", decoded);
}

test "zstd in, identity out" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    const body = "keep1\ndrop me\nkeep2\n";
    const compressed = try fixtures.compressZstdWith(testing.allocator, body, .{ .checksum = true });
    defer testing.allocator.free(compressed);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sink: DropSink = .{};
    _ = try run(testSpec(.zstd, .ndjson, .identity), compressed, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqualStrings("keep1\nkeep2\n", out.written());
}

test "decoded body over the bound aborts (PLAN 6.5.1 caller semantics)" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    // Compresses tiny, inflates past the bound.
    const compressed = try fixtures.compressGzip(testing.allocator, "a" ** 10_000);
    defer testing.allocator.free(compressed);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var sink: DropSink = .{};
    var small = testSpec(.gzip, .ndjson, .identity);
    small.max_decoded_bytes = 500;
    const too_large = run(small, compressed, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectError(error.DecodedBodyTooLarge, too_large);
    // The same bound holds for a body with no encoding.
    var plain = testSpec(.identity, .ndjson, .identity);
    plain.max_decoded_bytes = 500;
    const plain_too_large = run(plain, "b" ** 501, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectError(error.DecodedBodyTooLarge, plain_too_large);
}

test "corrupt gzip input propagates a decode error" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sink: DropSink = .{};
    const garbage = "\x1f\x8bnot really gzip at all, sorry";
    const result = run(testSpec(.gzip, .ndjson, .identity), garbage, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectError(error.Corrupt, result);
}

test "the pipeline rejects every prefix, a bad footer, and bytes after the last member" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    const good = try fixtures.compressGzip(testing.allocator, "one\ntwo\nthree\n");
    defer testing.allocator.free(good);
    var discard: std.Io.Writer.Discarding = .init(&.{});
    var sink: KeepAllSink = .{};
    const keep = testSpec(.gzip, .ndjson, .identity);
    const stats = try run(keep, good, &discard.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqual(@as(u64, 3), stats.records);

    for (0..good.len) |cut| {
        _ = run(keep, good[0..cut], &discard.writer, h.buffers(), h.codecs(), &sink) catch continue;
        return error.PrefixAccepted;
    }
    const bad = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(bad);
    bad[bad.len - 8] ^= 0xff;
    try testing.expectError(error.Corrupt, run(keep, bad, &discard.writer, h.buffers(), h.codecs(), &sink));
    const trailing = try std.mem.concat(testing.allocator, u8, &.{ good, "garbage" });
    defer testing.allocator.free(trailing);
    try testing.expectError(error.Corrupt, run(keep, trailing, &discard.writer, h.buffers(), h.codecs(), &sink));
}

test "two gzip members are one decoded stream" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    const a = try fixtures.compressGzip(testing.allocator, "one\ntwo\n");
    defer testing.allocator.free(a);
    const b = try fixtures.compressGzip(testing.allocator, "three\n");
    defer testing.allocator.free(b);
    const both = try std.mem.concat(testing.allocator, u8, &.{ a, b });
    defer testing.allocator.free(both);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var sink: KeepAllSink = .{};
    const stats = try run(testSpec(.gzip, .ndjson, .identity), both, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqual(@as(u64, 3), stats.records);
    try testing.expectEqualStrings("one\ntwo\nthree\n", out.written());
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

// The frontends forward the client's original compressed body, skipping the
// re-encode, whenever a batch comes back with `dropped == 0 and
// replaced == 0`. That is only safe if those two counters are the complete set
// of ways a record can differ from its input, so lock both directions here: a
// keep-everything pass must report zero, and a transform must report non-zero.
test "unchanged batches report no drops and no replacements" {
    var h: Harness = .{ .decoder = undefined, .encoder = undefined };
    try h.init();
    defer h.deinit();
    const body = "keep1\nkeep2\nkeep3\n";
    const compressed = try fixtures.compressGzip(testing.allocator, body);
    defer testing.allocator.free(compressed);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();

    var sink: KeepAllSink = .{};
    const stats = try run(testSpec(.gzip, .ndjson, .identity), compressed, &out.writer, h.buffers(), h.codecs(), &sink);
    try testing.expectEqual(@as(u64, 0), stats.dropped);
    try testing.expectEqual(@as(u64, 0), stats.replaced);
    try testing.expect(!stats.desynced);
    // Plaintext round-trips unchanged, so the original bytes are equivalent.
    try testing.expectEqualStrings(body, out.written());
}
