//! Safety tests for decoding a compressed body from a sender.
//!
//! One property holds in every test: a decode returns an error or the exact
//! bytes that were compressed. It never panics, never hangs, and never returns
//! other bytes. The tests call the functions the edge uses: `decodeResident`
//! for the buffered path and `pipeline.run` for the streamed path.
//!
//! The gzip cases guard a std bug: in Zig 0.16.0, `flate.Decompress` reaches
//! `unreachable` on a stream that ends early
//! (https://codeberg.org/ziglang/zig/issues/35789). The zstd cases guard a
//! second std bug, in `zstd.Decompress.decodeLiterals`, which the edge avoids
//! by decoding zstd with libzstd. The fuzz tests run their corpus in a normal
//! `zig build test`, and search for new inputs under `zig build test --fuzz`.
//!
//! `-Ddecode-test-scale=N` multiplies the random cases and the prefixes of
//! long streams. The default of 1 keeps `zig build test` fast. A deep run:
//! `zig build test -Doptimize=ReleaseSafe -Ddecode-test-scale=50`.
const std = @import("std");
const encoding = @import("encoding.zig");
const buffered = @import("compress_buffered.zig");
const pipeline = @import("pipeline.zig");
const framer_mod = @import("framer.zig");

const testing = std.testing;
const ContentEncoding = encoding.ContentEncoding;
const scale: usize = @import("build_options").decode_test_scale;

/// The largest zstd window the edge allows (`ZSTD_WINDOW_MAX`). The frames
/// here use up to 2 MiB windows, above the 1 MiB default.
const window_len: usize = 8 << 20;
const max_decoded: usize = 4 << 20;

/// Inputs a fuzz run found against the Zig 0.16.0 std decoders. Each entry is
/// a little-endian u32 length and then the bytes. Every gzip entry crashed
/// std flate when its input ended with `EndOfStream`.
const gzip_crashes = @embedFile("testdata/gzip_crashes.bin");
/// A full-length zstd frame with two changed bytes. It reaches `unreachable`
/// in `std.compress.zstd` in Zig 0.16.0.
const zstd_corrupt = @embedFile("testdata/zstd_corrupt.zst");

fn crashInputs() CrashIterator {
    return .{ .rest = gzip_crashes };
}

const CrashIterator = struct {
    rest: []const u8,

    fn next(self: *CrashIterator) ?[]const u8 {
        if (self.rest.len == 0) return null;
        const len = std.mem.readInt(u32, self.rest[0..4], .little);
        const input = self.rest[4..][0..len];
        self.rest = self.rest[4 + len ..];
        return input;
    }
};

// ------------------------------------------------------------- payloads

const Payloads = struct {
    list: [8][]u8,

    fn init(gpa: std.mem.Allocator) !Payloads {
        var prng: std.Random.DefaultPrng = .init(0x5afe);
        const rand = prng.random();
        var self: Payloads = undefined;
        self.list[0] = try gpa.dupe(u8, "");
        self.list[1] = try gpa.dupe(u8, "x");
        self.list[2] = try gpa.dupe(u8, "Test log message");
        self.list[3] = try jsonLogs(gpa, rand, 1_000);
        self.list[4] = try jsonLogs(gpa, rand, 70_000);
        // Incompressible, so zlib writes stored blocks at every level.
        self.list[5] = try gpa.alloc(u8, 20_000);
        rand.bytes(self.list[5]);
        // Long matches, far past the 32 KiB flate window.
        self.list[6] = try gpa.alloc(u8, 100_000);
        @memset(self.list[6], 'a');
        self.list[7] = try jsonLogs(gpa, rand, 300_000);
        return self;
    }

    fn deinit(self: *Payloads, gpa: std.mem.Allocator) void {
        for (self.list) |payload| gpa.free(payload);
        self.* = undefined;
    }

    fn jsonLogs(gpa: std.mem.Allocator, rand: std.Random, approx: usize) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        try out.writer.writeByte('[');
        var n: usize = 0;
        while (out.written().len < approx) : (n += 1) {
            if (n != 0) try out.writer.writeByte(',');
            const level = if (rand.boolean()) "INFO" else "DEBUG";
            try out.writer.print(
                "{{\"message\":\"{s} request {d} id={x}\",\"service\":\"orders-api\"}}",
                .{ level, n, rand.int(u64) },
            );
        }
        try out.writer.writeByte(']');
        return out.toOwnedSlice();
    }
};

// ------------------------------------------------------------ compressors

const gzip_levels = [_]c_int{ 0, 1, 6, 9 };

/// Every gzip form under test: zlib at four levels, and std's own encoder.
fn gzipForms(gpa: std.mem.Allocator, payload: []const u8) ![5][]u8 {
    var forms: [5][]u8 = undefined;
    var made: usize = 0;
    errdefer for (forms[0..made]) |form| gpa.free(form);
    for (gzip_levels) |level| {
        forms[made] = try buffered.compressGzipLevel(gpa, payload, level);
        made += 1;
    }
    forms[made] = try encodeWithStd(gpa, .gzip, payload);
    return forms;
}

fn freeForms(gpa: std.mem.Allocator, forms: []const []u8) void {
    for (forms) |form| gpa.free(form);
}

/// Encodes through `encoding.Encoder`, the edge's own encoder. For zstd this
/// writes a frame with no declared content size.
fn encodeWithStd(gpa: std.mem.Allocator, codec: ContentEncoding, payload: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    errdefer out.deinit();
    const buf = try gpa.alloc(u8, codec.encoderBufferLen());
    defer gpa.free(buf);
    var encoder: encoding.Encoder = try .init(codec, &out.writer, buf);
    defer encoder.deinit();
    try encoder.writer().writeAll(payload);
    try encoder.finish();
    return out.toOwnedSlice();
}

/// Every zstd form under test: three levels with and without a checksum, and
/// a frame with no declared content size.
fn zstdForms(gpa: std.mem.Allocator, payload: []const u8) ![7]ZstdForm {
    var forms: [7]ZstdForm = undefined;
    var made: usize = 0;
    errdefer for (forms[0..made]) |form| gpa.free(form.bytes);
    for ([_]c_int{ 1, 3, 19 }) |level| {
        for ([_]bool{ false, true }) |checksum| {
            forms[made] = .{
                .bytes = try buffered.compressZstdWith(gpa, payload, .{ .level = level, .checksum = checksum }),
                .checksum = checksum,
            };
            made += 1;
        }
    }
    forms[made] = .{ .bytes = try encodeWithStd(gpa, .zstd, payload), .checksum = false };
    return forms;
}

const ZstdForm = struct { bytes: []u8, checksum: bool };

fn freeZstdForms(gpa: std.mem.Allocator, forms: []const ZstdForm) void {
    for (forms) |form| gpa.free(form.bytes);
}

// --------------------------------------------------------------- checks

/// The core property. A decode that succeeds must return `expected`.
fn expectInputOrError(codec: ContentEncoding, raw: []const u8, expected: []const u8) !void {
    const decoded = encoding.decodeResident(codec, testing.allocator, raw, max_decoded, window_len) catch return;
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, expected, decoded);
}

/// The property for input with no reference: no crash, no leak, bounded.
fn expectNoCrash(codec: ContentEncoding, raw: []const u8) !void {
    const decoded = encoding.decodeResident(codec, testing.allocator, raw, max_decoded, window_len) catch return;
    defer testing.allocator.free(decoded);
    try testing.expect(decoded.len <= max_decoded);
}

fn expectDecodes(codec: ContentEncoding, raw: []const u8, expected: []const u8) !void {
    const decoded = try encoding.decodeResident(codec, testing.allocator, raw, max_decoded, window_len);
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, expected, decoded);
}

fn expectRejected(codec: ContentEncoding, raw: []const u8) !void {
    const decoded = encoding.decodeResident(codec, testing.allocator, raw, max_decoded, window_len) catch return;
    defer testing.allocator.free(decoded);
    std.debug.print("{s}: {d} bytes decoded as complete\n", .{ @tagName(codec), raw.len });
    return error.InputAccepted;
}

/// Every prefix for a short stream. A long stream gets every prefix near its
/// ends and some spread over the middle, which keeps the test fast.
fn cutPoints(len: usize, index: usize) ?usize {
    if (len <= 2048) return if (index < len) index else null;
    // @min narrows to the smallest type that holds 64 * scale, so widen it.
    const edge: usize = @min(64 * scale, len / 2);
    if (index < edge) return index;
    if (index < 2 * edge) return len - 2 * edge + index;
    const spread: usize = 32 * scale;
    if (index < 2 * edge + spread) return edge + (index - 2 * edge) * (len - 2 * edge) / spread;
    return null;
}

/// Changes 1 to 8 bytes at random, and sometimes cuts the end too.
fn corrupt(rand: std.Random, dst: []u8, src: []const u8) []u8 {
    @memcpy(dst[0..src.len], src);
    const flips = rand.intRangeAtMost(usize, 1, 8);
    for (0..flips) |_| {
        const at = rand.uintLessThan(usize, src.len);
        dst[at] = if (rand.boolean()) rand.int(u8) else dst[at] ^ (@as(u8, 1) << rand.int(u3));
    }
    const len = if (rand.uintLessThan(u8, 4) == 0) rand.uintAtMost(usize, src.len) else src.len;
    return dst[0..len];
}

// ---------------------------------------------------------------- gzip

test "gzip: valid streams decode to the input, and zlib agrees" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try gzipForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            try expectDecodes(.gzip, form, payload);
            const oracle = try buffered.decompressGzip(gpa, form, max_decoded);
            defer gpa.free(oracle);
            try testing.expectEqualSlices(u8, payload, oracle);
        }
    }
}

test "gzip: every prefix of a stream is rejected" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try gzipForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            var index: usize = 0;
            while (cutPoints(form.len, index)) |cut| : (index += 1) {
                try expectRejected(.gzip, form[0..cut]);
            }
        }
    }
}

test "gzip: corrupt bytes decode to an error or to the input" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0xc0ffee);
    const rand = prng.random();
    for (payloads.list[1..6]) |payload| {
        const forms = try gzipForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            const scratch = try gpa.alloc(u8, form.len);
            defer gpa.free(scratch);
            for (0..60 * scale) |_| try expectInputOrError(.gzip, corrupt(rand, scratch, form), payload);
        }
    }
}

test "gzip: random bytes behind a gzip header never crash" {
    var prng: std.Random.DefaultPrng = .init(0x9a4b);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    for (0..2000 * scale) |_| {
        const len = rand.intRangeAtMost(usize, 10, buf.len);
        rand.bytes(buf[0..len]);
        // A valid header, so the decoder reaches the deflate blocks.
        @memcpy(buf[0..4], "\x1f\x8b\x08\x00");
        try expectNoCrash(.gzip, buf[0..len]);
    }
}

test "gzip: every input that crashed std flate is rejected" {
    var inputs = crashInputs();
    var count: usize = 0;
    while (inputs.next()) |input| : (count += 1) {
        try expectRejected(.gzip, input);
        // zlib must reject it too, or the input is valid and the edge is wrong.
        const oracle = buffered.decompressGzip(testing.allocator, input, max_decoded) catch continue;
        testing.allocator.free(oracle);
        return error.OracleAcceptedCrashInput;
    }
    try testing.expect(count > 50);
}

test "gzip: a wrong CRC, a wrong length, or bytes after the member are rejected" {
    const gpa = testing.allocator;
    const payload = "the footer covers these bytes";
    const good = try buffered.compressGzip(gpa, payload);
    defer gpa.free(good);
    try expectDecodes(.gzip, good, payload);

    const bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    // The footer is the CRC32, then the length mod 2^32, both little-endian.
    for ([_]usize{ 8, 7, 5, 4, 3, 1 }) |from_end| {
        @memcpy(bad, good);
        bad[bad.len - from_end] ^= 0x01;
        try expectRejected(.gzip, bad);
    }

    const trailing = try std.mem.concat(gpa, u8, &.{ good, "x" });
    defer gpa.free(trailing);
    try expectRejected(.gzip, trailing);

    // std flate stops after one member, so two members must fail open and
    // not lose the second member.
    const two_members = try std.mem.concat(gpa, u8, &.{ good, good });
    defer gpa.free(two_members);
    try expectRejected(.gzip, two_members);
}

test "gzip: optional header fields do not change the data" {
    const gpa = testing.allocator;
    const payload = "header fields carry no data";
    const plain = try buffered.compressGzip(gpa, payload);
    defer gpa.free(plain);
    const deflate = plain[10 .. plain.len - 8];
    const footer = plain[plain.len - 8 ..];

    // FEXTRA, FNAME and FCOMMENT, each alone and together.
    const flags = [_]u8{ 0x04, 0x08, 0x10, 0x1c };
    for (flags) |flag| {
        var head: std.Io.Writer.Allocating = .init(gpa);
        defer head.deinit();
        try head.writer.writeAll(&[_]u8{ 0x1f, 0x8b, 0x08, flag, 0, 0, 0, 0, 0, 3 });
        if (flag & 0x04 != 0) try head.writer.writeAll(&[_]u8{ 3, 0, 'a', 'b', 'c' });
        if (flag & 0x08 != 0) try head.writer.writeAll("name.json\x00");
        if (flag & 0x10 != 0) try head.writer.writeAll("a comment\x00");
        const stream = try std.mem.concat(gpa, u8, &.{ head.written(), deflate, footer });
        defer gpa.free(stream);
        try expectDecodes(.gzip, stream, payload);
        // A cut inside the header fields is still rejected.
        for (1..head.written().len) |cut| try expectRejected(.gzip, stream[0..cut]);
    }
}

// ---------------------------------------------------------------- zstd

test "zstd: valid frames decode to the input" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try zstdForms(gpa, payload);
        defer freeZstdForms(gpa, &forms);
        for (forms) |form| try expectDecodes(.zstd, form.bytes, payload);
    }
}

test "zstd: several frames, and a skippable frame, decode in order" {
    const gpa = testing.allocator;
    const a = try buffered.compressZstdWith(gpa, "first frame,", .{});
    defer gpa.free(a);
    const b = try encodeWithStd(gpa, .zstd, "second frame");
    defer gpa.free(b);
    // A skippable frame: magic 0x184D2A50, a length, then that many bytes.
    const skip = "\x50\x2a\x4d\x18\x03\x00\x00\x00abc";
    const stream = try std.mem.concat(gpa, u8, &.{ a, skip, b });
    defer gpa.free(stream);
    try expectDecodes(.zstd, stream, "first frame,second frame");
    try expectRejected(.zstd, stream[0 .. stream.len - 1]);
}

test "zstd: every prefix of a frame is rejected" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try zstdForms(gpa, payload);
        defer freeZstdForms(gpa, &forms);
        for (forms) |form| {
            var index: usize = 0;
            while (cutPoints(form.bytes.len, index)) |cut| : (index += 1) {
                try expectRejected(.zstd, form.bytes[0..cut]);
            }
        }
    }
}

test "zstd: corrupt bytes never crash" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x2d57);
    const rand = prng.random();
    for (payloads.list[1..6]) |payload| {
        const forms = try zstdForms(gpa, payload);
        defer freeZstdForms(gpa, &forms);
        for (forms) |form| {
            const scratch = try gpa.alloc(u8, form.bytes.len);
            defer gpa.free(scratch);
            // No output check here. The checksum flag sits in the frame
            // header, so a corruption can turn the check off. libzstd then
            // decodes changed data with no error, which the format allows.
            for (0..40 * scale) |_| try expectNoCrash(.zstd, corrupt(rand, scratch, form.bytes));
        }
    }
}

/// Bytes of the zstd frame header, from its descriptor byte.
fn zstdHeaderLen(frame: []const u8) usize {
    const descriptor = frame[4];
    const single_segment = descriptor & 0x20 != 0;
    const fcs_lens = [_]usize{ @intFromBool(single_segment), 2, 4, 8 };
    const dict_lens = [_]usize{ 0, 1, 2, 4 };
    const fcs_len = fcs_lens[descriptor >> 6];
    const dict_len = dict_lens[descriptor & 0x03];
    return 5 + @as(usize, @intFromBool(!single_segment)) + dict_len + fcs_len;
}

test "zstd: a checksum frame with any bit changed after its header decodes to an error or the input" {
    const gpa = testing.allocator;
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list[1..4]) |payload| {
        const frame = try buffered.compressZstdWith(gpa, payload, .{ .checksum = true });
        defer gpa.free(frame);
        const damaged = try gpa.dupe(u8, frame);
        defer gpa.free(damaged);
        for (zstdHeaderLen(frame)..frame.len) |at| {
            for (0..8) |bit| {
                @memcpy(damaged, frame);
                damaged[at] ^= @as(u8, 1) << @intCast(bit);
                try expectInputOrError(.zstd, damaged, payload);
            }
        }
    }
}

test "zstd: the frame that crashed std zstd is rejected" {
    try expectRejected(.zstd, zstd_corrupt);
}

test "zstd: random bytes behind a frame header never crash" {
    var prng: std.Random.DefaultPrng = .init(0x7a57);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    for (0..2000 * scale) |_| {
        const len = rand.intRangeAtMost(usize, 6, buf.len);
        rand.bytes(buf[0..len]);
        @memcpy(buf[0..4], "\x28\xb5\x2f\xfd");
        try expectNoCrash(.zstd, buf[0..len]);
    }
}

test "zstd: a window above the cap is rejected, and one at the cap decodes" {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 3 << 20);
    defer gpa.free(payload);
    var prng: std.Random.DefaultPrng = .init(0x3d);
    // Repeats that sit 2 MiB apart, so the frame needs its full window.
    prng.random().bytes(payload[0 .. 1 << 20]);
    @memset(payload[1 << 20 .. 2 << 20], 0);
    @memcpy(payload[2 << 20 ..], payload[0 .. 1 << 20]);

    // No declared size, so libzstd must hold a window of the declared length.
    const cap: usize = 1 << 20;
    const wide = try buffered.compressZstdWith(gpa, payload, .{ .window_log = 23, .content_size = false });
    defer gpa.free(wide);
    if (buffered.decompressZstd(gpa, wide, max_decoded, cap)) |decoded| {
        gpa.free(decoded);
        return error.WideWindowAccepted;
    } else |err| try testing.expectEqual(error.DecompressionFailed, err);

    const fits = try buffered.compressZstdWith(gpa, payload, .{ .window_log = 20, .content_size = false });
    defer gpa.free(fits);
    const decoded = try buffered.decompressZstd(gpa, fits, max_decoded, cap);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, payload, decoded);
}

test "decoded size: the cap is exact for gzip and zstd" {
    const gpa = testing.allocator;
    const payload = try gpa.alloc(u8, 10_000);
    defer gpa.free(payload);
    @memset(payload, 'z');
    const gz = try buffered.compressGzip(gpa, payload);
    defer gpa.free(gz);
    const zs = try encodeWithStd(gpa, .zstd, payload);
    defer gpa.free(zs);
    for ([_]struct { ContentEncoding, []const u8 }{ .{ .gzip, gz }, .{ .zstd, zs } }) |case| {
        const at_cap = try encoding.decodeResident(case[0], gpa, case[1], payload.len, window_len);
        defer gpa.free(at_cap);
        try testing.expectEqual(payload.len, at_cap.len);
        try testing.expectError(
            error.DecodedBodyTooLarge,
            encoding.decodeResident(case[0], gpa, case[1], payload.len - 1, window_len),
        );
    }
}

// ------------------------------------------------ the streamed path (run)

const KeepSink = struct {
    pub fn onRecord(_: *KeepSink, _: []const u8) !framer_mod.Decision {
        return .keep;
    }
};

fn runGzip(raw: []const u8) !u64 {
    const gpa = testing.allocator;
    const spec: pipeline.PipelineSpec = .{
        .decode = .gzip,
        .format = .ndjson,
        .encode = .identity,
        .max_decoded_bytes = max_decoded,
        .zstd_window_len = window_len,
    };
    const buffers: pipeline.Buffers = .{
        .decoder = try gpa.alloc(u8, ContentEncoding.gzip.decoderBufferLen(window_len)),
        .encoder = &.{},
        .scratch = try gpa.alloc(u8, 4096),
        .chunk = try gpa.alloc(u8, 256),
    };
    defer {
        gpa.free(buffers.decoder);
        gpa.free(buffers.scratch);
        gpa.free(buffers.chunk);
    }
    var in = encoding.residentReader(.gzip, raw);
    var discard: std.Io.Writer.Discarding = .init(&.{});
    var sink: KeepSink = .{};
    const stats = try pipeline.run(spec, &in, &discard.writer, buffers, &sink);
    return stats.records;
}

test "run: the streamed path rejects every prefix, a bad footer, and trailing bytes" {
    const gpa = testing.allocator;
    const payload = "one\ntwo\nthree\n";
    const good = try buffered.compressGzipLevel(gpa, payload, 6);
    defer gpa.free(good);
    try testing.expectEqual(@as(u64, 3), try runGzip(good));

    for (0..good.len) |cut| {
        _ = runGzip(good[0..cut]) catch continue;
        return error.PrefixAccepted;
    }
    const bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    bad[bad.len - 8] ^= 0xff;
    try testing.expectError(error.ReadFailed, runGzip(bad));
    const trailing = try std.mem.concat(gpa, u8, &.{ good, good });
    defer gpa.free(trailing);
    try testing.expectError(error.ReadFailed, runGzip(trailing));
}

test "run: every input that crashed std flate is rejected on the streamed path" {
    var inputs = crashInputs();
    while (inputs.next()) |input| {
        _ = runGzip(input) catch continue;
        return error.CrashInputAccepted;
    }
}

// ----------------------------------------------------------------- fuzz

/// Builds an input from the fuzzer: raw bytes, or a valid stream with edits.
fn fuzzInput(smith: *testing.Smith, codec: ContentEncoding, buf: []u8, expected: *[]const u8) ![]u8 {
    const gpa = testing.allocator;
    const plain = "{\"message\":\"fuzz record\",\"service\":\"orders-api\"}\n" ** 40;
    if (smith.value(bool)) {
        expected.* = &.{};
        return buf[0..smith.slice(buf)];
    }
    const valid = switch (codec) {
        .gzip => try buffered.compressGzipLevel(gpa, plain, smith.valueRangeAtMost(u4, 0, 9)),
        .zstd => try buffered.compressZstdWith(gpa, plain, .{ .checksum = true }),
        .identity => unreachable,
    };
    defer gpa.free(valid);
    const len = @min(valid.len, buf.len);
    @memcpy(buf[0..len], valid[0..len]);
    var end: u32 = @intCast(len);
    while (!smith.eosWeightedSimple(3, 1)) {
        switch (smith.value(enum(u2) { flip, set, cut, grow })) {
            .flip => buf[smith.valueRangeLessThan(u32, 0, @max(end, 1))] ^= smith.value(u8),
            .set => buf[smith.valueRangeLessThan(u32, 0, @max(end, 1))] = smith.value(u8),
            .cut => end = smith.valueRangeAtMost(u32, 0, end),
            .grow => if (end < buf.len) {
                buf[end] = smith.value(u8);
                end += 1;
            },
        }
    }
    expected.* = plain;
    return buf[0..end];
}

fn fuzzOne(codec: ContentEncoding, smith: *testing.Smith) !void {
    var buf: [4096]u8 = undefined;
    var expected: []const u8 = &.{};
    const input = try fuzzInput(smith, codec, &buf, &expected);
    if (expected.len == 0) return expectNoCrash(codec, input);
    try expectInputOrError(codec, input, expected);
}

fn fuzzGzip(_: void, smith: *testing.Smith) anyerror!void {
    return fuzzOne(.gzip, smith);
}

fn fuzzZstd(_: void, smith: *testing.Smith) anyerror!void {
    return fuzzOne(.zstd, smith);
}

test "fuzz: gzip decode" {
    try testing.fuzz({}, fuzzGzip, .{});
}

test "fuzz: zstd decode" {
    try testing.fuzz({}, fuzzZstd, .{});
}
