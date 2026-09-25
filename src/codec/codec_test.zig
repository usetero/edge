//! Tests for `codec`. One property holds in every decode test: the result is
//! an error or the exact bytes that were compressed. It never panics, never
//! loops, and never returns other bytes.
//!
//! The oracle is independent: std's own decoders, which are correct on valid
//! input. Fixtures come from zlib at four levels, std's flate encoder, libzstd
//! with and without a checksum, and `codec.Encoder` itself.
//!
//! `-Ddecode-test-scale=N` multiplies the random cases and the prefixes of
//! long streams. A deep run:
//! `zig build test -Doptimize=ReleaseSafe -Ddecode-test-scale=50`.
const std = @import("std");
const codec = @import("root.zig");
const buffered = codec.fixtures;

const testing = std.testing;
const Codec = codec.Codec;
const Decoder = codec.Decoder;
const Encoder = codec.Encoder;
const scale: usize = @import("build_options").decode_test_scale;

/// The largest zstd window the edge allows. Test frames use up to 2 MiB.
const window_len: usize = 8 << 20;
const max_output: usize = 4 << 20;
const limits: codec.DecodeLimits = .{ .max_output = max_output, .window_len = window_len };

/// Inputs a fuzz run found against the Zig 0.16.0 std decoders: a
/// little-endian u32 length, then the bytes, for each input.
const gzip_crashes = @embedFile("testdata/gzip_crashes.bin");
/// A full-length zstd frame with two changed bytes. It reaches `unreachable`
/// in `std.compress.zstd` in Zig 0.16.0.
const zstd_corrupt = @embedFile("testdata/zstd_corrupt.zst");

const CrashIterator = struct {
    rest: []const u8 = gzip_crashes,

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

// ------------------------------------------------------------ fixtures

/// A compressed form of one payload, and whether a corruption must be caught.
const Form = struct { bytes: []u8, checked: bool };

fn freeForms(gpa: std.mem.Allocator, forms: []const Form) void {
    for (forms) |form| gpa.free(form.bytes);
}

/// zlib at levels 0, 1, 6 and 9, std's encoder at two levels, and ours.
/// gzip always carries a CRC, so every form is checked.
fn gzipForms(gpa: std.mem.Allocator, payload: []const u8) ![7]Form {
    var forms: [7]Form = undefined;
    var made: usize = 0;
    errdefer freeForms(gpa, forms[0..made]);
    for ([_]c_int{ 0, 1, 6, 9 }) |level| {
        forms[made] = .{ .bytes = try buffered.compressGzipLevel(gpa, payload, level), .checked = true };
        made += 1;
    }
    for ([_]std.compress.flate.Compress.Options{ .fastest, .best }) |options| {
        forms[made] = .{ .bytes = try stdGzip(gpa, payload, options), .checked = true };
        made += 1;
    }
    forms[made] = .{ .bytes = try encode(gpa, .gzip, payload), .checked = true };
    return forms;
}

/// libzstd at three levels with and without a checksum, a frame with no
/// declared size, and ours. Only a checksum frame must catch a change.
fn zstdForms(gpa: std.mem.Allocator, payload: []const u8) ![8]Form {
    var forms: [8]Form = undefined;
    var made: usize = 0;
    errdefer freeForms(gpa, forms[0..made]);
    for ([_]c_int{ 1, 3, 19 }) |level| {
        for ([_]bool{ false, true }) |checksum| {
            const bytes = try buffered.compressZstdWith(gpa, payload, .{ .level = level, .checksum = checksum });
            forms[made] = .{ .bytes = bytes, .checked = checksum };
            made += 1;
        }
    }
    const unsized = try buffered.compressZstdWith(gpa, payload, .{ .content_size = false });
    forms[made] = .{ .bytes = unsized, .checked = false };
    made += 1;
    forms[made] = .{ .bytes = try encode(gpa, .zstd, payload), .checked = false };
    return forms;
}

fn stdGzip(gpa: std.mem.Allocator, payload: []const u8, options: std.compress.flate.Compress.Options) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    errdefer out.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var compress: std.compress.flate.Compress = try .init(&out.writer, &window, .gzip, options);
    try compress.writer.writeAll(payload);
    try compress.finish();
    return out.toOwnedSlice();
}

/// Compresses with `codec.Encoder`.
fn encode(gpa: std.mem.Allocator, which: Codec, payload: []const u8) ![]u8 {
    var staging: [4096]u8 = undefined;
    var encoder: Encoder = try .init(gpa, &staging);
    defer encoder.deinit(gpa);
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try encoder.begin(which, &out.writer);
    try encoder.writer.writeAll(payload);
    try encoder.finish();
    return out.toOwnedSlice();
}

// --------------------------------------------------------------- oracle

/// std's decoders, for valid single-member and single-frame input only.
fn oracle(gpa: std.mem.Allocator, which: Codec, raw: []const u8) ![]u8 {
    var in: std.Io.Reader = .fixed(raw);
    switch (which) {
        .gzip => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompress: std.compress.flate.Decompress = .init(&in, .gzip, &window);
            return decompress.reader.allocRemaining(gpa, .unlimited);
        },
        .zstd => {
            const buf = try gpa.alloc(u8, window_len + std.compress.zstd.block_size_max);
            defer gpa.free(buf);
            var decompress: std.compress.zstd.Decompress = .init(&in, buf, .{ .window_len = window_len });
            return decompress.reader.allocRemaining(gpa, .unlimited);
        },
    }
}

// --------------------------------------------------------------- checks

/// Decodes all of `raw` through `decoder`, `chunk` bytes per read.
fn decodeWith(decoder: *Decoder, which: Codec, raw: []const u8, chunk: usize, lim: codec.DecodeLimits) ![]u8 {
    const gpa = testing.allocator;
    try decoder.begin(which, raw, lim);
    const buf = try gpa.alloc(u8, chunk);
    defer gpa.free(buf);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    while (true) {
        const n = try decoder.read(buf);
        if (n == 0) break;
        try out.appendSlice(gpa, buf[0..n]);
    }
    return out.toOwnedSlice(gpa);
}

fn expectDecodes(decoder: *Decoder, which: Codec, raw: []const u8, expected: []const u8) !void {
    const decoded = try decodeWith(decoder, which, raw, 4096, limits);
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, expected, decoded);
}

fn expectInputOrError(decoder: *Decoder, which: Codec, raw: []const u8, expected: []const u8) !void {
    const decoded = decodeWith(decoder, which, raw, 4096, limits) catch return;
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, expected, decoded);
}

fn expectNoCrash(decoder: *Decoder, which: Codec, raw: []const u8) !void {
    const decoded = decodeWith(decoder, which, raw, 4096, limits) catch return;
    defer testing.allocator.free(decoded);
    try testing.expect(decoded.len <= max_output);
}

fn expectRejected(decoder: *Decoder, which: Codec, raw: []const u8) !void {
    const decoded = decodeWith(decoder, which, raw, 4096, limits) catch return;
    defer testing.allocator.free(decoded);
    std.debug.print("{s}: {d} bytes decoded as complete\n", .{ @tagName(which), raw.len });
    return error.InputAccepted;
}

/// Every prefix for a short stream. A long stream gets every prefix near its
/// ends and a spread over the middle, which keeps the test fast.
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

fn newDecoder() !Decoder {
    return Decoder.init(testing.allocator);
}

// ------------------------------------------------------- valid streams

test "valid gzip decodes to the input at every chunk size, and std agrees" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try gzipForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            for ([_]usize{ 1, 7, 256, 4096, 65536, payload.len + 1 }) |chunk| {
                if (chunk == 1 and payload.len > 100_000) continue;
                const decoded = try decodeWith(&decoder, .gzip, form.bytes, chunk, limits);
                defer gpa.free(decoded);
                try testing.expectEqualSlices(u8, payload, decoded);
            }
            const expected = try oracle(gpa, .gzip, form.bytes);
            defer gpa.free(expected);
            try testing.expectEqualSlices(u8, payload, expected);
        }
    }
}

test "valid zstd decodes to the input at every chunk size, and std agrees" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const forms = try zstdForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            for ([_]usize{ 1, 7, 256, 4096, 65536, payload.len + 1 }) |chunk| {
                if (chunk == 1 and payload.len > 100_000) continue;
                const decoded = try decodeWith(&decoder, .zstd, form.bytes, chunk, limits);
                defer gpa.free(decoded);
                try testing.expectEqualSlices(u8, payload, decoded);
            }
            const expected = try oracle(gpa, .zstd, form.bytes);
            defer gpa.free(expected);
            try testing.expectEqualSlices(u8, payload, expected);
        }
    }
}

// ---------------------------------------------------------- truncation

test "every prefix of every stream is rejected" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    for (payloads.list) |payload| {
        const gz = try gzipForms(gpa, payload);
        defer freeForms(gpa, &gz);
        const zs = try zstdForms(gpa, payload);
        defer freeForms(gpa, &zs);
        for (gz) |form| {
            var index: usize = 0;
            while (cutPoints(form.bytes.len, index)) |cut| : (index += 1) {
                try expectRejected(&decoder, .gzip, form.bytes[0..cut]);
            }
        }
        for (zs) |form| {
            var index: usize = 0;
            while (cutPoints(form.bytes.len, index)) |cut| : (index += 1) {
                try expectRejected(&decoder, .zstd, form.bytes[0..cut]);
            }
        }
    }
}

test "a truncated body is reported as Truncated, not Corrupt" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    inline for (.{ Codec.gzip, Codec.zstd }) |which| {
        const raw = try encode(gpa, which, "a body the sender gave up on" ** 20);
        defer gpa.free(raw);
        for ([_]usize{ 0, raw.len / 2, raw.len - 1 }) |cut| {
            try testing.expectError(error.Truncated, decodeWith(&decoder, which, raw[0..cut], 4096, limits));
        }
    }
}

// ----------------------------------------------------------- corruption

test "corrupt gzip decodes to an error or to the input" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0xc0ffee);
    const rand = prng.random();
    for (payloads.list[1..6]) |payload| {
        const forms = try gzipForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            const scratch = try gpa.alloc(u8, form.bytes.len);
            defer gpa.free(scratch);
            for (0..60 * scale) |_| {
                try expectInputOrError(&decoder, .gzip, corrupt(rand, scratch, form.bytes), payload);
            }
        }
    }
}

test "corrupt zstd never crashes" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x2d57);
    const rand = prng.random();
    for (payloads.list[1..6]) |payload| {
        const forms = try zstdForms(gpa, payload);
        defer freeForms(gpa, &forms);
        for (forms) |form| {
            const scratch = try gpa.alloc(u8, form.bytes.len);
            defer gpa.free(scratch);
            // No output check: the checksum flag sits in the frame header,
            // so a corruption can turn the check off. The format allows that.
            for (0..40 * scale) |_| try expectNoCrash(&decoder, .zstd, corrupt(rand, scratch, form.bytes));
        }
    }
}

/// Bytes of the zstd frame header, from its descriptor byte.
fn zstdHeaderLen(frame: []const u8) usize {
    const descriptor = frame[4];
    const single_segment = descriptor & 0x20 != 0;
    const fcs_lens = [_]usize{ @intFromBool(single_segment), 2, 4, 8 };
    const dict_lens = [_]usize{ 0, 1, 2, 4 };
    return 5 + @as(usize, @intFromBool(!single_segment)) + dict_lens[descriptor & 0x03] + fcs_lens[descriptor >> 6];
}

test "a zstd checksum frame with any bit changed after its header decodes to an error or the input" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
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
                try expectInputOrError(&decoder, .zstd, damaged, payload);
            }
        }
    }
}

test "random bytes behind a valid header never crash" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x9a4b);
    const rand = prng.random();
    var buf: [2048]u8 = undefined;
    for (0..2000 * scale) |_| {
        const len = rand.intRangeAtMost(usize, 10, buf.len);
        rand.bytes(buf[0..len]);
        if (rand.boolean()) {
            @memcpy(buf[0..4], "\x1f\x8b\x08\x00");
            try expectNoCrash(&decoder, .gzip, buf[0..len]);
        } else {
            @memcpy(buf[0..4], "\x28\xb5\x2f\xfd");
            try expectNoCrash(&decoder, .zstd, buf[0..len]);
        }
    }
}

test "every input that crashed the std decoders is rejected" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var inputs: CrashIterator = .{};
    var count: usize = 0;
    while (inputs.next()) |input| : (count += 1) try expectRejected(&decoder, .gzip, input);
    try testing.expect(count > 50);
    try expectRejected(&decoder, .zstd, zstd_corrupt);
}

// --------------------------------------------------------- gzip framing

test "gzip: a wrong CRC, a wrong length, and bytes after the last member are rejected" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const payload = "the footer covers these bytes";
    const good = try buffered.compressGzip(gpa, payload);
    defer gpa.free(good);
    try expectDecodes(&decoder, .gzip, good, payload);

    const bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    // The footer is the CRC32, then the length mod 2^32, both little-endian.
    for (1..9) |from_end| {
        @memcpy(bad, good);
        bad[bad.len - from_end] ^= 0x01;
        try expectRejected(&decoder, .gzip, bad);
    }
    for ([_][]const u8{ "x", "\x00", "\x00\x00\x00\x00", "\x1f", "\x1f\x8b" }) |tail| {
        const trailing = try std.mem.concat(gpa, u8, &.{ good, tail });
        defer gpa.free(trailing);
        try expectRejected(&decoder, .gzip, trailing);
    }
}

test "gzip: several members decode to all of them, in order" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const a = try buffered.compressGzip(gpa, "first member,");
    defer gpa.free(a);
    const b = try encode(gpa, .gzip, "second member,");
    defer gpa.free(b);
    const empty = try buffered.compressGzip(gpa, "");
    defer gpa.free(empty);
    const stream = try std.mem.concat(gpa, u8, &.{ a, empty, b, a });
    defer gpa.free(stream);
    try expectDecodes(&decoder, .gzip, stream, "first member,second member,first member,");
    for (1..stream.len) |cut| {
        // A cut at a member boundary is a complete body of fewer members.
        const boundary = cut == a.len or cut == a.len + empty.len or cut == a.len + empty.len + b.len;
        if (!boundary) try expectRejected(&decoder, .gzip, stream[0..cut]);
    }
}

test "gzip: optional header fields do not change the data, and a bad header CRC is rejected" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const payload = "header fields carry no data";
    const plain = try buffered.compressGzip(gpa, payload);
    defer gpa.free(plain);
    const deflate = plain[10 .. plain.len - 8];
    const footer = plain[plain.len - 8 ..];

    // FEXTRA, FNAME and FCOMMENT alone and together, then with FHCRC.
    const flags = [_]u8{ 0x04, 0x08, 0x10, 0x1c, 0x1e };
    for (flags) |flag| {
        var head: std.Io.Writer.Allocating = .init(gpa);
        defer head.deinit();
        try head.writer.writeAll(&[_]u8{ 0x1f, 0x8b, 0x08, flag, 0, 0, 0, 0, 0, 3 });
        if (flag & 0x04 != 0) try head.writer.writeAll(&[_]u8{ 3, 0, 'a', 'b', 'c' });
        if (flag & 0x08 != 0) try head.writer.writeAll("name.json\x00");
        if (flag & 0x10 != 0) try head.writer.writeAll("a comment\x00");
        if (flag & 0x02 != 0) {
            // The header CRC is the low 16 bits of the CRC32 of the header.
            const crc: u16 = @truncate(std.hash.Crc32.hash(head.written()));
            try head.writer.writeInt(u16, crc, .little);
        }
        const stream = try std.mem.concat(gpa, u8, &.{ head.written(), deflate, footer });
        defer gpa.free(stream);
        try expectDecodes(&decoder, .gzip, stream, payload);
        for (1..head.written().len) |cut| try expectRejected(&decoder, .gzip, stream[0..cut]);
        if (flag & 0x02 != 0) {
            const bad = try gpa.dupe(u8, stream);
            defer gpa.free(bad);
            bad[head.written().len - 1] ^= 0xff;
            try expectRejected(&decoder, .gzip, bad);
        }
    }
}

// --------------------------------------------------------- zstd framing

test "zstd: several frames and a skippable frame decode in order" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const a = try buffered.compressZstdWith(gpa, "first frame,", .{ .checksum = true });
    defer gpa.free(a);
    const b = try encode(gpa, .zstd, "second frame");
    defer gpa.free(b);
    // A skippable frame: magic 0x184D2A50, a length, then that many bytes.
    const skip = "\x50\x2a\x4d\x18\x03\x00\x00\x00abc";
    const stream = try std.mem.concat(gpa, u8, &.{ skip, a, skip, b });
    defer gpa.free(stream);
    try expectDecodes(&decoder, .zstd, stream, "first frame,second frame");
    try expectRejected(&decoder, .zstd, stream[0 .. stream.len - 1]);
    const only_skip = try std.mem.concat(gpa, u8, &.{ skip, skip });
    defer gpa.free(only_skip);
    try expectDecodes(&decoder, .zstd, only_skip, "");
}

test "zstd: a window above the cap is WindowTooLarge, and one at the cap decodes" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const payload = try gpa.alloc(u8, 3 << 20);
    defer gpa.free(payload);
    var prng: std.Random.DefaultPrng = .init(0x3d);
    prng.random().bytes(payload[0 .. 1 << 20]);
    @memset(payload[1 << 20 .. 2 << 20], 0);
    @memcpy(payload[2 << 20 ..], payload[0 .. 1 << 20]);
    const cap: codec.DecodeLimits = .{ .max_output = max_output, .window_len = 1 << 20 };

    // No declared size, so libzstd must hold a window of the declared length.
    const wide = try buffered.compressZstdWith(gpa, payload, .{ .window_log = 23, .content_size = false });
    defer gpa.free(wide);
    try testing.expectError(error.WindowTooLarge, decodeWith(&decoder, .zstd, wide, 4096, cap));

    const fits = try buffered.compressZstdWith(gpa, payload, .{ .window_log = 20, .content_size = false });
    defer gpa.free(fits);
    const decoded = try decodeWith(&decoder, .zstd, fits, 4096, cap);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, payload, decoded);
}

// ------------------------------------------------------------- limits

test "the output cap is exact at every chunk size" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const payload = "z" ** 10_000;
    inline for (.{ Codec.gzip, Codec.zstd }) |which| {
        const raw = try encode(gpa, which, payload);
        defer gpa.free(raw);
        for ([_]usize{ 1, 100, 4096, 20_000 }) |chunk| {
            const cap: codec.DecodeLimits = .{ .max_output = payload.len, .window_len = window_len };
            const at_cap = try decodeWith(&decoder, which, raw, chunk, cap);
            defer gpa.free(at_cap);
            try testing.expectEqual(payload.len, at_cap.len);
            try testing.expectError(
                error.OutputTooLarge,
                decodeWith(&decoder, which, raw, chunk, .{ .max_output = payload.len - 1, .window_len = window_len }),
            );
        }
    }
}

test "an empty body is rejected" {
    var decoder = try newDecoder();
    defer decoder.deinit(testing.allocator);
    try testing.expectError(error.Truncated, decodeWith(&decoder, .gzip, "", 64, limits));
    try testing.expectError(error.Truncated, decodeWith(&decoder, .zstd, "", 64, limits));
}

test "readAll appends the whole body" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const payload = "readAll " ** 10_000;
    inline for (.{ Codec.gzip, Codec.zstd }) |which| {
        const raw = try encode(gpa, which, payload);
        defer gpa.free(raw);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try decoder.begin(which, raw, limits);
        try decoder.readAll(gpa, &out);
        try testing.expectEqualSlices(u8, payload, out.items);
    }
}

// -------------------------------------------------------------- reuse

test "one decoder serves thousands of good and bad bodies, and a bad one never affects the next" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0x7e57);
    const rand = prng.random();
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var gz: [4][]u8 = undefined;
    var zs: [4][]u8 = undefined;
    for (0..4) |i| {
        gz[i] = try encode(gpa, .gzip, payloads.list[i + 1]);
        zs[i] = try encode(gpa, .zstd, payloads.list[i + 1]);
    }
    defer for (0..4) |i| {
        gpa.free(gz[i]);
        gpa.free(zs[i]);
    };
    var scratch: [70_000]u8 = undefined;
    var buf: [512]u8 = undefined;
    for (0..1000 * scale) |_| {
        const i = rand.uintLessThan(usize, 4);
        const which: Codec = if (rand.boolean()) .gzip else .zstd;
        const raw = if (which == .gzip) gz[i] else zs[i];
        switch (rand.uintLessThan(u8, 4)) {
            // Valid, decoded in full.
            0, 1 => try expectDecodes(&decoder, which, raw, payloads.list[i + 1]),
            // Corrupt or cut.
            2 => try expectNoCrash(&decoder, which, corrupt(rand, &scratch, raw)),
            // Abandoned partway, as when a policy stops early.
            else => {
                try decoder.begin(which, raw, limits);
                _ = try decoder.read(&buf);
            },
        }
    }
}

// ------------------------------------------------------------ encoder

const WritePattern = enum { whole, small_pieces, splat, print };

fn encodeWith(encoder: *Encoder, which: Codec, payload: []const u8, pattern: WritePattern, rand: std.Random) ![]u8 {
    const gpa = testing.allocator;
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try encoder.begin(which, &out.writer);
    const w = &encoder.writer;
    switch (pattern) {
        .whole => try w.writeAll(payload),
        .small_pieces => {
            var rest = payload;
            while (rest.len != 0) {
                const n = @min(rest.len, rand.intRangeAtMost(usize, 1, 17));
                try w.writeAll(rest[0..n]);
                rest = rest[n..];
            }
        },
        .splat => {
            // Half through splats of the first byte, then the rest as is.
            const half = payload.len / 2;
            var i: usize = 0;
            while (i < half) {
                var run: usize = 1;
                while (i + run < half and payload[i + run] == payload[i]) run += 1;
                try w.splatByteAll(payload[i], run);
                i += run;
            }
            try w.writeAll(payload[half..]);
        },
        .print => try w.print("{s}", .{payload}),
    }
    try encoder.finish();
    return out.toOwnedSlice();
}

test "the encoder round-trips every payload, write pattern, and staging size" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0xe4c0);
    const rand = prng.random();
    const staging = try gpa.alloc(u8, 4096);
    defer gpa.free(staging);
    for ([_]usize{ 0, 1, 16, 4096 }) |staging_len| {
        var encoder: Encoder = try .init(gpa, staging[0..staging_len]);
        defer encoder.deinit(gpa);
        for (payloads.list[0..7]) |payload| {
            inline for (.{ Codec.gzip, Codec.zstd }) |which| {
                for (std.enums.values(WritePattern)) |pattern| {
                    const raw = try encodeWith(&encoder, which, payload, pattern, rand);
                    defer gpa.free(raw);
                    try expectDecodes(&decoder, which, raw, payload);
                    const independent = try oracle(gpa, which, raw);
                    defer gpa.free(independent);
                    try testing.expectEqualSlices(u8, payload, independent);
                }
            }
        }
    }
}

test "one encoder serves many streams, including ones it abandons" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var staging: [256]u8 = undefined;
    var encoder: Encoder = try .init(gpa, &staging);
    defer encoder.deinit(gpa);
    var prng: std.Random.DefaultPrng = .init(0xab);
    const rand = prng.random();
    for (0..200 * scale) |round| {
        const which: Codec = if (round % 2 == 0) .gzip else .zstd;
        var out: std.Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        try encoder.begin(which, &out.writer);
        var text: [300]u8 = undefined;
        const len = rand.uintAtMost(usize, text.len);
        rand.bytes(text[0..len]);
        try encoder.writer.writeAll(text[0..len]);
        // Every third stream is abandoned without `finish`.
        if (round % 3 == 0) continue;
        try encoder.finish();
        try expectDecodes(&decoder, which, out.written(), text[0..len]);
    }
}

test "an encoder whose output is full fails with WriteFailed, and the next stream works" {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    var staging: [64]u8 = undefined;
    var encoder: Encoder = try .init(gpa, &staging);
    defer encoder.deinit(gpa);
    var payloads: Payloads = try .init(gpa);
    defer payloads.deinit(gpa);
    inline for (.{ Codec.gzip, Codec.zstd }) |which| {
        var small: [32]u8 = undefined;
        var fixed: std.Io.Writer = .fixed(&small);
        try encoder.begin(which, &fixed);
        const result = blk: {
            encoder.writer.writeAll(payloads.list[5]) catch |err| break :blk err;
            encoder.finish() catch |err| break :blk err;
            break :blk error.NoFailure;
        };
        try testing.expectEqual(error.WriteFailed, result);

        var prng: std.Random.DefaultPrng = .init(1);
        const raw = try encodeWith(&encoder, which, "after a failure", .whole, prng.random());
        defer gpa.free(raw);
        try expectDecodes(&decoder, which, raw, "after a failure");
    }
}

// ---------------------------------------------------------------- fuzz

fn fuzzDecode(which: Codec, smith: *testing.Smith) !void {
    const gpa = testing.allocator;
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    const plain = "{\"message\":\"fuzz record\",\"service\":\"orders-api\"}\n" ** 40;
    var buf: [4096]u8 = undefined;
    if (smith.value(bool)) return expectNoCrash(&decoder, which, buf[0..smith.slice(&buf)]);

    const valid = switch (which) {
        .gzip => try buffered.compressGzipLevel(gpa, plain, smith.valueRangeAtMost(u4, 0, 9)),
        .zstd => try buffered.compressZstdWith(gpa, plain, .{ .checksum = true }),
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
    // A zstd edit can clear the checksum flag, so only gzip checks output.
    if (which == .gzip) return expectInputOrError(&decoder, which, buf[0..end], plain);
    return expectNoCrash(&decoder, which, buf[0..end]);
}

fn fuzzRoundTrip(smith: *testing.Smith) !void {
    const gpa = testing.allocator;
    var payload: [8192]u8 = undefined;
    const len = smith.slice(&payload);
    const which: Codec = if (smith.value(bool)) .gzip else .zstd;
    const raw = try encode(gpa, which, payload[0..len]);
    defer gpa.free(raw);
    var decoder = try newDecoder();
    defer decoder.deinit(gpa);
    try expectDecodes(&decoder, which, raw, payload[0..len]);
}

test "fuzz: gzip decode" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            return fuzzDecode(.gzip, smith);
        }
    }.run, .{});
}

test "fuzz: zstd decode" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            return fuzzDecode(.zstd, smith);
        }
    }.run, .{});
}

test "fuzz: encode then decode" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            return fuzzRoundTrip(smith);
        }
    }.run, .{});
}
