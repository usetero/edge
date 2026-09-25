//! gzip and zstd for request and response bodies.
//!
//! One reference library per format, in both directions: zlib for gzip and
//! libzstd for zstd. Both are fuzzed by OSS-Fuzz, check their own checksums,
//! and return an error for every malformed input. The std decoders in Zig
//! 0.16.0 do not: `flate.Decompress` reaches `unreachable` on a stream that
//! ends early (https://codeberg.org/ziglang/zig/issues/35789, fixed for 0.17),
//! and `zstd.Decompress` reaches `unreachable` on some corrupt frames. std
//! also has no zstd encoder. The tests use the std decoders as an independent
//! oracle on valid input.
//!
//! `Decoder` reads a complete body, so the caller must hold every byte of it
//! first. `Encoder` is a `std.Io.Writer` that compresses into another writer.
//! Both keep their library state between bodies: `begin` resets it, so a
//! caller that keeps one per thread or in a pool allocates nothing per body.
//! The caller owns that choice. A zstd compression context holds about 3.5 MiB
//! at level 3, so one per thread for every handler thread costs too much.
const std = @import("std");

pub const Decoder = @import("decoder.zig").Decoder;
pub const Encoder = @import("encoder.zig").Encoder;
pub const EncoderPool = @import("pool.zig").EncoderPool;
/// Compressors with explicit parameters, for tests and benchmarks.
pub const fixtures = @import("fixtures.zig");

/// A compression format the edge decodes and encodes.
pub const Codec = enum { gzip, zstd };

/// A body's `Content-Encoding`: none, or a `Codec`.
pub const ContentEncoding = enum {
    identity,
    gzip,
    zstd,

    /// Maps a `Content-Encoding` value. Null means the edge does not decode
    /// it, so the caller forwards the body untouched.
    pub fn fromHeader(value: []const u8) ?ContentEncoding {
        const trimmed = std.mem.trim(u8, value, " \t");
        if (trimmed.len == 0 or std.ascii.eqlIgnoreCase(trimmed, "identity")) return .identity;
        if (std.ascii.eqlIgnoreCase(trimmed, "gzip") or std.ascii.eqlIgnoreCase(trimmed, "x-gzip")) return .gzip;
        if (std.ascii.eqlIgnoreCase(trimmed, "zstd")) return .zstd;
        return null;
    }

    pub fn headerValue(self: ContentEncoding) []const u8 {
        return @tagName(self);
    }

    /// The codec for this encoding, or null for identity.
    pub fn codec(self: ContentEncoding) ?Codec {
        return switch (self) {
            .identity => null,
            .gzip => .gzip,
            .zstd => .zstd,
        };
    }
};

pub const DecodeError = error{
    /// The bytes are not a valid stream: bad data, a bad header, a CRC or
    /// length that does not match, or bytes after the last member or frame.
    Corrupt,
    /// The body ends inside a stream.
    Truncated,
    /// The decoded output passed `DecodeLimits.max_output`.
    OutputTooLarge,
    /// A zstd frame asks for a window above `DecodeLimits.window_len`.
    WindowTooLarge,
    OutOfMemory,
};

pub const DecodeLimits = struct {
    /// The most decoded bytes one body may produce.
    max_output: usize,
    /// zstd only: the largest window a frame may ask for. It bounds the
    /// memory libzstd holds for a frame with no declared size.
    window_len: usize,
};

test {
    _ = @import("decoder.zig");
    _ = @import("encoder.zig");
    _ = @import("pool.zig");
    _ = @import("codec_test.zig");
}

test "ContentEncoding.fromHeader" {
    const E = ContentEncoding;
    try std.testing.expectEqual(E.gzip, E.fromHeader("gzip").?);
    try std.testing.expectEqual(E.gzip, E.fromHeader("GZIP").?);
    try std.testing.expectEqual(E.gzip, E.fromHeader("x-gzip").?);
    try std.testing.expectEqual(E.gzip, E.fromHeader(" gzip ").?);
    try std.testing.expectEqual(E.zstd, E.fromHeader("zstd").?);
    try std.testing.expectEqual(E.identity, E.fromHeader("").?);
    try std.testing.expectEqual(E.identity, E.fromHeader("identity").?);
    try std.testing.expectEqual(@as(?E, null), E.fromHeader("br"));
    try std.testing.expectEqual(@as(?E, null), E.fromHeader("gzip, zstd"));
    try std.testing.expectEqual(@as(?Codec, null), E.identity.codec());
    try std.testing.expectEqual(Codec.zstd, E.zstd.codec().?);
}
