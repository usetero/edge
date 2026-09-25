//! Decodes a complete gzip or zstd body into caller-sized chunks.
//!
//! The input is a slice that holds the whole body, so the decoder never waits
//! for more input: when the library needs bytes the slice does not have, the
//! body is truncated. Every step makes progress or ends in an error, so a
//! read never loops without output.
const std = @import("std");
const root = @import("root.zig");
const c = @import("c.zig").c;

const Codec = root.Codec;
const DecodeError = root.DecodeError;
const DecodeLimits = root.DecodeLimits;

const log = std.log.scoped(.codec);

pub const Decoder = struct {
    /// zlib inflate state. On the heap, because zlib keeps a pointer back to
    /// its stream, and the `Decoder` itself may move.
    z: *c.z_stream,
    z_ready: bool = false,
    dctx: ?*c.ZSTD_DCtx = null,

    codec: Codec = .gzip,
    input: []const u8 = &.{},
    pos: usize = 0,
    produced: usize = 0,
    max_output: usize = 0,
    done: bool = true,

    pub fn init(allocator: std.mem.Allocator) std.mem.Allocator.Error!Decoder {
        const z = try allocator.create(c.z_stream);
        z.* = std.mem.zeroes(c.z_stream);
        return .{ .z = z };
    }

    pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
        if (self.z_ready and c.inflateEnd(self.z) != c.Z_OK) log.warn("inflateEnd failed", .{});
        if (self.dctx) |dctx| {
            if (c.ZSTD_isError(c.ZSTD_freeDCtx(dctx)) != 0) log.warn("ZSTD_freeDCtx failed", .{});
        }
        allocator.destroy(self.z);
        self.* = undefined;
    }

    /// Starts to decode `input`, which must hold the complete body. The
    /// decoder keeps its library state from the last body and resets it.
    pub fn begin(self: *Decoder, codec: Codec, input: []const u8, limits: DecodeLimits) DecodeError!void {
        switch (codec) {
            .gzip => {
                // 15 + 16: the largest window, with a gzip header and trailer.
                const rc = if (self.z_ready) c.inflateReset(self.z) else c.inflateInit2(self.z, 15 + 16);
                if (rc != c.Z_OK) return error.OutOfMemory;
                self.z_ready = true;
            },
            .zstd => {
                const dctx = self.dctx orelse c.ZSTD_createDCtx() orelse return error.OutOfMemory;
                self.dctx = dctx;
                if (c.ZSTD_isError(c.ZSTD_DCtx_reset(dctx, c.ZSTD_reset_session_and_parameters)) != 0) {
                    return error.OutOfMemory;
                }
                // 10 is ZSTD_WINDOWLOG_ABSOLUTEMIN, which zstd.h exports only
                // to static linking. 31 is the largest log libzstd accepts.
                const log_max = std.math.clamp(std.math.log2_int_ceil(usize, @max(limits.window_len, 1)), 10, 31);
                if (c.ZSTD_isError(c.ZSTD_DCtx_setParameter(dctx, c.ZSTD_d_windowLogMax, @intCast(log_max))) != 0) {
                    return error.OutOfMemory;
                }
            },
        }
        self.codec = codec;
        self.input = input;
        self.pos = 0;
        self.produced = 0;
        self.max_output = limits.max_output;
        self.done = false;
    }

    /// Writes decoded bytes to `dst` and returns how many. Returns 0 only
    /// once the whole body is decoded and every check in it has passed.
    pub fn read(self: *Decoder, dst: []u8) DecodeError!usize {
        std.debug.assert(dst.len > 0);
        while (!self.done) {
            const step = switch (self.codec) {
                .gzip => try self.stepGzip(dst),
                .zstd => try self.stepZstd(dst),
            };
            self.pos += step.consumed;
            self.produced += step.produced;
            if (self.produced > self.max_output) return error.OutputTooLarge;
            if (step.produced != 0) return step.produced;
            // No output and no input taken: the library needs bytes the body
            // does not have, or it refuses the bytes it has.
            if (step.consumed == 0 and !self.done) {
                return if (self.pos == self.input.len) error.Truncated else error.Corrupt;
            }
        }
        return 0;
    }

    /// Decodes the rest of the body and appends it to `out`.
    pub fn readAll(self: *Decoder, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) DecodeError!void {
        while (true) {
            if (out.unusedCapacitySlice().len == 0) try out.ensureUnusedCapacity(allocator, 16 * 1024);
            const n = try self.read(out.unusedCapacitySlice());
            if (n == 0) return;
            out.items.len += n;
        }
    }

    const Step = struct { consumed: usize, produced: usize };

    fn stepGzip(self: *Decoder, dst: []u8) DecodeError!Step {
        const rest = self.input[self.pos..];
        const in_len: c_uint = @intCast(@min(rest.len, std.math.maxInt(c_uint)));
        const out_len: c_uint = @intCast(@min(dst.len, std.math.maxInt(c_uint)));
        self.z.next_in = @constCast(rest.ptr);
        self.z.avail_in = in_len;
        self.z.next_out = dst.ptr;
        self.z.avail_out = out_len;
        const rc = c.inflate(self.z, c.Z_NO_FLUSH);
        const step: Step = .{ .consumed = in_len - self.z.avail_in, .produced = out_len - self.z.avail_out };
        switch (rc) {
            // Z_BUF_ERROR: no progress this call. `read` decides why.
            c.Z_OK, c.Z_BUF_ERROR => {},
            c.Z_STREAM_END => {
                // A member ends here. RFC 1952 allows more members after it,
                // and the decoded body is all of them in order.
                if (self.pos + step.consumed == self.input.len) {
                    self.done = true;
                } else if (c.inflateReset(self.z) != c.Z_OK) {
                    return error.Corrupt;
                }
            },
            c.Z_MEM_ERROR => return error.OutOfMemory,
            // Z_DATA_ERROR covers bad data, a bad header, and a CRC or length
            // that does not match.
            else => return error.Corrupt,
        }
        return step;
    }

    fn stepZstd(self: *Decoder, dst: []u8) DecodeError!Step {
        const rest = self.input[self.pos..];
        var in_buffer: c.ZSTD_inBuffer = .{ .src = rest.ptr, .size = rest.len, .pos = 0 };
        var out_buffer: c.ZSTD_outBuffer = .{ .dst = dst.ptr, .size = dst.len, .pos = 0 };
        const rc = c.ZSTD_decompressStream(self.dctx, &out_buffer, &in_buffer);
        if (c.ZSTD_isError(rc) != 0) return switch (c.ZSTD_getErrorCode(rc)) {
            c.ZSTD_error_frameParameter_windowTooLarge => error.WindowTooLarge,
            c.ZSTD_error_memory_allocation => error.OutOfMemory,
            else => error.Corrupt,
        };
        const step: Step = .{ .consumed = in_buffer.pos, .produced = out_buffer.pos };
        // 0: a frame is complete and flushed. More input is the next frame.
        if (rc == 0 and self.pos + step.consumed == self.input.len) self.done = true;
        return step;
    }
};

test "a decoder reads one gzip and one zstd body, then another of each" {
    const gpa = std.testing.allocator;
    var decoder: Decoder = try .init(gpa);
    defer decoder.deinit(gpa);
    const limits: DecodeLimits = .{ .max_output = 1 << 20, .window_len = 1 << 20 };
    // "hello", from Python's gzip (mtime 0) and zstandard modules.
    const gz = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x13\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00";
    const zs = "\x28\xb5\x2f\xfd\x20\x05\x29\x00\x00\x68\x65\x6c\x6c\x6f";
    var buf: [64]u8 = undefined;
    for (0..2) |_| {
        inline for (.{ .{ Codec.gzip, gz }, .{ Codec.zstd, zs } }) |case| {
            try decoder.begin(case[0], case[1], limits);
            const n = try decoder.read(&buf);
            try std.testing.expectEqualStrings("hello", buf[0..n]);
            try std.testing.expectEqual(@as(usize, 0), try decoder.read(&buf));
        }
    }
}
