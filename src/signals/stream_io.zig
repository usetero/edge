//! Reading a request body to the end, for the signal processors.
//!
//! Five copies of these two functions existed, byte-identical, one per
//! signal module. They are here so the next fix lands once.

const std = @import("std");

/// Copy `reader` into `writer` until end of stream.
///
/// **Only `error.EndOfStream` ends the loop.** The five copies this replaces
/// also stopped on a `0` return, which the `std.Io.Reader` vtable contract
/// says does not mean end of stream: std's gzip and zstd decompressors pick
/// an indirect vtable whenever they are given a decode buffer, and that
/// vtable decodes a block into the reader's own buffer and returns `0`, with
/// the bytes arriving on the next call. Treating that as EOF truncates the
/// body to nothing. Today every caller passes a reader over already-decoded
/// bytes, so the old copies were wrong but dormant; this keeps them from
/// waking up.
pub fn streamAll(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    while (true) {
        _ = reader.stream(writer, .unlimited) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };
    }
}

/// `streamAll` into an owned slice.
pub fn readAll(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try streamAll(reader, &out.writer);
    return out.toOwnedSlice();
}

const testing = std.testing;

test "streamAll does not treat a 0 return as end of stream" {
    // A reader whose vtable returns 0 before it returns any bytes, the shape
    // std's decompressors take. The copies this replaces stopped here and
    // returned an empty body.
    const Stalling = struct {
        interface: std.Io.Reader,
        payload: []const u8,
        zeros_left: usize,
        done: bool = false,

        const Self = @This();

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *Self = @alignCast(@fieldParentPtr("interface", r));
            if (self.zeros_left > 0) {
                self.zeros_left -= 1;
                return 0; // decoded into an internal buffer, nothing handed over yet
            }
            if (self.done) return error.EndOfStream;
            self.done = true;
            const n = @min(@intFromEnum(limit), self.payload.len);
            try w.writeAll(self.payload[0..n]);
            return n;
        }
    };

    var stalling: Stalling = .{
        .interface = .{
            .vtable = &.{ .stream = Stalling.stream },
            .buffer = &.{},
            .seek = 0,
            .end = 0,
        },
        .payload = "the body the sender actually sent",
        .zeros_left = 3,
    };

    const got = try readAll(testing.allocator, &stalling.interface);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("the body the sender actually sent", got);
}

test "streamAll copies a plain reader and stops at the end" {
    var reader: std.Io.Reader = .fixed("abc");
    const got = try readAll(testing.allocator, &reader);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("abc", got);
}

test "streamAll propagates a read failure rather than truncating" {
    const Failing = struct {
        interface: std.Io.Reader,
        fn stream(_: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
            return error.ReadFailed;
        }
    };
    var failing: Failing = .{ .interface = .{
        .vtable = &.{ .stream = Failing.stream },
        .buffer = &.{},
        .seek = 0,
        .end = 0,
    } };
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try testing.expectError(error.ReadFailed, streamAll(&failing.interface, &out.writer));
}
