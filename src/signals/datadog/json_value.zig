//! Write a zimdjson on-demand value back out as JSON. Logs and metric series
//! use this to re-emit their unknown fields.

const std = @import("std");
const zimdjson = @import("zimdjson");

pub const Parser = zimdjson.ondemand.FullParser(.default);
pub const Value = Parser.Value;
pub const AnyValue = Parser.AnyValue;

/// Serialize `value` to owned JSON bytes.
///
/// An on-demand container cannot be revisited once the parser's cursor moves
/// past it, so a caller that needs the bytes later must capture them while the
/// cursor is still inside. That is the only reason this exists.
pub fn stringify(allocator: std.mem.Allocator, value: AnyValue) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    var jws: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .minified },
    };
    try write(&jws, value);
    return out.toOwnedSlice();
}

/// Write `value` through an open `std.json.Stringify`.
///
/// `jws` is `anytype` because callers hold it by pointer or by value depending
/// on how they opened the object.
///
/// A malformed container surfaces as an error from the ondemand iterator, and
/// the error propagates. A swallowed error would leave `jws` after an
/// `objectField` with no value, where `endObject` is `unreachable`.
pub fn write(jws: anytype, value: AnyValue) !void {
    switch (value) {
        .null => try jws.write(null),
        .bool => |v| try jws.write(v),
        .number => |n| switch (n) {
            .unsigned => |v| try jws.write(v),
            .signed => |v| try jws.write(v),
            .double => |v| try jws.write(v),
        },
        // An unreadable string becomes "". A lost field is better than a
        // half-written object.
        .string => |v| try jws.write(v.get() catch ""),
        .array => |arr| {
            try jws.beginArray();
            var it = arr.iterator();
            while (it.next() catch return error.Malformed) |item| {
                try write(jws, try item.asAny());
            }
            try jws.endArray();
        },
        .object => |obj| {
            try jws.beginObject();
            var it = obj.iterator();
            while (it.next() catch return error.Malformed) |field| {
                try jws.objectField(try field.key.get());
                try write(jws, try field.value.asAny());
            }
            try jws.endObject();
        },
    }
}
