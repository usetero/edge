//! Writing a zimdjson on-demand value back out as JSON.
//!
//! Both record types carry unknown ("extra") fields as `AnyValue`, and both
//! have to re-emit them verbatim when a policy drops a sibling and forces a
//! re-serialization. The two had byte-identical copies of this walk; it lives
//! here so a fix to one is a fix to both.

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
pub fn write(jws: anytype, value: AnyValue) !void {
    switch (value) {
        .null => try jws.write(null),
        .bool => |v| try jws.write(v),
        .number => |n| switch (n) {
            .unsigned => |v| try jws.write(v),
            .signed => |v| try jws.write(v),
            .double => |v| try jws.write(v),
        },
        // An unreadable string becomes empty rather than aborting the walk:
        // the record is the customer's and a half-written object is worse than
        // a lost field. Kept verbatim from the two copies this replaces.
        .string => |v| try jws.write(v.get() catch ""),
        .array => |arr| {
            try jws.beginArray();
            var it = arr.iterator();
            while (it.next() catch null) |item| {
                try write(jws, item.asAny() catch continue);
            }
            try jws.endArray();
        },
        .object => |obj| {
            try jws.beginObject();
            var it = obj.iterator();
            while (it.next() catch null) |field| {
                try jws.objectField(field.key.get() catch continue);
                try write(jws, field.value.asAny() catch continue);
            }
            try jws.endObject();
        },
    }
}
