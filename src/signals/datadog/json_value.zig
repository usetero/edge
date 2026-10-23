//! zimdjson on-demand helpers shared by the Datadog record types: a safe
//! entry point for parsing, and writing a value back out as JSON.
//!
//! Both record types carry unknown ("extra") fields as `AnyValue`, and both
//! have to re-emit them verbatim when a policy drops a sibling and forces a
//! re-serialization. The two had byte-identical copies of this walk; it lives
//! here so a fix to one is a fix to both.
//!
//! Two rules keep a walk over a malformed document inside zimdjson's token
//! index, which has no bounds checks:
//!
//! - Parse through `parseContainer`, never `Parser.parseFromSlice` directly.
//! - Stop the whole walk on an error from `next` or `asAny`. After one, the
//!   cursor position is undefined, and the next read can run off the end of
//!   the index. An unescape error from `RawString.get` is the exception: the
//!   cursor has already moved past the string, so skipping that item is safe.

const std = @import("std");
const zimdjson = @import("zimdjson");

pub const Parser = zimdjson.ondemand.FullParser(.default);
pub const Value = Parser.Value;
pub const AnyValue = Parser.AnyValue;

/// Parse `bytes` with `parser`, but refuse a document that does not end with
/// `}` or `]`.
///
/// zimdjson ends its token index with one sentinel token. When the last real
/// token is `:`, `,` or `[`, the sentinel sits where a value belongs. Skipping
/// that value (an unread field, or `at()` passing over a key) consumes the
/// sentinel as a scalar, and the next read goes past the end of the index into
/// memory the indexer never wrote. That read produced a wild offset and a
/// segfault in production. When the last token is `}` or `]`, the sentinel
/// cannot sit at a value position. Every caller accepts only an object or an
/// array, so this refuses no valid input.
pub fn parseContainer(
    parser: *Parser,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !Parser.Document {
    const tail = std.mem.trimEnd(u8, bytes, " \t\r\n");
    if (tail.len == 0) return error.IncompleteDocument;
    switch (tail[tail.len - 1]) {
        '}', ']' => {},
        else => return error.IncompleteDocument,
    }
    return parser.parseFromSlice(allocator, bytes);
}

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
    try writeValue(&jws, value);
    return out.toOwnedSlice();
}

/// Write a scalar `value` through an open `std.json.Stringify`.
///
/// Only scalars, because this runs at re-serialization time, long after the
/// cursor left the record: a container cannot be walked then, and
/// `extras.Materialized.put` captured its bytes with `stringify` instead.
/// `jws` is `anytype` because callers hold it by pointer or by value depending
/// on how they opened the object.
pub fn writeScalar(jws: anytype, value: AnyValue) !void {
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
        .array, .object => unreachable,
    }
}

/// The walk behind `stringify`, run while the cursor is inside `value`.
/// A cursor error fails the whole value, and the record parse with it, which
/// fails open to the original bytes. The module doc says why the walk cannot
/// go on.
fn writeValue(jws: anytype, value: AnyValue) !void {
    switch (value) {
        .array => |arr| {
            try jws.beginArray();
            var it = arr.iterator();
            while (try it.next()) |item| {
                try writeValue(jws, try item.asAny());
            }
            try jws.endArray();
        },
        .object => |obj| {
            try jws.beginObject();
            var it = obj.iterator();
            while (try it.next()) |field| {
                // An unescape error leaves the cursor intact; the next `next`
                // skips the unread value.
                try jws.objectField(field.key.get() catch continue);
                try writeValue(jws, try field.value.asAny());
            }
            try jws.endObject();
        },
        else => try writeScalar(jws, value),
    }
}

test "parseContainer refuses a document that does not end with } or ]" {
    const testing = std.testing;
    var parser: Parser = .init;
    defer parser.deinit(testing.allocator);

    // Each ends with a token that puts zimdjson's sentinel at a value position.
    for ([_][]const u8{ "{\"a\":", "[1,", "{\"a\":[", "[", "", "  \n", "42", "{\"a\":1} x" }) |bytes| {
        try testing.expectError(error.IncompleteDocument, parseContainer(&parser, testing.allocator, bytes));
    }
    for ([_][]const u8{ "{}", "[]", "{\"a\":[1,2]} \r\n", "[{\"a\":1}]" }) |bytes| {
        _ = try parseContainer(&parser, testing.allocator, bytes);
    }
}

test "write fails on a malformed value instead of walking on" {
    const testing = std.testing;
    var parser: Parser = .init;
    defer parser.deinit(testing.allocator);

    // `x` is invalid where a value belongs. Before, the walk dropped it and
    // went on, from a cursor position zimdjson does not define.
    const doc = try parseContainer(&parser, testing.allocator, "{\"a\":[1,x],\"b\":2}");
    const value = try doc.asValue().asAny();
    try testing.expectError(error.IncorrectType, stringify(testing.allocator, value));
}
