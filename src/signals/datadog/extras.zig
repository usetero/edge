//! Storage and typed reads for the unknown ("extra") fields of a record.
//!
//! Logs and metric series both use this. Both must re-emit their extras
//! unchanged when a policy removes a sibling field.
//!
//! A record uses one of two shapes. `Materialized` holds a zimdjson parse:
//! typed `AnyValue`s, plus owned bytes for each container, because an
//! on-demand cursor cannot go back. `Spans` holds slices of the record from
//! the fast scan. It owns nothing and unescapes a string only when a policy
//! reads it.

const std = @import("std");
const jscan = @import("../json_scan.zig");
const policy = @import("policy_zig");
const json_value = @import("json_value.zig");

pub const AnyValue = json_value.AnyValue;
pub const Parser = json_value.Parser;

/// Unknown fields of one record, in record order.
///
/// A flat list, not a hash map: a record has few extras, so a linear scan
/// costs less than a map per record. Measured with
/// `zig build datadog-log-bench` against `std.StringArrayHashMapUnmanaged`:
/// scalar 94 ns against 127 ns, none 176 ns against 191 ns, nested 151 ns
/// against 139 ns. Run that comparison again before you change this to a map.
///
/// `get` scans backwards, so a duplicate key gives the last value. The list
/// keeps and re-emits both entries: RFC 8259 §4 does not define a duplicate's
/// meaning, so the bytes stay as sent. Fluent Bit can send duplicates.
pub const Spans = struct {
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub const Entry = struct { key: []const u8, value: []const u8 };

    pub fn deinit(self: *Spans, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn put(
        self: *Spans,
        allocator: std.mem.Allocator,
        key: []const u8,
        value: []const u8,
    ) !void {
        try self.entries.append(allocator, .{ .key = key, .value = value });
    }

    pub fn get(self: *const Spans, key: []const u8) ?[]const u8 {
        var i = self.entries.items.len;
        while (i > 0) {
            i -= 1;
            const entry = self.entries.items[i];
            if (std.mem.eql(u8, entry.key, key)) return entry.value;
        }
        return null;
    }

    pub fn count(self: *const Spans) usize {
        return self.entries.items.len;
    }

    pub fn items(self: *const Spans) []const Entry {
        return self.entries.items;
    }
};

/// Unescaped view of a raw span holding a JSON string, or null for
/// non-strings. Escape-free strings are borrowed; escaped ones are unescaped
/// into `allocator` (lazy — only fields a policy reads pay it).
pub fn spanString(allocator: std.mem.Allocator, span: []const u8) ?[]const u8 {
    return jscan.stringSpan(allocator, span) catch null;
}

/// Typed view of a parsed extra, so the typed matchers fire on numeric and
/// boolean values rather than falling back to a string compare.
pub fn anyValueTyped(v: AnyValue) ?policy.TypedValue {
    return switch (v) {
        .bool => |b| .{ .bool = b },
        .number => |n| switch (n) {
            .signed => |i| .{ .int = i },
            // u64 that overflows i64 can't be an .int; widen to double.
            .unsigned => |u| if (u <= std.math.maxInt(i64))
                .{ .int = @intCast(u) }
            else
                .{ .double = @floatFromInt(u) },
            .double => |d| .{ .double = d },
        },
        .string => |s| .{ .string = s.get() catch return null },
        .null, .object, .array => null,
    };
}

/// Classify a raw JSON value span (`parseRaw` storage) by its first byte.
pub fn spanTyped(allocator: std.mem.Allocator, span: []const u8) ?policy.TypedValue {
    if (span.len == 0) return null;
    switch (span[0]) {
        '"' => return .{ .string = spanString(allocator, span) orelse return null },
        't' => return .{ .bool = true },
        'f' => return .{ .bool = false },
        'n' => return null, // JSON null: not scalar-matchable
        else => {
            // A JSON number: integer if it has no fraction/exponent, else double.
            if (std.mem.indexOfAny(u8, span, ".eE") == null) {
                if (std.fmt.parseInt(i64, span, 10)) |i| return .{ .int = i } else |_| {}
            }
            if (std.fmt.parseFloat(f64, span)) |d| return .{ .double = d } else |_| {}
            return null;
        },
    }
}

/// Walk `remaining` through a container extra's captured JSON bytes.
///
/// The dotted-path fallback: the flat lookups above only answer for a key the
/// record listed literally, so a path that descends into an object or array
/// extra re-parses those bytes with `std.json` and walks them.
pub fn findNestedStringInRaw(
    allocator: std.mem.Allocator,
    raw_json: []const u8,
    remaining: []const []const u8,
) ?[]const u8 {
    if (remaining.len == 0) return null;

    const Parsed = std.json.Parsed(std.json.Value);
    const parsed: Parsed = std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{}) catch return null;
    defer parsed.deinit();
    var current = parsed.value;
    for (remaining) |segment| {
        current = switch (current) {
            .object => |obj| obj.get(segment) orelse return null,
            else => return null,
        };
    }
    return switch (current) {
        // std.json.Value strings live in the parsed arena, which the deinit
        // above frees — copy out or the caller reads freed memory.
        .string => |s| allocator.dupe(u8, s) catch null,
        else => null,
    };
}

/// Unknown fields from a zimdjson parse, in record order. The typed values,
/// the container bytes and the key order must change together.
pub const Materialized = struct {
    values: std.StringHashMapUnmanaged(AnyValue) = .empty,
    /// Object/array values, serialized while the parser's cursor was still
    /// inside them. An on-demand container cannot be revisited once the walk
    /// moves on, so without this a re-serialization emits an empty one.
    raw_json: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// Keys in first-seen order. These are the same allocations `values` owns.
    order: std.ArrayListUnmanaged([]const u8) = .empty,

    pub fn deinit(self: *Materialized, allocator: std.mem.Allocator) void {
        var it = self.values.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        self.values.deinit(allocator);

        var raw_it = self.raw_json.valueIterator();
        while (raw_it.next()) |raw| allocator.free(raw.*);
        self.raw_json.deinit(allocator);

        // Same allocations `values` freed above; only the list storage here.
        self.order.deinit(allocator);
        self.* = undefined;
    }

    /// Record one unknown field. `key` may borrow the parser buffer.
    ///
    /// A duplicate key keeps its first position and takes the last value.
    /// Reuse the key that the map owns: `HashMap.put` keeps the original key
    /// pointer, so a second copy enters neither the map nor `order`, and
    /// `deinit` frees keys through the map.
    pub fn put(self: *Materialized, allocator: std.mem.Allocator, key: []const u8, any: AnyValue) !void {
        const stored_key = if (self.values.getEntry(key)) |existing| blk: {
            if (self.raw_json.fetchRemove(existing.key_ptr.*)) |stale| allocator.free(stale.value);
            existing.value_ptr.* = any;
            break :blk existing.key_ptr.*;
        } else blk: {
            const key_copy = try allocator.dupe(u8, key);
            {
                errdefer allocator.free(key_copy);
                try self.values.put(allocator, key_copy, any);
            }
            try self.order.append(allocator, key_copy);
            break :blk key_copy;
        };
        switch (any) {
            .object, .array => {
                const raw = try json_value.stringify(allocator, any);
                errdefer allocator.free(raw);
                try self.raw_json.put(allocator, stored_key, raw);
            },
            else => {},
        }
    }

    pub fn get(self: *const Materialized, key: []const u8) ?AnyValue {
        return self.values.get(key);
    }

    pub fn rawJson(self: *const Materialized, key: []const u8) ?[]const u8 {
        return self.raw_json.get(key);
    }

    pub fn contains(self: *const Materialized, key: []const u8) bool {
        return self.values.contains(key);
    }

    pub fn count(self: *const Materialized) usize {
        return self.values.count();
    }

    /// Keys in the order the record listed them.
    pub fn keys(self: *const Materialized) []const []const u8 {
        return self.order.items;
    }

    /// Emit every extra into an open JSON object, in record order. A container
    /// goes out as its captured bytes; anything else is written from its
    /// typed value.
    pub fn write(self: *const Materialized, jws: anytype) !void {
        for (self.order.items) |key| {
            const value = self.values.get(key) orelse continue;
            try jws.objectField(key);
            if (self.raw_json.get(key)) |raw| {
                try jws.beginWriteRaw();
                try jws.writer.writeAll(raw);
                jws.endWriteRaw();
            } else {
                try json_value.write(jws, value);
            }
        }
    }
};

// ============================== Tests ==============================

const testing = std.testing;

/// Parse `json` and hand the named field's `AnyValue` to `run`. The parser
/// outlives the callback, which is what an on-demand value requires.
fn withValue(
    json: []const u8,
    key: []const u8,
    run: *const fn (AnyValue) anyerror!void,
) !void {
    var parser: Parser = .init;
    defer parser.deinit(testing.allocator);
    const doc = try parser.parseFromSlice(testing.allocator, json);
    var obj = try doc.asValue().asObject();
    var it = obj.iterator();
    while (try it.next()) |field| {
        if (std.mem.eql(u8, try field.key.get(), key)) return run(try field.value.asAny());
    }
    return error.KeyNotFound;
}

test "Spans: put, get and count" {
    var spans: Spans = .{};
    defer spans.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), spans.count());
    try testing.expect(spans.get("absent") == null);

    try spans.put(testing.allocator, "a", "1");
    try spans.put(testing.allocator, "b", "\"two\"");
    try testing.expectEqual(@as(usize, 2), spans.count());
    try testing.expectEqualStrings("1", spans.get("a").?);
    try testing.expectEqualStrings("\"two\"", spans.get("b").?);
    try testing.expect(spans.get("c") == null);
}

test "Spans: a duplicate key resolves to the last, and both are kept" {
    // The backwards scan is what makes last-wins work, and keeping both
    // entries is what lets `parseRaw` re-emit the record as the sender wrote
    // it. A map would collapse them; see the type comment.
    var spans: Spans = .{};
    defer spans.deinit(testing.allocator);

    try spans.put(testing.allocator, "dupe", "1");
    try spans.put(testing.allocator, "other", "9");
    try spans.put(testing.allocator, "dupe", "2");

    try testing.expectEqualStrings("2", spans.get("dupe").?);
    try testing.expectEqual(@as(usize, 3), spans.count());

    // `items` keeps document order, duplicates included.
    const items = spans.items();
    try testing.expectEqualStrings("dupe", items[0].key);
    try testing.expectEqualStrings("1", items[0].value);
    try testing.expectEqualStrings("dupe", items[2].key);
    try testing.expectEqualStrings("2", items[2].value);
}

test "spanString: borrows a plain string, unescapes an escaped one, refuses a non-string" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("plain", spanString(a, "\"plain\"").?);
    try testing.expectEqualStrings("a\"b", spanString(a, "\"a\\\"b\"").?);
    try testing.expectEqualStrings("tab\there", spanString(a, "\"tab\\there\"").?);
    try testing.expectEqualStrings("", spanString(a, "\"\"").?);
    // Non-strings are not this function's business.
    try testing.expect(spanString(a, "42") == null);
    try testing.expect(spanString(a, "true") == null);
    try testing.expect(spanString(a, "{\"k\":1}") == null);
}

test "spanTyped: classifies a raw value span by its first byte" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqualStrings("hi", spanTyped(a, "\"hi\"").?.string);
    try testing.expectEqual(true, spanTyped(a, "true").?.bool);
    try testing.expectEqual(false, spanTyped(a, "false").?.bool);
    try testing.expectEqual(@as(i64, 42), spanTyped(a, "42").?.int);
    try testing.expectEqual(@as(i64, -7), spanTyped(a, "-7").?.int);
    try testing.expectEqual(@as(f64, 1.5), spanTyped(a, "1.5").?.double);
    // An exponent makes it a double even with no fraction.
    try testing.expectEqual(@as(f64, 1e5), spanTyped(a, "1e5").?.double);

    // JSON null is not scalar-matchable, and neither is a container or an
    // empty span.
    try testing.expect(spanTyped(a, "null") == null);
    try testing.expect(spanTyped(a, "") == null);
    try testing.expect(spanTyped(a, "{\"k\":1}") == null);
    try testing.expect(spanTyped(a, "[1]") == null);
}

test "anyValueTyped: every variant, including the u64 that cannot be an int" {
    const json =
        \\{"b":true,"i":-5,"u":18446744073709551615,"d":2.5,"s":"txt","n":null,"o":{"k":1},"a":[1]}
    ;
    const check = struct {
        fn boolean(v: AnyValue) anyerror!void {
            try testing.expectEqual(true, anyValueTyped(v).?.bool);
        }
        fn signed(v: AnyValue) anyerror!void {
            try testing.expectEqual(@as(i64, -5), anyValueTyped(v).?.int);
        }
        fn hugeUnsigned(v: AnyValue) anyerror!void {
            // Past maxInt(i64) it cannot be an `.int`, so it widens to double
            // rather than wrapping into a negative.
            try testing.expect(anyValueTyped(v).?.double > 1.8e19);
        }
        fn double(v: AnyValue) anyerror!void {
            try testing.expectEqual(@as(f64, 2.5), anyValueTyped(v).?.double);
        }
        fn string(v: AnyValue) anyerror!void {
            try testing.expectEqualStrings("txt", anyValueTyped(v).?.string);
        }
        fn none(v: AnyValue) anyerror!void {
            try testing.expect(anyValueTyped(v) == null);
        }
    };
    try withValue(json, "b", check.boolean);
    try withValue(json, "i", check.signed);
    try withValue(json, "u", check.hugeUnsigned);
    try withValue(json, "d", check.double);
    try withValue(json, "s", check.string);
    // Null and containers have no scalar form.
    try withValue(json, "n", check.none);
    try withValue(json, "o", check.none);
    try withValue(json, "a", check.none);
}

test "findNestedStringInRaw: descends an object path and refuses the rest" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = "{\"x\":{\"y\":{\"z\":\"found\"},\"n\":7},\"arr\":[{\"z\":\"in array\"}]}";

    try testing.expectEqualStrings("found", findNestedStringInRaw(a, raw, &.{ "x", "y", "z" }).?);
    // A missing segment, a non-string leaf, and an empty path all yield null.
    try testing.expect(findNestedStringInRaw(a, raw, &.{ "x", "nope" }) == null);
    try testing.expect(findNestedStringInRaw(a, raw, &.{ "x", "n" }) == null);
    try testing.expect(findNestedStringInRaw(a, raw, &.{}) == null);
    // Arrays are not descended: the walk only steps through objects.
    try testing.expect(findNestedStringInRaw(a, raw, &.{ "arr", "z" }) == null);
    // Malformed input fails open rather than propagating a parse error.
    try testing.expect(findNestedStringInRaw(a, "{not json", &.{"x"}) == null);
}

/// Fill a `Materialized` from every unknown field of `json`, the way
/// `DatadogLog.parse` and `MetricSeries.parse` both do.
fn fillFrom(out: *Materialized, allocator: std.mem.Allocator, parser: *Parser, json: []const u8) !void {
    const doc = try parser.parseFromSlice(allocator, json);
    var obj = try doc.asValue().asObject();
    var it = obj.iterator();
    while (try it.next()) |field| {
        try out.put(allocator, try field.key.get(), try field.value.asAny());
    }
}

fn renderExtras(extras: *const Materialized, allocator: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    var jws: std.json.Stringify = .{ .writer = &out.writer, .options = .{ .whitespace = .minified } };
    try jws.beginObject();
    try extras.write(&jws);
    try jws.endObject();
    return out.toOwnedSlice();
}

test "Materialized: keys come back in the order the record listed them" {
    const gpa = testing.allocator;
    var parser: Parser = .init;
    defer parser.deinit(gpa);
    var extras: Materialized = .{};
    defer extras.deinit(gpa);

    try fillFrom(&extras, gpa, &parser, "{\"zeta\":1,\"alpha\":2,\"middle\":3,\"beta\":4}");

    const want = [_][]const u8{ "zeta", "alpha", "middle", "beta" };
    try testing.expectEqual(want.len, extras.keys().len);
    for (want, extras.keys()) |expected, actual| try testing.expectEqualStrings(expected, actual);
    try testing.expectEqual(@as(usize, 4), extras.count());
    try testing.expect(extras.contains("middle"));
    try testing.expect(!extras.contains("absent"));
    try testing.expect(extras.get("absent") == null);
}

test "Materialized: a duplicate keeps its position, takes the last value, strands nothing" {
    // `HashMap.put` keeps the original key pointer on a duplicate, so an
    // insert that dupes a second key leaves it unreachable: it enters neither
    // the map nor `order`, and `deinit` frees keys by walking the map. The
    // testing allocator fails this test on that leak.
    const gpa = testing.allocator;
    var parser: Parser = .init;
    defer parser.deinit(gpa);
    var extras: Materialized = .{};
    defer extras.deinit(gpa);

    try fillFrom(&extras, gpa, &parser, "{\"dupe\":1,\"keep\":\"x\",\"dupe\":2}");

    try testing.expectEqual(@as(usize, 2), extras.count());
    const rendered = try renderExtras(&extras, gpa);
    defer gpa.free(rendered);
    try testing.expectEqualStrings("{\"dupe\":2,\"keep\":\"x\"}", rendered);
}

test "Materialized: containers are captured at parse time and re-emitted whole" {
    // An on-demand container cannot be revisited once the cursor moves past
    // it, so a re-serialization from the stored value alone emits `{}`.
    const gpa = testing.allocator;
    var parser: Parser = .init;
    defer parser.deinit(gpa);
    var extras: Materialized = .{};
    defer extras.deinit(gpa);

    try fillFrom(&extras, gpa, &parser, "{\"obj\":{\"a\":1,\"b\":[2,3]},\"arr\":[{\"c\":\"d\"}],\"s\":7}");

    try testing.expectEqualStrings("{\"a\":1,\"b\":[2,3]}", extras.rawJson("obj").?);
    try testing.expectEqualStrings("[{\"c\":\"d\"}]", extras.rawJson("arr").?);
    // A scalar carries no captured bytes; it is written from its typed value.
    try testing.expect(extras.rawJson("s") == null);

    const rendered = try renderExtras(&extras, gpa);
    defer gpa.free(rendered);
    try testing.expectEqualStrings("{\"obj\":{\"a\":1,\"b\":[2,3]},\"arr\":[{\"c\":\"d\"}],\"s\":7}", rendered);
}

test "Materialized: replacing a container hands its captured bytes back" {
    // Both directions: a container replaced by another, and a container
    // replaced by a scalar, where the stale bytes have no successor to
    // overwrite them. A leak here fails the test.
    const gpa = testing.allocator;
    var parser: Parser = .init;
    defer parser.deinit(gpa);
    var extras: Materialized = .{};
    defer extras.deinit(gpa);

    const json = "{\"obj\":{\"a\":1},\"obj\":{\"b\":2}," ++
        "\"gone\":[1,2],\"gone\":9,\"grew\":1,\"grew\":{\"c\":3}}";
    try fillFrom(&extras, gpa, &parser, json);

    try testing.expectEqual(@as(usize, 3), extras.count());
    try testing.expectEqualStrings("{\"b\":2}", extras.rawJson("obj").?);
    try testing.expect(extras.rawJson("gone") == null);
    try testing.expectEqualStrings("{\"c\":3}", extras.rawJson("grew").?);

    const rendered = try renderExtras(&extras, gpa);
    defer gpa.free(rendered);
    try testing.expectEqualStrings("{\"obj\":{\"b\":2},\"gone\":9,\"grew\":{\"c\":3}}", rendered);
}

test "Materialized: an empty set deinits clean and writes nothing" {
    const gpa = testing.allocator;
    var extras: Materialized = .{};
    defer extras.deinit(gpa);

    try testing.expectEqual(@as(usize, 0), extras.count());
    try testing.expectEqual(@as(usize, 0), extras.keys().len);
    const rendered = try renderExtras(&extras, gpa);
    defer gpa.free(rendered);
    try testing.expectEqualStrings("{}", rendered);
}
