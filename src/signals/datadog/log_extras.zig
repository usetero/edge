//! Storage and typed reads for a log record's unknown ("extra") fields.
//!
//! Two parse paths fill two different shapes, and they are mutually exclusive
//! per record. The materializing `DatadogLog.parse` fills a map of typed
//! `AnyValue`s plus owned JSON bytes for containers. The fast `parseRaw` fills
//! `Spans`: verbatim slices of the record, nothing owned, nothing unescaped
//! until a policy actually reads the field.

const std = @import("std");
const jscan = @import("../json_scan.zig");
const policy = @import("policy_zig");
const json_value = @import("json_value.zig");

pub const AnyValue = json_value.AnyValue;
pub const Parser = json_value.Parser;

/// Unknown fields of one record, in the order the record listed them.
///
/// A flat list, not a hash map. A record carries a handful of extras and a
/// policy reads one or two of them, so hashing and growing a map per record
/// costs more than a linear scan over short keys. Measured with
/// `zig build datadog-log-bench`, per record, against an ordered map
/// (`std.StringArrayHashMapUnmanaged`) built to replace this: scalar extras
/// cost 94 ns here against 127 ns there, and a record with no extras at all
/// ran 176 ns against 191 ns. Nested extras were the one win for the map,
/// 139 ns against 151 ns, because it folds the container-JSON lookup into the
/// value. Do not swap this for a map without re-running that comparison.
///
/// `get` scans backwards, so a duplicate key resolves to the last one, as a
/// map's last-write-wins would. The list keeps both entries and re-emits both,
/// which a map cannot: RFC 8259 §4 makes key uniqueness a SHOULD and leaves a
/// duplicate's meaning undefined, so the conservative reading is that the
/// bytes are the sender's and only the intake may judge them. Nothing in the
/// fleet emits duplicates (the Datadog agent marshals a Go struct, the OTel
/// collector builds from pdata), but Fluent Bit can: msgpack maps admit
/// duplicate keys and its JSON encoder does not deduplicate, so a filter chain
/// could produce one.
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
