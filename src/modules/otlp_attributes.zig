//! Shared attribute helpers for OTLP and Datadog modules.
//!
//! These functions operate on proto KeyValue / AnyValue types and zimdjson
//! types, and are used by OTLP and Datadog signal modules for field access
//! and mutation.

const std = @import("std");
const proto = @import("proto");
const zimdjson = @import("zimdjson");

pub const AnyValue = proto.common.AnyValue;
pub const KeyValue = proto.common.KeyValue;

// =============================================================================
// Read helpers
// =============================================================================

/// Extract the string payload from an AnyValue, returning null for
/// missing values or non-string variants.
pub fn getStringValue(value: ?AnyValue) ?[]const u8 {
    const v = value orelse return null;
    const val_union = v.value orelse return null;
    return switch (val_union) {
        .string_value => |s| s,
        else => null,
    };
}

/// Find a top-level attribute by key and return its string value.
pub fn findAttribute(attributes: []const KeyValue, key: []const u8) ?[]const u8 {
    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, key)) {
            return getStringValue(kv.value);
        }
    }
    return null;
}

/// Walk a KeyValue list following `path` segments into nested kvlist_value
/// nodes.  Returns the string value at the leaf, or null if any segment
/// is missing or the leaf is not a string.
pub fn findNestedAttribute(attributes: []const KeyValue, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;

    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, path[0])) {
            if (path.len == 1) {
                return getStringValue(kv.value);
            }
            const val = kv.value orelse return null;
            const inner = val.value orelse return null;
            switch (inner) {
                .kvlist_value => |kvlist| {
                    return findNestedAttribute(kvlist.values.items, path[1..]);
                },
                else => return null,
            }
        }
    }
    return null;
}

/// Return the index of the first attribute whose key matches, or null.
pub fn findAttrIndex(attrs: []const KeyValue, key: []const u8) ?usize {
    for (attrs, 0..) |kv, i| {
        if (std.mem.eql(u8, kv.key, key)) return i;
    }
    return null;
}

// =============================================================================
// Mutation helpers
// =============================================================================

/// Remove the first attribute matching `key`.  Returns true if found.
pub fn removeAttribute(attributes: *std.ArrayListUnmanaged(KeyValue), key: []const u8) bool {
    for (attributes.items, 0..) |kv, i| {
        if (std.mem.eql(u8, kv.key, key)) {
            _ = attributes.orderedRemove(i);
            return true;
        }
    }
    return false;
}

/// Remove by path — currently only supports top-level keys.
pub fn removeAttributeByPath(attributes: *std.ArrayListUnmanaged(KeyValue), path: []const []const u8) bool {
    if (path.len == 0) return false;
    return removeAttribute(attributes, path[0]);
}

/// Set (or insert) a string attribute.  If the key already exists its
/// value is overwritten; otherwise a new entry is appended.
pub fn setAttribute(allocator: std.mem.Allocator, attributes: *std.ArrayListUnmanaged(KeyValue), key: []const u8, value: []const u8) bool {
    for (attributes.items) |*kv| {
        if (std.mem.eql(u8, kv.key, key)) {
            kv.value = .{ .value = .{ .string_value = value } };
            return true;
        }
    }
    attributes.append(allocator, .{
        .key = key,
        .value = .{ .value = .{ .string_value = value } },
    }) catch return false;
    return true;
}

/// Set by path — currently only supports top-level keys.
pub fn setAttributeByPath(allocator: std.mem.Allocator, attributes: *std.ArrayListUnmanaged(KeyValue), path: []const []const u8, value: []const u8) bool {
    if (path.len == 0) return false;
    return setAttribute(allocator, attributes, path[0], value);
}

// =============================================================================
// Datadog helpers
// =============================================================================

/// Return the first path segment, or null for empty paths.
/// Datadog uses flat attributes so only the first segment is meaningful.
pub fn getFirstPathSegment(path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    return path[0];
}

/// zimdjson AnyValue type used by Datadog log/metric extra fields.
pub const ZimdjsonAnyValue = zimdjson.ondemand.FullParser(.default).AnyValue;

/// Look up an attribute in a zimdjson extra fields HashMap.
/// Supports multi-segment paths by joining segments with '.' to form a dotted key,
/// which matches Datadog's flat attribute convention (e.g., "http.request.method").
pub fn findExtraField(extra: *const std.StringHashMapUnmanaged(ZimdjsonAnyValue), path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;

    // Try direct lookup of first segment
    if (extra.get(path[0])) |value| {
        if (path.len == 1) {
            if (value == .string) return value.string.get() catch null;
            return null;
        }
    }

    // For multi-segment paths, try dotted key (e.g., ["http", "method"] -> "http.method")
    if (path.len > 1) {
        var buf: [512]u8 = undefined;
        var pos: usize = 0;
        for (path) |segment| {
            if (pos > 0) {
                if (pos >= buf.len) return null;
                buf[pos] = '.';
                pos += 1;
            }
            if (pos + segment.len > buf.len) return null;
            @memcpy(buf[pos .. pos + segment.len], segment);
            pos += segment.len;
        }
        if (extra.get(buf[0..pos])) |value| {
            if (value == .string) return value.string.get() catch null;
        }
    }

    return null;
}

// =============================================================================
// Tests
// =============================================================================

// ── Test helpers ─────────────────────────────────────────────────────

fn makeKV(key: []const u8, str_val: []const u8) KeyValue {
    return .{
        .key = key,
        .value = .{ .value = .{ .string_value = str_val } },
    };
}

fn makeIntKV(key: []const u8, int_val: i64) KeyValue {
    return .{
        .key = key,
        .value = .{ .value = .{ .int_value = int_val } },
    };
}

fn makeNullKV(key: []const u8) KeyValue {
    return .{
        .key = key,
        .value = null,
    };
}

fn makeNestedKV(key: []const u8, children: []const KeyValue) KeyValue {
    // We need a mutable copy of the children slice for the kvlist.
    // In tests the slice lives on the stack so this is fine.
    return .{
        .key = key,
        .value = .{
            .value = .{
                .kvlist_value = .{
                    .values = .{
                        .items = @constCast(children),
                        .capacity = children.len,
                    },
                },
            },
        },
    };
}

fn makeMutableList(items: []const KeyValue) std.ArrayListUnmanaged(KeyValue) {
    return .{
        .items = @constCast(items),
        .capacity = items.len,
    };
}

// ── getStringValue ───────────────────────────────────────────────────

test "getStringValue - string value" {
    const v: AnyValue = .{ .value = .{ .string_value = "hello" } };
    try std.testing.expectEqualStrings("hello", getStringValue(v).?);
}

test "getStringValue - null AnyValue" {
    try std.testing.expectEqual(@as(?[]const u8, null), getStringValue(null));
}

test "getStringValue - null inner value" {
    const v: AnyValue = .{ .value = null };
    try std.testing.expectEqual(@as(?[]const u8, null), getStringValue(v));
}

test "getStringValue - int value returns null" {
    const v: AnyValue = .{ .value = .{ .int_value = 42 } };
    try std.testing.expectEqual(@as(?[]const u8, null), getStringValue(v));
}

test "getStringValue - bool value returns null" {
    const v: AnyValue = .{ .value = .{ .bool_value = true } };
    try std.testing.expectEqual(@as(?[]const u8, null), getStringValue(v));
}

test "getStringValue - empty string" {
    const v: AnyValue = .{ .value = .{ .string_value = "" } };
    try std.testing.expectEqualStrings("", getStringValue(v).?);
}

// ── findAttribute ────────────────────────────────────────────────────

test "findAttribute - found" {
    const attrs = [_]KeyValue{
        makeKV("host", "server-1"),
        makeKV("region", "us-east"),
    };
    try std.testing.expectEqualStrings("us-east", findAttribute(&attrs, "region").?);
}

test "findAttribute - not found" {
    const attrs = [_]KeyValue{makeKV("host", "server-1")};
    try std.testing.expectEqual(@as(?[]const u8, null), findAttribute(&attrs, "missing"));
}

test "findAttribute - empty list" {
    const attrs = [_]KeyValue{};
    try std.testing.expectEqual(@as(?[]const u8, null), findAttribute(&attrs, "any"));
}

test "findAttribute - first match wins" {
    const attrs = [_]KeyValue{
        makeKV("key", "first"),
        makeKV("key", "second"),
    };
    try std.testing.expectEqualStrings("first", findAttribute(&attrs, "key").?);
}

test "findAttribute - non-string value returns null" {
    const attrs = [_]KeyValue{makeIntKV("count", 42)};
    try std.testing.expectEqual(@as(?[]const u8, null), findAttribute(&attrs, "count"));
}

test "findAttribute - null value returns null" {
    const attrs = [_]KeyValue{makeNullKV("empty")};
    try std.testing.expectEqual(@as(?[]const u8, null), findAttribute(&attrs, "empty"));
}

// ── findNestedAttribute ──────────────────────────────────────────────

test "findNestedAttribute - single segment" {
    const attrs = [_]KeyValue{makeKV("service.name", "api")};
    const path = [_][]const u8{"service.name"};
    try std.testing.expectEqualStrings("api", findNestedAttribute(&attrs, &path).?);
}

test "findNestedAttribute - two segments" {
    const inner = [_]KeyValue{makeKV("method", "GET")};
    const attrs = [_]KeyValue{makeNestedKV("http", &inner)};
    const path = [_][]const u8{ "http", "method" };
    try std.testing.expectEqualStrings("GET", findNestedAttribute(&attrs, &path).?);
}

test "findNestedAttribute - three segments" {
    const deepest = [_]KeyValue{makeKV("code", "200")};
    const mid = [_]KeyValue{makeNestedKV("response", &deepest)};
    const attrs = [_]KeyValue{makeNestedKV("http", &mid)};
    const path = [_][]const u8{ "http", "response", "code" };
    try std.testing.expectEqualStrings("200", findNestedAttribute(&attrs, &path).?);
}

test "findNestedAttribute - empty path" {
    const attrs = [_]KeyValue{makeKV("key", "val")};
    const path = [_][]const u8{};
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - missing first segment" {
    const attrs = [_]KeyValue{makeKV("host", "server-1")};
    const path = [_][]const u8{"missing"};
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - missing nested segment" {
    const inner = [_]KeyValue{makeKV("method", "GET")};
    const attrs = [_]KeyValue{makeNestedKV("http", &inner)};
    const path = [_][]const u8{ "http", "missing" };
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - non-kvlist at intermediate level" {
    const attrs = [_]KeyValue{makeKV("http", "not-a-map")};
    const path = [_][]const u8{ "http", "method" };
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - null value at intermediate level" {
    const attrs = [_]KeyValue{makeNullKV("http")};
    const path = [_][]const u8{ "http", "method" };
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - non-string at leaf" {
    const inner = [_]KeyValue{makeIntKV("status", 200)};
    const attrs = [_]KeyValue{makeNestedKV("http", &inner)};
    const path = [_][]const u8{ "http", "status" };
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - empty attributes" {
    const attrs = [_]KeyValue{};
    const path = [_][]const u8{"key"};
    try std.testing.expectEqual(@as(?[]const u8, null), findNestedAttribute(&attrs, &path));
}

test "findNestedAttribute - multiple attributes picks correct one" {
    const inner = [_]KeyValue{makeKV("method", "POST")};
    const attrs = [_]KeyValue{
        makeKV("host", "server-1"),
        makeNestedKV("http", &inner),
        makeKV("region", "us-east"),
    };
    const path = [_][]const u8{ "http", "method" };
    try std.testing.expectEqualStrings("POST", findNestedAttribute(&attrs, &path).?);
}

// ── findAttrIndex ────────────────────────────────────────────────────

test "findAttrIndex - found" {
    const attrs = [_]KeyValue{
        makeKV("a", "1"),
        makeKV("b", "2"),
        makeKV("c", "3"),
    };
    try std.testing.expectEqual(@as(?usize, 1), findAttrIndex(&attrs, "b"));
}

test "findAttrIndex - first element" {
    const attrs = [_]KeyValue{makeKV("only", "val")};
    try std.testing.expectEqual(@as(?usize, 0), findAttrIndex(&attrs, "only"));
}

test "findAttrIndex - not found" {
    const attrs = [_]KeyValue{makeKV("a", "1")};
    try std.testing.expectEqual(@as(?usize, null), findAttrIndex(&attrs, "z"));
}

test "findAttrIndex - empty list" {
    const attrs = [_]KeyValue{};
    try std.testing.expectEqual(@as(?usize, null), findAttrIndex(&attrs, "any"));
}

test "findAttrIndex - duplicate keys returns first" {
    const attrs = [_]KeyValue{
        makeKV("dup", "first"),
        makeKV("dup", "second"),
    };
    try std.testing.expectEqual(@as(?usize, 0), findAttrIndex(&attrs, "dup"));
}

// ── removeAttribute ──────────────────────────────────────────────────

test "removeAttribute - removes existing key" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("a", "1"));
    try list.append(alloc, makeKV("b", "2"));
    try list.append(alloc, makeKV("c", "3"));

    try std.testing.expect(removeAttribute(&list, "b"));
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqualStrings("a", list.items[0].key);
    try std.testing.expectEqualStrings("c", list.items[1].key);
}

test "removeAttribute - missing key returns false" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("a", "1"));

    try std.testing.expect(!removeAttribute(&list, "z"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
}

test "removeAttribute - empty list returns false" {
    var list = std.ArrayListUnmanaged(KeyValue){};
    try std.testing.expect(!removeAttribute(&list, "any"));
}

test "removeAttribute - removes first of duplicates" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("x", "first"));
    try list.append(alloc, makeKV("x", "second"));

    try std.testing.expect(removeAttribute(&list, "x"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("second", getStringValue(list.items[0].value).?);
}

test "removeAttribute - removes only element" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("only", "val"));

    try std.testing.expect(removeAttribute(&list, "only"));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

// ── removeAttributeByPath ────────────────────────────────────────────

test "removeAttributeByPath - single segment" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("target", "val"));

    const path = [_][]const u8{"target"};
    try std.testing.expect(removeAttributeByPath(&list, &path));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "removeAttributeByPath - empty path" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("a", "1"));

    const path = [_][]const u8{};
    try std.testing.expect(!removeAttributeByPath(&list, &path));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
}

test "removeAttributeByPath - multi-segment removes top-level key" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("http", "nested"));

    const path = [_][]const u8{ "http", "method" };
    try std.testing.expect(removeAttributeByPath(&list, &path));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

// ── setAttribute ─────────────────────────────────────────────────────

test "setAttribute - updates existing key" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("key", "old"));

    try std.testing.expect(setAttribute(alloc, &list, "key", "new"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("new", getStringValue(list.items[0].value).?);
}

test "setAttribute - inserts new key" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);

    try std.testing.expect(setAttribute(alloc, &list, "new-key", "val"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("new-key", list.items[0].key);
    try std.testing.expectEqualStrings("val", getStringValue(list.items[0].value).?);
}

test "setAttribute - inserts into non-empty list" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeKV("existing", "val"));

    try std.testing.expect(setAttribute(alloc, &list, "added", "new"));
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
    try std.testing.expectEqualStrings("existing", list.items[0].key);
    try std.testing.expectEqualStrings("added", list.items[1].key);
}

test "setAttribute - overwrites non-string value" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);
    try list.append(alloc, makeIntKV("count", 42));

    // Int value won't match string lookup, so it appends (key comparison still matches)
    try std.testing.expect(setAttribute(alloc, &list, "count", "100"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("100", getStringValue(list.items[0].value).?);
}

// ── setAttributeByPath ───────────────────────────────────────────────

test "setAttributeByPath - single segment" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);

    const path = [_][]const u8{"key"};
    try std.testing.expect(setAttributeByPath(alloc, &list, &path, "val"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("val", getStringValue(list.items[0].value).?);
}

test "setAttributeByPath - empty path" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);

    const path = [_][]const u8{};
    try std.testing.expect(!setAttributeByPath(alloc, &list, &path, "val"));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
}

test "setAttributeByPath - multi-segment uses first" {
    const alloc = std.testing.allocator;
    var list = std.ArrayListUnmanaged(KeyValue){};
    defer list.deinit(alloc);

    const path = [_][]const u8{ "http", "method" };
    try std.testing.expect(setAttributeByPath(alloc, &list, &path, "GET"));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualStrings("http", list.items[0].key);
}

// ── getFirstPathSegment ──────────────────────────────────────────────

test "getFirstPathSegment - non-empty" {
    const path = [_][]const u8{ "first", "second" };
    try std.testing.expectEqualStrings("first", getFirstPathSegment(&path).?);
}

test "getFirstPathSegment - single element" {
    const path = [_][]const u8{"only"};
    try std.testing.expectEqualStrings("only", getFirstPathSegment(&path).?);
}

test "getFirstPathSegment - empty" {
    const path = [_][]const u8{};
    try std.testing.expectEqual(@as(?[]const u8, null), getFirstPathSegment(&path));
}

// ── findExtraField ──────────────────────────────────────────────────

test "findExtraField - empty path" {
    var map: std.StringHashMapUnmanaged(ZimdjsonAnyValue) = .empty;
    const path = [_][]const u8{};
    try std.testing.expectEqual(@as(?[]const u8, null), findExtraField(&map, &path));
}

test "findExtraField - empty map" {
    var map: std.StringHashMapUnmanaged(ZimdjsonAnyValue) = .empty;
    const path = [_][]const u8{"key"};
    try std.testing.expectEqual(@as(?[]const u8, null), findExtraField(&map, &path));
}

test "findExtraField - dotted key joins segments" {
    // This tests the path joining logic with a pre-populated map.
    // Real integration is tested in datadog_logs_v2 and datadog_metrics_v2.
    const allocator = std.testing.allocator;
    const Parser = zimdjson.ondemand.FullParser(.default);
    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"http.method": "GET"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var obj = try doc.asValue().asObject();
    var map: std.StringHashMapUnmanaged(ZimdjsonAnyValue) = .empty;
    defer map.deinit(allocator);
    var it = obj.iterator();
    while (try it.next()) |field| {
        const key_copy = try allocator.dupe(u8, try field.key.get());
        map.put(allocator, key_copy, try field.value.asAny()) catch {
            allocator.free(key_copy);
        };
    }
    defer {
        var key_it = map.keyIterator();
        while (key_it.next()) |k| allocator.free(k.*);
    }

    const path = [_][]const u8{ "http", "method" };
    const result = findExtraField(&map, &path);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("GET", result.?);
}
