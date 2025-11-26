const std = @import("std");

const c = @cImport({
    @cInclude("jsoncons_wrapper.h");
});

pub const JsonDoc = struct {
    handle: *c.JsonDoc,

    pub fn parse(json_str: []const u8) !JsonDoc {
        const handle = c.json_parse(json_str.ptr, json_str.len);
        if (handle == null) {
            std.debug.print("Parse error: {s}\n", .{c.json_last_error()});
            return error.ParseError;
        }
        return .{ .handle = handle.? };
    }

    pub fn deinit(self: JsonDoc) void {
        c.json_free(self.handle);
    }

    pub fn query(self: JsonDoc, path: [:0]const u8) !JsonPathResult {
        const result = c.json_path_query(self.handle, path.ptr);
        if (result == null) {
            std.debug.print("Query error: {s}\n", .{c.json_last_error()});
            return error.QueryError;
        }
        return .{ .handle = result.? };
    }
};

pub const JsonPathResult = struct {
    handle: *c.JsonPathResult,

    pub fn deinit(self: JsonPathResult) void {
        c.json_path_result_free(self.handle);
    }

    pub fn count(self: JsonPathResult) usize {
        return c.json_path_result_count(self.handle);
    }

    pub fn get(self: JsonPathResult, index: usize) ?[]const u8 {
        var len: usize = 0;
        const ptr = c.json_path_result_get(self.handle, index, &len);
        if (ptr == null) return null;
        return ptr[0..len];
    }

    pub fn iterator(self: JsonPathResult) Iterator {
        return .{ .result = self, .index = 0 };
    }

    pub const Iterator = struct {
        result: JsonPathResult,
        index: usize,

        pub fn next(self: *Iterator) ?[]const u8 {
            if (self.index >= self.result.count()) return null;
            const val = self.result.get(self.index);
            self.index += 1;
            return val;
        }
    };
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "JsonDoc.parse parses valid JSON" {
    const json_str =
        \\{"name": "test", "value": 42}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();
}

test "JsonDoc.parse fails on invalid JSON" {
    const invalid_json = "{ invalid json }";
    const result = JsonDoc.parse(invalid_json);
    try testing.expectError(error.ParseError, result);
}

test "JsonDoc.query extracts simple field" {
    const json_str =
        \\{"name": "hello", "value": 42}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.name");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.count());
    try testing.expectEqualStrings("hello", result.get(0).?);
}

test "JsonDoc.query extracts numeric field as string" {
    const json_str =
        \\{"name": "hello", "value": 42}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.value");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.count());
    try testing.expectEqualStrings("42", result.get(0).?);
}

test "JsonDoc.query handles nested objects" {
    const json_str =
        \\{"outer": {"inner": {"deep": "value"}}}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.outer.inner.deep");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.count());
    try testing.expectEqualStrings("value", result.get(0).?);
}

test "JsonDoc.query handles array indexing" {
    const json_str =
        \\{"items": ["first", "second", "third"]}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.items[1]");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 1), result.count());
    try testing.expectEqualStrings("second", result.get(0).?);
}

test "JsonDoc.query handles wildcard on array" {
    const json_str =
        \\{"items": ["a", "b", "c"]}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.items[*]");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 3), result.count());
    try testing.expectEqualStrings("a", result.get(0).?);
    try testing.expectEqualStrings("b", result.get(1).?);
    try testing.expectEqualStrings("c", result.get(2).?);
}

test "JsonDoc.query handles recursive descent" {
    const json_str =
        \\{"a": {"name": "first"}, "b": {"name": "second"}}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$..name");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 2), result.count());
}

test "JsonDoc.query returns empty for non-existent path" {
    const json_str =
        \\{"name": "test"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.nonexistent");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 0), result.count());
    try testing.expect(result.get(0) == null);
}

test "JsonDoc.query handles filter expressions" {
    const json_str =
        \\{"books": [
        \\  {"title": "A", "price": 10},
        \\  {"title": "B", "price": 20},
        \\  {"title": "C", "price": 15}
        \\]}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.books[?(@.price > 12)].title");
    defer result.deinit();

    try testing.expectEqual(@as(usize, 2), result.count());
}

test "JsonPathResult.iterator iterates all results" {
    const json_str =
        \\{"items": ["one", "two", "three"]}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$.items[*]");
    defer result.deinit();

    var iter = result.iterator();
    var count: usize = 0;
    while (iter.next()) |_| {
        count += 1;
    }

    try testing.expectEqual(@as(usize, 3), count);
}

test "JsonPathResult.iterator returns values in order" {
    const json_str =
        \\["alpha", "beta", "gamma"]
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const result = try doc.query("$[*]");
    defer result.deinit();

    var iter = result.iterator();
    try testing.expectEqualStrings("alpha", iter.next().?);
    try testing.expectEqualStrings("beta", iter.next().?);
    try testing.expectEqualStrings("gamma", iter.next().?);
    try testing.expect(iter.next() == null);
}

test "JsonDoc.query with Datadog log format" {
    const json_str =
        \\[
        \\  {
        \\    "ddsource": "nginx",
        \\    "ddtags": "env:staging,version:5.1",
        \\    "hostname": "i-012345678",
        \\    "message": "2019-11-19T14:37:58,995 INFO Hello",
        \\    "service": "payment"
        \\  },
        \\  {
        \\    "ddsource": "apache",
        \\    "ddtags": "env:production",
        \\    "hostname": "i-987654321",
        \\    "message": "2019-11-19T14:37:59,000 ERROR Failure",
        \\    "service": "auth"
        \\  }
        \\]
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Extract all messages
    const messages = try doc.query("$[*].message");
    defer messages.deinit();
    try testing.expectEqual(@as(usize, 2), messages.count());

    // Extract all hostnames
    const hostnames = try doc.query("$[*].hostname");
    defer hostnames.deinit();
    try testing.expectEqual(@as(usize, 2), hostnames.count());
    try testing.expectEqualStrings("i-012345678", hostnames.get(0).?);
    try testing.expectEqualStrings("i-987654321", hostnames.get(1).?);

    // Filter by service
    const payment_msgs = try doc.query("$[?(@.service == 'payment')].message");
    defer payment_msgs.deinit();
    try testing.expectEqual(@as(usize, 1), payment_msgs.count());
}
