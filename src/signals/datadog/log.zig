const std = @import("std");
const zimdjson = @import("zimdjson");

pub const Parser = zimdjson.ondemand.FullParser(.default);
pub const Value = Parser.Value;
pub const AnyValue = Parser.AnyValue;

/// Datadog log schema for parsing and serialization
/// Uses zimdjson ondemand parser for efficient deserialization
pub const DatadogLog = struct {
    message: ?[]const u8 = null,
    status: ?[]const u8 = null,
    level: ?[]const u8 = null,
    service: ?[]const u8 = null,
    hostname: ?[]const u8 = null,
    ddsource: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    timestamp: ?i64 = null,
    environment: ?[]const u8 = null,
    custom_field: ?[]const u8 = null,

    extra: std.StringHashMapUnmanaged(AnyValue) = .empty,
    extra_raw_json: std.StringHashMapUnmanaged([]const u8) = .empty,

    /// Lazily-computed unwrapping of a JSON-stringified `message`/`msg`/`log`
    /// field (e.g. logs forwarded from GCP/Cloud Run, where the real payload
    /// is escaped inside `message`). On the first matcher miss the wrapped
    /// JSON is parsed once with zimdjson, its string leaves flattened into a
    /// dotted-key map, and the nested body recorded; both are reused for every
    /// subsequent lookup. Values are copied out, so the transient parser owns
    /// nothing that outlives it.
    message_flat: std.StringHashMapUnmanaged([]const u8) = .empty,
    message_unwrapped: bool = false,

    /// Mutable, re-serializable view of a JSON-wrapped `message`, built lazily
    /// only when a transform targets a field *inside* the wrapper. Edits go to
    /// `message_tree`; `message_rewrapped` holds the re-serialized result that
    /// `jsonStringify` emits in place of the original `message`.
    message_tree: ?std.json.Parsed(std.json.Value) = null,
    message_tree_tried: bool = false,
    message_dirty: bool = false,
    message_rewrapped: ?[]const u8 = null,

    /// Free extra field keys allocated during parsing
    pub fn deinit(self: *DatadogLog, allocator: std.mem.Allocator) void {
        var it = self.extra.keyIterator();
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        self.extra.deinit(allocator);

        var raw_it = self.extra_raw_json.valueIterator();
        while (raw_it.next()) |raw| {
            allocator.free(raw.*);
        }
        self.extra_raw_json.deinit(allocator);
        var flat_it = self.message_flat.iterator();
        while (flat_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.message_flat.deinit(allocator);
        if (self.message_tree) |*tree| tree.deinit();
        if (self.message_rewrapped) |s| allocator.free(s);
        self.* = undefined;
    }

    /// Parse a DatadogLog from a zimdjson Value (object)
    pub fn parse(allocator: std.mem.Allocator, value: Value) !DatadogLog {
        var log: DatadogLog = .{};
        errdefer log.deinit(allocator);

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "message")) {
                log.message = try field.value.asString();
            } else if (std.mem.eql(u8, key, "status")) {
                log.status = try field.value.asString();
            } else if (std.mem.eql(u8, key, "level")) {
                log.level = try field.value.asString();
            } else if (std.mem.eql(u8, key, "service")) {
                log.service = try field.value.asString();
            } else if (std.mem.eql(u8, key, "hostname")) {
                log.hostname = try field.value.asString();
            } else if (std.mem.eql(u8, key, "ddsource")) {
                log.ddsource = try field.value.asString();
            } else if (std.mem.eql(u8, key, "ddtags")) {
                log.ddtags = try field.value.asString();
            } else if (std.mem.eql(u8, key, "timestamp")) {
                log.timestamp = try field.value.asSigned();
            } else if (std.mem.eql(u8, key, "environment")) {
                log.environment = try field.value.asString();
            } else if (std.mem.eql(u8, key, "custom_field")) {
                log.custom_field = try field.value.asString();
            } else {
                // Store unknown fields in extra map - need to dupe the key since it's from the parser buffer.
                const key_copy = try allocator.dupe(u8, key);
                const any = try field.value.asAny();
                try log.extra.put(allocator, key_copy, any);
                switch (any) {
                    .object, .array => {
                        const raw_json = try stringifyAnyValue(allocator, any);
                        try log.extra_raw_json.put(allocator, key_copy, raw_json);
                    },
                    else => {},
                }
            }
        }

        return log;
    }

    /// Custom JSON serialization for known fields only.
    /// Note: Extra fields are serialized via AnyValue while parser data is alive.
    pub fn jsonStringify(self: *const DatadogLog, jws: *std.json.Stringify) !void {
        try jws.beginObject();

        // Prefer the re-serialized wrapper when a transform edited inside it.
        if (self.message_rewrapped orelse self.message) |v| {
            try jws.objectField("message");
            try jws.write(v);
        }
        if (self.status) |v| {
            try jws.objectField("status");
            try jws.write(v);
        }
        if (self.level) |v| {
            try jws.objectField("level");
            try jws.write(v);
        }
        if (self.service) |v| {
            try jws.objectField("service");
            try jws.write(v);
        }
        if (self.hostname) |v| {
            try jws.objectField("hostname");
            try jws.write(v);
        }
        if (self.ddsource) |v| {
            try jws.objectField("ddsource");
            try jws.write(v);
        }
        if (self.ddtags) |v| {
            try jws.objectField("ddtags");
            try jws.write(v);
        }
        if (self.timestamp) |v| {
            try jws.objectField("timestamp");
            try jws.write(v);
        }
        if (self.environment) |v| {
            try jws.objectField("environment");
            try jws.write(v);
        }
        if (self.custom_field) |v| {
            try jws.objectField("custom_field");
            try jws.write(v);
        }
        // Write extra fields
        var it = self.extra.iterator();
        while (it.next()) |entry| {
            try jws.objectField(entry.key_ptr.*);
            if (self.extra_raw_json.get(entry.key_ptr.*)) |raw_json| {
                try jws.beginWriteRaw();
                try jws.writer.writeAll(raw_json);
                jws.endWriteRaw();
            } else {
                try writeAnyValue(jws, entry.value_ptr.*);
            }
        }

        try jws.endObject();
    }

    /// Look up a string extra field value by single or dotted multi-segment path.
    pub fn findExtraString(
        self: *const DatadogLog,
        allocator: std.mem.Allocator,
        path: []const []const u8,
    ) ?[]const u8 {
        if (path.len == 0) return null;

        if (self.extra.get(path[0])) |value| {
            if (path.len == 1) {
                if (value == .string) return value.string.get() catch null;
                return null;
            }
        }

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
            if (self.extra.get(buf[0..pos])) |value| {
                if (value == .string) return value.string.get() catch null;
            }
            if (self.extra_raw_json.get(path[0])) |raw_json| {
                return findNestedStringInRaw(allocator, raw_json, path[1..]);
            }
        }

        return null;
    }

    /// When the outer `message`/`msg`/`log` field is itself a JSON document,
    /// the real log body lives under `data.jsonPayload` at one of these keys
    /// (GCP/Cloud Run -> Datadog shape).
    const inner_body_paths = [_][]const u8{
        "data.jsonPayload.message",
        "data.jsonPayload.body",
        "data.jsonPayload.log",
    };

    /// Return the raw (still-stringified) wrapped log, looking at `message`
    /// first, then `msg`/`log` extras.
    fn wrappedMessageRaw(self: *const DatadogLog) ?[]const u8 {
        if (self.message) |m| return m;
        if (self.extra.get("msg")) |v| {
            if (v == .string) return v.string.get() catch null;
        }
        if (self.extra.get("log")) |v| {
            if (v == .string) return v.string.get() catch null;
        }
        return null;
    }

    /// Lazily unwrap the wrapped `message`/`msg`/`log` field once: parse it
    /// with zimdjson and flatten its string leaves into `message_flat` (dotted
    /// keys), so both body and attribute lookups become map hits. No-op when
    /// the field is absent or not a JSON object. Values are copied into
    /// `allocator`, so the transient parser is freed immediately.
    fn ensureUnwrapped(self: *DatadogLog, allocator: std.mem.Allocator) void {
        if (self.message_unwrapped) return;
        self.message_unwrapped = true;

        const raw = self.wrappedMessageRaw() orelse return;
        // Fast path: only attempt a parse when the value looks like a JSON
        // object, so plain-text messages bail without invoking the parser.
        const head = std.mem.trimStart(u8, raw, " \t\r\n");
        if (head.len == 0 or head[0] != '{') return;

        var parser: Parser = .init;
        defer parser.deinit(allocator);
        const doc = parser.parseFromSlice(allocator, raw) catch return;

        var prefix: std.ArrayList(u8) = .empty;
        defer prefix.deinit(allocator);
        // Best-effort: an OOM mid-flatten just yields fewer leaves (fail-open
        // matching), consistent with the rest of this accessor.
        self.flattenValue(allocator, &prefix, doc.asValue().asAny() catch return) catch return;
    }

    /// Recursively flatten a parsed value, recording every string leaf under
    /// its dotted path (pre-order; first leaf wins on a key collision).
    fn flattenValue(
        self: *DatadogLog,
        allocator: std.mem.Allocator,
        prefix: *std.ArrayList(u8),
        any: AnyValue,
    ) !void {
        switch (any) {
            .string => |v| {
                const s = v.get() catch return;
                if (prefix.items.len == 0) return;
                // First leaf wins on a dotted-key collision (e.g. sibling
                // string array elements, which don't extend the path).
                if (self.message_flat.contains(prefix.items)) return;
                const key = try allocator.dupe(u8, prefix.items);
                errdefer allocator.free(key);
                const value = try allocator.dupe(u8, s);
                try self.message_flat.put(allocator, key, value);
            },
            .object => |obj| {
                var it = obj.iterator();
                while (it.next() catch null) |field| {
                    const key = field.key.get() catch continue;
                    const base = prefix.items.len;
                    if (base != 0) try prefix.append(allocator, '.');
                    try prefix.appendSlice(allocator, key);
                    try self.flattenValue(allocator, prefix, field.value.asAny() catch {
                        prefix.shrinkRetainingCapacity(base);
                        continue;
                    });
                    prefix.shrinkRetainingCapacity(base);
                }
            },
            .array => |arr| {
                // Arrays don't extend the dotted attribute path, but a body
                // can still be nested inside one.
                var it = arr.iterator();
                while (it.next() catch null) |item| {
                    try self.flattenValue(allocator, prefix, item.asAny() catch continue);
                }
            },
            else => {},
        }
    }

    /// Body value for matching. When the message is a JSON-wrapped log, the
    /// real body lives at `data.jsonPayload.{message|body|log}`; return that.
    /// Otherwise return the raw message verbatim.
    /// note: targets the GCP/Cloud Run `data.jsonPayload` shape only; other
    /// wrappers fall through to the raw message.
    pub fn bodyForMatch(self: *DatadogLog, allocator: std.mem.Allocator) ?[]const u8 {
        // Honor `msg`/`log` wrappers too, not just top-level `message` —
        // otherwise body filters silently miss logs wrapped in those extras.
        const raw = self.wrappedMessageRaw() orelse return null;
        self.ensureUnwrapped(allocator);
        if (self.message_flat.count() != 0) {
            for (inner_body_paths) |path| {
                if (self.message_flat.get(path)) |body| return body;
            }
        }
        return raw;
    }

    /// Attribute fallback: look up `path` (joined with '.') inside the
    /// unwrapped JSON message. Returns null when the message is not JSON or
    /// the path is absent.
    pub fn unwrappedAttribute(
        self: *DatadogLog,
        allocator: std.mem.Allocator,
        path: []const []const u8,
    ) ?[]const u8 {
        if (path.len == 0) return null;
        self.ensureUnwrapped(allocator);
        if (self.message_flat.count() == 0) return null;

        var buf: [512]u8 = undefined;
        var pos: usize = 0;
        for (path, 0..) |segment, i| {
            if (i != 0) {
                if (pos >= buf.len) return null;
                buf[pos] = '.';
                pos += 1;
            }
            if (pos + segment.len > buf.len) return null;
            @memcpy(buf[pos .. pos + segment.len], segment);
            pos += segment.len;
        }
        return self.message_flat.get(buf[0..pos]);
    }

    /// Lazily parse `message` into a mutable, re-serializable JSON tree for
    /// in-place edits. Cached. Only the `message` field is rewritable here
    /// (the common GCP/Cloud Run wrapper); `msg`/`log` wrappers stay read-only.
    fn ensureMessageTree(self: *DatadogLog, allocator: std.mem.Allocator) ?*std.json.Value {
        if (!self.message_tree_tried) {
            self.message_tree_tried = true;
            const raw = self.message orelse return null;
            const head = std.mem.trimStart(u8, raw, " \t\r\n");
            if (head.len == 0 or head[0] != '{') return null;
            self.message_tree = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch null;
        }
        return if (self.message_tree) |*parsed| &parsed.value else null;
    }

    /// Re-serialize the edited message tree into `message_rewrapped` (owned)
    /// once, if any wrapper edit is pending. Called after all transforms run,
    /// so a log with N edits is serialized once rather than per edit.
    pub fn finalizeWrapped(self: *DatadogLog, allocator: std.mem.Allocator) void {
        if (!self.message_dirty) return;
        self.message_dirty = false;
        const tree = if (self.message_tree) |*p| p.value else return;
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        std.json.Stringify.value(tree, .{}, &out.writer) catch return;
        const serialized = out.toOwnedSlice() catch return;
        if (self.message_rewrapped) |old| allocator.free(old);
        self.message_rewrapped = serialized;
    }

    /// Walk to the parent object of `path` (all but the last segment).
    fn navigateParent(root: *std.json.Value, path: []const []const u8) ?*std.json.Value {
        var current = root;
        for (path[0 .. path.len - 1]) |segment| {
            switch (current.*) {
                .object => |*obj| current = obj.getPtr(segment) orelse return null,
                else => return null,
            }
        }
        return current;
    }

    /// Replace an existing leaf inside the wrapped message with a string value
    /// and re-serialize. Returns true iff the leaf existed (redact/set).
    pub fn setWrapped(
        self: *DatadogLog,
        allocator: std.mem.Allocator,
        path: []const []const u8,
        value: []const u8,
    ) bool {
        if (path.len == 0) return false;
        const root = self.ensureMessageTree(allocator) orelse return false;
        const parent = navigateParent(root, path) orelse return false;
        switch (parent.*) {
            .object => |*obj| {
                const entry = obj.getPtr(path[path.len - 1]) orelse return false;
                // Owned by the tree's arena so it survives until tree.deinit().
                const dup = self.message_tree.?.arena.allocator().dupe(u8, value) catch return false;
                entry.* = .{ .string = dup };
                self.message_dirty = true;
                return true;
            },
            else => return false,
        }
    }

    /// Remove an existing leaf from the wrapped message and re-serialize.
    /// Returns true iff the leaf existed (remove).
    pub fn deleteWrapped(
        self: *DatadogLog,
        allocator: std.mem.Allocator,
        path: []const []const u8,
    ) bool {
        if (path.len == 0) return false;
        const root = self.ensureMessageTree(allocator) orelse return false;
        const parent = navigateParent(root, path) orelse return false;
        switch (parent.*) {
            .object => |*obj| {
                if (!obj.orderedRemove(path[path.len - 1])) return false;
                self.message_dirty = true;
                return true;
            },
            else => return false,
        }
    }

    /// Drop every cache derived from the previous `message` (e.g. when the
    /// whole body is replaced). Resets both the write side (rewrite/tree) and
    /// the read side (flat/unwrapped) so the next access re-derives from the
    /// new `message`; otherwise a later wrapped edit would serialize the stale
    /// tree (overwriting the new body) and reads would return stale leaves.
    pub fn clearWrappedRewrite(self: *DatadogLog, allocator: std.mem.Allocator) void {
        if (self.message_rewrapped) |s| allocator.free(s);
        self.message_rewrapped = null;
        self.message_dirty = false;

        if (self.message_tree) |*tree| tree.deinit();
        self.message_tree = null;
        self.message_tree_tried = false;

        var flat_it = self.message_flat.iterator();
        while (flat_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            allocator.free(entry.value_ptr.*);
        }
        self.message_flat.deinit(allocator);
        self.message_flat = .empty;
        self.message_unwrapped = false;
    }

    fn findNestedStringInRaw(
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
            .string => |s| s,
            else => null,
        };
    }

    fn stringifyAnyValue(allocator: std.mem.Allocator, value: AnyValue) ![]u8 {
        var out: std.Io.Writer.Allocating = .init(allocator);
        errdefer out.deinit();
        var jws: std.json.Stringify = .{
            .writer = &out.writer,
            .options = .{},
        };
        try writeAnyValue(&jws, value);
        return out.toOwnedSlice();
    }

    /// Write a zimdjson AnyValue to a JSON writer
    fn writeAnyValue(jws: anytype, value: AnyValue) !void {
        switch (value) {
            .null => try jws.write(null),
            .bool => |v| try jws.write(v),
            .number => |n| switch (n) {
                .unsigned => |v| try jws.write(v),
                .signed => |v| try jws.write(v),
                .double => |v| try jws.write(v),
            },
            .string => |v| try jws.write(v.get() catch ""),
            .array => |arr| {
                try jws.beginArray();
                var arr_it = arr.iterator();
                while (arr_it.next() catch null) |item| {
                    try writeAnyValue(jws, item.asAny() catch continue);
                }
                try jws.endArray();
            },
            .object => |obj| {
                try jws.beginObject();
                var obj_it = obj.iterator();
                while (obj_it.next() catch null) |field| {
                    try jws.objectField(field.key.get() catch continue);
                    try writeAnyValue(jws, field.value.asAny() catch continue);
                }
                try jws.endObject();
            },
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "DatadogLog - parse basic fields" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test message", "status": "info", "service": "my-service"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqualStrings("test message", log.message.?);
    try std.testing.expectEqualStrings("info", log.status.?);
    try std.testing.expectEqualStrings("my-service", log.service.?);
    try std.testing.expect(log.level == null);
    try std.testing.expect(log.hostname == null);
}

test "DatadogLog - parse all known fields" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        "{\"message\": \"log body\", \"status\": \"error\", \"level\": \"ERROR\", " ++
        "\"service\": \"api\", \"hostname\": \"host1\", \"ddsource\": \"nginx\", " ++
        "\"ddtags\": \"env:prod\", \"timestamp\": 1703001234, " ++
        "\"environment\": \"production\", \"custom_field\": \"custom_value\"}";

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqualStrings("log body", log.message.?);
    try std.testing.expectEqualStrings("error", log.status.?);
    try std.testing.expectEqualStrings("ERROR", log.level.?);
    try std.testing.expectEqualStrings("api", log.service.?);
    try std.testing.expectEqualStrings("host1", log.hostname.?);
    try std.testing.expectEqualStrings("nginx", log.ddsource.?);
    try std.testing.expectEqualStrings("env:prod", log.ddtags.?);
    try std.testing.expectEqual(@as(i64, 1703001234), log.timestamp.?);
    try std.testing.expectEqualStrings("production", log.environment.?);
    try std.testing.expectEqualStrings("custom_value", log.custom_field.?);
}

test "DatadogLog - parse with extra fields" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "unknown_field": "value", "another_extra": 123}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    try std.testing.expectEqualStrings("test", log.message.?);
    try std.testing.expectEqual(@as(usize, 2), log.extra.count());
    try std.testing.expect(log.extra.contains("unknown_field"));
    try std.testing.expect(log.extra.contains("another_extra"));
}

test "DatadogLog - parse empty object" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json = "{}";

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expect(log.message == null);
    try std.testing.expect(log.status == null);
    try std.testing.expect(log.service == null);
    try std.testing.expect(log.timestamp == null);
    try std.testing.expectEqual(@as(usize, 0), log.extra.count());
}

test "DatadogLog - jsonStringify basic fields" {
    const allocator = std.testing.allocator;

    const log: DatadogLog = .{
        .message = "test message",
        .status = "info",
        .service = "my-service",
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    const output = out.written();

    // Verify JSON structure
    try std.testing.expect(std.mem.indexOf(u8, output, "\"message\":\"test message\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"status\":\"info\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"service\":\"my-service\"") != null);

    // Fields that are null should not appear
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"hostname\"") == null);
}

test "DatadogLog - jsonStringify all fields" {
    const allocator = std.testing.allocator;

    const log: DatadogLog = .{
        .message = "body",
        .status = "error",
        .level = "ERROR",
        .service = "api",
        .hostname = "host1",
        .ddsource = "nginx",
        .ddtags = "env:prod",
        .timestamp = 1703001234,
        .environment = "production",
        .custom_field = "custom",
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"message\":\"body\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"status\":\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"ERROR\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"service\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"hostname\":\"host1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ddsource\":\"nginx\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ddtags\":\"env:prod\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"timestamp\":1703001234") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"environment\":\"production\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"custom_field\":\"custom\"") != null);
}

test "DatadogLog - jsonStringify empty log" {
    const allocator = std.testing.allocator;

    const log: DatadogLog = .{};

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    try std.testing.expectEqualStrings("{}", out.written());
}

test "DatadogLog - jsonStringify with timestamp" {
    const allocator = std.testing.allocator;

    const log: DatadogLog = .{
        .timestamp = 1703001234567,
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    try std.testing.expectEqualStrings("{\"timestamp\":1703001234567}", out.written());
}

test "DatadogLog - field mutation remove message" {
    var log: DatadogLog = .{
        .message = "test message",
        .status = "info",
    };

    // Remove message
    log.message = null;

    try std.testing.expect(log.message == null);
    try std.testing.expectEqualStrings("info", log.status.?);
}

test "DatadogLog - field mutation set message" {
    var log: DatadogLog = .{
        .message = "original",
    };

    // Set new message
    log.message = "modified";

    try std.testing.expectEqualStrings("modified", log.message.?);
}

test "DatadogLog - field mutation remove all fields" {
    var log: DatadogLog = .{
        .message = "body",
        .status = "error",
        .level = "ERROR",
        .service = "api",
        .hostname = "host1",
        .ddsource = "nginx",
        .ddtags = "env:prod",
        .timestamp = 1703001234,
        .environment = "production",
        .custom_field = "custom",
    };

    // Remove all fields
    log.message = null;
    log.status = null;
    log.level = null;
    log.service = null;
    log.hostname = null;
    log.ddsource = null;
    log.ddtags = null;
    log.timestamp = null;
    log.environment = null;
    log.custom_field = null;

    try std.testing.expect(log.message == null);
    try std.testing.expect(log.status == null);
    try std.testing.expect(log.level == null);
    try std.testing.expect(log.service == null);
    try std.testing.expect(log.hostname == null);
    try std.testing.expect(log.ddsource == null);
    try std.testing.expect(log.ddtags == null);
    try std.testing.expect(log.timestamp == null);
    try std.testing.expect(log.environment == null);
    try std.testing.expect(log.custom_field == null);
}

test "DatadogLog - parse and reserialize preserves data" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "status": "info", "service": "api"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    // Serialize back
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    const output = out.written();

    // Verify all fields preserved
    try std.testing.expect(std.mem.indexOf(u8, output, "\"message\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"status\":\"info\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"service\":\"api\"") != null);
}

test "DatadogLog - parse mutate and reserialize" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "status": "info", "service": "api"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());

    // Mutate - remove service
    log.service = null;

    // Serialize back
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    const output = out.written();

    // Verify mutation
    try std.testing.expect(std.mem.indexOf(u8, output, "\"message\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"status\":\"info\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"service\"") == null);
}

test "DatadogLog - bodyForMatch unwraps msg/log wrappers, not just message" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // Body wrapped in `msg` with no top-level `message`. Regression: bodyForMatch
    // used to bail on `self.message == null` and never consult the unwrapped flat.
    const json =
        \\{"msg": "{\"data\":{\"jsonPayload\":{\"message\":\"hello-body\"}}}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const body = log.bodyForMatch(allocator);
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("hello-body", body.?);
}

test "DatadogLog - clearWrappedRewrite drops stale message tree" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // `message` is a JSON-wrapped object keyed `old`.
    const json =
        \\{"message": "{\"old\":\"alice\"}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    // Warm the wrapper tree by editing the original message.
    try std.testing.expect(log.setWrapped(allocator, &.{"old"}, "redacted-1"));

    // A later transform replaces the whole body with a differently-shaped
    // wrapper (key `new`); the stale `old` tree must be dropped.
    log.message = "{\"new\":\"bob\"}";
    log.clearWrappedRewrite(allocator);

    // Editing `new` must operate on the NEW message. Without the reset,
    // ensureMessageTree returns the stale `old` tree, which has no `new` key —
    // so the edit silently no-ops (returns false) and the redact is lost.
    try std.testing.expect(log.setWrapped(allocator, &.{"new"}, "redacted-2"));
    log.finalizeWrapped(allocator);

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "redacted-2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "bob") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "redacted-1") == null);
}

test "DatadogLog - special characters in strings" {
    const allocator = std.testing.allocator;

    const log_out: DatadogLog = .{
        .message = "line1\nline2\ttab\"quote\\backslash",
        .service = "service-with-dash",
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log_out, .{}, &out.writer);

    // Parse the output to verify it's valid JSON
    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const doc = try parser.parseFromSlice(allocator, out.written());
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqualStrings("line1\nline2\ttab\"quote\\backslash", log.message.?);
    try std.testing.expectEqualStrings("service-with-dash", log.service.?);
}

test "DatadogLog - unicode in strings" {
    const allocator = std.testing.allocator;

    const log_out: DatadogLog = .{
        .message = "Hello 世界 🌍",
        .service = "サービス",
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log_out, .{}, &out.writer);

    // Parse the output to verify it's valid JSON
    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const doc = try parser.parseFromSlice(allocator, out.written());
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqualStrings("Hello 世界 🌍", log.message.?);
    try std.testing.expectEqualStrings("サービス", log.service.?);
}

test "DatadogLog - negative timestamp" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"timestamp": -1000}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqual(@as(i64, -1000), log.timestamp.?);
}

test "DatadogLog - large timestamp" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // Timestamp in nanoseconds (common for some logging systems)
    const json =
        \\{"timestamp": 1703001234567890123}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const log = try DatadogLog.parse(allocator, doc.asValue());

    try std.testing.expectEqual(@as(i64, 1703001234567890123), log.timestamp.?);
}
