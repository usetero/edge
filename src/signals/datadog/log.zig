const std = @import("std");
const zimdjson = @import("zimdjson");
const jscan = @import("../json_scan.zig");

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

    /// Unknown fields captured by `parseRaw` as verbatim spans of the input
    /// record — key and value both borrow the record bytes, so nothing here
    /// is owned. String
    /// values keep their quotes/escapes; `findExtraString` unescapes lazily
    /// only when a policy actually reads the field. Mutually exclusive with
    /// `extra`/`extra_raw_json` (which the materializing `parse` fills).
    extra_spans: std.StringHashMapUnmanaged([]const u8) = .empty,

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
        self.extra_spans.deinit(allocator); // contents are borrowed
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

    /// Single-pass zero-copy parse for the per-record eval path — no zimdjson
    /// involved. The FieldWalker scans the record once, validating structure
    /// as it goes: known string fields borrow slices of `raw` directly when
    /// they contain no escapes (the overwhelmingly common case), and unknown
    /// fields are captured verbatim into `extra_spans` — never materialized,
    /// never duped; string extras are unescaped lazily on first policy read.
    ///
    /// `raw` must outlive the returned log. Anything the walker doesn't like
    /// (structural surprises, escaped keys, malformed scalar tokens, trailing
    /// bytes) errors out; callers retry with the zimdjson-validated
    /// materializing `parse`, so semantics never depend on this path.
    pub fn parseRaw(allocator: std.mem.Allocator, raw: []const u8) !DatadogLog {
        var log: DatadogLog = .{};
        errdefer log.deinit(allocator);

        var walker = try jscan.FieldWalker.init(raw);
        while (try walker.nextField()) |field| {
            // Escaped keys are ~nonexistent in log records; the fallback
            // parse handles them rather than paying an unescape here.
            if (std.mem.findScalar(u8, field.key, '\\') != null) return error.Malformed;
            const key = field.key;

            if (std.mem.eql(u8, key, "message")) {
                log.message = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "status")) {
                log.status = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "level")) {
                log.level = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "service")) {
                log.service = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "hostname")) {
                log.hostname = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "ddsource")) {
                log.ddsource = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "ddtags")) {
                log.ddtags = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "timestamp")) {
                log.timestamp = std.fmt.parseInt(i64, field.value, 10) catch return error.Malformed;
            } else if (std.mem.eql(u8, key, "environment")) {
                log.environment = try jscan.stringSpan(allocator, field.value);
            } else if (std.mem.eql(u8, key, "custom_field")) {
                log.custom_field = try jscan.stringSpan(allocator, field.value);
            } else {
                if (!jscan.validValueSpan(field.value)) return error.Malformed;
                try log.extra_spans.put(allocator, key, field.value);
            }
        }
        try walker.finish();

        return log;
    }

    /// Unescaped view of a raw span holding a JSON string, or null for
    /// non-strings. Escape-free strings are borrowed; escaped ones are
    /// unescaped into `allocator` (lazy — only fields a policy reads pay it).
    fn spanString(allocator: std.mem.Allocator, span: []const u8) ?[]const u8 {
        return jscan.stringSpan(allocator, span) catch null;
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
        // parseRaw extras: verbatim spans of the input, all value types.
        var span_it = self.extra_spans.iterator();
        while (span_it.next()) |entry| {
            try jws.objectField(entry.key_ptr.*);
            try jws.beginWriteRaw();
            try jws.writer.writeAll(entry.value_ptr.*);
            jws.endWriteRaw();
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
        if (self.extra_spans.get(path[0])) |span| {
            if (path.len == 1) return spanString(allocator, span);
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
            if (self.extra_spans.get(buf[0..pos])) |span| {
                if (spanString(allocator, span)) |s| return s;
            }
            if (self.extra_raw_json.get(path[0])) |raw_json| {
                return findNestedStringInRaw(allocator, raw_json, path[1..]);
            }
            if (self.extra_spans.get(path[0])) |span| {
                if (span.len > 0 and (span[0] == '{' or span[0] == '[')) {
                    return findNestedStringInRaw(allocator, span, path[1..]);
                }
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
    /// first, then `msg`/`log` extras. `allocator` backs the lazy unescape of
    /// span-captured extras (a stringified-JSON wrapper always has escapes).
    fn wrappedMessageRaw(self: *const DatadogLog, allocator: std.mem.Allocator) ?[]const u8 {
        if (self.message) |m| return m;
        for ([_][]const u8{ "msg", "log" }) |key| {
            if (self.extra.get(key)) |v| {
                if (v == .string) return v.string.get() catch null;
            }
            if (self.extra_spans.get(key)) |span| {
                if (spanString(allocator, span)) |s| return s;
            }
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

        const raw = self.wrappedMessageRaw(allocator) orelse return;
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
        const raw = self.wrappedMessageRaw(allocator) orelse return null;
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
            // std.json.Value strings live in the parsed arena, which the
            // deinit above frees — copy out or the caller reads freed memory.
            .string => |s| allocator.dupe(u8, s) catch null,
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

test "DatadogLog - parseRaw borrows known fields and captures extras as spans" {
    const allocator = std.testing.allocator;

    const json =
        \\{ "message": "hello world", "status": "info", "timestamp": 1733946000000,
        \\  "trace_id": "abc-123", "count": 42, "ratio": 1e5, "ok": true,
        \\  "http": {"method": "GET", "codes": [200, 204]} }
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);

    try std.testing.expectEqualStrings("hello world", log.message.?);
    try std.testing.expectEqualStrings("info", log.status.?);
    try std.testing.expectEqual(@as(i64, 1733946000000), log.timestamp.?);
    // Borrowed, not copied: the slices point into the input record.
    try std.testing.expect(@intFromPtr(log.message.?.ptr) >= @intFromPtr(json.ptr));
    try std.testing.expect(@intFromPtr(log.message.?.ptr) < @intFromPtr(json.ptr) + json.len);

    // Extras are verbatim spans of all value types, formatting preserved.
    try std.testing.expectEqual(@as(usize, 5), log.extra_spans.count());
    try std.testing.expectEqualStrings("\"abc-123\"", log.extra_spans.get("trace_id").?);
    try std.testing.expectEqualStrings("42", log.extra_spans.get("count").?);
    try std.testing.expectEqualStrings("1e5", log.extra_spans.get("ratio").?);
    try std.testing.expectEqualStrings("true", log.extra_spans.get("ok").?);
    try std.testing.expectEqualStrings(
        "{\"method\": \"GET\", \"codes\": [200, 204]}",
        log.extra_spans.get("http").?,
    );
}

test "DatadogLog - parseRaw unescapes escaped strings into the allocator" {
    // Escaped values unescape via parseFromSliceLeaky: allocator must be an
    // arena, exactly like the production record arena.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"message":"line one\nline \"two\"","status":"info"}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);

    try std.testing.expectEqualStrings("line one\nline \"two\"", log.message.?);
    try std.testing.expectEqualStrings("info", log.status.?);
}

test "DatadogLog - parseRaw findExtraString unescapes span values lazily" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const json =
        \\{"message":"m","plain":"no escapes","esc":"a\tb","num":7,
        \\ "http.method":"GET","nested":{"inner":{"deep":"v"}}}
    ;
    var log = try DatadogLog.parseRaw(arena.allocator(), json);
    defer log.deinit(arena.allocator());

    const a = arena.allocator();
    try std.testing.expectEqualStrings("no escapes", log.findExtraString(a, &.{"plain"}).?);
    try std.testing.expectEqualStrings("a\tb", log.findExtraString(a, &.{"esc"}).?);
    // Non-string extras are not string-matchable, same as the AnyValue path.
    try std.testing.expect(log.findExtraString(a, &.{"num"}) == null);
    // Dotted-key join and nested raw-JSON descent both work over spans.
    try std.testing.expectEqualStrings("GET", log.findExtraString(a, &.{ "http", "method" }).?);
    try std.testing.expectEqualStrings("v", log.findExtraString(a, &.{ "nested", "inner", "deep" }).?);
}

test "DatadogLog - parseRaw jsonStringify re-emits extras verbatim" {
    const allocator = std.testing.allocator;

    const json =
        \\{"message":"m","ratio":1e5,"tags":["a","b"],"meta":{"k":"v"}}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);

    // Number formatting and container contents survive byte-for-byte.
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"ratio\":1e5") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"tags\":[\"a\",\"b\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"meta\":{\"k\":\"v\"}") != null);
}

test "DatadogLog - parseRaw unwraps msg/log span extras for bodyForMatch" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // Wrapper arrives in `log` (an unknown field), stringified with escapes.
    const json =
        \\{"status":"info","log":"{\"data\":{\"jsonPayload\":{\"message\":\"inner body\"}}}"}
    ;
    var log = try DatadogLog.parseRaw(arena.allocator(), json);
    defer log.deinit(arena.allocator());

    const body = log.bodyForMatch(arena.allocator());
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("inner body", body.?);
}

test "DatadogLog - findExtraString escaped nested string survives the transient parser" {
    // Regression (macroscope PR 214): findNestedStringInRaw returned a slice
    // into the std.json parsed arena for ESCAPED nested strings, then freed
    // it via parsed.deinit(). testing.allocator poisons freed memory, so this
    // fails loudly on the old code. The returned copy is caller-owned here
    // (the escaped-nested case dupes; production passes the record arena).
    const allocator = std.testing.allocator;

    const json =
        \\{"message":"m","nested":{"k":"a\tb"}}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);

    const value = log.findExtraString(allocator, &.{ "nested", "k" }).?;
    defer allocator.free(value);
    try std.testing.expectEqualStrings("a\tb", value);
}

test "DatadogLog - parseRaw rejects malformed scalar tokens" {
    // Regression (macroscope PR 214): the loose charset check let malformed
    // numbers through, so records the full parser rejects could be filtered
    // instead of failing open. Each must now error out of parseRaw.
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "1e+", "--1", "01", "1..2", "1.", ".5", "1e", "-" }) |bad| {
        var buf: [64]u8 = undefined;
        const json = try std.fmt.bufPrint(&buf, "{{\"message\":\"ok\",\"bad\":{s}}}", .{bad});
        try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator, json));
    }
    // Well-formed numbers still pass.
    for ([_][]const u8{ "0", "-0.5", "1e5", "1E+10", "42", "123.456e-7" }) |good| {
        var buf: [64]u8 = undefined;
        const json = try std.fmt.bufPrint(&buf, "{{\"message\":\"ok\",\"n\":{s}}}", .{good});
        var log = try DatadogLog.parseRaw(allocator, json);
        defer log.deinit(allocator);
        try std.testing.expectEqualStrings(good, log.extra_spans.get("n").?);
    }
}

test "DatadogLog - parseRaw output is byte-identical to materializing parse" {
    // Equivalence: for records both paths accept, serialization must match
    // byte-for-byte. Fixtures avoid escapes/floats/whitespace-in-containers,
    // where the old path canonicalizes and spans stay verbatim (an intended
    // difference covered elsewhere).
    const allocator = std.testing.allocator;

    const fixtures = [_][]const u8{
        // ziglint-ignore: Z024 (one record = one fixture line)
        \\{"message":"hello","status":"info","level":"warn","service":"svc","hostname":"h1","ddsource":"src","ddtags":"a:b","timestamp":1733946000000,"environment":"prod","custom_field":"cf"}
        ,
        \\{"message":"m","trace_id":"abc","count":42,"neg":-7,"ok":true,"missing":null,"usr.id":"u1"}
        ,
        \\{"message":"m","http":{"method":"GET","code":200},"tags":["a","b"],"empty":{}}
        ,
        \\{}
        ,
    };

    for (fixtures) |json| {
        var parser: Parser = .init;
        defer parser.deinit(allocator);
        const doc = try parser.parseFromSlice(allocator, json);
        var old_log = try DatadogLog.parse(allocator, doc.asValue());
        defer old_log.deinit(allocator);
        var new_log = try DatadogLog.parseRaw(allocator, json);
        defer new_log.deinit(allocator);

        var old_out: std.Io.Writer.Allocating = .init(allocator);
        defer old_out.deinit();
        try std.json.Stringify.value(old_log, .{}, &old_out.writer);
        var new_out: std.Io.Writer.Allocating = .init(allocator);
        defer new_out.deinit();
        try std.json.Stringify.value(new_log, .{}, &new_out.writer);

        try std.testing.expectEqualStrings(old_out.written(), new_out.written());
    }
}

test "DatadogLog - parseRaw decodes every escape sequence" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"message":"q\" b\\ s\/ bs\b ff\f nl\n cr\r tab\t"}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings(
        "q\" b\\ s/ bs\x08 ff\x0c nl\n cr\r tab\t",
        log.message.?,
    );
}

test "DatadogLog - parseRaw decodes unicode escapes and surrogate pairs" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // \u escapes in the input (BMP char + surrogate pair) must decode to
    // the UTF-8 forms.
    const json =
        \\{"message":"caf\u00e9 \ud83d\ude00 end"}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings("café 😀 end", log.message.?);
}

test "DatadogLog - parseRaw rejects invalid escape sequences" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const bad_records = [_][]const u8{
        // Unknown escape letter.
        \\{"message":"a\qb"}
        ,
        // Lone high surrogate.
        \\{"message":"a\uD83Db"}
        ,
        // Lone low surrogate.
        \\{"message":"a\uDE00b"}
        ,
        // Truncated \u sequence.
        \\{"message":"a\u12"}
        ,
        // Non-hex in \u sequence.
        \\{"message":"a\uZZZZb"}
        ,
    };
    for (bad_records) |json| {
        // Unescape failures propagate: the record routes to the validating
        // fallback rather than being trusted.
        try std.testing.expectError(error.InvalidEscape, DatadogLog.parseRaw(allocator, json));
    }
}

test "DatadogLog - parseRaw rejects non-string known fields (parse parity)" {
    const allocator = std.testing.allocator;

    // The materializing parse errors on all of these (asString/asSigned), so
    // parseRaw must too — the record fails open verbatim either way.
    const bad_records = [_][]const u8{
        \\{"message":42}
        ,
        \\{"service":null}
        ,
        \\{"status":true}
        ,
        \\{"message":{"nested":"object"}}
        ,
        \\{"timestamp":1.5}
        ,
        \\{"timestamp":"1733946000000"}
        ,
    };
    for (bad_records) |json| {
        try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator, json));
    }
}

test "DatadogLog - parseRaw rejects escaped keys and trailing garbage" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator,
        \\{"a\tb":1}
    ));
    try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator,
        \\{"message":"m"} trailing
    ));
    try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator,
        \\{"message":"m"}}
    ));
}

test "DatadogLog - parseRaw duplicate keys: last wins (parse parity)" {
    const allocator = std.testing.allocator;

    const json =
        \\{"status":"first","x":1,"status":"last","x":2}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings("last", log.status.?);
    try std.testing.expectEqualStrings("2", log.extra_spans.get("x").?);
}

test "DatadogLog - parseRaw empty object and empty string values" {
    const allocator = std.testing.allocator;

    var empty = try DatadogLog.parseRaw(allocator, "{}");
    defer empty.deinit(allocator);
    try std.testing.expect(empty.message == null);
    try std.testing.expectEqual(@as(usize, 0), empty.extra_spans.count());

    var log = try DatadogLog.parseRaw(allocator,
        \\{"message":"","service":"","x":""}
    );
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings("", log.message.?);
    try std.testing.expectEqualStrings("", log.service.?);
    try std.testing.expectEqualStrings("\"\"", log.extra_spans.get("x").?);
}

test "DatadogLog - parseRaw long strings exercise the bulk-scan paths" {
    // Strings longer than the 32-byte linear windows force the memchr
    // branches in stringEnd and unescape.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pad = "x" ** 100;
    // Escape-free long string: single-memchr stringEnd + borrowed slice.
    {
        const json = "{\"message\":\"" ++ pad ++ "\"}";
        var log = try DatadogLog.parseRaw(allocator, json);
        defer log.deinit(allocator);
        try std.testing.expectEqualStrings(pad, log.message.?);
    }
    // Escape past the window: memchr run, then decode, then another run.
    {
        const json = "{\"message\":\"" ++ pad ++ "\\t" ++ pad ++ "\"}";
        var log = try DatadogLog.parseRaw(allocator, json);
        defer log.deinit(allocator);
        try std.testing.expectEqualStrings(pad ++ "\t" ++ pad, log.message.?);
    }
}

test "DatadogLog - bodyForMatch prefers message over msg/log span extras" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var log = try DatadogLog.parseRaw(allocator,
        \\{"message":"outer body","msg":"shadowed","log":"also shadowed"}
    );
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings("outer body", log.bodyForMatch(allocator).?);
}

test "DatadogLog - findExtraString span misses: arrays, deep paths, non-strings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var log = try DatadogLog.parseRaw(allocator,
        \\{"message":"m","tags":["a","b"],"n":7,"http":{"code":200}}
    );
    defer log.deinit(allocator);

    // Array and number spans are not string-matchable.
    try std.testing.expect(log.findExtraString(allocator, &.{"tags"}) == null);
    try std.testing.expect(log.findExtraString(allocator, &.{"n"}) == null);
    // Descent into an array or past a leaf yields null, not garbage.
    try std.testing.expect(log.findExtraString(allocator, &.{ "tags", "0" }) == null);
    try std.testing.expect(log.findExtraString(allocator, &.{ "http", "code" }) == null);
    try std.testing.expect(log.findExtraString(allocator, &.{ "http", "missing", "deep" }) == null);
}

test "DatadogLog - parseRaw escaped known field re-escapes on serialization" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"message":"a\tb \"quoted\"","status":"info"}
    ;
    var log = try DatadogLog.parseRaw(allocator, json);
    defer log.deinit(allocator);

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);

    // Round-trip through std.json: the decoded body must survive intact.
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, allocator, out.written(), .{});
    try std.testing.expectEqualStrings("a\tb \"quoted\"", parsed.object.get("message").?.string);
}

test "DatadogLog - parseRaw rejects comma separator violations (parse parity)" {
    // Regression (macroscope PR 214): the walker used to accept a trailing
    // comma; leading and missing commas were the same hole. All three are
    // invalid JSON the full parser rejects, so they must fail open.
    const allocator = std.testing.allocator;

    const bad_records = [_][]const u8{
        // Trailing comma before '}'.
        \\{"message":"m",}
        ,
        // Comma before the first field.
        \\{,"message":"m"}
        ,
        // Missing comma between fields.
        \\{"message":"m" "status":"info"}
        ,
        // Double comma.
        \\{"message":"m",,"status":"info"}
        ,
    };
    for (bad_records) |json| {
        try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator, json));
    }

    // Whitespace around a single legitimate comma still parses.
    var log = try DatadogLog.parseRaw(allocator,
        \\{"message":"m" , "status":"info"}
    );
    defer log.deinit(allocator);
    try std.testing.expectEqualStrings("info", log.status.?);
}

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
