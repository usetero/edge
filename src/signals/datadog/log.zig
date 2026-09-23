const std = @import("std");
const jscan = @import("../json_scan.zig");
const policy = @import("policy_zig");
const extras = @import("extras.zig");
const json_value = @import("json_value.zig");

pub const Parser = json_value.Parser;
const Value = json_value.Value;
const AnyValue = json_value.AnyValue;

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

    extra: extras.Materialized = .{},

    /// Unknown fields from `parseRaw`, as slices of the record. Nothing here
    /// is owned. String values keep their quotes and escapes;
    /// `findExtraString` unescapes them only when a policy reads them.
    /// `parse` fills `extra` instead, and a log uses only one of the two.
    extra_spans: extras.Spans = .{},

    /// Lazily-computed unwrapping of a JSON-stringified `message`/`msg`/`log`
    /// field (e.g. logs forwarded from GCP/Cloud Run, where the real payload
    /// is escaped inside `message`). On the first matcher miss the wrapped
    /// JSON is parsed once with zimdjson, its string leaves flattened into a
    /// dotted-key map, and the nested body recorded; both are reused for every
    /// subsequent lookup. Values are copied out, so the transient parser owns
    /// nothing that outlives it.
    message_flat: std.StringHashMapUnmanaged([]const u8) = .empty,
    message_unwrapped: bool = false,

    /// Borrowed reused parser for `ensureUnwrapped`. zimdjson sizes its
    /// structural index to the document and keeps the buffer, so one parser
    /// per record throws that away. Null falls back to a local parser, which
    /// is what the tests do.
    unwrap_parser: ?*Parser = null,
    unwrap_parser_gpa: ?std.mem.Allocator = null,

    /// Body found by `innerBodyDirect`, owned here so the slice handed to
    /// callers outlives the parse and is released with the rest of the log —
    /// matching what a `message_flat` lookup returns.
    direct_body: ?[]const u8 = null,

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
        self.extra.deinit(allocator);
        self.extra_spans.deinit(allocator);
        self.clearWrappedRewrite(allocator);
        self.* = undefined;
    }

    /// The known top-level fields, in the order `jsonStringify` writes them.
    /// `timestamp` is the only one that is not a string.
    const known_fields = [_][]const u8{
        "message",  "status", "level",     "service",     "hostname",
        "ddsource", "ddtags", "timestamp", "environment", "custom_field",
    };

    /// Parse a DatadogLog from a zimdjson Value (object)
    pub fn parse(allocator: std.mem.Allocator, value: Value) !DatadogLog {
        var log: DatadogLog = .{};
        errdefer log.deinit(allocator);

        var obj = try value.asObject();
        var it = obj.iterator();
        fields: while (try it.next()) |field| {
            const key = try field.key.get();
            inline for (known_fields) |name| {
                if (std.mem.eql(u8, key, name)) {
                    @field(log, name) = if (comptime std.mem.eql(u8, name, "timestamp"))
                        try field.value.asSigned()
                    else
                        try field.value.asString();
                    continue :fields;
                }
            }
            try log.extra.put(allocator, key, try field.value.asAny());
        }

        return log;
    }

    /// Parse one record in a single pass, with no copy and no zimdjson. Known
    /// string fields borrow from `raw` when they have no escapes. Unknown
    /// fields go into `extra_spans` as slices of `raw`.
    ///
    /// `raw` must outlive the log. `allocator` must be an arena for the
    /// record: `deinit` frees only map storage.
    ///
    /// Input the walker does not accept returns an error. The caller then
    /// uses `parse`, so results never depend on this path.
    pub fn parseRaw(allocator: std.mem.Allocator, raw: []const u8) !DatadogLog {
        var log: DatadogLog = .{};
        errdefer log.deinit(allocator);

        var walker = try jscan.FieldWalker.init(raw);
        fields: while (try walker.nextField()) |field| {
            // Escaped keys are ~nonexistent in log records; the fallback
            // parse handles them rather than paying an unescape here.
            if (std.mem.findScalar(u8, field.key, '\\') != null) return error.Malformed;
            const key = field.key;
            inline for (known_fields) |name| {
                if (std.mem.eql(u8, key, name)) {
                    @field(log, name) = if (comptime std.mem.eql(u8, name, "timestamp"))
                        std.fmt.parseInt(i64, field.value, 10) catch return error.Malformed
                    else
                        try jscan.stringSpan(allocator, field.value);
                    continue :fields;
                }
            }
            if (!jscan.validValueSpan(field.value)) return error.Malformed;
            try log.extra_spans.put(allocator, key, field.value);
        }
        try walker.finish();

        return log;
    }

    /// Typed view of a single-segment extra, so typed matchers fire on
    /// numbers and booleans. Reads `extra` after `parse` and `extra_spans`
    /// after `parseRaw`.
    pub fn findExtraTyped(self: *const DatadogLog, allocator: std.mem.Allocator, key: []const u8) ?policy.TypedValue {
        if (self.extra.count() != 0) {
            if (self.extra.get(key)) |v| return extras.anyValueTyped(v);
        } else if (self.extra_spans.get(key)) |span| {
            return extras.spanTyped(allocator, span);
        }
        return null;
    }

    /// Write the known fields, then the extras in record order.
    pub fn jsonStringify(self: *const DatadogLog, jws: *std.json.Stringify) !void {
        comptime std.debug.assert(std.mem.eql(u8, known_fields[0], "message"));
        try jws.beginObject();

        // Prefer the re-serialized wrapper when a transform edited inside it.
        if (self.message_rewrapped orelse self.message) |v| {
            try jws.objectField("message");
            try jws.write(v);
        }
        inline for (known_fields[1..]) |name| {
            if (@field(self, name)) |v| {
                try jws.objectField(name);
                try jws.write(v);
            }
        }
        // Only the writer can fail here. Map the error to the
        // `std.json.Stringify` error set.
        self.extra.write(jws) catch return error.WriteFailed;
        // parseRaw extras: verbatim spans of the input, all value types.
        for (self.extra_spans.items()) |entry| {
            try jws.objectField(entry.key);
            try jws.beginWriteRaw();
            try jws.writer.writeAll(entry.value);
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
            if (path.len == 1) return extras.spanString(allocator, span);
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
                if (extras.spanString(allocator, span)) |s| return s;
            }
            if (self.extra.rawJson(path[0])) |raw_json| {
                return extras.findNestedStringInRaw(allocator, raw_json, path[1..]);
            }
            if (self.extra_spans.get(path[0])) |span| {
                if (span.len > 0 and (span[0] == '{' or span[0] == '[')) {
                    return extras.findNestedStringInRaw(allocator, span, path[1..]);
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

    /// The raw wrapped log: `message` first, then the `msg` or `log` extra.
    /// `allocator` holds the unescaped copy of a span extra.
    fn wrappedMessageRaw(self: *const DatadogLog, allocator: std.mem.Allocator) ?[]const u8 {
        if (self.message) |m| return m;
        for ([_][]const u8{ "msg", "log" }) |key| {
            if (self.extra.get(key)) |v| {
                if (v == .string) return v.string.get() catch null;
            }
            if (self.extra_spans.get(key)) |span| {
                if (extras.spanString(allocator, span)) |s| return s;
            }
        }
        return null;
    }

    /// Unwrap the `message`, `msg` or `log` field one time. Parse it with
    /// zimdjson and copy each string leaf into `message_flat` under its
    /// dotted path. Do nothing when the field is absent or is not a JSON
    /// object.
    pub fn ensureUnwrapped(self: *DatadogLog, allocator: std.mem.Allocator) void {
        if (self.message_unwrapped) return;
        self.message_unwrapped = true;

        const raw = self.wrappedMessageRaw(allocator) orelse return;
        // Fast path: only attempt a parse when the value looks like a JSON
        // object, so plain-text messages bail without invoking the parser.
        const head = std.mem.trimStart(u8, raw, " \t\r\n");
        if (head.len == 0 or head[0] != '{') return;

        var local: Parser = .init;
        const parser = self.unwrap_parser orelse &local;
        const parser_gpa = self.unwrap_parser_gpa orelse allocator;
        defer if (self.unwrap_parser == null) local.deinit(allocator);
        const doc = parser.parseFromSlice(parser_gpa, raw) catch return;

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

    /// Body value for matching. For a GCP/Cloud Run wrapped log, this is
    /// `data.jsonPayload.{message|body|log}`. For other input, this is the
    /// raw message.
    pub fn bodyForMatch(self: *DatadogLog, allocator: std.mem.Allocator) ?[]const u8 {
        const raw = self.wrappedMessageRaw(allocator) orelse return null;

        // The full flatten used 58% of request CPU on GCP-shaped logs. Go
        // directly to `data.jsonPayload` first. When that walk cannot decide,
        // use the flatten, so both paths give the same answer.
        if (self.innerBodyDirect(allocator, raw)) |found| return found orelse raw;

        self.ensureUnwrapped(allocator);
        if (self.message_flat.count() != 0) {
            for (inner_body_paths) |path| {
                if (self.message_flat.get(path)) |body| return body;
            }
        }
        return raw;
    }

    /// Targeted lookup of `data.jsonPayload.{message,body,log}`.
    ///
    /// Returns null when the document is not the plain GCP object shape this
    /// handles (an array anywhere on the path, a non-object, a parse failure),
    /// which means "ask the flatten instead". An inner null means the shape
    /// was understood and no body field is present.
    fn innerBodyDirect(self: *DatadogLog, allocator: std.mem.Allocator, raw: []const u8) ??[]const u8 {
        // Already flattened for an earlier lookup: reuse it, the work is done.
        if (self.message_unwrapped) return null;

        const head = std.mem.trimStart(u8, raw, " \t\r\n");
        if (head.len == 0 or head[0] != '{') return null;

        var local: Parser = .init;
        const parser = self.unwrap_parser orelse &local;
        const parser_gpa = self.unwrap_parser_gpa orelse allocator;
        defer if (self.unwrap_parser == null) local.deinit(allocator);

        const doc = parser.parseFromSlice(parser_gpa, raw) catch return null;
        const payload = doc.asValue().at("data").at("jsonPayload");
        var obj = payload.asObject() catch return null;

        // One forward pass: on-demand values cannot be revisited, so collect
        // every candidate as we go and apply `inner_body_paths` priority after.
        var hits: [inner_body_paths.len]?[]const u8 = @splat(null);
        var it = obj.iterator();
        while (it.next() catch return null) |field| {
            const key = field.key.get() catch continue;
            const slot: usize = if (std.mem.eql(u8, key, "message"))
                0
            else if (std.mem.eql(u8, key, "body"))
                1
            else if (std.mem.eql(u8, key, "log"))
                2
            else
                continue;
            // The first occurrence wins, as in `flattenValue`. The two paths
            // must agree, or a second benign `message` could bypass a body
            // policy.
            if (hits[slot] != null) continue;
            switch (field.value.asAny() catch continue) {
                .string => |v| {
                    const text = v.get() catch continue;
                    hits[slot] = allocator.dupe(u8, text) catch return null;
                },
                // This walk cannot go into an array, but the flatten can.
                // Return the outer null so `bodyForMatch` uses the flatten.
                .array => return null,
                else => {},
            }
        }
        // Priority follows `inner_body_paths`, not document order. Free the
        // losing candidates.
        var winner: ?[]const u8 = null;
        for (hits) |hit| {
            const body = hit orelse continue;
            if (winner == null) winner = body else allocator.free(body);
        }
        self.direct_body = winner;
        return winner;
    }

    /// Attribute fallback into a JSON-wrapped message. Once edited, the tree
    /// supplies live values using the same dotted paths and first-string-wins
    /// order as the original flattened snapshot.
    pub fn unwrappedAttribute(
        self: *DatadogLog,
        allocator: std.mem.Allocator,
        path: []const []const u8,
    ) ?[]const u8 {
        if (path.len == 0) return null;
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
        const dotted_path = buf[0..pos];
        if (self.message_tree) |parsed| {
            return findTreeString(parsed.value, dotted_path, 0);
        }
        self.ensureUnwrapped(allocator);
        return self.message_flat.get(dotted_path);
    }

    /// Read the tree as `flattenValue` would: arrays do not extend the path,
    /// literal dots in keys are preserved, and the first string leaf wins.
    /// Matching prefixes avoids building another map after every edit.
    fn findTreeString(value: std.json.Value, path: []const u8, prefix_len: usize) ?[]const u8 {
        switch (value) {
            .string => |s| return if (prefix_len != 0 and prefix_len == path.len) s else null,
            .object => |obj| {
                var offset = prefix_len;
                if (offset != 0) {
                    if (offset == path.len or path[offset] != '.') return null;
                    offset += 1;
                }
                var it = obj.iterator();
                while (it.next()) |entry| {
                    const key = entry.key_ptr.*;
                    if (!std.mem.startsWith(u8, path[offset..], key)) continue;
                    if (findTreeString(entry.value_ptr.*, path, offset + key.len)) |s| return s;
                }
            },
            .array => |arr| {
                for (arr.items) |item| {
                    if (findTreeString(item, path, prefix_len)) |s| return s;
                }
            },
            else => {},
        }
        return null;
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

    /// Drop every cache built from the previous `message`. Call this when the
    /// whole body changes, or later reads and edits use the old message.
    pub fn clearWrappedRewrite(self: *DatadogLog, allocator: std.mem.Allocator) void {
        if (self.message_rewrapped) |s| allocator.free(s);
        self.message_rewrapped = null;
        self.message_dirty = false;

        if (self.message_tree) |*tree| tree.deinit();
        self.message_tree = null;

        if (self.direct_body) |b| allocator.free(b);
        self.direct_body = null;
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
};
