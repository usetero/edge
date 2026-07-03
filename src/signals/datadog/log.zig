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

        var walker = try FieldWalker.init(raw);
        while (try walker.nextField()) |field| {
            // Escaped keys are ~nonexistent in log records; the fallback
            // parse handles them rather than paying an unescape here.
            if (std.mem.findScalar(u8, field.key, '\\') != null) return error.Desync;
            const key = field.key;

            if (std.mem.eql(u8, key, "message")) {
                log.message = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "status")) {
                log.status = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "level")) {
                log.level = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "service")) {
                log.service = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "hostname")) {
                log.hostname = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "ddsource")) {
                log.ddsource = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "ddtags")) {
                log.ddtags = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "timestamp")) {
                log.timestamp = std.fmt.parseInt(i64, field.value, 10) catch return error.Desync;
            } else if (std.mem.eql(u8, key, "environment")) {
                log.environment = try stringValue(allocator, field.value);
            } else if (std.mem.eql(u8, key, "custom_field")) {
                log.custom_field = try stringValue(allocator, field.value);
            } else {
                if (!validScalarOrStructureSpan(field.value)) return error.Desync;
                try log.extra_spans.put(allocator, key, field.value);
            }
        }
        try walker.finish();

        return log;
    }

    /// The unescaped string inside a raw `"..."` span: borrowed zero-copy
    /// when escape-free, unescaped into `allocator` otherwise. Errors on
    /// non-string values, matching `parse`'s asString behavior (the record
    /// falls open to the materializing path, which rejects it identically).
    fn stringValue(allocator: std.mem.Allocator, span: []const u8) ![]const u8 {
        if (span.len < 2 or span[0] != '"') return error.Desync;
        const inner = span[1 .. span.len - 1];
        if (std.mem.findScalar(u8, inner, '\\') == null) return inner;
        return unescape(allocator, inner) catch return error.Desync;
    }

    /// JSON string unescape over the bytes between the quotes, including
    /// \uXXXX surrogate pairs. Escape scanning is adaptive: a short linear
    /// window resolves escape-dense text (wrapped JSON messages are ~all
    /// `\"` every few bytes) without memchr call overhead, while sparse text
    /// bulk-skips with one memchr per long run. Output is at most inner.len
    /// bytes (every escape shrinks), so capacity is reserved once up front.
    fn unescape(allocator: std.mem.Allocator, inner: []const u8) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.ensureTotalCapacity(allocator, inner.len);

        var i: usize = 0;
        while (i < inner.len) {
            const window_end = @min(inner.len, i + 32);
            var backslash = i;
            while (backslash < window_end and inner[backslash] != '\\') backslash += 1;
            if (backslash == window_end) {
                backslash = std.mem.findScalarPos(u8, inner, window_end, '\\') orelse inner.len;
            }
            out.appendSliceAssumeCapacity(inner[i..backslash]);
            if (backslash == inner.len) break;
            if (backslash + 1 >= inner.len) return error.InvalidEscape;
            i = backslash + 2;
            switch (inner[backslash + 1]) {
                '"', '\\', '/' => |c| out.appendAssumeCapacity(c),
                'b' => out.appendAssumeCapacity(0x08),
                'f' => out.appendAssumeCapacity(0x0c),
                'n' => out.appendAssumeCapacity('\n'),
                'r' => out.appendAssumeCapacity('\r'),
                't' => out.appendAssumeCapacity('\t'),
                'u' => {
                    const first = try hex4(inner, i);
                    i += 4;
                    var codepoint: u21 = first;
                    if (first >= 0xD800 and first <= 0xDBFF) {
                        // High surrogate: a \uXXXX low surrogate must follow.
                        if (i + 6 > inner.len or inner[i] != '\\' or inner[i + 1] != 'u') {
                            return error.InvalidEscape;
                        }
                        const low = try hex4(inner, i + 2);
                        i += 6;
                        if (low < 0xDC00 or low > 0xDFFF) return error.InvalidEscape;
                        codepoint = 0x10000 +
                            ((@as(u21, first - 0xD800) << 10) | (low - 0xDC00));
                    } else if (first >= 0xDC00 and first <= 0xDFFF) {
                        return error.InvalidEscape; // lone low surrogate
                    }
                    var buf: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(codepoint, &buf) catch
                        return error.InvalidEscape;
                    out.appendSliceAssumeCapacity(buf[0..n]);
                },
                else => return error.InvalidEscape,
            }
        }
        return out.toOwnedSlice(allocator);
    }

    fn hex4(inner: []const u8, at: usize) error{InvalidEscape}!u16 {
        if (at + 4 > inner.len) return error.InvalidEscape;
        return std.fmt.parseInt(u16, inner[at .. at + 4], 16) catch error.InvalidEscape;
    }

    /// Guards extra spans against structurally-plausible garbage the walker
    /// would otherwise wave through (e.g. `tru`, `1x2`). Strings and
    /// containers were already structurally validated by the walker; scalar
    /// tokens must look like JSON literals so a record the full parser would
    /// reject can't be filtered (it fails open verbatim instead, as today).
    fn validScalarOrStructureSpan(span: []const u8) bool {
        if (span.len == 0) return false;
        return switch (span[0]) {
            '"', '{', '[' => true,
            't' => std.mem.eql(u8, span, "true"),
            'f' => std.mem.eql(u8, span, "false"),
            'n' => std.mem.eql(u8, span, "null"),
            '-', '0'...'9' => blk: {
                for (span[1..]) |byte| switch (byte) {
                    '0'...'9', 'e', 'E', '+', '-', '.' => {},
                    else => break :blk false,
                };
                break :blk true;
            },
            else => false,
        };
    }

    /// Unescaped view of a raw span holding a JSON string, or null for
    /// non-strings. Escape-free strings are borrowed; escaped ones are
    /// unescaped into `allocator` (lazy — only fields a policy reads pay it).
    fn spanString(allocator: std.mem.Allocator, span: []const u8) ?[]const u8 {
        if (span.len < 2 or span[0] != '"') return null;
        const inner = span[1 .. span.len - 1];
        if (std.mem.findScalar(u8, inner, '\\') == null) return inner;
        return unescape(allocator, inner) catch null;
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

/// Tracks raw byte offsets of `"key": value` pairs while zimdjson iterates
/// the same object, so parseFast can capture field values as verbatim spans
/// of the input record. Structure only — zimdjson stays authoritative for
/// types and validation; parseFast cross-checks every key against zimdjson's
/// and bails with error.Desync on any divergence (callers fall back to the
/// materializing parse).
const FieldWalker = struct {
    raw: []const u8,
    pos: usize = 0,

    const RawField = struct {
        /// Key bytes between the quotes, escapes intact.
        key: []const u8,
        /// Value bytes, verbatim JSON (quotes/braces included).
        value: []const u8,
    };

    fn init(raw: []const u8) error{Desync}!FieldWalker {
        var walker: FieldWalker = .{ .raw = raw };
        walker.skipWhitespace();
        if (walker.pos >= raw.len or raw[walker.pos] != '{') return error.Desync;
        walker.pos += 1;
        return walker;
    }

    fn nextField(self: *FieldWalker) error{Desync}!?RawField {
        self.skipWhitespace();
        if (self.pos < self.raw.len and self.raw[self.pos] == ',') {
            self.pos += 1;
            self.skipWhitespace();
        }
        if (self.pos >= self.raw.len) return error.Desync;
        if (self.raw[self.pos] == '}') return null;
        if (self.raw[self.pos] != '"') return error.Desync;

        const key_start = self.pos + 1;
        const key_close = self.stringEnd(self.pos) orelse return error.Desync;
        const key = self.raw[key_start .. key_close - 1];
        self.pos = key_close;

        self.skipWhitespace();
        if (self.pos >= self.raw.len or self.raw[self.pos] != ':') return error.Desync;
        self.pos += 1;
        self.skipWhitespace();

        const value_start = self.pos;
        const value_end = try self.valueEnd(value_start);
        self.pos = value_end;
        return .{ .key = key, .value = self.raw[value_start..value_end] };
    }

    fn skipWhitespace(self: *FieldWalker) void {
        while (self.pos < self.raw.len) : (self.pos += 1) {
            switch (self.raw[self.pos]) {
                ' ', '\t', '\r', '\n' => {},
                else => return,
            }
        }
    }

    /// Asserts nothing but whitespace follows the object's closing brace, so
    /// a record with trailing bytes can't be treated as parsed (the full
    /// parser would reject it; error here routes it to that path).
    fn finish(self: *FieldWalker) error{Desync}!void {
        // nextField returned null at the '}'.
        self.pos += 1;
        self.skipWhitespace();
        if (self.pos != self.raw.len) return error.Desync;
    }

    /// With `start` at an opening quote, returns the index just past the
    /// closing quote, honoring escapes. Escape-free strings (the common
    /// case) cost exactly one memchr + a parity check; the first escaped
    /// quote proves the string dense and the rest scans linearly — memchr
    /// hop overhead on `\"`-riddled wrapped messages costs more than bytes.
    fn stringEnd(self: *const FieldWalker, start: usize) ?usize {
        const quote = std.mem.findScalarPos(u8, self.raw, start + 1, '"') orelse return null;
        var first_backslash = quote;
        while (first_backslash > start + 1 and self.raw[first_backslash - 1] == '\\') {
            first_backslash -= 1;
        }
        if ((quote - first_backslash) % 2 == 0) return quote + 1;

        var i = quote + 1;
        while (i < self.raw.len) : (i += 1) {
            switch (self.raw[i]) {
                '\\' => i += 1, // skip the escaped byte
                '"' => return i + 1,
                else => {},
            }
        }
        return null;
    }

    /// Returns the index just past the JSON value starting at `start`.
    fn valueEnd(self: *const FieldWalker, start: usize) error{Desync}!usize {
        if (start >= self.raw.len) return error.Desync;
        switch (self.raw[start]) {
            '"' => return self.stringEnd(start) orelse error.Desync,
            '{', '[' => {
                var depth: u32 = 0;
                var i = start;
                while (i < self.raw.len) : (i += 1) {
                    switch (self.raw[i]) {
                        // Bulk of container bytes are string keys/values:
                        // vault over them with the vectorized scan.
                        '"' => i = (self.stringEnd(i) orelse return error.Desync) - 1,
                        '{', '[' => depth += 1,
                        '}', ']' => {
                            depth -= 1;
                            if (depth == 0) return i + 1;
                        },
                        else => {},
                    }
                }
                return error.Desync;
            },
            else => {
                // Scalar: runs to the next structural byte or whitespace.
                var i = start;
                while (i < self.raw.len) : (i += 1) {
                    switch (self.raw[i]) {
                        ',', '}', ']', ' ', '\t', '\r', '\n' => return i,
                        else => {},
                    }
                }
                // A top-level scalar can't legally end the enclosing object.
                return error.Desync;
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

test "FieldWalker - spans across whitespace, escapes, and nesting" {
    const json =
        \\ { "a" : "x\"y" , "b": [1, {"c": "}"}] , "d" :null }
    ;
    var walker = try FieldWalker.init(json);

    const a = (try walker.nextField()).?;
    try std.testing.expectEqualStrings("a", a.key);
    try std.testing.expectEqualStrings("\"x\\\"y\"", a.value);

    const b = (try walker.nextField()).?;
    try std.testing.expectEqualStrings("b", b.key);
    try std.testing.expectEqualStrings("[1, {\"c\": \"}\"}]", b.value);

    const d = (try walker.nextField()).?;
    try std.testing.expectEqualStrings("d", d.key);
    try std.testing.expectEqualStrings("null", d.value);

    try std.testing.expectEqual(@as(?FieldWalker.RawField, null), try walker.nextField());
}

test "FieldWalker - malformed input errors instead of desyncing silently" {
    try std.testing.expectError(error.Desync, FieldWalker.init("[1,2]"));

    var truncated = try FieldWalker.init("{\"a\": \"unterminated");
    try std.testing.expectError(error.Desync, truncated.nextField());

    var bad_sep = try FieldWalker.init("{\"a\" \"b\"}");
    try std.testing.expectError(error.Desync, bad_sep.nextField());
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
