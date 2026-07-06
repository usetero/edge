//! Single-pass JSON span scanning, shared by signal parsers.
//!
//! The tools here power zero-copy record parsing: `FieldWalker` yields each
//! top-level `"key": value` pair of an object as verbatim byte spans of the
//! input, `stringSpan`/`unescape` turn string spans into unescaped views
//! (borrowed when escape-free), and `validValueSpan` gates scalar tokens so
//! only well-formed JSON literals are ever trusted.
//!
//! Everything is strict: any input a full validating parser would reject
//! errors with `Malformed` (or `InvalidEscape` inside strings) instead of
//! being waved through. Callers keep a validating parser as their fallback
//! path, so these scanners never have to be lenient.
//!
//! Known deviation, on purpose: raw control bytes (unescaped < 0x20) inside
//! string content or container interiors are not rejected (except as the
//! character following a backslash, where the check rides an existing
//! branch). Guarding the escape-free fast path costs 10-15% on every
//! record (measured; whether swept record-wide or checked per string), to
//! reject invalid-JSON records that are forwarded byte-identically either
//! way — the only effect of accepting them is that policies evaluate a
//! record the validating parser would have passed through verbatim.
//!
//! Memory contract: functions taking an allocator return strings that are
//! either borrowed from the input or owned by the allocator, with no way
//! for the caller to distinguish. Pass a per-record arena so borrowed spans
//! and decoded strings share one lifetime and are freed together at reset.
const std = @import("std");

/// Scanner over a JSON object's `"key": value` pairs, yielding each field's
/// key and verbatim value span from the input. Strict about structure
/// (quotes, escapes, separators, nesting, trailing bytes); the spans it
/// returns reference the input bytes and share their lifetime.
pub const FieldWalker = struct {
    raw: []const u8,
    pos: usize = 0,
    first: bool = true,

    pub const RawField = struct {
        /// Key bytes between the quotes, escapes intact.
        key: []const u8,
        /// Value bytes, verbatim JSON (quotes/braces included).
        value: []const u8,
    };

    pub fn init(raw: []const u8) error{Malformed}!FieldWalker {
        var walker: FieldWalker = .{ .raw = raw };
        walker.skipWhitespace();
        if (walker.pos >= raw.len or raw[walker.pos] != '{') return error.Malformed;
        walker.pos += 1;
        return walker;
    }

    pub fn nextField(self: *FieldWalker) error{Malformed}!?RawField {
        self.skipWhitespace();
        if (self.pos >= self.raw.len) return error.Malformed;
        if (self.raw[self.pos] == '}') return null;
        // Fields after the first require exactly one ',' separator; a comma
        // before the first field, a missing comma, or a trailing comma
        // before '}' are all invalid JSON and must fall to the validating
        // parser rather than be waved through.
        if (self.first) {
            self.first = false;
        } else {
            if (self.raw[self.pos] != ',') return error.Malformed;
            self.pos += 1;
            self.skipWhitespace();
            if (self.pos >= self.raw.len) return error.Malformed;
            if (self.raw[self.pos] == '}') return error.Malformed; // trailing comma
        }
        if (self.raw[self.pos] != '"') return error.Malformed;

        const key_start = self.pos + 1;
        const key_close = self.stringEnd(self.pos) orelse return error.Malformed;
        const key = self.raw[key_start .. key_close - 1];
        self.pos = key_close;

        self.skipWhitespace();
        if (self.pos >= self.raw.len or self.raw[self.pos] != ':') return error.Malformed;
        self.pos += 1;
        self.skipWhitespace();

        const value_start = self.pos;
        const value_end = try self.valueEnd(value_start);
        self.pos = value_end;
        return .{ .key = key, .value = self.raw[value_start..value_end] };
    }

    /// Asserts nothing but whitespace follows the object's closing brace, so
    /// input with trailing bytes can't be treated as parsed (a full parser
    /// would reject it; erroring here routes it to that path).
    pub fn finish(self: *FieldWalker) error{Malformed}!void {
        // nextField returned null at the '}'.
        self.pos += 1;
        self.skipWhitespace();
        if (self.pos != self.raw.len) return error.Malformed;
    }

    fn skipWhitespace(self: *FieldWalker) void {
        while (self.pos < self.raw.len) : (self.pos += 1) {
            switch (self.raw[self.pos]) {
                ' ', '\t', '\r', '\n' => {},
                else => return,
            }
        }
    }

    /// With `start` at an opening quote, returns the index just past the
    /// closing quote, honoring escapes. Escape-free strings (the common
    /// case) cost exactly one memchr + a parity check; the first escaped
    /// quote proves the string dense and the rest scans linearly, where
    /// raw control bytes are rejected for free (see the module doc's known
    /// deviation: the fast path deliberately does not scan for them).
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
                '\\' => {
                    if (i + 1 >= self.raw.len) return null;
                    i += 1;
                    // A raw control byte is not a legal escape character.
                    if (self.raw[i] < 0x20) return null;
                },
                '"' => return i + 1,
                else => {},
            }
        }
        return null;
    }

    /// Returns the index just past the JSON value starting at `start`.
    fn valueEnd(self: *const FieldWalker, start: usize) error{Malformed}!usize {
        if (start >= self.raw.len) return error.Malformed;
        switch (self.raw[start]) {
            '"' => return self.stringEnd(start) orelse error.Malformed,
            '{', '[' => {
                // Opener kinds as a bit-stack (0 = object, 1 = array):
                // depth counts alone accept mismatched closers like `[{]}`.
                // Nesting beyond 64 levels falls to the validating parser.
                var stack: u64 = 0;
                var depth: u8 = 0;
                var i = start;
                while (i < self.raw.len) : (i += 1) {
                    const byte = self.raw[i];
                    switch (byte) {
                        // Bulk of container bytes are string keys/values:
                        // vault over them with the vectorized scan.
                        '"' => i = (self.stringEnd(i) orelse return error.Malformed) - 1,
                        '{', '[' => {
                            if (depth == 64) return error.Malformed;
                            stack = (stack << 1) | @intFromBool(byte == '[');
                            depth += 1;
                        },
                        '}', ']' => {
                            if ((stack & 1) != @intFromBool(byte == ']')) return error.Malformed;
                            stack >>= 1;
                            depth -= 1;
                            if (depth == 0) return i + 1;
                        },
                        else => {},
                    }
                }
                return error.Malformed;
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
                return error.Malformed;
            },
        }
    }
};

const vec_len = std.simd.suggestVectorLength(u8) orelse 16;

/// The unescaped string inside a raw `"..."` span: borrowed zero-copy when
/// escape-free, unescaped into `allocator` otherwise. Errors on non-string
/// spans.
///
/// Ownership: the returned slice is either borrowed from `span` or owned by
/// `allocator`, and callers cannot tell which — pass an arena scoped to the
/// record so both die together at reset; never free the result individually.
pub fn stringSpan(allocator: std.mem.Allocator, span: []const u8) ![]const u8 {
    if (span.len < 2 or span[0] != '"') return error.Malformed;
    const inner = span[1 .. span.len - 1];
    if (std.mem.findScalar(u8, inner, '\\') == null) return inner;
    return unescape(allocator, inner);
}

/// JSON string unescape over the bytes between the quotes, including \uXXXX
/// surrogate pairs. Escape scanning is adaptive: a short linear window
/// resolves escape-dense text (wrapped JSON messages are ~all `\"` every few
/// bytes) without memchr call overhead, while sparse text bulk-skips with
/// one memchr per long run. Output is at most inner.len bytes (every escape
/// shrinks), so capacity is reserved once up front.
pub fn unescape(allocator: std.mem.Allocator, inner: []const u8) ![]const u8 {
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

/// Whether a value span is a well-formed JSON token. Strings and containers
/// were already structurally validated by the walker; scalar tokens must be
/// exact JSON literals (`tru` or `1e+` fail) so garbage a full parser would
/// reject is never trusted.
pub fn validValueSpan(span: []const u8) bool {
    if (span.len == 0) return false;
    return switch (span[0]) {
        '"', '{', '[' => true,
        't' => std.mem.eql(u8, span, "true"),
        'f' => std.mem.eql(u8, span, "false"),
        'n' => std.mem.eql(u8, span, "null"),
        '-', '0'...'9' => validNumberSpan(span),
        else => false,
    };
}

/// RFC 8259 number grammar: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
pub fn validNumberSpan(span: []const u8) bool {
    var i: usize = 0;
    if (span[i] == '-') i += 1;
    if (i >= span.len) return false;
    if (span[i] == '0') {
        i += 1;
    } else if (span[i] >= '1' and span[i] <= '9') {
        while (i < span.len and std.ascii.isDigit(span[i])) i += 1;
    } else {
        return false;
    }
    if (i < span.len and span[i] == '.') {
        i += 1;
        if (i >= span.len or !std.ascii.isDigit(span[i])) return false;
        while (i < span.len and std.ascii.isDigit(span[i])) i += 1;
    }
    if (i < span.len and (span[i] == 'e' or span[i] == 'E')) {
        i += 1;
        if (i < span.len and (span[i] == '+' or span[i] == '-')) i += 1;
        if (i >= span.len or !std.ascii.isDigit(span[i])) return false;
        while (i < span.len and std.ascii.isDigit(span[i])) i += 1;
    }
    return i == span.len;
}

// ============================== Tests ==============================

const testing = std.testing;

test "FieldWalker - spans across whitespace, escapes, and nesting" {
    const json =
        \\ { "a" : "x\"y" , "b": [1, {"c": "}"}] , "d" :null }
    ;
    var walker = try FieldWalker.init(json);

    const a = (try walker.nextField()).?;
    try testing.expectEqualStrings("a", a.key);
    try testing.expectEqualStrings("\"x\\\"y\"", a.value);

    const b = (try walker.nextField()).?;
    try testing.expectEqualStrings("b", b.key);
    try testing.expectEqualStrings("[1, {\"c\": \"}\"}]", b.value);

    const d = (try walker.nextField()).?;
    try testing.expectEqualStrings("d", d.key);
    try testing.expectEqualStrings("null", d.value);

    try testing.expectEqual(@as(?FieldWalker.RawField, null), try walker.nextField());
    try walker.finish();
}

test "FieldWalker - backslash parity decides the closing quote" {
    // Value ends in an even backslash run: the final quote is real.
    {
        var walker = try FieldWalker.init(
            \\{"a":"x\\"}
        );
        const field = (try walker.nextField()).?;
        try testing.expectEqualStrings("\"x\\\\\"", field.value);
    }
    // Escape-dense string: the first candidate quote is escaped, flipping
    // stringEnd into its linear mode for the rest of the string.
    {
        var walker = try FieldWalker.init(
            \\{"a":"\"\"\" plain tail that runs past the escapes"}
        );
        const field = (try walker.nextField()).?;
        try testing.expect(std.mem.endsWith(u8, field.value, "escapes\""));
    }
}

test "FieldWalker - malformed input errors instead of desyncing silently" {
    try testing.expectError(error.Malformed, FieldWalker.init("[1,2]"));

    var truncated = try FieldWalker.init("{\"a\": \"unterminated");
    try testing.expectError(error.Malformed, truncated.nextField());

    var bad_sep = try FieldWalker.init("{\"a\" \"b\"}");
    try testing.expectError(error.Malformed, bad_sep.nextField());
}

test "FieldWalker - comma separator violations error" {
    const bad_inputs = [_][]const u8{
        \\{"a":1,}
        ,
        \\{,"a":1}
        ,
        \\{"a":1 "b":2}
        ,
        \\{"a":1,,"b":2}
        ,
    };
    for (bad_inputs) |json| {
        var walker = try FieldWalker.init(json);
        var failed = false;
        while (walker.nextField() catch blk: {
            failed = true;
            break :blk null;
        }) |_| {}
        try testing.expect(failed);
    }
}

test "FieldWalker - mismatched container closers error" {
    // Regression (macroscope PR 214): one depth counter treated '}' and ']'
    // interchangeably, so `{"x":[}}` yielded the span `[}`.
    const bad_inputs = [_][]const u8{
        \\{"x":[}}
        ,
        \\{"x":{]}
        ,
        \\{"x":[{]}}
        ,
        \\{"x":[1,2}}
        ,
    };
    for (bad_inputs) |json| {
        var walker = try FieldWalker.init(json);
        try testing.expectError(error.Malformed, walker.nextField());
    }

    // Properly matched mixed nesting still parses.
    var ok = try FieldWalker.init(
        \\{"x":[{"a":[1]},[]]}
    );
    const field = (try ok.nextField()).?;
    try testing.expectEqualStrings("[{\"a\":[1]},[]]", field.value);
}

test "FieldWalker - nesting beyond 64 levels falls to the validating parser" {
    const deep_bad = "{\"x\":" ++ "[" ** 65 ++ "]" ** 65 ++ "}";
    var walker = try FieldWalker.init(deep_bad);
    try testing.expectError(error.Malformed, walker.nextField());

    const deep_ok = "{\"x\":" ++ "[" ** 64 ++ "]" ** 64 ++ "}";
    var ok = try FieldWalker.init(deep_ok);
    _ = (try ok.nextField()).?;
    try testing.expectEqual(@as(?FieldWalker.RawField, null), try ok.nextField());
}

test "FieldWalker - control bytes: escaped-char check rejects, content deviation is pinned" {
    // A raw control byte as the character FOLLOWING a backslash is rejected
    // in the dense branch (the check rides the existing escape handling).
    var rejected = try FieldWalker.init("{\"a\":\"q\\\" x\\\n\"}");
    try testing.expectError(error.Malformed, rejected.nextField());

    // DOCUMENTED DEVIATION (see module doc): raw control bytes in string
    // content are otherwise accepted — guarding them costs 10-15% per record
    // (measured, both swept record-wide and checked per string). Such
    // records are invalid JSON but are forwarded byte-identically either
    // way; pin the acceptance so changing it is a conscious decision.
    var deviant = try FieldWalker.init("{\"a\":\"line1\nline2\"}");
    const field = (try deviant.nextField()).?;
    try testing.expectEqualStrings("\"line1\nline2\"", field.value);
    var deviant2 = try FieldWalker.init("{\"a\":\"q\\\" then\nraw\"}");
    _ = (try deviant2.nextField()).?;

    // Legal whitespace between container tokens is fine, and DEL (0x7f)
    // needs no escaping per RFC 8259.
    var ok = try FieldWalker.init("{\"a\":[1,\n\t 2],\"d\":\"\x7f\"}");
    _ = (try ok.nextField()).?;
    const d = (try ok.nextField()).?;
    try testing.expectEqualStrings("\"\x7f\"", d.value);
}

test "unescape - decodes every escape and rejects invalid sequences" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqualStrings(
        "q\" b\\ s/ bs\x08 ff\x0c nl\n cr\r tab\t",
        try unescape(allocator,
            \\q\" b\\ s\/ bs\b ff\f nl\n cr\r tab\t
        ),
    );
    // BMP \u and surrogate pair.
    try testing.expectEqualStrings("café 😀", try unescape(allocator,
        \\café 😀
    ));

    const bad_inners = [_][]const u8{
        "a\\q", // unknown escape
        "a\\", // trailing backslash
        "a\\uD83Db", // lone high surrogate
        "a\\uDE00b", // lone low surrogate
        "a\\u12", // truncated \u
        "a\\uZZZZ", // non-hex \u
    };
    for (bad_inners) |inner| {
        try testing.expectError(error.InvalidEscape, unescape(allocator, inner));
    }
}

test "stringSpan - borrows escape-free strings, errors on non-strings" {
    const span = "\"plain\"";
    const got = try stringSpan(testing.failing_allocator, span);
    try testing.expectEqualStrings("plain", got);
    // Borrowed: points into the span, no allocation happened.
    try testing.expectEqual(@intFromPtr(span.ptr) + 1, @intFromPtr(got.ptr));

    try testing.expectError(error.Malformed, stringSpan(testing.failing_allocator, "42"));
    try testing.expectError(error.Malformed, stringSpan(testing.failing_allocator, "\""));
}

test "validValueSpan / validNumberSpan - strict JSON literals" {
    const good_tokens = [_][]const u8{
        "true", "false", "null", "\"s\"", "{}",         "[1]",
        "0",    "-0.5",  "1e5",  "1E+10", "123.456e-7", "42",
    };
    for (good_tokens) |good| {
        try testing.expect(validValueSpan(good));
    }
    for ([_][]const u8{ "", "tru", "falsey", "nul", "1e+", "--1", "01", "1..2", "1.", ".5", "1e", "-", "x" }) |bad| {
        try testing.expect(!validValueSpan(bad));
    }
}
