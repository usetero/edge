//! Tests for `log.zig`.
//!
//! Split out because the record type and its parse paths are ~700 lines and
//! the cases exercising them are ~1000. Nothing here reaches past the public
//! surface of `DatadogLog`.

const std = @import("std");
const log_mod = @import("log.zig");
const DatadogLog = log_mod.DatadogLog;
const Parser = log_mod.Parser;
const Value = log_mod.Value;
const AnyValue = log_mod.AnyValue;

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

test "DatadogLog - extras serialize in the order the record listed them" {
    // Field order is not semantic in JSON, but it is what the sender wrote,
    // and both parse paths must agree: a record that takes the fallback must
    // not reach the intake shaped differently from one that does not. The
    // fast path keeps the order by construction; the materializing path keeps
    // `extra_order` for it.
    const allocator = std.testing.allocator;
    const json =
        \\{"message":"m","zeta":1,"alpha":2,"middle":3,"beta":4}
    ;
    const want = "{\"message\":\"m\",\"zeta\":1,\"alpha\":2,\"middle\":3,\"beta\":4}";

    var fast = try DatadogLog.parseRaw(allocator, json);
    defer fast.deinit(allocator);
    var fast_out: std.Io.Writer.Allocating = .init(allocator);
    defer fast_out.deinit();
    try std.json.Stringify.value(fast, .{}, &fast_out.writer);
    try std.testing.expectEqualStrings(want, fast_out.written());

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    const doc = try parser.parseFromSlice(allocator, json);
    var slow = try DatadogLog.parse(allocator, doc.asValue());
    defer slow.deinit(allocator);
    var slow_out: std.Io.Writer.Allocating = .init(allocator);
    defer slow_out.deinit();
    try std.json.Stringify.value(slow, .{}, &slow_out.writer);
    try std.testing.expectEqualStrings(want, slow_out.written());
}

test "DatadogLog - a duplicate extra key resolves to the last value" {
    // The map kept the last write; the flat list scans backwards for the same
    // answer. RFC 8259 §4 makes key uniqueness a SHOULD and leaves a
    // duplicate's meaning undefined, so the fast path keeps both entries and
    // re-emits the record as the sender wrote it, rather than picking a
    // winner on the intake's behalf. See `ExtraSpans`.
    const allocator = std.testing.allocator;
    const json =
        \\{"message":"m","dupe":1,"dupe":2}
    ;

    var fast = try DatadogLog.parseRaw(allocator, json);
    defer fast.deinit(allocator);
    try std.testing.expectEqualStrings("2", fast.extra_spans.get("dupe").?);
    try std.testing.expectEqual(@as(usize, 2), fast.extra_spans.count());

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(fast, .{}, &out.writer);
    try std.testing.expectEqualStrings(
        "{\"message\":\"m\",\"dupe\":1,\"dupe\":2}",
        out.written(),
    );
}

test "DatadogLog - a duplicate extra key does not strand its key copy" {
    // `HashMap.put` replaces the value and keeps the original key pointer, so
    // the materializing path must reuse the stored key on a duplicate rather
    // than dupe a second one: `deinit` frees keys by walking the map, and a
    // copy that entered neither the map nor `extra_order` is unreachable.
    // The testing allocator fails this test on that leak.
    const allocator = std.testing.allocator;
    const json =
        \\{"message":"m","dupe":1,"keep":"x","dupe":2}
    ;

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    // The map collapses the duplicate; the first position and the last value
    // both survive.
    try std.testing.expectEqual(@as(usize, 2), log.extra.count());
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    try std.testing.expectEqualStrings(
        "{\"message\":\"m\",\"dupe\":2,\"keep\":\"x\"}",
        out.written(),
    );
}

test "DatadogLog - a duplicate container extra frees the value it replaces" {
    // `parse` stringifies an object/array extra into owned bytes. A duplicate
    // replaces that value, and the bytes it displaces have to go back to the
    // allocator or the testing allocator reports the leak here. The third
    // shape covers a container replaced by a scalar, where the stale bytes
    // have no successor to overwrite them.
    const allocator = std.testing.allocator;
    const json =
        \\{"message":"m","obj":{"a":1},"obj":{"b":2},"arr":[1],"arr":[2],"gone":{"c":3},"gone":9}
    ;

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 3), log.extra.count());
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    try std.testing.expectEqualStrings(
        "{\"message\":\"m\",\"obj\":{\"b\":2},\"arr\":[2],\"gone\":9}",
        out.written(),
    );
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

test "bodyForMatch: targeted lookup and full flatten agree" {
    const testing = std.testing;
    // The targeted walk in `innerBodyDirect` must never disagree with the
    // flatten it short-circuits. Forcing `ensureUnwrapped` first makes the
    // direct path bail, so the same input runs both ways.
    // parseRaw's memory contract wants an arena; borrowed spans and decoded
    // strings share one lifetime and are released together.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const cases = [_][]const u8{
        // GCP shape the direct path handles.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":\"inner body\",\"other\":1}}}"}
        ,
        // `body` instead of `message`.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"body\":\"via body\"}}}"}
        ,
        // Priority: message wins over body and log.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"log\":\"l\",\"body\":\"b\",\"message\":\"m\"}}}"}
        ,
        // Understood shape, no body field present -> falls back to raw.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"severity\":\"INFO\"}}}"}
        ,
        // Shapes the direct path must refuse: array, missing path, plain text.
        \\{"message":"{\"data\":{\"jsonPayload\":[{\"message\":\"in array\"}]}}"}
        ,
        \\{"message":"{\"data\":{\"other\":{\"message\":\"elsewhere\"}}}"}
        ,
        \\{"message":"not json at all"}
        ,
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":{\"nested\":\"object\"}}}}"}
        ,
        // Duplicate keys: the first occurrence wins in both paths. If the
        // direct walk took the last one instead, a body policy matching the
        // first value could be bypassed by appending a benign second.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":\"secret\",\"message\":\"benign\"}}}"}
        ,
        \\{"message":"{\"data\":{\"jsonPayload\":{\"body\":\"first\",\"body\":\"second\",\"log\":\"l\"}}}"}
        ,
        // Array-valued body candidates: the targeted walk cannot descend
        // arrays, so it must defer to flatten (which does). Without the
        // `.array => return null` arm in `innerBodyDirect`, the first two
        // shapes flip keep/drop policy decisions (`drop-debug-logs` matches
        // `log_field: body` against /debug|trace/): the targeted path would
        // resolve a wrong string sibling while flatten resolves the array's
        // string leaf.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":[\"innocuous\"],\"body\":\"debug stuff\"}}}"}
        ,
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":[\"debug stuff\"],\"body\":\"innocuous\"}}}"}
        ,
        // A string leaf inside the array must be recovered by the flatten
        // path the targeted walk defers to.
        \\{"message":"{\"data\":{\"jsonPayload\":{\"message\":[\"the body\"]}}}"}
        ,
    };

    for (cases, 0..) |json, i| {
        var direct = try DatadogLog.parseRaw(allocator, json);
        defer direct.deinit(allocator);
        const via_direct = direct.bodyForMatch(allocator);

        var flat = try DatadogLog.parseRaw(allocator, json);
        defer flat.deinit(allocator);
        flat.ensureUnwrapped(allocator); // makes innerBodyDirect bail
        const via_flat = flat.bodyForMatch(allocator);

        errdefer std.debug.print("case {d}: {s}\n", .{ i, json });
        try testing.expect((via_direct == null) == (via_flat == null));
        if (via_direct) |d| try testing.expectEqualStrings(via_flat.?, d);
    }
}

test "DatadogLog - unwrappedAttribute observes a setWrapped edit on the same path" {
    // Regression (PR #203): `setWrapped` edits `message_tree` but leaves
    // `message_flat` stale, so a later read on the same path returned the
    // pre-transform value.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"{\"data\":{\"jsonPayload\":{\"email\":\"alice@example.com\"}}}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const path = [_][]const u8{ "data", "jsonPayload", "email" };

    // Prime the one-shot flat cache with a read (mirrors the engine reading
    // via `unwrappedAttribute` for the first redact rule).
    try std.testing.expectEqualStrings(
        "alice@example.com",
        log.unwrappedAttribute(allocator, &path).?,
    );

    // Rule 1 edits the leaf. The tree is now dirty; the flat is NOT refreshed.
    try std.testing.expect(log.setWrapped(allocator, &path, "ALICE_R@example.com"));

    // A later read on the same path must return rule 1's edit, not the stale
    // flat snapshot of the original value. Pre-fix this returned
    // "alice@example.com".
    try std.testing.expectEqualStrings(
        "ALICE_R@example.com",
        log.unwrappedAttribute(allocator, &path).?,
    );

    // Rule 2 composes on top of rule 1's edit, then reads it back.
    try std.testing.expect(log.setWrapped(allocator, &path, "ALICE_R@EXAMPLE_R.com"));
    try std.testing.expectEqualStrings(
        "ALICE_R@EXAMPLE_R.com",
        log.unwrappedAttribute(allocator, &path).?,
    );

    // The forwarded record carries both redactions and neither original token.
    log.finalizeWrapped(allocator);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    const output = out.written();
    try std.testing.expect(std.mem.indexOf(u8, output, "ALICE_R@EXAMPLE_R.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "alice") == null);
}

test "DatadogLog - unwrappedAttribute returns null after deleteWrapped removes the leaf" {
    // `deleteWrapped` leaves the stale flat entry in place, but a later read
    // must see the leaf as absent.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"{\"data\":{\"jsonPayload\":{\"email\":\"alice@example.com\",\"note\":\"keep\"}}}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const email_path = [_][]const u8{ "data", "jsonPayload", "email" };
    const note_path = [_][]const u8{ "data", "jsonPayload", "note" };

    // Prime the flat with a read.
    try std.testing.expectEqualStrings(
        "alice@example.com",
        log.unwrappedAttribute(allocator, &email_path).?,
    );

    // Remove the leaf — the tree is now dirty and the leaf is gone.
    try std.testing.expect(log.deleteWrapped(allocator, &email_path));

    // Reading the removed leaf returns null, not the stale flat value.
    try std.testing.expect(log.unwrappedAttribute(allocator, &email_path) == null);

    // A sibling leaf that was never edited still resolves (the flat fallback
    // stays authoritative for never-edited paths even while the tree is dirty).
    try std.testing.expectEqualStrings(
        "keep",
        log.unwrappedAttribute(allocator, &note_path).?,
    );

    // The forwarded record no longer carries the removed leaf or its value.
    log.finalizeWrapped(allocator);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    const output = out.written();
    try std.testing.expect(std.mem.indexOf(u8, output, "email") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "keep") != null);
}

test "DatadogLog - unwrappedAttribute returns null when an ancestor object key was deleted" {
    // deleteWrapped(["data","jsonPayload"]) then a read of
    // ["data","jsonPayload","email"] must return null, not the stale flat
    // value.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"{\"data\":{\"jsonPayload\":{\"email\":\"alice@example.com\"}}}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const email_path = [_][]const u8{ "data", "jsonPayload", "email" };
    const payload_path = [_][]const u8{ "data", "jsonPayload" };

    // Prime the flat cache with a read.
    try std.testing.expectEqualStrings(
        "alice@example.com",
        log.unwrappedAttribute(allocator, &email_path).?,
    );

    // Delete the ancestor object ("jsonPayload"), not the leaf directly.
    try std.testing.expect(log.deleteWrapped(allocator, &payload_path));

    // Reading through the now-absent ancestor must return null, not the stale
    // flat entry for "data.jsonPayload.email".
    try std.testing.expect(log.unwrappedAttribute(allocator, &email_path) == null);

    // The forwarded record must not carry the removed subtree.
    log.finalizeWrapped(allocator);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(log, .{}, &out.writer);
    const output = out.written();
    try std.testing.expect(std.mem.indexOf(u8, output, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "jsonPayload") == null);
}

test "DatadogLog - unwrappedAttribute still resolves array-of-objects paths after an unrelated edit" {
    // The flattener reaches string leaves inside an array of objects, but
    // the tree walk only descends into objects. The read must defer to the
    // flat, also when an unrelated edit made the tree dirty.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"{\"items\":[{\"event_type\":\"Started\"}],\"note\":\"orig\"}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const arr_path = [_][]const u8{ "items", "event_type" };
    const note_path = [_][]const u8{"note"};

    // The array-of-objects leaf resolves through the flat (first leaf wins).
    try std.testing.expectEqualStrings(
        "Started",
        log.unwrappedAttribute(allocator, &arr_path).?,
    );

    // Edit an unrelated sibling so the tree is dirty for the rest of the pass.
    try std.testing.expect(log.setWrapped(allocator, &note_path, "new"));

    // The array-of-objects leaf must still resolve through the flat.
    try std.testing.expectEqualStrings(
        "Started",
        log.unwrappedAttribute(allocator, &arr_path).?,
    );
    // The edited sibling reflects the live tree value, not the stale flat.
    try std.testing.expectEqualStrings(
        "new",
        log.unwrappedAttribute(allocator, &note_path).?,
    );
}

test "DatadogLog - unwrappedAttribute falls through for array-string entries after an unrelated edit" {
    // `items` is an array of strings. `flattenValue` stores the first string
    // under "items", so the flat has the value and the tree leaf is not a
    // string.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"{\"items\":[\"secret\"],\"note\":\"orig\"}"}
    ;
    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    const items_path = [_][]const u8{"items"};
    const note_path = [_][]const u8{"note"};

    // Before any edit the flat is authoritative.
    try std.testing.expectEqualStrings(
        "secret",
        log.unwrappedAttribute(allocator, &items_path).?,
    );

    // Dirty the tree with an unrelated edit.
    try std.testing.expect(log.setWrapped(allocator, &note_path, "new"));

    // The array-string leaf must still resolve through the flat.
    try std.testing.expectEqualStrings(
        "secret",
        log.unwrappedAttribute(allocator, &items_path).?,
    );
    // The edited sibling reflects the live tree value.
    try std.testing.expectEqualStrings(
        "new",
        log.unwrappedAttribute(allocator, &note_path).?,
    );
}
test "DatadogLog - parseRaw rejects malformed container interiors (parse parity)" {
    // Regression: FieldWalker.valueEnd skipped the interior bytes of a
    // container, so a malformed unknown-field value went into `extra_spans`
    // verbatim. parseRaw must reject what a full parser rejects.
    const allocator = std.testing.allocator;

    const bad_record_values = [_][]const u8{
        "[1,]", // trailing comma in array
        "[,]", // leading comma in array
        "[1 2]", // missing comma in array
        "[1,,2]", // double comma / missing value in array
        "{\"k\":}", // missing object value
        "{1:2}", // non-string object key
        "{\"a\":1,}", // trailing comma in object
        "[tru]", // malformed scalar token in array
        "[1e+]", // incomplete number in array
        "{\"a\":1 \"b\":2}", // missing comma between object pairs
    };
    for (bad_record_values) |val| {
        var buf: [128]u8 = undefined;
        const json = std.fmt.bufPrint(
            &buf,
            "{{\"message\":\"matched\",\"service\":\"s\",\"x\":{s}}}",
            .{val},
        ) catch unreachable;
        try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator, json));
    }

    // A container in a known string field already went to the validating
    // path. Pin that it still does.
    try std.testing.expectError(error.Malformed, DatadogLog.parseRaw(allocator,
        \\{"message":[1,],"service":"s"}
    ));

    // Valid containers in unknown fields still parse byte-for-byte.
    var ok = try DatadogLog.parseRaw(allocator,
        \\{"message":"m","http":{"method":"GET","code":200},"tags":["a","b"],"empty":{},"n":42,"ok":true}
    );
    defer ok.deinit(allocator);
    try std.testing.expectEqualStrings("{\"method\":\"GET\",\"code\":200}", ok.extra_spans.get("http").?);
    try std.testing.expectEqualStrings("[\"a\",\"b\"]", ok.extra_spans.get("tags").?);
    try std.testing.expectEqualStrings("{}", ok.extra_spans.get("empty").?);
    try std.testing.expectEqualStrings("42", ok.extra_spans.get("n").?);
    try std.testing.expectEqualStrings("true", ok.extra_spans.get("ok").?);
}
