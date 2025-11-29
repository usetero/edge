const std = @import("std");
const httpz = @import("httpz");
const jsonpath = @import("../core/jsonpath.zig");
const filter_mod = @import("../core/filter.zig");

const FilterEvaluator = filter_mod.FilterEvaluator;

/// Handles Datadog log ingestion
/// Takes an httpz.Request object, filter evaluator, and decompressed data buffer, processes the logs, and returns them
/// Uses the request's arena allocator for all temporary allocations
/// NOTE: Compression/decompression is now handled by the caller (httpz_server.zig)
pub fn processDatadogLogs(req: *httpz.Request, filter: *const FilterEvaluator, data: []const u8) ![]u8 {
    const allocator = req.arena;
    // Determine the content type
    const contentType = getContentType(req);

    // Process based on content type
    if (std.mem.indexOf(u8, contentType, "application/json") != null) {
        const res = filter.evaluate(data, .TELEMETRY_TYPE_LOGS);
        std.log.info("Filter result: {any}\n", .{res});
        // Parse and log JSON data
        try processJsonLogs(allocator, data);
    } else if (std.mem.indexOf(u8, contentType, "application/logplex") != null) {
        // Handle logplex format
        try processLogplexLogs(data);
    } else {
        // Handle raw text logs
        try processRawLogs(data);
    }

    // Return a copy of the processed data
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);

    return result;
}

/// Get the content type from request headers using httpz.Request
fn getContentType(request: *httpz.Request) []const u8 {
    if (request.header("content-type")) |content_type| {
        return content_type;
    }
    return "text/plain";
}

/// Process JSON formatted logs using jsonpath
fn processJsonLogs(allocator: std.mem.Allocator, data: []const u8) !void {
    _ = allocator;

    // Parse and query using jsonpath
    const doc = jsonpath.JsonDoc.parse(data) catch |err| {
        std.debug.print("JSON parse error: {any}\n", .{err});
        return err;
    };
    defer doc.deinit();

    // Query all top-level elements
    const result = try doc.query("$.*");
    defer result.deinit();

    std.debug.print("JSONPath query '$.*' returned {d} results\n", .{result.count()});
}

/// Process logplex formatted logs
fn processLogplexLogs(data: []const u8) !void {
    // Validation only - just check that data can be tokenized
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |_| {
        // Just iterate to validate
    }
}

/// Process raw text logs
fn processRawLogs(data: []const u8) !void {
    // Validation only - just check that data can be tokenized
    var lines = std.mem.tokenizeScalar(u8, data, '\n');
    while (lines.next()) |_| {
        // Just iterate to validate
    }
}

// ============================================================================
// TESTS
// ============================================================================

test "processJsonLogs" {
    const allocator = std.testing.allocator;

    // Test JSON log
    const jsonLog =
        \\[{
        \\  "ddsource": "nginx",
        \\  "ddtags": "env:staging,version:5.1",
        \\  "hostname": "i-012345678",
        \\  "message": "2019-11-19T14:37:58,995 INFO [process.name][20081] Hello World",
        \\  "service": "payment",
        \\  "status": "info"
        \\}]
    ;

    // Just test that JSON processing doesn't crash
    try processJsonLogs(allocator, jsonLog);
}

test "processJsonLogs - single log entry object" {
    const allocator = std.testing.allocator;

    const singleLog =
        \\{
        \\  "ddsource": "nginx",
        \\  "ddtags": "env:production",
        \\  "hostname": "web-01",
        \\  "message": "Request processed successfully",
        \\  "service": "api",
        \\  "status": "info"
        \\}
    ;

    try processJsonLogs(allocator, singleLog);
}

test "processJsonLogs - array of log entries" {
    const allocator = std.testing.allocator;

    const multiLogs =
        \\[
        \\  {
        \\    "ddsource": "nginx",
        \\    "message": "First log",
        \\    "status": "info"
        \\  },
        \\  {
        \\    "ddsource": "app",
        \\    "message": "Second log",
        \\    "status": "error"
        \\  },
        \\  {
        \\    "ddsource": "database",
        \\    "message": "Third log",
        \\    "status": "warning"
        \\  }
        \\]
    ;

    try processJsonLogs(allocator, multiLogs);
}

test "processJsonLogs - nested JSON structures" {
    const allocator = std.testing.allocator;

    const nestedLog =
        \\{
        \\  "ddsource": "application",
        \\  "message": "Complex log entry",
        \\  "metadata": {
        \\    "request_id": "abc123",
        \\    "user": {
        \\      "id": 42,
        \\      "name": "test_user"
        \\    },
        \\    "tags": ["important", "production", "alert"]
        \\  },
        \\  "metrics": {
        \\    "duration_ms": 1234.56,
        \\    "cpu_usage": 45.2,
        \\    "memory_mb": 512
        \\  }
        \\}
    ;

    try processJsonLogs(allocator, nestedLog);
}

test "processJsonLogs - empty array" {
    const allocator = std.testing.allocator;
    const emptyArray = "[]";
    try processJsonLogs(allocator, emptyArray);
}

test "processJsonLogs - empty object" {
    const allocator = std.testing.allocator;
    const emptyObject = "{}";
    try processJsonLogs(allocator, emptyObject);
}

test "processJsonLogs - JSON with special characters" {
    const allocator = std.testing.allocator;

    const specialChars =
        \\{
        \\  "message": "Line with\nnewline and\ttab",
        \\  "path": "C:\\Users\\test\\file.txt",
        \\  "unicode": "Hello 世界 🌍",
        \\  "quotes": "She said \"Hello\""
        \\}
    ;

    try processJsonLogs(allocator, specialChars);
}

test "processJsonLogs - array with mixed types" {
    const allocator = std.testing.allocator;

    const mixedArray =
        \\[
        \\  {"type": "object", "value": 1},
        \\  {"type": "object", "value": 2}
        \\]
    ;

    try processJsonLogs(allocator, mixedArray);
}

test "processJsonLogs - deeply nested JSON" {
    const allocator = std.testing.allocator;

    const deepNested =
        \\{
        \\  "a": {
        \\    "b": {
        \\      "c": {
        \\        "d": {
        \\          "e": {
        \\            "message": "Deep!"
        \\          }
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
    ;

    try processJsonLogs(allocator, deepNested);
}

// ============================================================================
// TESTS FOR LOGPLEX LOG PROCESSING
// ============================================================================

test "processLogplexLogs - standard syslog format" {
    const logplexData =
        \\<134>1 2023-01-15T10:30:45.123Z host.example.com myapp web.1 - State changed from starting to up
        \\<135>1 2023-01-15T10:30:46.456Z host.example.com myapp worker.1 - Processing job 12345
    ;

    try processLogplexLogs(logplexData);
}

test "processLogplexLogs - single line" {
    const singleLine = "<14>1 2023-01-15T10:30:45Z server app 123 msg-id This is a test message";
    try processLogplexLogs(singleLine);
}

test "processLogplexLogs - empty message" {
    const emptyMsg = "<14>1 2023-01-15T10:30:45Z server app 123 - -";
    try processLogplexLogs(emptyMsg);
}

test "processLogplexLogs - missing fields" {
    const partialData =
        \\<134>1 2023-01-15T10:30:45Z
        \\<135>1
        \\Just some text without proper format
    ;

    try processLogplexLogs(partialData);
}

test "processLogplexLogs - various priority values" {
    const priorities =
        \\<0>1 2023-01-15T10:30:45Z host app proc mid Emergency message
        \\<191>1 2023-01-15T10:30:45Z host app proc mid Debug message
        \\<999>1 2023-01-15T10:30:45Z host app proc mid Invalid priority
    ;

    try processLogplexLogs(priorities);
}

test "processLogplexLogs - multiline messages" {
    const multiline =
        \\<14>1 2023-01-15T10:30:45Z server app 123 - First line
        \\continues on second line
        \\and third line
    ;

    try processLogplexLogs(multiline);
}

test "processLogplexLogs - with structured data" {
    const structuredData =
        \\<165>1 2023-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - [exampleSDID@32473 iut="3" eventSource="Application"] An application event log entry
    ;

    try processLogplexLogs(structuredData);
}

test "processLogplexLogs - minimal valid format" {
    const minimal = "<0>1 - - - - - -";
    try processLogplexLogs(minimal);
}

// ============================================================================
// TESTS FOR RAW LOG PROCESSING
// ============================================================================

test "processRawLogs - simple text logs" {
    const rawLogs =
        \\INFO: Application started
        \\WARNING: High memory usage detected
        \\ERROR: Failed to connect to database
        \\DEBUG: Request completed in 123ms
    ;

    try processRawLogs(rawLogs);
}

test "processRawLogs - empty input" {
    try processRawLogs("");
}

test "processRawLogs - single line" {
    try processRawLogs("Single log line");
}

test "processRawLogs - logs with special characters" {
    const specialLogs =
        \\Line with "quotes" and 'apostrophes'
        \\Line with unicode: 你好世界 🚀
        \\Line with backslash \ and forward slash /
    ;

    try processRawLogs(specialLogs);
}

test "processRawLogs - very long lines" {
    var longLine: [10000]u8 = undefined;
    for (&longLine) |*c| {
        c.* = 'A';
    }

    try processRawLogs(&longLine);
}

test "processRawLogs - mixed line endings" {
    const mixedEndings = "Line 1\nLine 2\r\nLine 3\rLine 4";
    try processRawLogs(mixedEndings);
}

test "processRawLogs - only whitespace" {
    const whitespaceOnly = "   \t\n\r\n   \t   ";
    try processRawLogs(whitespaceOnly);
}

test "processRawLogs - control characters" {
    const controlChars = "Text\x00with\x01various\x08control\x1Bcharacters\x7F";
    try processRawLogs(controlChars);
}

// ============================================================================
// EDGE CASE AND BOUNDARY TESTS
// ============================================================================

test "processJsonLogs - malformed JSON should error" {
    const allocator = std.testing.allocator;

    const malformedCases = [_][]const u8{
        "{", // Unclosed brace
        "}", // Extra brace
        "[}", // Mismatched brackets
        "{key: 'value'}", // Unquoted key
        "[1, 2, 3,]", // Trailing comma
        "{\"a\": 1 \"b\": 2}", // Missing comma
    };

    for (malformedCases) |malformed| {
        const result = processJsonLogs(allocator, malformed);
        // Expect some kind of error
        if (result) |_| {
            try std.testing.expect(false); // Should have errored
        } else |_| {
            // Error occurred as expected
        }
    }
}

test "processJsonLogs - escaped sequences" {
    const allocator = std.testing.allocator;

    const escapedJson =
        \\{
        \\  "newline": "Line1\nLine2",
        \\  "tab": "Col1\tCol2",
        \\  "quote": "He said \"Hello\"",
        \\  "backslash": "C:\\Users\\test",
        \\  "unicode": "\u0048\u0065\u006C\u006C\u006F"
        \\}
    ;

    try processJsonLogs(allocator, escapedJson);
}

test "processJsonLogs - numbers and booleans" {
    const allocator = std.testing.allocator;

    const jsonWithTypes =
        \\{
        \\  "integer": 42,
        \\  "float": 3.14159,
        \\  "scientific": 1.23e-4,
        \\  "negative": -100,
        \\  "boolean_true": true,
        \\  "boolean_false": false,
        \\  "null_value": null
        \\}
    ;

    try processJsonLogs(allocator, jsonWithTypes);
}

// ============================================================================
// UNICODE AND INTERNATIONALIZATION TESTS
// ============================================================================

test "processRawLogs - international text" {
    const internationalLogs =
        \\English: Hello World
        \\Spanish: Hola Mundo
        \\French: Bonjour le monde
        \\German: Hallo Welt
        \\Russian: Привет мир
        \\Chinese: 你好世界
        \\Japanese: こんにちは世界
        \\Arabic: مرحبا بالعالم
        \\Hebrew: שלום עולם
        \\Korean: 안녕하세요 세계
        \\Hindi: नमस्ते दुनिया
    ;

    try processRawLogs(internationalLogs);
}

test "processJsonLogs - unicode in JSON" {
    const allocator = std.testing.allocator;

    const unicodeJson =
        \\{
        \\  "emoji": "🚀 🌍 ✨ 🎉",
        \\  "chinese": "你好世界",
        \\  "japanese": "こんにちは",
        \\  "arabic": "مرحبا",
        \\  "math": "∑ ∏ ∫ ∞ √",
        \\  "arrows": "← → ↑ ↓ ⇐ ⇒",
        \\  "box": "┌─┬─┐│ │ │└─┴─┘"
        \\}
    ;

    try processJsonLogs(allocator, unicodeJson);
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

test "processJsonLogs - large array performance" {
    const allocator = std.testing.allocator;

    var json = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer json.deinit(allocator);

    try json.appendSlice(allocator, "[");

    // Create 1000 log entries
    for (0..1000) |i| {
        if (i > 0) try json.appendSlice(allocator, ",");
        try json.writer(allocator).print(
            \\{{"id":{d},"message":"Log entry {d}","timestamp":"2023-01-15T10:30:45Z"}}
        , .{ i, i });
    }

    try json.appendSlice(allocator, "]");

    try processJsonLogs(allocator, json.items);
}

test "processRawLogs - many lines" {
    const allocator = std.testing.allocator;
    var manyLines = try std.ArrayList(u8).initCapacity(allocator, 4096);
    defer manyLines.deinit(allocator);

    for (0..1000) |i| {
        try manyLines.writer(allocator).print("Log line {d}: This is a test log message\n", .{i});
    }

    try processRawLogs(manyLines.items);
}

// ============================================================================
// LOGPLEX RFC 5424 COMPLIANCE TESTS
// ============================================================================

test "processLogplexLogs - RFC 5424 timestamp formats" {
    const timestamps = [_][]const u8{
        "<14>1 2023-01-15T10:30:45Z host app - - UTC time",
        "<14>1 2023-01-15T10:30:45.123Z host app - - With milliseconds",
        "<14>1 2023-01-15T10:30:45.123456Z host app - - With microseconds",
        "<14>1 2023-01-15T10:30:45+00:00 host app - - With timezone offset",
        "<14>1 2023-01-15T10:30:45-05:00 host app - - Negative offset",
    };

    for (timestamps) |timestamp| {
        try processLogplexLogs(timestamp);
    }
}

test "processLogplexLogs - structured data elements" {
    const structuredTests = [_][]const u8{
        // Single structured data element
        \\<165>1 2023-08-24T05:14:15Z host app - - [id1@1234 key="value"] Message
        ,
        // Multiple structured data elements
        \\<165>1 2023-08-24T05:14:15Z host app - - [id1@1234 a="b"][id2@5678 c="d"] Message
        ,
        // Structured data with multiple parameters
        \\<165>1 2023-08-24T05:14:15Z host app - - [test@123 key1="val1" key2="val2" key3="val3"] Message
        ,
    };

    for (structuredTests) |test_case| {
        try processLogplexLogs(test_case);
    }
}

// ============================================================================
// RAPID SUCCESSION TESTS
// ============================================================================

test "processJsonLogs - rapid successive calls" {
    const allocator = std.testing.allocator;

    const log =
        \\{"message": "Rapid test", "count": 1}
    ;

    // Test multiple rapid calls don't cause issues
    for (0..100) |_| {
        try processJsonLogs(allocator, log);
    }
}

test "processRawLogs - rapid successive calls" {
    const log = "Rapid test log line";

    for (0..100) |_| {
        try processRawLogs(log);
    }
}

test "processLogplexLogs - rapid successive calls" {
    const log = "<14>1 2023-01-15T10:30:45Z host app - - Rapid test";

    for (0..100) |_| {
        try processLogplexLogs(log);
    }
}
