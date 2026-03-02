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

    /// Free extra field keys allocated during parsing
    pub fn deinit(self: *DatadogLog, allocator: std.mem.Allocator) void {
        var it = self.extra.keyIterator();
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        self.extra.deinit(allocator);
    }

    /// Parse a DatadogLog from a zimdjson Value (object)
    pub fn parse(allocator: std.mem.Allocator, value: Value) !DatadogLog {
        var log = DatadogLog{};

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
                // Store unknown fields in extra map - need to dupe the key since it's from the parser buffer
                const key_copy = try allocator.dupe(u8, key);
                try log.extra.put(allocator, key_copy, try field.value.asAny());
            }
        }

        return log;
    }

    /// Custom JSON serialization for known fields only.
    /// Note: Extra fields cannot be serialized because zimdjson AnyValue contains
    /// lazy iterators that may become invalid after document parsing.
    /// When no logs are dropped, original data is returned unchanged preserving all fields.
    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();

        if (self.message) |v| {
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
            try writeAnyValue(jws, entry.value_ptr.*);
        }

        try jws.endObject();
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
        \\{"message": "log body", "status": "error", "level": "ERROR", "service": "api", "hostname": "host1", "ddsource": "nginx", "ddtags": "env:prod", "timestamp": 1703001234, "environment": "production", "custom_field": "custom_value"}
    ;

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
    defer {
        var it = log.extra.keyIterator();
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        log.extra.deinit(allocator);
    }

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

    const log = DatadogLog{
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

    const log = DatadogLog{
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

    const log = DatadogLog{};

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    try std.testing.expectEqualStrings("{}", out.written());
}

test "DatadogLog - jsonStringify with timestamp" {
    const allocator = std.testing.allocator;

    const log = DatadogLog{
        .timestamp = 1703001234567,
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(log, .{}, &out.writer);

    try std.testing.expectEqualStrings("{\"timestamp\":1703001234567}", out.written());
}

test "DatadogLog - field mutation remove message" {
    var log = DatadogLog{
        .message = "test message",
        .status = "info",
    };

    // Remove message
    log.message = null;

    try std.testing.expect(log.message == null);
    try std.testing.expectEqualStrings("info", log.status.?);
}

test "DatadogLog - field mutation set message" {
    var log = DatadogLog{
        .message = "original",
    };

    // Set new message
    log.message = "modified";

    try std.testing.expectEqualStrings("modified", log.message.?);
}

test "DatadogLog - field mutation remove all fields" {
    var log = DatadogLog{
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

test "DatadogLog - special characters in strings" {
    const allocator = std.testing.allocator;

    const log_out = DatadogLog{
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

    const log_out = DatadogLog{
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
