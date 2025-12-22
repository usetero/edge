const std = @import("std");
const zimdjson = @import("zimdjson");
const policy_engine = @import("../policy/policy_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const PolicyEngine = policy_engine.PolicyEngine;
const PolicyResult = policy_engine.PolicyResult;
const FilterDecision = policy_engine.FilterDecision;
const FieldRef = policy_engine.FieldRef;
const LogField = @import("proto").policy.LogField;
const MAX_POLICIES = @import("../hyperscan/matcher_index.zig").MAX_POLICIES;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const StreamParser = zimdjson.ondemand.StreamParser(.default);
const Object = StreamParser.Object;
const Document = StreamParser.Document;
const ArrayList = std.ArrayListUnmanaged;

/// Datadog log schema for parsing and serialization
/// Uses zimdjson schema inference for deserialization
const DatadogLog = struct {
    pub const schema: StreamParser.schema.Infer(@This()) = .{
        .fields = .{ .extra = .{ .skip = true } },
        .on_unknown_field = .{ .handle = @This().handleUnknownField },
    };

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

    extra: std.StringHashMapUnmanaged(StreamParser.AnyValue) = .empty,

    pub fn handleUnknownField(self: *@This(), alloc: ?std.mem.Allocator, key: []const u8, value: StreamParser.Value) StreamParser.schema.Error!void {
        const gpa = alloc orelse return error.ExpectedAllocator;
        return self.extra.put(gpa, key, try value.asAny());
    }

    /// Custom JSON serialization for known fields only.
    /// Note: Extra fields cannot be serialized because zimdjson AnyValue contains
    /// lazy iterators that may become invalid after document parsing.
    /// When no logs are dropped, original data is returned unchanged preserving all fields.
    pub fn jsonStringify(self: *const @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();

        if (self.message) |v| {
            try jw.objectField("message");
            try jw.write(v);
        }
        if (self.status) |v| {
            try jw.objectField("status");
            try jw.write(v);
        }
        if (self.level) |v| {
            try jw.objectField("level");
            try jw.write(v);
        }
        if (self.service) |v| {
            try jw.objectField("service");
            try jw.write(v);
        }
        if (self.hostname) |v| {
            try jw.objectField("hostname");
            try jw.write(v);
        }
        if (self.ddsource) |v| {
            try jw.objectField("ddsource");
            try jw.write(v);
        }
        if (self.ddtags) |v| {
            try jw.objectField("ddtags");
            try jw.write(v);
        }
        if (self.timestamp) |v| {
            try jw.objectField("timestamp");
            try jw.write(v);
        }
        if (self.environment) |v| {
            try jw.objectField("environment");
            try jw.write(v);
        }
        if (self.custom_field) |v| {
            try jw.objectField("custom_field");
            try jw.write(v);
        }
        // Write extra fields
        var it = self.extra.iterator();
        while (it.next()) |entry| {
            try jw.objectField(entry.key_ptr.*);
            try writeAnyValue(jw, entry.value_ptr.*);
        }

        try jw.endObject();
    }

    /// Write a zimdjson AnyValue to a JSON writer
    fn writeAnyValue(jw: anytype, value: StreamParser.AnyValue) @TypeOf(jw.*).Error!void {
        switch (value) {
            .null => try jw.write(null),
            .bool => |v| try jw.write(v),
            .number => |n| switch (n) {
                .unsigned => |v| try jw.write(v),
                .signed => |v| try jw.write(v),
                .double => |v| try jw.write(v),
            },
            .string => |v| try jw.write(v.get() catch ""),
            .array => |arr| {
                try jw.beginArray();
                var it = arr.iterator();
                while (it.next() catch null) |item| {
                    try writeAnyValue(jw, item.asAny() catch continue);
                }
                try jw.endArray();
            },
            .object => |obj| {
                try jw.beginObject();
                var it = obj.iterator();
                while (it.next() catch null) |field| {
                    try jw.objectField(field.key.get() catch continue);
                    try writeAnyValue(jw, field.value.asAny() catch continue);
                }
                try jw.endObject();
            },
        }
    }
};

/// Result of processing logs
pub const ProcessResult = struct {
    /// The processed data (caller owns this slice)
    data: []u8,
    /// Number of logs that were dropped by filter policies
    dropped_count: usize,
    /// Original number of logs before filtering
    original_count: usize,

    /// Returns true if any logs were dropped
    pub fn wasModified(self: ProcessResult) bool {
        return self.dropped_count > 0;
    }

    /// Returns true if all logs were dropped
    pub fn allDropped(self: ProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Process Datadog logs with filter evaluation
/// Takes decompressed JSON data and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
///
/// This is a standalone function that doesn't depend on httpz
pub fn processLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    // Process based on content type
    if (std.mem.indexOf(u8, content_type, "application/json") != null) {
        // Parse JSON and apply filter policies
        return processJsonLogsWithFilter(allocator, registry, bus, data);
    }

    // For non-JSON content types (logplex, raw), return unchanged
    // (no filtering support for these formats yet)
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);
    return .{
        .data = result,
        .dropped_count = 0,
        .original_count = 0, // Unknown for non-JSON
    };
}

/// Context for field accessor - holds the DatadogLog struct
const FieldAccessorContext = struct {
    log: *const DatadogLog,
};

/// Field accessor for Datadog JSON log format
/// Datadog logs have fields at the root level: message, status/level, ddtags, service, etc.
fn datadogFieldAccessor(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const field_ctx: *const FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const log = field_ctx.log;

    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => log.message,
            .LOG_FIELD_SEVERITY_TEXT => log.status orelse log.level,
            // Datadog JSON format doesn't have direct equivalents for these OTLP fields
            else => null,
        },
        .log_attribute => |key| {
            // For attributes, look up by key name
            if (std.mem.eql(u8, key, "service")) return log.service;
            if (std.mem.eql(u8, key, "hostname")) return log.hostname;
            if (std.mem.eql(u8, key, "ddsource")) return log.ddsource;
            if (std.mem.eql(u8, key, "ddtags")) return log.ddtags;
            if (std.mem.eql(u8, key, "environment")) return log.environment;
            if (std.mem.eql(u8, key, "custom_field")) return log.custom_field;
            // TODO: handle additional dynamic fields
            return null;
        },
        // Datadog JSON format doesn't have resource/scope attributes
        .resource_attribute, .scope_attribute => null,
    };
}

/// Evaluate a single log against policies.
/// Returns true if the log should be kept, false if it should be dropped.
fn filterLog(engine: *const PolicyEngine, log: *const DatadogLog, policy_id_buf: [][]const u8) bool {
    var field_ctx = FieldAccessorContext{ .log = log };
    const result = engine.evaluate(@ptrCast(&field_ctx), datadogFieldAccessor, null, policy_id_buf, null);
    return result.decision.shouldContinue();
}

/// Accumulated state for filtering logs
const FilterState = struct {
    kept: ArrayList(DatadogLog) = .empty,
    original_count: usize = 0,
    dropped_count: usize = 0,

    fn deinit(self: *FilterState, allocator: std.mem.Allocator) void {
        self.kept.deinit(allocator);
    }
};

/// Build the final ProcessResult from filtering state.
/// Handles the three cases: nothing dropped, everything dropped, or partial drop.
fn buildResult(
    allocator: std.mem.Allocator,
    state: *const FilterState,
    original_data: []const u8,
) !ProcessResult {
    // If nothing was dropped, return original data
    if (state.dropped_count == 0) {
        const result = try allocator.alloc(u8, original_data.len);
        @memcpy(result, original_data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = state.original_count,
        };
    }

    // If everything was dropped, return empty array
    if (state.kept.items.len == 0) {
        const result = try allocator.alloc(u8, 2);
        result[0] = '[';
        result[1] = ']';
        return .{
            .data = result,
            .dropped_count = state.dropped_count,
            .original_count = state.original_count,
        };
    }

    // Serialize kept logs
    var out: std.Io.Writer.Allocating = .init(allocator);
    try std.json.Stringify.value(state.kept.items, .{}, &out.writer);

    return .{
        .data = try out.toOwnedSlice(),
        .dropped_count = state.dropped_count,
        .original_count = state.original_count,
    };
}

/// Return data unchanged (fail-open behavior)
fn returnUnchanged(allocator: std.mem.Allocator, data: []const u8, original_count: usize) !ProcessResult {
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);
    return .{
        .data = result,
        .dropped_count = 0,
        .original_count = original_count,
    };
}

/// Process JSON logs with filter evaluation using zimdjson streaming parser
/// Detects if input is an array or single object, applies filter to each log
fn processJsonLogsWithFilter(allocator: std.mem.Allocator, registry: *const PolicyRegistry, bus: *EventBus, data: []const u8) !ProcessResult {
    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    var reader = std.Io.Reader.fixed(data);
    const document: Document = parser.parseFromReader(allocator, &reader) catch {
        return returnUnchanged(allocator, data, 0);
    };

    const engine = PolicyEngine.init(allocator, bus, @constCast(registry));

    const value_type = document.getType() catch {
        return returnUnchanged(allocator, data, 0);
    };

    var state = FilterState{};
    defer state.deinit(allocator);
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;

    switch (value_type) {
        .array => {
            var array: std.json.Parsed([]DatadogLog) = document.as([]DatadogLog, allocator, .{}) catch {
                return returnUnchanged(allocator, data, 0);
            };
            defer array.deinit();

            for (array.value) |*log_obj| {
                state.original_count += 1;
                if (filterLog(&engine, log_obj, &policy_id_buf)) {
                    try state.kept.append(allocator, log_obj.*);
                } else {
                    state.dropped_count += 1;
                }
            }

            return buildResult(allocator, &state, data);
        },
        .object => {
            var log_obj: std.json.Parsed(DatadogLog) = document.as(DatadogLog, allocator, .{}) catch {
                return returnUnchanged(allocator, data, 1);
            };
            defer log_obj.deinit();

            state.original_count = 1;
            if (filterLog(&engine, &log_obj.value, &policy_id_buf)) {
                try state.kept.append(allocator, log_obj.value);
            } else {
                state.dropped_count = 1;
            }

            return buildResult(allocator, &state, data);
        },
        else => return returnUnchanged(allocator, data, 0),
    }
}

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

test "processLogs - no policies keeps all logs in array" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs =
        \\[{"status": "info", "message": "test1"}, {"status": "error", "message": "test2"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "test1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "test2") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processLogs - DROP policy filters logs from array" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for DEBUG logs
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs =
        \\[{"status": "debug", "message": "debug msg"}, {"status": "error", "message": "error msg"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // DEBUG log should be dropped, ERROR log should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug msg") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "error msg") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processLogs - DROP policy drops single object" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const log =
        \\{"status": "debug", "message": "debug msg"}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), log, "application/json");
    defer allocator.free(result.data);

    // Single dropped log returns empty array
    try std.testing.expectEqualStrings("[]", result.data);
    try std.testing.expect(result.allDropped());
}

test "processLogs - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), malformed, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - non-JSON content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some raw log data";

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), data, "text/plain");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - Datadog format with ddtags and service" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs =
        \\[{"message": "User login", "service": "auth-service", "hostname": "web-01", "ddsource": "nodejs", "ddtags": "env:prod", "status": "info", "timestamp": 1733946000000}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "User login") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "auth-service") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
}

test "processLogs - filter on arbitrary custom field" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches on a custom field "environment"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-dev-env"),
        .name = try allocator.dupe(u8, "drop-dev-env"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "environment") },
        .match = .{ .regex = try allocator.dupe(u8, "development") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Logs with custom "environment" field - one dev, one prod
    const logs =
        \\[{"message": "dev log", "environment": "development", "custom_field": "abc"}, {"message": "prod log", "environment": "production", "custom_field": "xyz"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // Dev log should be dropped, prod log should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "dev log") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "prod log") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processLogs - extra fields are preserved when no logs dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - all logs kept, original data returned unchanged

    // Logs with extra fields not in the DatadogLog schema
    const logs =
        \\[{"status": "info", "message": "kept log", "extra_field": "should_be_preserved", "nested": {"key": "value"}, "array_field": [1, 2, 3]}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    std.debug.print("-----------\n", .{});
    std.debug.print("{s}\n", .{result.data});
    std.debug.print("-----------\n", .{});

    // When nothing is dropped, original data is returned unchanged - extra fields preserved
    try std.testing.expect(std.mem.indexOf(u8, result.data, "kept log") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "extra_field") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "should_be_preserved") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "nested") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "array_field") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
}
