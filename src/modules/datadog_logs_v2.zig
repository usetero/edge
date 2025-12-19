const std = @import("std");
const zimdjson = @import("zimdjson");
const filter_engine = @import("../policy/filter_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const FilterEngine = filter_engine.FilterEngine;
const FilterResult = filter_engine.FilterResult;
const MatchCase = filter_engine.MatchCase;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const StreamParser = zimdjson.ondemand.StreamParser(.default);
const Object = StreamParser.Object;
const ArrayList = std.ArrayListUnmanaged;

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

/// Context for field accessor - holds the zimdjson Object for field lookups
const FieldAccessorContext = struct {
    object: Object,
};

/// Field accessor for Datadog JSON log format using zimdjson
/// Datadog logs have fields at the root level: message, status/level, ddtags, service, etc.
/// Supports arbitrary field lookups via the zimdjson Object
fn datadogFieldAccessor(ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8 {
    const field_ctx: *const FieldAccessorContext = @ptrCast(@alignCast(ctx));

    // Map match_case to appropriate field name(s)
    const field_name: []const u8 = switch (match_case) {
        .log_body => "message",
        .log_severity_text => blk: {
            // Datadog uses "status" for severity, but also check "level" as fallback
            const status_value = field_ctx.object.at("status");
            if (status_value.asString()) |s| return s else |_| {}
            break :blk "level"; // Try level as fallback
        },
        .log_attribute => key, // For attributes, use the key directly (supports any field)
        // Datadog JSON format doesn't have direct equivalents for these OTLP fields
        .log_trace_id,
        .log_span_id,
        .log_event_name,
        .resource_schema_url,
        .scope_schema_url,
        .resource_attribute,
        .scope_attribute,
        => return null,
    };

    // Look up the field in the zimdjson object
    const field_value = field_ctx.object.at(field_name);
    return field_value.asString() catch null;
}

/// Process JSON logs with filter evaluation using zimdjson streaming parser
/// Detects if input is an array or single object, applies filter to each log
fn processJsonLogsWithFilter(allocator: std.mem.Allocator, registry: *const PolicyRegistry, bus: *EventBus, data: []const u8) !ProcessResult {
    // Initialize zimdjson streaming parser
    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    // Create a fixed reader from the data slice for streaming parsing
    var reader = std.Io.Reader.fixed(data);

    // Parse the JSON document using streaming parser
    const document = parser.parseFromReader(allocator, &reader) catch {
        // If JSON parsing fails, return data unchanged (fail-open)
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = 0,
        };
    };

    // Create filter engine for evaluation (gets snapshot from registry internally)
    const engine = FilterEngine.init(allocator, bus, @constCast(registry));

    // Get the value type to determine if it's an array or object
    const value_type = document.getType() catch {
        // If we can't determine the type, return unchanged
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = 0,
        };
    };

    switch (value_type) {
        .array => {
            // Process array of logs using schema-based parsing
            const array = document.asArray() catch {
                const result = try allocator.alloc(u8, data.len);
                @memcpy(result, data);
                return .{
                    .data = result,
                    .dropped_count = 0,
                    .original_count = 0,
                };
            };

            // Collect indices of kept logs
            var kept_indices: ArrayList(usize) = .empty;
            defer kept_indices.deinit(allocator);

            var dropped_count: usize = 0;
            var original_count: usize = 0;

            var it = array.iterator();
            while (it.next() catch null) |log_value| {
                original_count += 1;

                // Get the log object for field lookups
                const log_obj = log_value.asObject() catch {
                    // If not an object, keep the log (fail-open)
                    try kept_indices.append(allocator, original_count - 1);
                    continue;
                };

                const field_ctx = FieldAccessorContext{
                    .object = log_obj,
                };

                const filter_result = engine.evaluate(@ptrCast(&field_ctx), datadogFieldAccessor);
                if (filter_result == .keep) {
                    try kept_indices.append(allocator, original_count - 1);
                } else {
                    dropped_count += 1;
                }
            }

            // If nothing was dropped, return original data
            if (dropped_count == 0) {
                const result = try allocator.alloc(u8, data.len);
                @memcpy(result, data);
                return .{
                    .data = result,
                    .dropped_count = 0,
                    .original_count = original_count,
                };
            }

            // If everything was dropped, return empty array
            if (kept_indices.items.len == 0) {
                const result = try allocator.alloc(u8, 2);
                result[0] = '[';
                result[1] = ']';
                return .{
                    .data = result,
                    .dropped_count = dropped_count,
                    .original_count = original_count,
                };
            }

            // Serialize kept logs
            var out: std.Io.Writer.Allocating = .init(allocator);
            try std.json.Stringify.value(kept_indices.items, .{}, &out.writer);

            return .{
                .data = try out.toOwnedSlice(),
                .dropped_count = dropped_count,
                .original_count = original_count,
            };
        },
        .object => {
            // Process single log object
            const log_obj = document.asObject() catch {
                // If not an object, return unchanged (fail-open)
                const result = try allocator.alloc(u8, data.len);
                @memcpy(result, data);
                return .{
                    .data = result,
                    .dropped_count = 0,
                    .original_count = 1,
                };
            };

            const field_ctx = FieldAccessorContext{
                .object = log_obj,
            };

            const filter_result = engine.evaluate(@ptrCast(&field_ctx), datadogFieldAccessor);
            if (filter_result == .drop) {
                // Return empty array for dropped single log
                const result = try allocator.alloc(u8, 2);
                result[0] = '[';
                result[1] = ']';
                return .{
                    .data = result,
                    .dropped_count = 1,
                    .original_count = 1,
                };
            }
            // Keep the log - return as-is
            const result = try allocator.alloc(u8, data.len);
            @memcpy(result, data);
            return .{
                .data = result,
                .dropped_count = 0,
                .original_count = 1,
            };
        },
        else => {
            // Not an array or object, return unchanged
            const result = try allocator.alloc(u8, data.len);
            @memcpy(result, data);
            return .{
                .data = result,
                .dropped_count = 0,
                .original_count = 0,
            };
        },
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
