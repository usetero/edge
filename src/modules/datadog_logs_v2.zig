const std = @import("std");
const filter_engine = @import("../policy/filter_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const FilterEngine = filter_engine.FilterEngine;
const FilterResult = filter_engine.FilterResult;
const MatchCase = filter_engine.MatchCase;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

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

/// Field accessor for Datadog JSON log format
/// Datadog logs have fields at the root level: message, level, ddtags, service, etc.
fn datadogFieldAccessor(ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8 {
    const json_value: *const std.json.Value = @ptrCast(@alignCast(ctx));

    // Only object values have fields
    const obj = switch (json_value.*) {
        .object => |o| o,
        else => return null,
    };

    // Map match_case to the appropriate field
    const field_name: []const u8 = switch (match_case) {
        .log_body => "message",
        .log_severity_text => "level",
        .log_severity_number => "severity_number",
        .log_attribute => key, // For attributes, use the key directly (e.g., "ddtags", "service")
        // TODO: These are unsupported today.
        // resource_schema_url
        // resource_attribute
        // scope_schema_url
        // scope_name
        // scope_version
        // scope_attribute
        else => return null,
    };

    // Get the field value
    const value = obj.get(field_name) orelse return null;

    // Return string value
    return switch (value) {
        .string => |s| s,
        else => null, // Only string values supported for now
    };
}

/// Process JSON logs with filter evaluation
/// Detects if input is an array or single object, applies filter to each log
fn processJsonLogsWithFilter(allocator: std.mem.Allocator, registry: *const PolicyRegistry, bus: *EventBus, data: []const u8) !ProcessResult {
    // Parse the JSON using std.json
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, data, .{}) catch {
        // If JSON parsing fails, return data unchanged (fail-open)
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = 0,
        };
    };
    defer parsed.deinit();

    // Create filter engine for evaluation (gets snapshot from registry internally)
    const engine = FilterEngine.init(allocator, bus, @constCast(registry));

    switch (parsed.value) {
        .array => |arr| {
            // Process array of logs
            var kept_logs: std.ArrayList(std.json.Value) = try .initCapacity(allocator, arr.capacity);
            defer kept_logs.deinit(allocator);

            var dropped_count: usize = 0;

            for (arr.items) |log_value| {
                // Evaluate filter using Hyperscan-accelerated regex matching
                const filter_result = engine.evaluate(@ptrCast(&log_value), datadogFieldAccessor);
                if (filter_result == .keep) {
                    try kept_logs.append(allocator, log_value);
                } else {
                    dropped_count += 1;
                }
            }

            // Build output JSON array
            var out: std.Io.Writer.Allocating = .init(allocator);
            try std.json.Stringify.value(kept_logs.items, .{}, &out.writer);
            return .{
                .data = try out.toOwnedSlice(),
                .dropped_count = dropped_count,
                .original_count = arr.items.len,
            };
        },
        .object => {
            // Process single log object
            const filter_result = engine.evaluate(@ptrCast(&parsed.value), datadogFieldAccessor);
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
        \\[{"level": "INFO", "message": "test1"}, {"level": "ERROR", "message": "test2"}]
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
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "DEBUG") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs =
        \\[{"level": "DEBUG", "message": "debug msg"}, {"level": "ERROR", "message": "error msg"}]
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
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "DEBUG") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const log =
        \\{"level": "DEBUG", "message": "debug msg"}
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
