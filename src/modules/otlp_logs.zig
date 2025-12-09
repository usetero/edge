const std = @import("std");
const proto = @import("proto");
const filter_engine = @import("../policy/filter_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const LogsData = proto.logs.LogsData;
const ResourceLogs = proto.logs.ResourceLogs;
const ScopeLogs = proto.logs.ScopeLogs;
const LogRecord = proto.logs.LogRecord;
const AnyValue = proto.common.AnyValue;
const KeyValue = proto.common.KeyValue;
const InstrumentationScope = proto.common.InstrumentationScope;

const FilterEngine = filter_engine.FilterEngine;
const FilterResult = filter_engine.FilterResult;
const MatchCase = filter_engine.MatchCase;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const LogsProcessingFailed = struct { err: []const u8 };

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

/// Process OTLP logs with filter evaluation
/// Takes decompressed JSON data and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
///
/// OTLP JSON format (ExportLogsServiceRequest/LogsData):
/// {
///   "resourceLogs": [
///     {
///       "resource": { "attributes": [...] },
///       "scopeLogs": [
///         {
///           "scope": { "name": "...", "version": "...", "attributes": [...] },
///           "logRecords": [
///             {
///               "body": { "stringValue": "..." },
///               "severityText": "INFO",
///               "severityNumber": 9,
///               "attributes": [...]
///             }
///           ]
///         }
///       ]
///     }
///   ]
/// }
pub fn processLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    // Only process JSON content types
    if (std.mem.indexOf(u8, content_type, "application/json") != null) {
        return processJsonLogs(allocator, registry, bus, data) catch |err| {
            bus.err(LogsProcessingFailed{ .err = @errorName(err) });
            const result = try allocator.alloc(u8, data.len);
            @memcpy(result, data);
            return .{
                .data = result,
                .dropped_count = 0,
                .original_count = 0,
            };
        };
    }

    // For non-JSON content types (protobuf), return unchanged
    // TODO: Add protobuf support in the future
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);
    return .{
        .data = result,
        .dropped_count = 0,
        .original_count = 0,
    };
}

/// Context for OTLP log field accessor - provides access to log record plus parent context
const OtlpLogContext = struct {
    log_record: *const LogRecord,
    resource_logs: *const ResourceLogs,
    scope_logs: *const ScopeLogs,
};

/// Extract string value from an AnyValue
fn getAnyValueString(value: ?AnyValue) ?[]const u8 {
    const v = value orelse return null;
    const val_union = v.value orelse return null;
    return switch (val_union) {
        .string_value => |s| s,
        else => null,
    };
}

/// Find attribute value by key in a KeyValue list
fn findAttribute(attributes: []const KeyValue, key: []const u8) ?[]const u8 {
    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, key)) {
            return getAnyValueString(kv.value);
        }
    }
    return null;
}

/// Field accessor for OTLP log format
/// Maps MatchCase to the appropriate field in the OTLP log structure
fn otlpFieldAccessor(ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8 {
    const log_ctx: *const OtlpLogContext = @ptrCast(@alignCast(ctx));

    return switch (match_case) {
        .log_body => getAnyValueString(log_ctx.log_record.body),
        .log_severity_text => if (log_ctx.log_record.severity_text.len > 0) log_ctx.log_record.severity_text else null,
        .log_attribute => findAttribute(log_ctx.log_record.attributes.items, key),
        .resource_schema_url => if (log_ctx.resource_logs.schema_url.len > 0) log_ctx.resource_logs.schema_url else null,
        .resource_attribute => if (log_ctx.resource_logs.resource) |res| findAttribute(res.attributes.items, key) else null,
        .scope_schema_url => if (log_ctx.scope_logs.schema_url.len > 0) log_ctx.scope_logs.schema_url else null,
        .scope_name => if (log_ctx.scope_logs.scope) |scope| (if (scope.name.len > 0) scope.name else null) else null,
        .scope_version => if (log_ctx.scope_logs.scope) |scope| (if (scope.version.len > 0) scope.version else null) else null,
        .scope_attribute => if (log_ctx.scope_logs.scope) |scope| findAttribute(scope.attributes.items, key) else null,
        // log_severity_number uses min/max range matching, not regex - handled separately
        .log_severity_number => null,
    };
}

fn processJsonLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Parse JSON into LogsData protobuf struct
    proto.protobuf.json.pb_options.emit_oneof_field_name = false;
    var parsed = try LogsData.jsonDecode(data, .{
        .ignore_unknown_fields = true,
    }, allocator);
    defer parsed.deinit();

    // Create filter engine for evaluation
    const engine = FilterEngine.init(allocator, bus, @constCast(registry));

    var original_count: usize = 0;
    var dropped_count: usize = 0;

    // Iterate through the nested structure and filter logs in place
    // Structure: LogsData -> ResourceLogs[] -> ScopeLogs[] -> LogRecord[]
    for (parsed.value.resource_logs.items) |*resource_logs| {
        for (resource_logs.scope_logs.items) |*scope_logs| {
            // Count original logs
            original_count += scope_logs.log_records.items.len;

            // Filter log records in place by shrinking the list
            var write_idx: usize = 0;
            for (scope_logs.log_records.items) |*log_record| {
                const ctx = OtlpLogContext{
                    .log_record = log_record,
                    .resource_logs = resource_logs,
                    .scope_logs = scope_logs,
                };

                const filter_result = engine.evaluate(@ptrCast(&ctx), otlpFieldAccessor);

                if (filter_result == .keep) {
                    // Keep this log - move to write position if needed
                    if (write_idx != scope_logs.log_records.items.len - 1) {
                        scope_logs.log_records.items[write_idx] = log_record.*;
                    }
                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_logs.log_records.shrinkRetainingCapacity(write_idx);
        }
    }

    // Re-serialize to JSON
    const output = try parsed.value.jsonEncode(.{}, allocator);

    return .{
        .data = @constCast(output),
        .dropped_count = dropped_count,
        .original_count = original_count,
    };
}

// =============================================================================
// Tests
// =============================================================================

test "processLogs - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs =
        \\{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"logs-integration-test"}}]},"scopeLogs":[{"scope":{"name":"my-target","version":""},"logRecords":[{"observedTimeUnixNano":"1715753202587469939","severityNumber":9,"severityText":"INFO","body":{"stringValue":"hello from banana. My price is 2.99."},"traceId":"","spanId":""}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "banana") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "resourceLogs") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
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

    const data = "some protobuf data";

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), data, "application/x-protobuf");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - no policies keeps all logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs =
        \\{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"msg1"}},{"severityText":"DEBUG","body":{"stringValue":"msg2"}}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "msg1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "msg2") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processLogs - DROP policy filters logs by severity" {
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
        \\{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"info msg"}},{"severityText":"DEBUG","body":{"stringValue":"debug msg"}}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // DEBUG log should be dropped, INFO log should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug msg") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "info msg") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processLogs - DROP policy filters logs by body content" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs containing "secret"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-secret"),
        .name = try allocator.dupe(u8, "drop-secret"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "secret") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs =
        \\{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"normal message"}},{"severityText":"INFO","body":{"stringValue":"contains secret data"}}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // Log with "secret" should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "normal message") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
}

test "processLogs - DROP policy filters logs by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs from "test-service"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-test-service"),
        .name = try allocator.dupe(u8, "drop-test-service"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .resource_attribute = .{
            .key = try allocator.dupe(u8, "service.name"),
            .regex = try allocator.dupe(u8, "test-service"),
        } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs =
        \\{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"from test service"}}]}]},{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"prod-service"}}]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"from prod service"}}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // Logs from test-service should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from test service") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from prod service") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}

test "processLogs - all logs dropped returns empty structure" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all logs (using body pattern that matches both messages)
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "msg") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs =
        \\{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"scope":{"name":"test"},"logRecords":[{"severityText":"INFO","body":{"stringValue":"msg1"}},{"severityText":"DEBUG","body":{"stringValue":"msg2"}}]}]}]}
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 2), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.allDropped());
}
