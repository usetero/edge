const std = @import("std");
const proto = @import("proto");
const policy_engine = @import("../policy/policy_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const LogsData = proto.logs.LogsData;
const ResourceLogs = proto.logs.ResourceLogs;
const ScopeLogs = proto.logs.ScopeLogs;
const LogRecord = proto.logs.LogRecord;
const AnyValue = proto.common.AnyValue;
const KeyValue = proto.common.KeyValue;
const InstrumentationScope = proto.common.InstrumentationScope;

const PolicyEngine = policy_engine.PolicyEngine;
const PolicyResult = policy_engine.PolicyResult;
const FilterDecision = policy_engine.FilterDecision;
const MatchCase = policy_engine.MatchCase;
const MAX_POLICIES = @import("../hyperscan/matcher_index.zig").MAX_POLICIES;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const LogsProcessingFailed = struct { err: []const u8, contentType: []const u8 };

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

/// Content format for OTLP logs
pub const ContentFormat = enum {
    json,
    protobuf,
    unknown,

    /// Detect format from content-type header
    pub fn fromContentType(content_type: []const u8) ContentFormat {
        if (std.mem.indexOf(u8, content_type, "application/json") != null) {
            return .json;
        }
        if (std.mem.indexOf(u8, content_type, "application/x-protobuf") != null) {
            return .protobuf;
        }
        return .unknown;
    }
};

/// Process OTLP logs with filter evaluation
/// Takes decompressed data (JSON or protobuf) and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
///
/// OTLP format (ExportLogsServiceRequest/LogsData):
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
const LogsProcessingStarted = struct {
    content_type: []const u8,
    data_len: usize,
    format: []const u8,
};

pub fn processLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    const format = ContentFormat.fromContentType(content_type);

    bus.debug(LogsProcessingStarted{
        .content_type = content_type,
        .data_len = data.len,
        .format = @tagName(format),
    });

    return switch (format) {
        .json => processJsonLogs(allocator, registry, bus, data) catch |err| {
            bus.err(LogsProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .protobuf => processProtobufLogs(allocator, registry, bus, data) catch |err| {
            bus.err(LogsProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .unknown => copyUnchanged(allocator, data),
    };
}

/// Copy data unchanged (fail-open behavior)
fn copyUnchanged(allocator: std.mem.Allocator, data: []const u8) !ProcessResult {
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
        .log_trace_id => if (log_ctx.log_record.trace_id.len > 0) log_ctx.log_record.trace_id else null,
        .log_span_id => if (log_ctx.log_record.span_id.len > 0) log_ctx.log_record.span_id else null,
        .log_event_name => null, // OTLP LogRecord doesn't have a dedicated event_name field
        .log_attribute => findAttribute(log_ctx.log_record.attributes.items, key),
        .resource_schema_url => if (log_ctx.resource_logs.schema_url.len > 0) log_ctx.resource_logs.schema_url else null,
        .resource_attribute => if (log_ctx.resource_logs.resource) |res| findAttribute(res.attributes.items, key) else null,
        .scope_schema_url => if (log_ctx.scope_logs.schema_url.len > 0) log_ctx.scope_logs.schema_url else null,
        .scope_attribute => if (log_ctx.scope_logs.scope) |scope| findAttribute(scope.attributes.items, key) else null,
    };
}

/// Result of filtering logs in-place
const FilterCounts = struct {
    original_count: usize,
    dropped_count: usize,
};

/// Filter logs in-place within the LogsData structure
/// This is the shared filtering logic used by both JSON and protobuf processing
///
/// Note: This function does not free dropped log records. The caller is responsible
/// for memory management (e.g., via json.Parsed.deinit() or LogsData.deinit()).
fn filterLogsInPlace(
    logs_data: *LogsData,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    allocator: std.mem.Allocator,
) FilterCounts {
    const engine = PolicyEngine.init(allocator, bus, @constCast(registry));

    var original_count: usize = 0;
    var dropped_count: usize = 0;

    // Buffer for matched policy IDs (stack allocated)
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;

    // Iterate through the nested structure and filter logs in place
    // Structure: LogsData -> ResourceLogs[] -> ScopeLogs[] -> LogRecord[]
    for (logs_data.resource_logs.items) |*resource_logs| {
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

                const result = engine.evaluate(@ptrCast(&ctx), otlpFieldAccessor, &policy_id_buf);

                if (result.decision.shouldContinue()) {
                    // Keep this log - move to write position if needed
                    // TODO: Apply transforms using result.matched_policy_ids
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

    return .{
        .original_count = original_count,
        .dropped_count = dropped_count,
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

    // Filter logs in-place
    const counts = filterLogsInPlace(&parsed.value, registry, bus, allocator);

    // Re-serialize to JSON
    const output = try parsed.value.jsonEncode(.{}, allocator);

    return .{
        .data = @constCast(output),
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
    };
}

fn processProtobufLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Basic validation: empty data or data that looks like JSON should not be decoded as protobuf.
    // The protobuf library panics on certain invalid inputs, so we validate first.
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON (starts with '{' or '[') - this would cause protobuf decoder to panic
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Use an arena for the protobuf decode/filter/encode cycle.
    // This ensures all allocations (including dropped log records) are freed together.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into LogsData struct using arena
    var logs_data = try LogsData.decode(&reader, arena_alloc);

    // Filter logs in-place
    const counts = filterLogsInPlace(&logs_data, registry, bus, arena_alloc);

    // Re-serialize to protobuf - use main allocator for output since we return it
    // TODO: we should be passing the IO Writer to these methods to write the response bytes
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try logs_data.encode(&output_writer.writer, arena_alloc);

    // Transfer ownership of the written data to caller
    const output = try output_writer.toOwnedSlice();

    return .{
        .data = output,
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
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

test "processLogs - unknown content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some unknown data";

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), data, "text/plain");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - malformed protobuf returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "not valid protobuf";

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), malformed, "application/x-protobuf");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "DEBUG") },
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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "secret") },
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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .resource_attribute = try allocator.dupe(u8, "service.name") },
        .match = .{ .regex = try allocator.dupe(u8, "test-service") },
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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "msg") },
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

// =============================================================================
// Protobuf Tests
// =============================================================================

/// Helper to create protobuf-encoded LogsData for testing
fn createTestProtobufLogs(allocator: std.mem.Allocator, messages: []const []const u8) ![]u8 {
    // Use an arena for the temporary protobuf structures
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var scope_logs = ScopeLogs{};
    for (messages) |msg| {
        const log_record = LogRecord{
            .severity_text = "INFO",
            .body = .{ .value = .{ .string_value = msg } },
        };
        try scope_logs.log_records.append(arena_alloc, log_record);
    }

    var resource_logs = ResourceLogs{};
    try resource_logs.scope_logs.append(arena_alloc, scope_logs);

    var logs_data = LogsData{};
    try logs_data.resource_logs.append(arena_alloc, resource_logs);

    // Encode to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try logs_data.encode(&output_writer.writer, arena_alloc);

    return try output_writer.toOwnedSlice();
}

test "processLogs - protobuf parses and re-serializes" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create valid protobuf data
    const proto_data = try createTestProtobufLogs(allocator, &.{ "hello world", "test message" });
    defer allocator.free(proto_data);

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    // With no policies, all logs should be kept
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processLogs - protobuf DROP policy filters logs" {
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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "secret") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with one log containing "secret"
    const proto_data = try createTestProtobufLogs(allocator, &.{ "normal message", "contains secret data" });
    defer allocator.free(proto_data);

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    // One log should be dropped
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());

    // Verify the result can be decoded and contains only the normal message
    var reader = std.Io.Reader.fixed(result.data);
    var decoded = try LogsData.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    // Should have 1 log record remaining
    var total_logs: usize = 0;
    for (decoded.resource_logs.items) |*rl| {
        for (rl.scope_logs.items) |*sl| {
            total_logs += sl.log_records.items.len;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), total_logs);
}

test "processLogs - protobuf all logs dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all logs
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "msg") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with logs that all match the pattern
    const proto_data = try createTestProtobufLogs(allocator, &.{ "msg1", "msg2", "msg3" });
    defer allocator.free(proto_data);

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 3), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 3), result.original_count);
    try std.testing.expect(result.allDropped());
}

test "ContentFormat.fromContentType" {
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json"));
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json; charset=utf-8"));
    try std.testing.expectEqual(ContentFormat.protobuf, ContentFormat.fromContentType("application/x-protobuf"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType("text/plain"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType(""));
}
