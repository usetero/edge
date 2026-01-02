const std = @import("std");
const zimdjson = @import("zimdjson");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");
const datadog_log = @import("datadog_log.zig");

const PolicyEngine = policy.PolicyEngine;
const PolicyResult = policy.PolicyResult;
const FilterDecision = policy.FilterDecision;
const FieldRef = policy.FieldRef;
const LogField = @import("proto").policy.LogField;
const MAX_MATCHES_PER_SCAN = policy.MAX_MATCHES_PER_SCAN;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;
const DatadogLog = datadog_log.DatadogLog;

const StreamParser = zimdjson.ondemand.StreamParser(.default);
const Object = StreamParser.Object;
const Document = StreamParser.Document;
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

/// Context for field accessor and mutator - holds the DatadogLog struct
const FieldAccessorContext = struct {
    log: *DatadogLog,
};

const MutateOp = policy.MutateOp;
const FieldMutator = policy.FieldMutator;

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
            // Check extra fields for dynamic attributes
            if (log.extra.get(key)) |any_value| {
                // Only string values can be matched with regex
                if (any_value == .string) {
                    return any_value.string.get() catch null;
                }
            }
            return null;
        },
        // Datadog JSON format doesn't have resource/scope attributes
        .resource_attribute, .scope_attribute => null,
    };
}

/// Field mutator for Datadog JSON log format
/// Supports remove and set operations on known fields
fn datadogFieldMutator(ctx: *anyopaque, op: MutateOp) bool {
    const field_ctx: *FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const log = field_ctx.log;

    switch (op) {
        .remove => |field| {
            switch (field) {
                .log_field => |lf| switch (lf) {
                    .LOG_FIELD_BODY => {
                        if (log.message != null) {
                            log.message = null;
                            return true;
                        }
                        return false;
                    },
                    .LOG_FIELD_SEVERITY_TEXT => {
                        var removed = false;
                        if (log.status != null) {
                            log.status = null;
                            removed = true;
                        }
                        if (log.level != null) {
                            log.level = null;
                            removed = true;
                        }
                        return removed;
                    },
                    else => return false,
                },
                .log_attribute => |key| {
                    if (std.mem.eql(u8, key, "service")) {
                        if (log.service != null) {
                            log.service = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "hostname")) {
                        if (log.hostname != null) {
                            log.hostname = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "ddsource")) {
                        if (log.ddsource != null) {
                            log.ddsource = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "ddtags")) {
                        if (log.ddtags != null) {
                            log.ddtags = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "environment")) {
                        if (log.environment != null) {
                            log.environment = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "custom_field")) {
                        if (log.custom_field != null) {
                            log.custom_field = null;
                            return true;
                        }
                        return false;
                    }
                    return false;
                },
                .resource_attribute, .scope_attribute => return false,
            }
        },
        .set => |s| {
            switch (s.field) {
                .log_field => |lf| switch (lf) {
                    .LOG_FIELD_BODY => {
                        if (s.upsert or log.message != null) {
                            log.message = s.value;
                            return true;
                        }
                        return false;
                    },
                    .LOG_FIELD_SEVERITY_TEXT => {
                        if (s.upsert or log.status != null) {
                            log.status = s.value;
                            return true;
                        }
                        return false;
                    },
                    else => return false,
                },
                .log_attribute => |key| {
                    if (std.mem.eql(u8, key, "service")) {
                        if (s.upsert or log.service != null) {
                            log.service = s.value;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "hostname")) {
                        if (s.upsert or log.hostname != null) {
                            log.hostname = s.value;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "ddsource")) {
                        if (s.upsert or log.ddsource != null) {
                            log.ddsource = s.value;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "ddtags")) {
                        if (s.upsert or log.ddtags != null) {
                            log.ddtags = s.value;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "environment")) {
                        if (s.upsert or log.environment != null) {
                            log.environment = s.value;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "custom_field")) {
                        if (s.upsert or log.custom_field != null) {
                            log.custom_field = s.value;
                            return true;
                        }
                        return false;
                    }
                    return false;
                },
                .resource_attribute, .scope_attribute => return false,
            }
        },
        .rename => {
            // Rename not yet supported for Datadog logs
            return false;
        },
    }
}

/// Result of evaluating a single log
const FilterLogResult = struct {
    keep: bool,
    mutated: bool,
};

/// Evaluate a single log against policies, applying transforms if matched.
/// Returns whether to keep the log and whether it was mutated.
fn filterLog(engine: *const PolicyEngine, log: *DatadogLog, policy_id_buf: [][]const u8) FilterLogResult {
    var field_ctx = FieldAccessorContext{ .log = log };
    const result = engine.evaluate(.log, &field_ctx, datadogFieldAccessor, datadogFieldMutator, policy_id_buf);
    return .{
        .keep = result.decision.shouldContinue(),
        .mutated = result.matched_policy_ids.len > 0,
    };
}

/// Accumulated state for filtering logs
const FilterState = struct {
    kept: ArrayList(DatadogLog) = .empty,
    original_count: usize = 0,
    dropped_count: usize = 0,
    mutated: bool = false,

    fn deinit(self: *FilterState, allocator: std.mem.Allocator) void {
        self.kept.deinit(allocator);
    }
};

/// Build the final ProcessResult from filtering state.
/// Handles the cases: nothing changed, everything dropped, or needs reserialization.
fn buildResult(
    allocator: std.mem.Allocator,
    state: *const FilterState,
    original_data: []const u8,
) !ProcessResult {
    // If nothing was dropped and nothing mutated, return original data
    if (state.dropped_count == 0 and !state.mutated) {
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

    // Serialize kept logs (either some dropped or mutations applied)
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

    const engine = PolicyEngine.init(bus, @constCast(registry));

    const value_type = document.getType() catch {
        return returnUnchanged(allocator, data, 0);
    };

    var state = FilterState{};
    defer state.deinit(allocator);
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;

    switch (value_type) {
        .array => {
            var array: std.json.Parsed([]DatadogLog) = document.as([]DatadogLog, allocator, .{}) catch {
                return returnUnchanged(allocator, data, 0);
            };
            defer array.deinit();

            for (array.value) |*log_obj| {
                state.original_count += 1;
                const filter_result = filterLog(&engine, log_obj, &policy_id_buf);
                if (filter_result.mutated) state.mutated = true;
                if (filter_result.keep) {
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
            const filter_result = filterLog(&engine, &log_obj.value, &policy_id_buf);
            if (filter_result.mutated) state.mutated = true;
            if (filter_result.keep) {
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

test "datadogFieldAccessor - extra field lookup" {
    // Unit test to verify the field accessor can retrieve extra fields
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "trace_id": "abc123-def456"}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    var parsed = try doc.as(DatadogLog, allocator, .{});
    defer parsed.deinit();

    // Verify the extra field was parsed
    try std.testing.expectEqual(@as(usize, 1), parsed.value.extra.count());
    try std.testing.expect(parsed.value.extra.contains("trace_id"));

    // Test the accessor directly
    var field_ctx = FieldAccessorContext{ .log = &parsed.value };

    // Test known field
    const message_val = datadogFieldAccessor(&field_ctx, .{ .log_field = .LOG_FIELD_BODY });
    try std.testing.expect(message_val != null);
    try std.testing.expectEqualStrings("test", message_val.?);

    // Test extra field - this is the critical test
    const trace_val = datadogFieldAccessor(&field_ctx, .{ .log_attribute = "trace_id" });
    try std.testing.expect(trace_val != null);
    try std.testing.expectEqualStrings("abc123-def456", trace_val.?);
}

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
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
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
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
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
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
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

    // When nothing is dropped, original data is returned unchanged - extra fields preserved
    try std.testing.expect(std.mem.indexOf(u8, result.data, "kept log") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "extra_field") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "should_be_preserved") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "nested") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "array_field") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
}

test "processLogs - mutation triggers reserialization and removes field" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a policy with keep=all and a transform that removes the 'service' field
    var transform = proto.policy.LogTransform{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
    });

    var test_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "remove-service-policy"),
        .name = try allocator.dupe(u8, "remove-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    // Match on message containing "test"
    try test_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer test_policy.deinit(allocator);

    try registry.updatePolicies(&.{test_policy}, "test", .file);

    // Log with service field that should be removed
    const logs =
        \\[{"message": "test log message", "service": "my-service", "status": "info"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // The log should be kept (keep=all)
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);

    // The message and status should still be present
    try std.testing.expect(std.mem.indexOf(u8, result.data, "test log message") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "info") != null);

    // The service field should be removed by the transform
    try std.testing.expect(std.mem.indexOf(u8, result.data, "my-service") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "\"service\"") == null);
}

test "processLogs - filter on dynamic extra field not in schema" {
    // Tests that we can filter on arbitrary fields that are not part of the
    // known DatadogLog schema (stored in the 'extra' hashmap)
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches on a dynamic field "trace_id" (not in schema)
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-trace"),
        .name = try allocator.dupe(u8, "drop-trace-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "trace_id") },
        .match = .{ .regex = try allocator.dupe(u8, "^abc123") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Logs with dynamic "trace_id" field - one matches pattern, one doesn't
    // Using unique message strings to avoid substring matching issues
    const logs =
        \\[{"message": "first-log-match", "trace_id": "abc123-def456"}, {"message": "second-log-nomatch", "trace_id": "xyz789-other"}, {"message": "third-log-notrace"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // Check counts
    try std.testing.expectEqual(@as(usize, 3), result.original_count);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);

    // Log with trace_id starting with "abc123" should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "first-log-match") == null);
    // Logs with other trace_id or no trace_id should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "second-log-nomatch") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "third-log-notrace") != null);
}

test "processLogs - filter on nested extra field with exists" {
    // Tests using exists matching on dynamic extra fields
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that drops logs where "debug_info" field exists
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-info"),
        .name = try allocator.dupe(u8, "drop-debug-info-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "debug_info") },
        .match = .{ .exists = true },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Mix of logs with and without the debug_info field
    const logs =
        \\[{"message": "debug log", "debug_info": "stack trace here"}, {"message": "normal log", "service": "api"}]
    ;

    const result = try processLogs(allocator, &registry, noop_bus.eventBus(), logs, "application/json");
    defer allocator.free(result.data);

    // Log with debug_info should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug log") == null);
    // Log without debug_info should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "normal log") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}
