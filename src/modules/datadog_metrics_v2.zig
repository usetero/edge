const std = @import("std");
const zimdjson = @import("zimdjson");
const policy_engine = @import("../policy/policy_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");
const datadog_metric = @import("datadog_metric.zig");

const PolicyEngine = policy_engine.PolicyEngine;
const PolicyResult = policy_engine.PolicyResult;
const FilterDecision = policy_engine.FilterDecision;
const MetricFieldRef = policy_engine.MetricFieldRef;
const MetricField = @import("proto").policy.MetricField;
const MAX_POLICIES = policy.MAX_POLICIES;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;
const MetricSeries = datadog_metric.MetricSeries;
const MetricPayload = datadog_metric.MetricPayload;

const StreamParser = zimdjson.ondemand.StreamParser(.default);
const ArrayList = std.ArrayListUnmanaged;

/// Result of processing metrics
pub const ProcessResult = struct {
    /// The processed data (caller owns this slice)
    data: []u8,
    /// Number of metrics that were dropped by filter policies
    dropped_count: usize,
    /// Original number of metrics before filtering
    original_count: usize,

    /// Returns true if any metrics were dropped
    pub fn wasModified(self: ProcessResult) bool {
        return self.dropped_count > 0;
    }

    /// Returns true if all metrics were dropped
    pub fn allDropped(self: ProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Process Datadog metrics with filter evaluation
/// Takes decompressed JSON data and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
pub fn processMetrics(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    // Process based on content type
    if (std.mem.indexOf(u8, content_type, "application/json") != null) {
        // Parse JSON and apply filter policies
        return processJsonMetricsWithFilter(allocator, registry, bus, data);
    }

    // For non-JSON content types, return unchanged
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);
    return .{
        .data = result,
        .dropped_count = 0,
        .original_count = 0,
    };
}

/// Context for field accessor - holds the MetricSeries struct
const FieldAccessorContext = struct {
    series: *MetricSeries,
    /// Cached concatenated tags string for tag matching
    tags_cache: ?[]const u8,
};

const MetricMutateOp = policy.MetricMutateOp;
const MetricFieldMutator = policy.MetricFieldMutator;

/// Field accessor for Datadog metric format
/// Maps MetricFieldRef to actual field values in MetricSeries
fn datadogMetricFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const field_ctx: *const FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const series = field_ctx.series;

    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => series.metric,
            .METRIC_FIELD_UNIT => series.unit,
            // Datadog format doesn't have these OTLP fields
            .METRIC_FIELD_DESCRIPTION,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL,
            .METRIC_FIELD_SCOPE_SCHEMA_URL,
            .METRIC_FIELD_SCOPE_NAME,
            .METRIC_FIELD_SCOPE_VERSION,
            .METRIC_FIELD_UNSPECIFIED,
            => null,
            // Handle any unknown/future enum values
            _ => null,
        },
        .datapoint_attribute => |key| {
            // For tags, we match on the concatenated tags string
            if (std.mem.eql(u8, key, "tags")) {
                return field_ctx.tags_cache;
            }
            // source_type_name is accessible as an attribute
            if (std.mem.eql(u8, key, "source_type_name")) {
                return series.source_type_name;
            }
            return null;
        },
        .resource_attribute => |key| {
            // Check resources for matching type
            if (series.resources) |resources| {
                for (resources) |*res| {
                    if (res.type) |res_type| {
                        if (std.mem.eql(u8, key, res_type)) {
                            return res.name;
                        }
                    }
                }
            }
            return null;
        },
        .scope_attribute => null, // Datadog format doesn't have scope attributes
    };
}

/// Field mutator for Datadog metric format
/// Supports remove and set operations on known fields
fn datadogMetricFieldMutator(ctx: *anyopaque, op: MetricMutateOp) bool {
    const field_ctx: *FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const series = field_ctx.series;

    switch (op) {
        .remove => |field| {
            switch (field) {
                .metric_field => |mf| switch (mf) {
                    .METRIC_FIELD_NAME => {
                        if (series.metric != null) {
                            series.metric = null;
                            return true;
                        }
                        return false;
                    },
                    .METRIC_FIELD_UNIT => {
                        if (series.unit != null) {
                            series.unit = null;
                            return true;
                        }
                        return false;
                    },
                    else => return false,
                },
                .datapoint_attribute => |key| {
                    if (std.mem.eql(u8, key, "tags")) {
                        if (series.tags != null) {
                            series.tags = null;
                            return true;
                        }
                        return false;
                    }
                    if (std.mem.eql(u8, key, "source_type_name")) {
                        if (series.source_type_name != null) {
                            series.source_type_name = null;
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
                .metric_field => |mf| switch (mf) {
                    .METRIC_FIELD_NAME => {
                        if (s.upsert or series.metric != null) {
                            series.metric = s.value;
                            return true;
                        }
                        return false;
                    },
                    .METRIC_FIELD_UNIT => {
                        if (s.upsert or series.unit != null) {
                            series.unit = s.value;
                            return true;
                        }
                        return false;
                    },
                    else => return false,
                },
                .datapoint_attribute => |key| {
                    if (std.mem.eql(u8, key, "source_type_name")) {
                        if (s.upsert or series.source_type_name != null) {
                            series.source_type_name = s.value;
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
            // Rename not yet supported for Datadog metrics
            return false;
        },
    }
}

/// Result of evaluating a single metric series
const FilterMetricResult = struct {
    keep: bool,
    mutated: bool,
};

/// Evaluate a single metric series against policies
fn filterMetric(
    allocator: std.mem.Allocator,
    engine: *const PolicyEngine,
    series: *MetricSeries,
    policy_id_buf: [][]const u8,
) FilterMetricResult {
    // Build tags cache for matching
    const tags_cache = buildTagsCache(allocator, series.tags) catch null;
    defer if (tags_cache) |tc| allocator.free(tc);

    var field_ctx = FieldAccessorContext{
        .series = series,
        .tags_cache = tags_cache,
    };
    const result = engine.evaluate(.metric, &field_ctx, datadogMetricFieldAccessor, datadogMetricFieldMutator, policy_id_buf);
    return .{
        .keep = result.decision.shouldContinue(),
        .mutated = result.matched_policy_ids.len > 0,
    };
}

/// Build a concatenated string of tags for pattern matching
fn buildTagsCache(allocator: std.mem.Allocator, tags: ?[][]const u8) !?[]const u8 {
    const t = tags orelse return null;
    if (t.len == 0) return null;

    // Calculate total length
    var total_len: usize = 0;
    for (t) |tag| {
        if (total_len > 0) total_len += 1; // separator
        total_len += tag.len;
    }

    // Allocate and build
    const buf = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (t) |tag| {
        if (pos > 0) {
            buf[pos] = ',';
            pos += 1;
        }
        @memcpy(buf[pos .. pos + tag.len], tag);
        pos += tag.len;
    }

    return buf;
}

/// Accumulated state for filtering metrics
const FilterState = struct {
    kept: ArrayList(MetricSeries) = .empty,
    original_count: usize = 0,
    dropped_count: usize = 0,
    mutated: bool = false,

    fn deinit(self: *FilterState, allocator: std.mem.Allocator) void {
        self.kept.deinit(allocator);
    }
};

/// Build the final ProcessResult from filtering state
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

    // If everything was dropped, return empty series
    if (state.kept.items.len == 0) {
        const empty_payload = "{\"errors\":[]}";
        const result = try allocator.alloc(u8, empty_payload.len);
        @memcpy(result, empty_payload);
        return .{
            .data = result,
            .dropped_count = state.dropped_count,
            .original_count = state.original_count,
        };
    }

    // Serialize kept metrics as a payload
    var out: std.Io.Writer.Allocating = .init(allocator);

    const payload = MetricPayload{
        .series = state.kept.items,
    };
    try std.json.Stringify.value(payload, .{}, &out.writer);

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

/// Process JSON metrics with filter evaluation using zimdjson streaming parser
fn processJsonMetricsWithFilter(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    var reader = std.Io.Reader.fixed(data);
    const document = parser.parseFromReader(allocator, &reader) catch {
        return returnUnchanged(allocator, data, 0);
    };

    const engine = PolicyEngine.init(bus, @constCast(registry));

    // Parse as MetricPayload
    var payload: std.json.Parsed(MetricPayload) = document.as(MetricPayload, allocator, .{}) catch {
        return returnUnchanged(allocator, data, 0);
    };
    defer payload.deinit();

    const series_list = payload.value.series orelse {
        return returnUnchanged(allocator, data, 0);
    };

    var state = FilterState{};
    defer state.deinit(allocator);
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;

    for (series_list) |*series| {
        state.original_count += 1;
        const filter_result = filterMetric(allocator, &engine, @constCast(series), &policy_id_buf);
        if (filter_result.mutated) state.mutated = true;
        if (filter_result.keep) {
            try state.kept.append(allocator, series.*);
        } else {
            state.dropped_count += 1;
        }
    }

    return buildResult(allocator, &state, data);
}

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

test "processMetrics - no policies keeps all metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "system.load.1") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processMetrics - DROP policy filters metrics by name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-metrics"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug\\.") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"series": [
        \\  {"metric": "debug.internal", "type": 3, "points": [{"timestamp": 1636629071, "value": 1.0}]},
        \\  {"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}
        \\]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    // debug.internal should be dropped, system.load.1 should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "system.load.1") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processMetrics - returns 202-compatible response when all metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches the test metric
    var drop_all = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_all.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "system") },
    });
    defer drop_all.deinit(allocator);

    try registry.updatePolicies(&.{drop_all}, "file-provider", .file);

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings("{\"errors\":[]}", result.data);
    try std.testing.expect(result.allDropped());
}

test "processMetrics - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), malformed, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processMetrics - non-JSON content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some raw metric data";

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), data, "text/plain");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processMetrics - filter on tags" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches on tags containing "env:dev"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-dev-env"),
        .name = try allocator.dupe(u8, "drop-dev-env"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try allocator.dupe(u8, "tags") },
        .match = .{ .regex = try allocator.dupe(u8, "env:dev") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"series": [
        \\  {"metric": "dev.metric", "type": 3, "points": [{"timestamp": 1, "value": 1.0}], "tags": ["env:dev", "service:test"]},
        \\  {"metric": "prod.metric", "type": 3, "points": [{"timestamp": 1, "value": 1.0}], "tags": ["env:prod", "service:web"]}
        \\]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    // dev.metric should be dropped, prod.metric should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "dev.metric") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "prod.metric") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}

test "processMetrics - preserves all fields when no metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - all metrics kept, original data returned unchanged

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "interval": 60, "unit": "percent", "points": [{"timestamp": 1636629071, "value": 0.7}], "tags": ["env:prod"], "resources": [{"name": "host1", "type": "host"}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    // When nothing is dropped, original data is returned unchanged
    try std.testing.expect(std.mem.indexOf(u8, result.data, "system.load.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "interval") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "resources") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
}

test "buildTagsCache - concatenates tags with comma separator" {
    const allocator = std.testing.allocator;

    var tags = [_][]const u8{ "env:prod", "service:web", "region:us-east" };
    const cache = try buildTagsCache(allocator, &tags);
    defer if (cache) |c| allocator.free(c);

    try std.testing.expectEqualStrings("env:prod,service:web,region:us-east", cache.?);
}

test "buildTagsCache - returns null for null tags" {
    const allocator = std.testing.allocator;

    const cache = try buildTagsCache(allocator, null);
    try std.testing.expect(cache == null);
}

test "buildTagsCache - returns null for empty tags" {
    const allocator = std.testing.allocator;

    var tags = [_][]const u8{};
    const cache = try buildTagsCache(allocator, &tags);
    try std.testing.expect(cache == null);
}
