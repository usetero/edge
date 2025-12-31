//! OTLP Metrics Processing Module
//!
//! Processes OpenTelemetry metrics with policy-based filtering.
//! Supports both JSON and protobuf formats.
//!
//! OTLP Metrics Structure:
//! MetricsData
//! └─── ResourceMetrics
//!   ├── Resource
//!   ├── SchemaURL
//!   └── ScopeMetrics
//!      ├── Scope
//!      ├── SchemaURL
//!      └── Metric
//!         ├── Name
//!         ├── Description
//!         ├── Unit
//!         └── data (Gauge, Sum, Histogram, ExponentialHistogram, Summary)

const std = @import("std");
const proto = @import("proto");
const policy_engine = @import("../policy/policy_engine.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const MetricsData = proto.metrics.MetricsData;
const ResourceMetrics = proto.metrics.ResourceMetrics;
const ScopeMetrics = proto.metrics.ScopeMetrics;
const Metric = proto.metrics.Metric;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;

const PolicyEngine = policy_engine.PolicyEngine;
const PolicyResult = policy_engine.PolicyResult;
const FilterDecision = policy_engine.FilterDecision;
const MetricFieldRef = policy_engine.MetricFieldRef;
const MetricField = proto.policy.MetricField;
const MAX_POLICIES = policy.MAX_POLICIES;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Observability Events
// =============================================================================

const MetricsProcessingStarted = struct {
    content_type: []const u8,
    data_len: usize,
    format: []const u8,
};

const MetricsProcessingFailed = struct { err: []const u8, contentType: []const u8 };

// =============================================================================
// Public API
// =============================================================================

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

/// Content format for OTLP metrics
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

/// Process OTLP metrics with filter evaluation
/// Takes decompressed data (JSON or protobuf) and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
pub fn processMetrics(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    const format = ContentFormat.fromContentType(content_type);

    bus.debug(MetricsProcessingStarted{
        .content_type = content_type,
        .data_len = data.len,
        .format = @tagName(format),
    });

    return switch (format) {
        .json => processJsonMetrics(allocator, registry, bus, data) catch |err| {
            bus.err(MetricsProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .protobuf => processProtobufMetrics(allocator, registry, bus, data) catch |err| {
            bus.err(MetricsProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .unknown => copyUnchanged(allocator, data),
    };
}

// =============================================================================
// Internal Implementation
// =============================================================================

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

/// Context for OTLP metric field accessor - provides access to metric plus parent context
const OtlpMetricContext = struct {
    metric: *Metric,
    resource_metrics: *ResourceMetrics,
    scope_metrics: *ScopeMetrics,
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

/// Field accessor for OTLP metric format
/// Maps MetricFieldRef to the appropriate field in the OTLP metric structure
fn otlpMetricFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const metric_ctx: *const OtlpMetricContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => if (metric_ctx.metric.name.len > 0) metric_ctx.metric.name else null,
            .METRIC_FIELD_DESCRIPTION => if (metric_ctx.metric.description.len > 0) metric_ctx.metric.description else null,
            .METRIC_FIELD_UNIT => if (metric_ctx.metric.unit.len > 0) metric_ctx.metric.unit else null,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL => if (metric_ctx.resource_metrics.schema_url.len > 0) metric_ctx.resource_metrics.schema_url else null,
            .METRIC_FIELD_SCOPE_SCHEMA_URL => if (metric_ctx.scope_metrics.schema_url.len > 0) metric_ctx.scope_metrics.schema_url else null,
            .METRIC_FIELD_SCOPE_NAME => if (metric_ctx.scope_metrics.scope) |scope| (if (scope.name.len > 0) scope.name else null) else null,
            .METRIC_FIELD_SCOPE_VERSION => if (metric_ctx.scope_metrics.scope) |scope| (if (scope.version.len > 0) scope.version else null) else null,
            else => null,
        },
        .datapoint_attribute => |key| {
            // For datapoint attributes, we need to check attributes in the data points
            // This is complex as metrics have different data types (gauge, sum, histogram, etc.)
            // For now, we check metadata attributes on the metric itself
            return findAttribute(metric_ctx.metric.metadata.items, key);
        },
        .resource_attribute => |key| if (metric_ctx.resource_metrics.resource) |res| findAttribute(res.attributes.items, key) else null,
        .scope_attribute => |key| if (metric_ctx.scope_metrics.scope) |scope| findAttribute(scope.attributes.items, key) else null,
    };
}

const MetricMutateOp = policy.MetricMutateOp;

/// Field mutator for OTLP metric format
/// Currently only supports drop decision (keep=false), no transforms
fn otlpMetricFieldMutator(_: *anyopaque, _: MetricMutateOp) bool {
    // Metric transforms not yet implemented for OTLP
    return false;
}

/// Result of filtering metrics in-place
const FilterCounts = struct {
    original_count: usize,
    dropped_count: usize,
};

/// Filter metrics in-place within the MetricsData structure
/// This is the shared filtering logic used by both JSON and protobuf processing
fn filterMetricsInPlace(
    metrics_data: *MetricsData,
    registry: *const PolicyRegistry,
    bus: *EventBus,
) FilterCounts {
    const engine = PolicyEngine.init(bus, @constCast(registry));

    var original_count: usize = 0;
    var dropped_count: usize = 0;

    // Buffer for matched policy IDs (stack allocated)
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;

    // Iterate through the nested structure and filter metrics in place
    // Structure: MetricsData -> ResourceMetrics[] -> ScopeMetrics[] -> Metric[]
    for (metrics_data.resource_metrics.items) |*resource_metrics| {
        for (resource_metrics.scope_metrics.items) |*scope_metrics| {
            // Count original metrics
            original_count += scope_metrics.metrics.items.len;

            // Filter metrics in place by shrinking the list
            var write_idx: usize = 0;
            for (scope_metrics.metrics.items) |*metric| {
                var ctx = OtlpMetricContext{
                    .metric = metric,
                    .resource_metrics = resource_metrics,
                    .scope_metrics = scope_metrics,
                };

                const result = engine.evaluate(.metric, &ctx, otlpMetricFieldAccessor, otlpMetricFieldMutator, &policy_id_buf);

                if (result.decision.shouldContinue()) {
                    // Keep this metric - move to write position if needed
                    if (write_idx != scope_metrics.metrics.items.len - 1) {
                        scope_metrics.metrics.items[write_idx] = metric.*;
                    }
                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_metrics.metrics.shrinkRetainingCapacity(write_idx);
        }
    }

    return .{
        .original_count = original_count,
        .dropped_count = dropped_count,
    };
}

fn processJsonMetrics(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Parse JSON into MetricsData protobuf struct
    proto.protobuf.json.pb_options.emit_oneof_field_name = false;
    var parsed = try MetricsData.jsonDecode(data, .{
        .ignore_unknown_fields = true,
    }, allocator);
    defer parsed.deinit();

    // Filter metrics in-place
    const counts = filterMetricsInPlace(&parsed.value, registry, bus);

    // Re-serialize to JSON
    const output = try parsed.value.jsonEncode(.{}, allocator);

    return .{
        .data = @constCast(output),
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
    };
}

fn processProtobufMetrics(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Basic validation
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON - this would cause protobuf decoder to fail
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Use an arena for the protobuf decode/filter/encode cycle
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into MetricsData struct using arena
    var metrics_data = try MetricsData.decode(&reader, arena_alloc);

    // Filter metrics in-place
    const counts = filterMetricsInPlace(&metrics_data, registry, bus);

    // Re-serialize to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try metrics_data.encode(&output_writer.writer, arena_alloc);

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

test "processMetrics - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeMetrics":[{"scope":{"name":"my-meter","version":"1.0"},"metrics":[{"name":"http.requests","description":"HTTP request count","unit":"1","sum":{"dataPoints":[{"asInt":"100"}]}}]}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "http.requests") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "resourceMetrics") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
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

test "processMetrics - unknown content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some unknown data";

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), data, "text/plain");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processMetrics - no policies keeps all metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"metric1"},{"name":"metric2"}]}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "metric1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "metric2") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processMetrics - DROP policy filters metrics by name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics matching "debug"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-metrics"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"http.requests"},{"name":"debug.internal"}]}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    // debug metric should be dropped, http.requests should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "http.requests") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processMetrics - DROP policy filters metrics by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics from "test-service"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-test-service"),
        .name = try allocator.dupe(u8, "drop-test-service"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .resource_attribute = try allocator.dupe(u8, "service.name") },
        .match = .{ .regex = try allocator.dupe(u8, "test-service") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeMetrics":[{"scope":{},"metrics":[{"name":"from.test"}]}]},{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"prod-service"}}]},"scopeMetrics":[{"scope":{},"metrics":[{"name":"from.prod"}]}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    // Metrics from test-service should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from.test") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from.prod") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}

test "processMetrics - all metrics dropped returns empty structure" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "metric") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"metric1"},{"name":"metric2"}]}]}]}
    ;

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), metrics, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 2), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.allDropped());
}

test "ContentFormat.fromContentType" {
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json"));
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json; charset=utf-8"));
    try std.testing.expectEqual(ContentFormat.protobuf, ContentFormat.fromContentType("application/x-protobuf"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType("text/plain"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType(""));
}

// =============================================================================
// Protobuf Tests
// =============================================================================

const Gauge = proto.metrics.Gauge;
const NumberDataPoint = proto.metrics.NumberDataPoint;

/// Helper to create protobuf-encoded MetricsData for testing
fn createTestProtobufMetrics(allocator: std.mem.Allocator, names: []const []const u8) ![]u8 {
    // Use an arena for the temporary protobuf structures
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var scope_metrics = ScopeMetrics{};
    for (names) |name| {
        var gauge = Gauge{};
        try gauge.data_points.append(arena_alloc, NumberDataPoint{
            .value = .{ .as_int = 42 },
        });
        const metric = Metric{
            .name = name,
            .data = .{ .gauge = gauge },
        };
        try scope_metrics.metrics.append(arena_alloc, metric);
    }

    var resource_metrics = ResourceMetrics{};
    try resource_metrics.scope_metrics.append(arena_alloc, scope_metrics);

    var metrics_data = MetricsData{};
    try metrics_data.resource_metrics.append(arena_alloc, resource_metrics);

    // Encode to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try metrics_data.encode(&output_writer.writer, arena_alloc);

    return try output_writer.toOwnedSlice();
}

test "processMetrics - protobuf parses and re-serializes" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create valid protobuf data
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "cpu.usage", "memory.usage" });
    defer allocator.free(proto_data);

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    // With no policies, all metrics should be kept
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processMetrics - protobuf DROP policy filters metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics containing "debug"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with one metric containing "debug"
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "http.requests", "debug.internal" });
    defer allocator.free(proto_data);

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    // One metric should be dropped
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());

    // Verify the result can be decoded and contains only the http.requests metric
    var reader = std.Io.Reader.fixed(result.data);
    var decoded = try MetricsData.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    // Should have 1 metric remaining
    var total_metrics: usize = 0;
    for (decoded.resource_metrics.items) |*rm| {
        for (rm.scope_metrics.items) |*sm| {
            total_metrics += sm.metrics.items.len;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), total_metrics);
}

test "processMetrics - protobuf all metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "usage") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with metrics that all match the pattern
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "cpu.usage", "memory.usage", "disk.usage" });
    defer allocator.free(proto_data);

    const result = try processMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, "application/x-protobuf");
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 3), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 3), result.original_count);
    try std.testing.expect(result.allDropped());
}
