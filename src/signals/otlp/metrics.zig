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
const stream_io = @import("../stream_io.zig");
const proto = @import("proto");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const otlp_attr = @import("attributes.zig");
const common = @import("common.zig");

const MetricsData = proto.metrics.MetricsData;
const ResourceMetrics = proto.metrics.ResourceMetrics;
const ScopeMetrics = proto.metrics.ScopeMetrics;
const Metric = proto.metrics.Metric;
const KeyValue = proto.common.KeyValue;
const PolicyEngine = policy.PolicyEngine;
pub const MetricFieldRef = policy.MetricFieldRef;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Public API
// =============================================================================

pub const Format = common.Format;
pub const StreamProcessResult = common.StreamProcessResult;

/// Apply metric policies to an OTLP metrics body (JSON or protobuf) and write the result to out_writer.
pub fn processMetricsStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
    format: Format,
) !StreamProcessResult {
    switch (format) {
        .json => {
            const data = try stream_io.readAll(allocator, in_reader);
            defer allocator.free(data);
            return processJsonMetrics(allocator, registry, bus, data, out_writer);
        },
        .protobuf => {
            // Read into a page-allocator arena (see processProtobufMetrics).
            var read_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer read_arena.deinit();
            const data = try stream_io.readAll(read_arena.allocator(), in_reader);
            return processProtobufMetrics(registry, bus, data, out_writer);
        },
    }
}

// =============================================================================
// Internal Implementation
// =============================================================================

/// Context for OTLP metric field accessor - provides access to metric plus parent context.
pub const OtlpMetricContext = struct {
    metric: *Metric,
    resource_metrics: *ResourceMetrics,
    scope_metrics: *ScopeMetrics,
    datapoint_attributes: []const KeyValue,
};

/// String view of a scalar metric field. `metricTypedValue` reads attribute
/// fields itself, so the attribute arms return null.
pub fn metricValue(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const metric_ctx: *const OtlpMetricContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => metric_ctx.metric.name,
            .METRIC_FIELD_DESCRIPTION => metric_ctx.metric.description,
            .METRIC_FIELD_UNIT => metric_ctx.metric.unit,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL => metric_ctx.resource_metrics.schema_url,
            .METRIC_FIELD_SCOPE_SCHEMA_URL => metric_ctx.scope_metrics.schema_url,
            .METRIC_FIELD_SCOPE_NAME => if (metric_ctx.scope_metrics.scope) |scope| scope.name else null,
            .METRIC_FIELD_SCOPE_VERSION => if (metric_ctx.scope_metrics.scope) |scope| scope.version else null,
            else => null,
        },
        .datapoint_attribute, .resource_attribute, .scope_attribute => null,
        .metric_type => |requested_type| blk: {
            const data = metric_ctx.metric.data orelse break :blk null;
            const actual_type: @TypeOf(requested_type) = switch (data) {
                .gauge => .METRIC_TYPE_GAUGE,
                .sum => .METRIC_TYPE_SUM,
                .histogram => .METRIC_TYPE_HISTOGRAM,
                .exponential_histogram => .METRIC_TYPE_EXPONENTIAL_HISTOGRAM,
                .summary => .METRIC_TYPE_SUMMARY,
            };
            break :blk if (actual_type == requested_type) @tagName(requested_type) else null;
        },
        .aggregation_temporality => |requested_at| blk: {
            const data = metric_ctx.metric.data orelse break :blk null;
            const actual_at = switch (data) {
                .sum => |s| s.aggregation_temporality,
                .histogram => |h| h.aggregation_temporality,
                .exponential_histogram => |eh| eh.aggregation_temporality,
                .gauge, .summary => break :blk null,
            };
            break :blk if (@intFromEnum(actual_at) == @intFromEnum(requested_at)) @tagName(requested_at) else null;
        },
    };
}

/// Number of data points carried by a metric, across every data variant.
fn dataPointCount(metric: *const Metric) usize {
    const data = metric.data orelse return 0;
    return switch (data) {
        inline else => |variant| variant.data_points.items.len,
    };
}

/// Typed read primitive. Attributes keep their OTLP type so typed matchers
/// work on non-string values. Scalar metric fields are strings.
pub fn metricTypedValue(ctx: *const anyopaque, field: MetricFieldRef) ?policy.TypedValue {
    const metric_ctx: *const OtlpMetricContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .datapoint_attribute => |attr_path| otlp_attr.findNestedAttributeTyped(
            metric_ctx.datapoint_attributes,
            attr_path.path.items,
        ),
        .resource_attribute => |attr_path| if (metric_ctx.resource_metrics.resource) |res|
            otlp_attr.findNestedAttributeTyped(res.attributes.items, attr_path.path.items)
        else
            null,
        .scope_attribute => |attr_path| if (metric_ctx.scope_metrics.scope) |scope|
            otlp_attr.findNestedAttributeTyped(scope.attributes.items, attr_path.path.items)
        else
            null,
        else => otlp_attr.typedStr(metricValue(ctx, field)),
    };
}

/// MetricAccessor template wiring the OTLP metric value primitive.
/// Metric mutations aren't part of the policy-zig MetricAccessor interface.
pub const metric_accessor: policy.MetricAccessor = .{
    .typed_value = metricTypedValue,
};

/// Result of filtering metrics in-place, counted in data points
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
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;

    // Iterate through the nested structure and filter metrics in place
    // Structure: MetricsData -> ResourceMetrics[] -> ScopeMetrics[] -> Metric[]
    for (metrics_data.resource_metrics.items) |*resource_metrics| {
        for (resource_metrics.scope_metrics.items) |*scope_metrics| {
            // Filter metrics in place by shrinking the list
            var write_idx: usize = 0;
            for (scope_metrics.metrics.items) |*metric| {
                // The data point is the record unit (policy spec v1.7.1).
                // Evaluate and drop each data point by itself. Remove a metric
                // only when policy dropped all its data points. Keep a metric
                // that arrived with no data points.
                const original_dp = dataPointCount(metric);

                if (metric.data) |*metric_data| switch (metric_data.*) {
                    inline else => |*variant| {
                        var d: usize = 0;
                        while (d < variant.data_points.items.len) {
                            original_count += 1;
                            var ctx: OtlpMetricContext = .{
                                .metric = metric,
                                .resource_metrics = resource_metrics,
                                .scope_metrics = scope_metrics,
                                .datapoint_attributes = variant.data_points.items[d].attributes.items,
                            };

                            const result = engine.evaluate(.metric, &metric_accessor, &ctx, &policy_id_buf, .{
                                .io = bus.io,
                            });

                            if (result.decision.shouldContinue()) {
                                d += 1;
                            } else {
                                _ = variant.data_points.orderedRemove(d);
                                dropped_count += 1;
                            }
                        }
                    },
                };

                if (original_dp > 0 and dataPointCount(metric) == 0) continue;
                scope_metrics.metrics.items[write_idx] = metric.*;
                write_idx += 1;
            }

            // Shrink the list to only kept items (zero allocation)
            scope_metrics.metrics.shrinkRetainingCapacity(write_idx);
        }

        common.pruneEmpty(&resource_metrics.scope_metrics, "metrics");
    }

    common.pruneEmpty(&metrics_data.resource_metrics, "scope_metrics");

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
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // Exemplar trace_id/span_id are not in hex_bytes_fields, so they decode
    // and encode as base64.
    var parsed = try MetricsData.jsonDecode(data, .{
        .ignore_unknown_fields = true,
    }, allocator);
    defer parsed.deinit();

    // Filter metrics in-place
    const counts = filterMetricsInPlace(&parsed.value, registry, bus);

    const output = try parsed.value.jsonEncode(.{}, .{
        .emit_oneof_field_name = false,
    }, allocator);
    defer allocator.free(output);
    try out_writer.writeAll(output);

    return .{
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
    };
}

fn processProtobufMetrics(
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // Basic validation
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON - this would cause protobuf decoder to fail
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Back the scratch arena with the page allocator. Some caller allocators
    // (httpz fixed-buffer fallback) corrupt memory on resize-then-free. This
    // path does not allocate from the caller allocator.
    var arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into MetricsData struct using arena
    var metrics_data = try MetricsData.decode(&reader, arena_alloc);

    // Filter metrics in-place
    const counts = filterMetricsInPlace(&metrics_data, registry, bus);

    // Return the input bytes when no data point was dropped.
    if (counts.dropped_count == 0) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = counts.original_count };
    }

    // Encode into the arena.
    var output_writer = std.Io.Writer.Allocating.init(arena_alloc);
    try metrics_data.encode(&output_writer.writer, arena_alloc);
    try out_writer.writeAll(output_writer.written());

    return .{
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
    };
}

// =============================================================================
// Tests
// =============================================================================

fn runMetrics(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    input: []const u8,
    format: Format,
) !common.TestRun {
    var in_reader = std.Io.Reader.fixed(input);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const result = try processMetricsStream(allocator, registry, bus, &in_reader, &out_writer.writer, format);
    return .{ .data = try out_writer.toOwnedSlice(), .result = result };
}

/// Load a policy that drops each data point whose `field` matches `regex`.
fn loadMetricDropPolicy(
    allocator: std.mem.Allocator,
    registry: *PolicyRegistry,
    id: []const u8,
    field: proto.policy.MetricMatcher.field_union,
    regex: []const u8,
) !void {
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .enabled = true,
        .target = .{ .metric = .{ .keep = false } },
    };
    defer drop_policy.deinit(allocator);
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = field,
        .match = .{ .regex = try allocator.dupe(u8, regex) },
    });
    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);
}

test "processMetrics - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name",
    ++
        \\"value":{"stringValue":"test-service"}}]},"scopeMetrics":[{"scope":
    ++
        \\{"name":"my-meter","version":"1.0"},"metrics":[{"name":"http.requests",
    ++
        \\"description":"HTTP request count","unit":"1","sum":{"dataPoints":[{"asInt":"100"}]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "http.requests") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "resourceMetrics") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "processMetrics - malformed JSON returns an error" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";
    try std.testing.expect(std.meta.isError(runMetrics(allocator, &registry, noop_bus.eventBus(), malformed, .json)));
}

test "processMetrics - no policies keeps all metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},
    ++
        \\"metrics":[{"name":"metric1","sum":{"dataPoints":[{"asInt":"1"}]}},
    ++
        \\{"name":"metric2","sum":{"dataPoints":[{"asInt":"2"}]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "metric1") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "metric2") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
}

test "processMetrics - DROP policy filters metrics by name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics matching "debug"
    try loadMetricDropPolicy(
        allocator,
        &registry,
        "drop-debug-metrics",
        .{ .metric_field = .METRIC_FIELD_NAME },
        "debug",
    );

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},
    ++
        \\"metrics":[{"name":"http.requests","sum":{"dataPoints":[{"asInt":"1"}]}},
    ++
        \\{"name":"debug.internal","sum":{"dataPoints":[{"asInt":"2"}]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    // debug metric should be dropped, http.requests should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "http.requests") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());
}

test "processMetrics - DROP policy filters metrics by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics from "test-service"
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service.name"));
    try loadMetricDropPolicy(
        allocator,
        &registry,
        "drop-test-service",
        .{ .resource_attribute = attr_path },
        "test-service",
    );

    const metrics =
        \\{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name",
    ++
        \\"value":{"stringValue":"test-service"}}]},"scopeMetrics":
    ++
        \\[{"scope":{},"metrics":[{"name":"from.test","sum":{"dataPoints":[{"asInt":"1"}]}}]}]},
    ++
        \\{"resource":
    ++
        \\{"attributes":[{"key":"service.name","value":{"stringValue":"prod-service"}}]},
    ++
        \\"scopeMetrics":[{"scope":{},"metrics":[{"name":"from.prod",
    ++
        \\"sum":{"dataPoints":[{"asInt":"2"}]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    // Metrics from test-service should be dropped
    try std.testing.expect(std.mem.indexOf(u8, run.data, "from.test") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "from.prod") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "processMetrics - all metrics dropped returns empty structure" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all metrics
    try loadMetricDropPolicy(allocator, &registry, "drop-all", .{ .metric_field = .METRIC_FIELD_NAME }, "metric");

    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},
    ++
        \\"metrics":[{"name":"metric1","sum":{"dataPoints":[{"asInt":"1"}]}},
    ++
        \\{"name":"metric2","sum":{"dataPoints":[{"asInt":"2"}]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 2), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.allDropped());
}

test "processMetrics - DROP policy filters individual data points" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "env"));
    try loadMetricDropPolicy(
        allocator,
        &registry,
        "drop-canary-datapoints",
        .{ .datapoint_attribute = attr_path },
        "canary",
    );

    // One metric, three data points: only the canary one matches, so the metric
    // survives with the other two intact.
    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[
    ++
        \\{"name":"http.requests","sum":{"dataPoints":[
    ++
        \\{"asInt":"1","attributes":[{"key":"env","value":{"stringValue":"prod"}}]},
    ++
        \\{"asInt":"2","attributes":[{"key":"env","value":{"stringValue":"canary"}}]},
    ++
        \\{"asInt":"3","attributes":[{"key":"env","value":{"stringValue":"staging"}}]}
    ++
        \\]}}]}]}]}
    ;

    var in_reader = std.Io.Reader.fixed(metrics);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const result = try processMetricsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        .json,
    );

    const data = out_writer.written();
    try std.testing.expect(std.mem.indexOf(u8, data, "http.requests") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "prod") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "staging") != null);
    try std.testing.expect(std.mem.indexOf(u8, data, "canary") == null);
    try std.testing.expectEqual(@as(usize, 3), result.original_count);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expect(!result.allDropped());
}

// =============================================================================
// Protobuf Tests
// =============================================================================

const Gauge = proto.metrics.Gauge;

/// Helper to create protobuf-encoded MetricsData for testing
fn createTestProtobufMetrics(allocator: std.mem.Allocator, names: []const []const u8) ![]u8 {
    // Use an arena for the temporary protobuf structures
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var scope_metrics: ScopeMetrics = .{};
    for (names) |name| {
        var gauge: Gauge = .{};
        try gauge.data_points.append(arena_alloc, .{
            .value = .{ .as_int = 42 },
        });
        const metric: Metric = .{
            .name = name,
            .data = .{ .gauge = gauge },
        };
        try scope_metrics.metrics.append(arena_alloc, metric);
    }

    var resource_metrics: ResourceMetrics = .{};
    try resource_metrics.scope_metrics.append(arena_alloc, scope_metrics);

    var metrics_data: MetricsData = .{};
    try metrics_data.resource_metrics.append(arena_alloc, resource_metrics);

    // Encode to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try metrics_data.encode(&output_writer.writer, arena_alloc);

    return output_writer.toOwnedSlice();
}

test "processMetrics - protobuf parses and re-serializes" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create valid protobuf data
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "cpu.usage", "memory.usage" });
    defer allocator.free(proto_data);

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // With no policies, all metrics should be kept
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
}

test "processMetrics - protobuf DROP policy filters metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics containing "debug"
    try loadMetricDropPolicy(allocator, &registry, "drop-debug", .{ .metric_field = .METRIC_FIELD_NAME }, "debug");

    // Create protobuf data with one metric containing "debug"
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "http.requests", "debug.internal" });
    defer allocator.free(proto_data);

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // One metric should be dropped
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());

    // Verify the result can be decoded and contains only the http.requests metric
    var reader = std.Io.Reader.fixed(run.data);
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
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all metrics
    try loadMetricDropPolicy(allocator, &registry, "drop-all", .{ .metric_field = .METRIC_FIELD_NAME }, "usage");

    // Create protobuf data with metrics that all match the pattern
    const proto_data = try createTestProtobufMetrics(allocator, &.{ "cpu.usage", "memory.usage", "disk.usage" });
    defer allocator.free(proto_data);

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 3), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 3), run.result.original_count);
    try std.testing.expect(run.result.allDropped());
}

// =============================================================================
// Empty metric descriptors (data set, no data points)
// =============================================================================

/// Build a protobuf-encoded MetricsData carrying a mix of populated and empty
/// gauge metrics, so tests can exercise the "data oneof set but data_points
/// empty" wire form that the prune logic must not drop.
fn createProtobufMetricsMixed(allocator: std.mem.Allocator, names_with_dps: []const struct {
    name: []const u8,
    data_points: usize,
}) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var scope_metrics: ScopeMetrics = .{};
    for (names_with_dps) |spec| {
        var gauge: Gauge = .{};
        var i: usize = 0;
        while (i < spec.data_points) : (i += 1) {
            try gauge.data_points.append(aa, .{
                .value = .{ .as_int = @intCast(i) },
            });
        }
        try scope_metrics.metrics.append(aa, .{
            .name = spec.name,
            .data = .{ .gauge = gauge },
        });
    }

    var resource_metrics: ResourceMetrics = .{};
    try resource_metrics.scope_metrics.append(aa, scope_metrics);

    var metrics_data: MetricsData = .{};
    try metrics_data.resource_metrics.append(aa, resource_metrics);

    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();
    try metrics_data.encode(&output_writer.writer, aa);
    return output_writer.toOwnedSlice();
}

/// Collect surviving metric names (in decode order) into `out`. Returns the
/// number written; the caller must size `out` to fit.
fn collectMetricNames(decoded: *const MetricsData, out: [][]const u8) usize {
    var n: usize = 0;
    for (decoded.resource_metrics.items) |*rm| {
        for (rm.scope_metrics.items) |*sm| {
            for (sm.metrics.items) |m| {
                out[n] = m.name;
                n += 1;
            }
        }
    }
    return n;
}

test "empty metric descriptor survives non-matching policy (protobuf)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // A DROP policy whose regex matches nothing — but it still routes the
    // metric signal through the decode -> filter -> re-encode path.
    try loadMetricDropPolicy(
        allocator,
        &registry,
        "no-match",
        .{ .metric_field = .METRIC_FIELD_NAME },
        "does-not-exist",
    );

    // One populated gauge + one empty gauge (`data` oneof SET, data_points empty).
    const proto_data = try createProtobufMetricsMixed(allocator, &.{
        .{ .name = "populated.gauge", .data_points = 1 },
        .{ .name = "empty.gauge", .data_points = 0 },
    });
    defer allocator.free(proto_data);

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // The policy matched nothing — no data points were evaluated/dropped.
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    // original_count is a data-point count (1 from the populated gauge).
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);

    // Both metrics survive.
    var reader = std.Io.Reader.fixed(run.data);
    var decoded = try MetricsData.decode(&reader, allocator);
    defer decoded.deinit(allocator);
    var names: [4][]const u8 = undefined;
    const names_len = collectMetricNames(&decoded, &names);
    try std.testing.expectEqual(@as(usize, 2), names_len);
    try std.testing.expectEqualStrings("populated.gauge", names[0]);
    try std.testing.expectEqualStrings("empty.gauge", names[1]);
}

test "filterMetricsInPlace: prunes policy-emptied metric but keeps originally-empty one (protobuf)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // DROP by name match "drop": drops every data point of "drop.me", emptying
    // it. The originally-empty "empty.gauge" and the unrelated "keep.me" must
    // survive untouched.
    try loadMetricDropPolicy(allocator, &registry, "drop-by-name", .{ .metric_field = .METRIC_FIELD_NAME }, "drop");

    const proto_data = try createProtobufMetricsMixed(allocator, &.{
        .{ .name = "drop.me", .data_points = 1 },
        .{ .name = "keep.me", .data_points = 1 },
        .{ .name = "empty.gauge", .data_points = 0 },
    });
    defer allocator.free(proto_data);

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // drop.me's single data point was dropped; keep.me and empty.gauge have no
    // data points dropped.
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);

    var reader = std.Io.Reader.fixed(run.data);
    var decoded = try MetricsData.decode(&reader, allocator);
    defer decoded.deinit(allocator);
    var names: [4][]const u8 = undefined;
    const names_len = collectMetricNames(&decoded, &names);
    try std.testing.expectEqual(@as(usize, 2), names_len);
    try std.testing.expectEqualStrings("keep.me", names[0]);
    try std.testing.expectEqualStrings("empty.gauge", names[1]);
}

test "empty metric descriptor survives non-matching policy (JSON)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    try loadMetricDropPolicy(
        allocator,
        &registry,
        "no-match",
        .{ .metric_field = .METRIC_FIELD_NAME },
        "does-not-exist",
    );

    // Populated gauge (1 data point) + empty gauge (`gauge` set, dataPoints empty).
    const metrics =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},
    ++
        \\"metrics":[{"name":"populated.gauge","gauge":{"dataPoints":[{"asInt":"1"}]}},
    ++
        \\{"name":"empty.gauge","gauge":{"dataPoints":[]}}]}]}]}
    ;

    const run = try runMetrics(allocator, &registry, noop_bus.eventBus(), metrics, .json);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);

    // Both metrics survive.
    try std.testing.expect(std.mem.indexOf(u8, run.data, "populated.gauge") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "empty.gauge") != null);
}
