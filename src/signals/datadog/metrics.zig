const std = @import("std");
const stream_io = @import("../stream_io.zig");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const datadog_metric = @import("metric.zig");
const otlp_attr = @import("../otlp/attributes.zig");

const PolicyEngine = policy.PolicyEngine;
pub const MetricFieldRef = policy.MetricFieldRef;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;
const MetricSeries = datadog_metric.MetricSeries;
const MetricPayload = datadog_metric.MetricPayload;

const Parser = datadog_metric.Parser;
const ArrayList = std.ArrayListUnmanaged;

pub const StreamProcessResult = struct {
    was_transformed: bool = false,
    dropped_count: usize,
    original_count: usize,

    pub fn wasModified(self: StreamProcessResult) bool {
        return self.dropped_count > 0 or self.was_transformed;
    }

    pub fn allDropped(self: StreamProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Filter a Datadog metrics JSON payload from `in_reader` into `out_writer`.
/// When the payload does not parse, write it unchanged (fail open).
pub fn processMetricsStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    const data = try stream_io.readAll(allocator, in_reader);
    defer allocator.free(data);

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();

    const series_list = parseSeries(arena.allocator(), allocator, &parser, data) orelse {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = 0 };
    };

    const engine = PolicyEngine.init(bus, @constCast(registry));
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;
    var kept: ArrayList(MetricSeries) = .empty;
    var result: StreamProcessResult = .{ .dropped_count = 0, .original_count = series_list.len };
    for (series_list) |*series| {
        const verdict = filterMetric(allocator, &engine, series, &policy_id_buf);
        if (verdict.mutated) result.was_transformed = true;
        if (verdict.keep) {
            try kept.append(arena.allocator(), series.*);
        } else {
            result.dropped_count += 1;
        }
    }

    if (!result.wasModified()) {
        try out_writer.writeAll(data);
    } else if (kept.items.len == 0) {
        try out_writer.writeAll("{\"errors\":[]}");
    } else {
        const payload: MetricPayload = .{ .series = kept.items };
        try std.json.Stringify.value(payload, .{}, out_writer);
    }
    return result;
}

/// Parse the series of a payload into `arena`. Return null when the payload
/// does not parse or has no series.
fn parseSeries(
    arena: std.mem.Allocator,
    parser_gpa: std.mem.Allocator,
    parser: *Parser,
    data: []const u8,
) ?[]MetricSeries {
    const document = parser.parseFromSlice(parser_gpa, data) catch return null;
    const payload = MetricPayload.parse(arena, document.asValue()) catch return null;
    return payload.series;
}

/// Context for field accessor - holds the MetricSeries struct.
pub const FieldAccessorContext = struct {
    series: *MetricSeries,
    /// Cached concatenated tags string for tag matching
    tags_cache: ?[]const u8,
};

/// Look up an attribute across all Datadog metric data sources.
/// Searches tags, source_type_name, resources, and extra HashMap (with nested support).
/// Since Datadog has no resource/scope distinction, all attribute types
/// search the same flat namespace.
fn lookupMetricAttribute(series: *MetricSeries, tags_cache: ?[]const u8, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    const key = path[0];

    // Check tags and source_type_name (single-segment only)
    if (path.len == 1) {
        if (std.mem.eql(u8, key, "tags")) return tags_cache;
        if (std.mem.eql(u8, key, "source_type_name")) return series.source_type_name;
    }

    // Check resources array: path[0] matches resource type
    if (series.resources) |resources| {
        for (resources) |*res| {
            if (res.type) |res_type| {
                if (std.mem.eql(u8, key, res_type)) {
                    if (path.len == 1) return res.name;
                    // Two-segment path: ["host", "name"] or ["host", "type"]
                    if (path.len == 2) {
                        if (std.mem.eql(u8, path[1], "name")) return res.name;
                        if (std.mem.eql(u8, path[1], "type")) return res.type;
                    }
                }
            }
        }
    }

    // Check extra fields (supports nested dotted-key paths)
    return findExtraField(&series.extra.values, path);
}

const findExtraField = otlp_attr.findExtraField;

/// Field accessor for Datadog metric format.
/// Maps `MetricFieldRef` to actual field values in MetricSeries.
/// All attribute types (datapoint, resource, scope) search the same flat namespace since
/// Datadog has no OTLP-style resource/scope hierarchy.
pub fn metricValue(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
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
        // All attribute types search the same Datadog flat namespace
        .datapoint_attribute, .resource_attribute, .scope_attribute => |attr_path| lookupMetricAttribute(
            series,
            field_ctx.tags_cache,
            attr_path.path.items,
        ),
        .metric_type => getDatadogMetricTypeString(series),
        .aggregation_temporality => null,
    };
}

/// Returns the Datadog metric type as a string for regex matching
/// Datadog types: 0=unspecified, 1=count, 2=rate, 3=gauge
fn getDatadogMetricTypeString(series: *MetricSeries) ?[]const u8 {
    const metric_type = series.type orelse return null;
    return switch (metric_type) {
        0 => "unspecified",
        1 => "count",
        2 => "rate",
        3 => "gauge",
        else => null,
    };
}

/// Datadog metric fields are strings, so the typed read wraps the string
/// read. Metrics have no set or delete; the engine only filters them.
pub fn metricTypedValue(ctx: *const anyopaque, field: policy.MetricFieldRef) ?policy.TypedValue {
    return .{ .string = metricValue(ctx, field) orelse return null };
}

pub const metric_accessor: policy.MetricAccessor = .{
    .typed_value = metricTypedValue,
};

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

    var field_ctx: FieldAccessorContext = .{
        .series = series,
        .tags_cache = tags_cache,
    };
    const result = engine.evaluate(.metric, &metric_accessor, &field_ctx, policy_id_buf, .{ .io = engine.bus.io });
    return .{
        .keep = result.decision.shouldContinue(),
        .mutated = result.was_transformed,
    };
}

/// Build a concatenated string of tags for pattern matching
fn buildTagsCache(allocator: std.mem.Allocator, tags: ?[][]const u8) !?[]const u8 {
    const t = tags orelse return null;
    if (t.len == 0) return null;
    const joined = try std.mem.join(allocator, ",", t);
    return joined;
}

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

/// Test helper to create an AttributePath from a single key string.
/// Uses comptime to ensure the array literal has static storage.
fn testAttrPath(comptime key: []const u8) proto.policy.AttributePath {
    const items = @constCast(&[_][]const u8{key});
    return .{ .path = .{ .items = items, .capacity = items.len } };
}

test "datadogMetricFieldAccessor - extra field lookup" {
    // Unit test to verify the field accessor can retrieve fields
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "system.load.1", "type": 3, "tags": ["env:prod", "service:web"]}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.tags.?);

    // Build tags cache for matching
    const tags_cache = try buildTagsCache(allocator, series.tags);
    defer if (tags_cache) |tc| allocator.free(tc);

    var field_ctx: FieldAccessorContext = .{
        .series = &series,
        .tags_cache = tags_cache,
    };

    // Test known field
    const metric_val = metricValue(&field_ctx, .{ .metric_field = .METRIC_FIELD_NAME });
    try std.testing.expect(metric_val != null);
    try std.testing.expectEqualStrings("system.load.1", metric_val.?);

    // Test tags field
    const tags_val = metricValue(&field_ctx, .{ .datapoint_attribute = testAttrPath("tags") });
    try std.testing.expect(tags_val != null);
    try std.testing.expectEqualStrings("env:prod,service:web", tags_val.?);

    // Test metric type
    const type_val = metricValue(&field_ctx, .{ .metric_type = .METRIC_TYPE_UNSPECIFIED });
    try std.testing.expect(type_val != null);
    try std.testing.expectEqualStrings("gauge", type_val.?);
}

/// Output and counts of one `processMetricsStream` run in a test.
const StreamRun = struct {
    data: []u8,
    result: StreamProcessResult,
};

/// Run `input` through `processMetricsStream`. The caller frees `data`.
fn runStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    input: []const u8,
) !StreamRun {
    var in_reader = std.Io.Reader.fixed(input);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const result = try processMetricsStream(allocator, registry, bus, &in_reader, &out_writer.writer);
    return .{ .data = try out_writer.toOwnedSlice(), .result = result };
}

/// Build a policy that drops a metric when `field` matches `regex`. The
/// caller owns the policy.
fn dropMetricPolicy(
    allocator: std.mem.Allocator,
    id: []const u8,
    field: proto.policy.MetricMatcher.field_union,
    regex: []const u8,
) !proto.policy.Policy {
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .enabled = true,
        .target = .{ .metric = .{ .keep = false } },
    };
    errdefer drop_policy.deinit(allocator);
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = field,
        .match = .{ .regex = try allocator.dupe(u8, regex) },
    });
    return drop_policy;
}

test "processMetrics - no policies keeps all metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "system.load.1") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
}

test "processMetrics - DROP policy filters metrics by name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var drop_policy = try dropMetricPolicy(
        allocator,
        "drop-debug-metrics",
        .{ .metric_field = .METRIC_FIELD_NAME },
        "^debug\\.",
    );
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"series": [
        \\  {"metric": "debug.internal", "type": 3, "points": [{"timestamp": 1636629071, "value": 1.0}]},
        \\  {"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}
        \\]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    // debug.internal should be dropped, system.load.1 should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "system.load.1") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());
}

test "processMetrics - returns 202-compatible response when all metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var drop_all = try dropMetricPolicy(allocator, "drop-all", .{ .metric_field = .METRIC_FIELD_NAME }, "system");
    defer drop_all.deinit(allocator);

    try registry.updatePolicies(&.{drop_all}, "file-provider", .file);

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    try std.testing.expectEqualStrings("{\"errors\":[]}", run.data);
    try std.testing.expect(run.result.allDropped());
}

test "processMetrics - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), malformed);
    defer allocator.free(run.data);

    try std.testing.expectEqualStrings(malformed, run.data);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "processMetrics - filter on tags" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Drop metrics whose tags contain "env:dev".
    var attr_path_tags: proto.policy.AttributePath = .{};
    try attr_path_tags.path.append(allocator, try allocator.dupe(u8, "tags"));
    var drop_policy = try dropMetricPolicy(
        allocator,
        "drop-dev-env",
        .{ .datapoint_attribute = attr_path_tags },
        "env:dev",
    );
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"series": [
        \\  {"metric": "dev.metric", "type": 3, "points": [{"timestamp": 1, "value": 1.0}],
        \\   "tags": ["env:dev", "service:test"]},
        \\  {"metric": "prod.metric", "type": 3, "points": [{"timestamp": 1, "value": 1.0}],
        \\   "tags": ["env:prod", "service:web"]}
        \\]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    // dev.metric should be dropped, prod.metric should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "dev.metric") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "prod.metric") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "processMetrics - preserves all fields when no metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - all metrics kept, original data returned unchanged

    const metrics =
        \\{"series": [{"metric": "system.load.1", "type": 3, "interval": 60, "unit": "percent",
        \\ "points": [{"timestamp": 1636629071, "value": 0.7}], "tags": ["env:prod"],
        \\ "resources": [{"name": "host1", "type": "host"}]}]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    // When nothing is dropped, original data is returned unchanged
    try std.testing.expect(std.mem.indexOf(u8, run.data, "system.load.1") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "interval") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "resources") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
}

test "processMetrics - extra fields are preserved when no metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No policies - all metrics kept, original data returned unchanged

    // Metrics with extra fields not in the MetricSeries schema
    const metrics =
        \\{"series": [{"metric": "test", "type": 3, "points": [],
        \\ "extra_field": "should_be_preserved", "nested": {"key": "value"}}]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    // When nothing is dropped, original data is returned unchanged - extra fields preserved
    try std.testing.expect(std.mem.indexOf(u8, run.data, "test") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "extra_field") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "should_be_preserved") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "nested") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
}

test "processMetrics - filter on metric type" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // The regex matches the type name, so the enum value does not matter.
    var drop_policy = try dropMetricPolicy(
        allocator,
        "drop-count-metrics",
        .{ .metric_type = .METRIC_TYPE_UNSPECIFIED },
        "^count$",
    );
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const metrics =
        \\{"series": [
        \\  {"metric": "requests.total", "type": 1, "points": [{"timestamp": 1, "value": 100}]},
        \\  {"metric": "cpu.usage", "type": 3, "points": [{"timestamp": 1, "value": 0.5}]}
        \\]}
    ;

    const run = try runStream(allocator, &registry, noop_bus.eventBus(), metrics);
    defer allocator.free(run.data);

    // count metric (type=1) should be dropped, gauge metric (type=3) should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "requests.total") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "cpu.usage") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "datadogMetricFieldAccessor - scope_attribute searches metric attributes" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "system.load.1", "type": 3, "tags": ["env:prod", "service:web"],
        \\ "resources": [{"type": "host", "name": "web-01"}]}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.tags.?);
    defer allocator.free(series.resources.?);

    const tags_cache = try buildTagsCache(allocator, series.tags);
    defer if (tags_cache) |tc| allocator.free(tc);

    var field_ctx: FieldAccessorContext = .{
        .series = &series,
        .tags_cache = tags_cache,
    };

    // scope_attribute should find tags
    const tags_val = metricValue(&field_ctx, .{ .scope_attribute = testAttrPath("tags") });
    try std.testing.expect(tags_val != null);
    try std.testing.expectEqualStrings("env:prod,service:web", tags_val.?);

    // scope_attribute should find resources
    const host_val = metricValue(&field_ctx, .{ .scope_attribute = testAttrPath("host") });
    try std.testing.expect(host_val != null);
    try std.testing.expectEqualStrings("web-01", host_val.?);
}

test "datadogMetricFieldAccessor - resource with nested path" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "system.cpu", "type": 3, "resources": [{"type": "host", "name": "web-01"}]}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.resources.?);

    var field_ctx: FieldAccessorContext = .{
        .series = &series,
        .tags_cache = null,
    };

    // Two-segment path ["host", "name"] should find resource type=host and return name
    const nested_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "host", "name" }), .capacity = 2 },
    };
    const name_val = metricValue(&field_ctx, .{ .resource_attribute = nested_path });
    try std.testing.expect(name_val != null);
    try std.testing.expectEqualStrings("web-01", name_val.?);

    // Two-segment path ["host", "type"] should return the type
    const type_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "host", "type" }), .capacity = 2 },
    };
    const type_val = metricValue(&field_ctx, .{ .resource_attribute = type_path });
    try std.testing.expect(type_val != null);
    try std.testing.expectEqualStrings("host", type_val.?);
}

test "datadogMetricFieldAccessor - nested extra field via dotted key" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // Datadog uses dotted keys for nested attributes
    const json =
        \\{"metric": "custom.metric", "type": 3, "custom_data.region": "us-east"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var series = try MetricSeries.parse(allocator, doc.asValue());
    defer series.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{
        .series = &series,
        .tags_cache = null,
    };

    // Two-segment path joined with '.' to match dotted key
    const nested_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "custom_data", "region" }), .capacity = 2 },
    };
    const val = metricValue(&field_ctx, .{ .datapoint_attribute = nested_path });
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("us-east", val.?);
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

    var tags: [0][]const u8 = .{};
    const cache = try buildTagsCache(allocator, &tags);
    try std.testing.expect(cache == null);
}
