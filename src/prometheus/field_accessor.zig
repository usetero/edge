//! Prometheus Field Accessor
//!
//! Provides field access for Prometheus metrics to integrate with the policy engine.
//! Maps MetricFieldRef to values from Prometheus exposition format lines.
//!
//! Prometheus metrics have:
//! - metric_name: The metric name (maps to METRIC_FIELD_NAME)
//! - labels: Key-value pairs (maps to datapoint_attribute)
//! - value: The sample value (accessible as a special field)
//!

const std = @import("std");
const line_parser = @import("line_parser.zig");
const policy = @import("../policy/root.zig");

const MetricFieldRef = policy.MetricFieldRef;
const MetricField = @import("proto").policy.MetricField;

/// Context for Prometheus field access.
/// Contains the parsed line and a labels cache for efficient lookups.
pub const PrometheusFieldContext = struct {
    /// The parsed Prometheus line (must be a sample)
    parsed: line_parser.ParsedLine,
    /// The original line buffer (labels point into this)
    line_buffer: []const u8,
    /// Cached concatenated labels for pattern matching (optional)
    /// Format: "key1=value1,key2=value2,..."
    labels_cache: ?[]const u8 = null,

    /// Create a context from a parsed sample line
    pub fn fromSample(parsed: line_parser.ParsedLine, line_buffer: []const u8) ?PrometheusFieldContext {
        return switch (parsed) {
            .sample => .{
                .parsed = parsed,
                .line_buffer = line_buffer,
            },
            else => null,
        };
    }

    /// Get the metric name from the context
    pub fn getMetricName(self: *const PrometheusFieldContext) ?[]const u8 {
        return switch (self.parsed) {
            .sample => |s| if (s.metric_name.len > 0) s.metric_name else null,
            else => null,
        };
    }

    /// Get the sample value from the context
    pub fn getValue(self: *const PrometheusFieldContext) ?[]const u8 {
        return switch (self.parsed) {
            .sample => |s| if (s.value.len > 0) s.value else null,
            else => null,
        };
    }

    /// Get the timestamp from the context (if present)
    pub fn getTimestamp(self: *const PrometheusFieldContext) ?[]const u8 {
        return switch (self.parsed) {
            .sample => |s| s.timestamp,
            else => null,
        };
    }

    /// Get a label value by name
    pub fn getLabelValue(self: *const PrometheusFieldContext, label_name: []const u8) ?[]const u8 {
        return switch (self.parsed) {
            .sample => |s| {
                var iter = s.labels;
                while (iter.next()) |label| {
                    if (std.mem.eql(u8, label.name, label_name)) {
                        return label.value;
                    }
                }
                return null;
            },
            else => null,
        };
    }
};

/// Field accessor function for Prometheus metrics.
/// Maps MetricFieldRef to values from the Prometheus context.
///
/// This follows the same signature as other metric field accessors
/// (otlpMetricFieldAccessor, datadogMetricFieldAccessor).
pub fn prometheusFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const prom_ctx: *const PrometheusFieldContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => prom_ctx.getMetricName(),
            // Prometheus doesn't have these fields directly
            .METRIC_FIELD_DESCRIPTION,
            .METRIC_FIELD_UNIT,
            .METRIC_FIELD_RESOURCE_SCHEMA_URL,
            .METRIC_FIELD_SCOPE_SCHEMA_URL,
            .METRIC_FIELD_SCOPE_NAME,
            .METRIC_FIELD_SCOPE_VERSION,
            .METRIC_FIELD_UNSPECIFIED,
            => null,
            // Handle any future enum values
            _ => null,
        },
        // In Prometheus, labels are like datapoint attributes
        .datapoint_attribute => |key| {
            // Special case: "labels" returns the cached labels string
            if (std.mem.eql(u8, key, "labels")) {
                return prom_ctx.labels_cache;
            }
            // Special case: "value" returns the sample value
            if (std.mem.eql(u8, key, "value")) {
                return prom_ctx.getValue();
            }
            // Special case: "timestamp" returns the sample timestamp
            if (std.mem.eql(u8, key, "timestamp")) {
                return prom_ctx.getTimestamp();
            }
            // Otherwise, look up the label by key
            return prom_ctx.getLabelValue(key);
        },
        // Prometheus doesn't have resource/scope attributes
        .resource_attribute => null,
        .scope_attribute => null,
        // Prometheus doesn't have metric type or aggregation temporality in the sample
        // (TYPE lines are metadata, not attached to individual samples)
        .metric_type => null,
        .aggregation_temporality => null,
    };
}

/// Build a labels cache string for pattern matching.
/// Format: "key1=value1,key2=value2,..."
/// Caller owns the returned memory.
pub fn buildLabelsCache(allocator: std.mem.Allocator, parsed: line_parser.ParsedLine) !?[]u8 {
    const sample = switch (parsed) {
        .sample => |s| s,
        else => return null,
    };

    // Count total size needed
    var total_len: usize = 0;
    var label_count: usize = 0;
    var iter = sample.labels;
    while (iter.next()) |label| {
        total_len += label.name.len + 1 + label.value.len; // name=value
        label_count += 1;
    }

    if (label_count == 0) return null;

    // Add commas between labels
    total_len += label_count - 1;

    // Allocate and build the string
    const result = try allocator.alloc(u8, total_len);
    errdefer allocator.free(result);

    var pos: usize = 0;
    var first = true;
    iter = sample.labels; // Reset iterator
    while (iter.next()) |label| {
        if (!first) {
            result[pos] = ',';
            pos += 1;
        }
        first = false;

        @memcpy(result[pos..][0..label.name.len], label.name);
        pos += label.name.len;
        result[pos] = '=';
        pos += 1;
        @memcpy(result[pos..][0..label.value.len], label.value);
        pos += label.value.len;
    }

    return result;
}

// =============================================================================
// Tests
// =============================================================================

test "prometheusFieldAccessor - metric name" {
    const line = "http_requests_total{method=\"get\"} 100";
    const parsed = line_parser.parseLine(line);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;

    const name = prometheusFieldAccessor(&ctx, .{ .metric_field = .METRIC_FIELD_NAME });
    try std.testing.expect(name != null);
    try std.testing.expectEqualStrings("http_requests_total", name.?);
}

test "prometheusFieldAccessor - label lookup" {
    const line = "http_requests_total{method=\"get\",status=\"200\"} 100";
    const parsed = line_parser.parseLine(line);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;

    // Lookup existing label
    const method = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "method" });
    try std.testing.expect(method != null);
    try std.testing.expectEqualStrings("get", method.?);

    const status = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "status" });
    try std.testing.expect(status != null);
    try std.testing.expectEqualStrings("200", status.?);

    // Lookup non-existing label
    const missing = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "host" });
    try std.testing.expect(missing == null);
}

test "prometheusFieldAccessor - value access" {
    const line = "cpu_usage 0.75";
    const parsed = line_parser.parseLine(line);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;

    const value = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "value" });
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("0.75", value.?);
}

test "prometheusFieldAccessor - timestamp access" {
    const line = "cpu_usage 0.75 1234567890";
    const parsed = line_parser.parseLine(line);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;

    const ts = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "timestamp" });
    try std.testing.expect(ts != null);
    try std.testing.expectEqualStrings("1234567890", ts.?);
}

test "prometheusFieldAccessor - unsupported fields return null" {
    const line = "metric_name 1";
    const parsed = line_parser.parseLine(line);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;

    // Description not available in Prometheus
    const desc = prometheusFieldAccessor(&ctx, .{ .metric_field = .METRIC_FIELD_DESCRIPTION });
    try std.testing.expect(desc == null);

    // Resource attributes not available
    const res = prometheusFieldAccessor(&ctx, .{ .resource_attribute = "service.name" });
    try std.testing.expect(res == null);

    // Metric type not available on sample lines
    const mt = prometheusFieldAccessor(&ctx, .metric_type);
    try std.testing.expect(mt == null);
}

test "prometheusFieldAccessor - labels cache" {
    const allocator = std.testing.allocator;

    const line = "metric{a=\"1\",b=\"2\",c=\"3\"} 100";
    const parsed = line_parser.parseLine(line);

    const labels_cache = try buildLabelsCache(allocator, parsed);
    defer if (labels_cache) |lc| allocator.free(lc);

    var ctx = PrometheusFieldContext.fromSample(parsed, line).?;
    ctx.labels_cache = labels_cache;

    const labels = prometheusFieldAccessor(&ctx, .{ .datapoint_attribute = "labels" });
    try std.testing.expect(labels != null);
    try std.testing.expectEqualStrings("a=1,b=2,c=3", labels.?);
}

test "buildLabelsCache - no labels" {
    const allocator = std.testing.allocator;

    const line = "metric_without_labels 42";
    const parsed = line_parser.parseLine(line);

    const labels_cache = try buildLabelsCache(allocator, parsed);
    try std.testing.expect(labels_cache == null);
}

test "buildLabelsCache - non-sample line" {
    const allocator = std.testing.allocator;

    const line = "# HELP http_requests_total Total requests";
    const parsed = line_parser.parseLine(line);

    const labels_cache = try buildLabelsCache(allocator, parsed);
    try std.testing.expect(labels_cache == null);
}
