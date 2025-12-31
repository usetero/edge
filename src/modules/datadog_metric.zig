const std = @import("std");
const zimdjson = @import("zimdjson");

const StreamParser = zimdjson.ondemand.StreamParser(.default);

/// Datadog metric intake type enum values
/// See: https://docs.datadoghq.com/api/v2/metrics/#submit-metrics
pub const MetricIntakeType = enum(i32) {
    unspecified = 0,
    count = 1,
    rate = 2,
    gauge = 3,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.write(@intFromEnum(self.*));
    }
};

/// A single data point with timestamp and value
pub const MetricPoint = struct {
    /// POSIX timestamp in seconds
    timestamp: ?i64 = null,
    /// 64-bit float gauge-type value
    value: ?f64 = null,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();
        if (self.timestamp) |v| {
            try jws.objectField("timestamp");
            try jws.write(v);
        }
        if (self.value) |v| {
            try jws.objectField("value");
            try jws.write(v);
        }
        try jws.endObject();
    }
};

/// Resource associated with a metric
pub const MetricResource = struct {
    /// The name of the resource
    name: ?[]const u8 = null,
    /// The type of the resource
    type: ?[]const u8 = null,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();
        if (self.name) |v| {
            try jws.objectField("name");
            try jws.write(v);
        }
        if (self.type) |v| {
            try jws.objectField("type");
            try jws.write(v);
        }
        try jws.endObject();
    }
};

/// Metric origin information
pub const MetricOrigin = struct {
    /// The origin metric type code
    metric_type: ?i32 = null,
    /// The origin product code
    product: ?i32 = null,
    /// The origin service code
    service: ?i32 = null,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();
        if (self.metric_type) |v| {
            try jws.objectField("metric_type");
            try jws.write(v);
        }
        if (self.product) |v| {
            try jws.objectField("product");
            try jws.write(v);
        }
        if (self.service) |v| {
            try jws.objectField("service");
            try jws.write(v);
        }
        try jws.endObject();
    }
};

/// Metadata for the metric
pub const MetricMetadata = struct {
    /// Metric origin information
    origin: ?MetricOrigin = null,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();
        if (self.origin) |v| {
            try jws.objectField("origin");
            try v.jsonStringify(jws);
        }
        try jws.endObject();
    }
};

/// A single metric series
pub const MetricSeries = struct {
    pub const schema: StreamParser.schema.Infer(@This()) = .{
        .fields = .{ .extra = .{ .skip = true } },
        .on_unknown_field = .{ .handle = @This().handleUnknownField },
    };

    /// The name of the timeseries (required)
    metric: ?[]const u8 = null,
    /// Points relating to a metric (required)
    points: ?[]MetricPoint = null,
    /// The type of metric (0=unspecified, 1=count, 2=rate, 3=gauge)
    type: ?i32 = null,
    /// If the type is rate or count, define the corresponding interval in seconds
    interval: ?i64 = null,
    /// The unit of point value
    unit: ?[]const u8 = null,
    /// Metadata for the metric
    metadata: ?MetricMetadata = null,
    /// A list of resources to associate with this metric
    resources: ?[]MetricResource = null,
    /// The source type name
    source_type_name: ?[]const u8 = null,
    /// A list of tags associated with the metric
    tags: ?[][]const u8 = null,

    extra: std.StringHashMapUnmanaged(StreamParser.AnyValue) = .empty,

    pub fn handleUnknownField(self: *@This(), alloc: ?std.mem.Allocator, key: []const u8, value: StreamParser.Value) StreamParser.schema.Error!void {
        const gpa = alloc orelse return error.ExpectedAllocator;
        return self.extra.put(gpa, key, try value.asAny());
    }

    /// Custom JSON serialization for known fields only
    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();

        if (self.metric) |v| {
            try jws.objectField("metric");
            try jws.write(v);
        }
        if (self.points) |pts| {
            try jws.objectField("points");
            try jws.beginArray();
            for (pts) |*pt| {
                try pt.jsonStringify(jws);
            }
            try jws.endArray();
        }
        if (self.type) |v| {
            try jws.objectField("type");
            try jws.write(v);
        }
        if (self.interval) |v| {
            try jws.objectField("interval");
            try jws.write(v);
        }
        if (self.unit) |v| {
            try jws.objectField("unit");
            try jws.write(v);
        }
        if (self.metadata) |v| {
            try jws.objectField("metadata");
            try v.jsonStringify(jws);
        }
        if (self.resources) |res| {
            try jws.objectField("resources");
            try jws.beginArray();
            for (res) |*r| {
                try r.jsonStringify(jws);
            }
            try jws.endArray();
        }
        if (self.source_type_name) |v| {
            try jws.objectField("source_type_name");
            try jws.write(v);
        }
        if (self.tags) |t| {
            try jws.objectField("tags");
            try jws.beginArray();
            for (t) |tag| {
                try jws.write(tag);
            }
            try jws.endArray();
        }

        // Write extra fields
        var it = self.extra.iterator();
        while (it.next()) |entry| {
            try jws.objectField(entry.key_ptr.*);
            try writeAnyValue(jws, entry.value_ptr.*);
        }

        try jws.endObject();
    }

    /// Write a zimdjson AnyValue to a JSON writer
    fn writeAnyValue(jws: anytype, value: StreamParser.AnyValue) !void {
        switch (value) {
            .null => try jws.write(null),
            .bool => |v| try jws.write(v),
            .number => |n| switch (n) {
                .unsigned => |v| try jws.write(v),
                .signed => |v| try jws.write(v),
                .double => |v| try jws.write(v),
            },
            .string => |v| try jws.write(v.get() catch ""),
            .array => |arr| {
                try jws.beginArray();
                var it = arr.iterator();
                while (it.next() catch null) |item| {
                    try writeAnyValue(jws, item.asAny() catch continue);
                }
                try jws.endArray();
            },
            .object => |obj| {
                try jws.beginObject();
                var it = obj.iterator();
                while (it.next() catch null) |field| {
                    try jws.objectField(field.key.get() catch continue);
                    try writeAnyValue(jws, field.value.asAny() catch continue);
                }
                try jws.endObject();
            },
        }
    }
};

/// The payload for submitting metrics to Datadog
pub const MetricPayload = struct {
    pub const schema: StreamParser.schema.Infer(@This()) = .{};

    /// A list of timeseries to submit to Datadog
    series: ?[]MetricSeries = null,

    pub fn jsonStringify(self: *const @This(), jws: *std.json.Stringify) !void {
        try jws.beginObject();
        if (self.series) |s| {
            try jws.objectField("series");
            try jws.beginArray();
            for (s) |*series| {
                try series.jsonStringify(jws);
            }
            try jws.endArray();
        }
        try jws.endObject();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "MetricPoint - parse and serialize" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"timestamp": 1636629071, "value": 0.7}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricPoint, allocator, .{});
    defer parsed.deinit();
    const point = parsed.value;

    try std.testing.expectEqual(@as(i64, 1636629071), point.timestamp.?);
    try std.testing.expectApproxEqAbs(@as(f64, 0.7), point.value.?, 0.001);

    // Serialize back
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try std.json.Stringify.value(point, .{}, &out.writer);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "1636629071") != null);
}

test "MetricResource - parse and serialize" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"name": "demobox", "type": "host"}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricResource, allocator, .{});
    defer parsed.deinit();
    const resource = parsed.value;

    try std.testing.expectEqualStrings("demobox", resource.name.?);
    try std.testing.expectEqualStrings("host", resource.type.?);
}

test "MetricSeries - parse basic fields" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}], "tags": ["env:prod", "service:web"]}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricSeries, allocator, .{});
    defer parsed.deinit();
    const series = parsed.value;

    try std.testing.expectEqualStrings("system.load.1", series.metric.?);
    try std.testing.expectEqual(@as(i32, 3), series.type.?);
    try std.testing.expectEqual(@as(usize, 1), series.points.?.len);
    try std.testing.expectEqual(@as(usize, 2), series.tags.?.len);
    try std.testing.expectEqualStrings("env:prod", series.tags.?[0]);
}

test "MetricSeries - parse all known fields" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{
        \\  "metric": "system.load.1",
        \\  "type": 3,
        \\  "interval": 60,
        \\  "unit": "percent",
        \\  "source_type_name": "custom",
        \\  "points": [{"timestamp": 1636629071, "value": 0.7}],
        \\  "resources": [{"name": "demobox", "type": "host"}],
        \\  "tags": ["env:prod"],
        \\  "metadata": {"origin": {"product": 1, "service": 2, "metric_type": 3}}
        \\}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricSeries, allocator, .{});
    defer parsed.deinit();
    const series = parsed.value;

    try std.testing.expectEqualStrings("system.load.1", series.metric.?);
    try std.testing.expectEqual(@as(i32, 3), series.type.?);
    try std.testing.expectEqual(@as(i64, 60), series.interval.?);
    try std.testing.expectEqualStrings("percent", series.unit.?);
    try std.testing.expectEqualStrings("custom", series.source_type_name.?);
    try std.testing.expectEqual(@as(usize, 1), series.points.?.len);
    try std.testing.expectEqual(@as(usize, 1), series.resources.?.len);
    try std.testing.expectEqualStrings("demobox", series.resources.?[0].name.?);
    try std.testing.expectEqual(@as(i32, 1), series.metadata.?.origin.?.product.?);
}

test "MetricSeries - parse with extra fields" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "test", "points": [], "unknown_field": "value", "another_extra": 123}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    var parsed = try doc.as(MetricSeries, allocator, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("test", parsed.value.metric.?);
    try std.testing.expectEqual(@as(usize, 2), parsed.value.extra.count());
    try std.testing.expect(parsed.value.extra.contains("unknown_field"));
    try std.testing.expect(parsed.value.extra.contains("another_extra"));
}

test "MetricPayload - parse series array" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{
        \\  "series": [
        \\    {"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]},
        \\    {"metric": "system.load.5", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.5}]}
        \\  ]
        \\}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricPayload, allocator, .{});
    defer parsed.deinit();
    const payload = parsed.value;

    try std.testing.expectEqual(@as(usize, 2), payload.series.?.len);
    try std.testing.expectEqualStrings("system.load.1", payload.series.?[0].metric.?);
    try std.testing.expectEqualStrings("system.load.5", payload.series.?[1].metric.?);
}

test "MetricSeries - jsonStringify basic" {
    const allocator = std.testing.allocator;

    const pt = MetricPoint{
        .timestamp = 1636629071,
        .value = 0.7,
    };

    const series = MetricSeries{
        .metric = "system.load.1",
        .type = 3,
        .points = @constCast(&[_]MetricPoint{pt}),
        .tags = @constCast(&[_][]const u8{ "env:prod", "service:web" }),
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(series, .{}, &out.writer);

    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"metric\":\"system.load.1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"type\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"points\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"tags\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"env:prod\"") != null);
}

test "MetricPayload - jsonStringify" {
    const allocator = std.testing.allocator;

    const pt = MetricPoint{
        .timestamp = 1636629071,
        .value = 0.7,
    };

    const series1 = MetricSeries{
        .metric = "system.load.1",
        .type = 3,
        .points = @constCast(&[_]MetricPoint{pt}),
    };

    const payload = MetricPayload{
        .series = @constCast(&[_]MetricSeries{series1}),
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(payload, .{}, &out.writer);

    const output = out.written();

    try std.testing.expect(std.mem.indexOf(u8, output, "\"series\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"metric\":\"system.load.1\"") != null);
}

test "MetricSeries - empty fields not serialized" {
    const allocator = std.testing.allocator;

    const series = MetricSeries{
        .metric = "test",
    };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(series, .{}, &out.writer);

    const output = out.written();

    // Only metric should be present
    try std.testing.expect(std.mem.indexOf(u8, output, "\"metric\":\"test\"") != null);
    // Optional fields should not be present
    try std.testing.expect(std.mem.indexOf(u8, output, "\"type\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"interval\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"unit\"") == null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"points\"") == null);
}

test "MetricSeries - field mutation remove metric name" {
    var series = MetricSeries{
        .metric = "system.load.1",
        .type = 3,
    };

    series.metric = null;

    try std.testing.expect(series.metric == null);
    try std.testing.expectEqual(@as(i32, 3), series.type.?);
}

test "MetricSeries - field mutation set tags" {
    const allocator = std.testing.allocator;

    var series = MetricSeries{
        .metric = "system.load.1",
    };

    // Set new tags
    const new_tags = try allocator.alloc([]const u8, 2);
    defer allocator.free(new_tags);
    new_tags[0] = "env:staging";
    new_tags[1] = "region:us-west";
    series.tags = new_tags;

    try std.testing.expectEqual(@as(usize, 2), series.tags.?.len);
    try std.testing.expectEqualStrings("env:staging", series.tags.?[0]);
}

test "MetricSeries - parse and reserialize preserves data" {
    const allocator = std.testing.allocator;

    var parser: StreamParser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "test", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}
    ;

    var reader = std.Io.Reader.fixed(json);
    var doc = try parser.parseFromReader(allocator, &reader);

    const parsed = try doc.as(MetricSeries, allocator, .{});
    defer parsed.deinit();
    const series = parsed.value;

    // Serialize back
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    try std.json.Stringify.value(series, .{}, &out.writer);

    const output = out.written();

    // Verify all fields preserved
    try std.testing.expect(std.mem.indexOf(u8, output, "\"metric\":\"test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"type\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "1636629071") != null);
}
