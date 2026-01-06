const std = @import("std");
const zimdjson = @import("zimdjson");

pub const Parser = zimdjson.ondemand.FullParser(.default);
pub const Value = Parser.Value;
pub const AnyValue = Parser.AnyValue;

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

    pub fn parse(value: Value) !MetricPoint {
        var point = MetricPoint{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "timestamp")) {
                point.timestamp = try field.value.asSigned();
            } else if (std.mem.eql(u8, key, "value")) {
                point.value = try field.value.asDouble();
            }
        }

        return point;
    }

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

    pub fn parse(value: Value) !MetricResource {
        var resource = MetricResource{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "name")) {
                resource.name = try field.value.asString();
            } else if (std.mem.eql(u8, key, "type")) {
                resource.type = try field.value.asString();
            }
        }

        return resource;
    }

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

    pub fn parse(value: Value) !MetricOrigin {
        var origin = MetricOrigin{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "metric_type")) {
                origin.metric_type = @intCast(try field.value.asSigned());
            } else if (std.mem.eql(u8, key, "product")) {
                origin.product = @intCast(try field.value.asSigned());
            } else if (std.mem.eql(u8, key, "service")) {
                origin.service = @intCast(try field.value.asSigned());
            }
        }

        return origin;
    }

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

    pub fn parse(value: Value) !MetricMetadata {
        var metadata = MetricMetadata{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "origin")) {
                metadata.origin = try MetricOrigin.parse(field.value);
            }
        }

        return metadata;
    }

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

    extra: std.StringHashMapUnmanaged(AnyValue) = .empty,

    /// Free extra field keys allocated during parsing
    pub fn deinit(self: *MetricSeries, allocator: std.mem.Allocator) void {
        var it = self.extra.keyIterator();
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        self.extra.deinit(allocator);
    }

    /// Parse a MetricSeries from a zimdjson Value (object)
    pub fn parse(allocator: std.mem.Allocator, value: Value) !MetricSeries {
        var series = MetricSeries{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "metric")) {
                series.metric = try field.value.asString();
            } else if (std.mem.eql(u8, key, "type")) {
                series.type = @intCast(try field.value.asSigned());
            } else if (std.mem.eql(u8, key, "interval")) {
                series.interval = try field.value.asSigned();
            } else if (std.mem.eql(u8, key, "unit")) {
                series.unit = try field.value.asString();
            } else if (std.mem.eql(u8, key, "source_type_name")) {
                series.source_type_name = try field.value.asString();
            } else if (std.mem.eql(u8, key, "metadata")) {
                series.metadata = try MetricMetadata.parse(field.value);
            } else if (std.mem.eql(u8, key, "points")) {
                var points_arr = try field.value.asArray();
                var points_list: std.ArrayListUnmanaged(MetricPoint) = .empty;
                var points_it = points_arr.iterator();
                while (try points_it.next()) |point_val| {
                    try points_list.append(allocator, try MetricPoint.parse(point_val));
                }
                series.points = try points_list.toOwnedSlice(allocator);
            } else if (std.mem.eql(u8, key, "resources")) {
                var res_arr = try field.value.asArray();
                var res_list: std.ArrayListUnmanaged(MetricResource) = .empty;
                var res_it = res_arr.iterator();
                while (try res_it.next()) |res_val| {
                    try res_list.append(allocator, try MetricResource.parse(res_val));
                }
                series.resources = try res_list.toOwnedSlice(allocator);
            } else if (std.mem.eql(u8, key, "tags")) {
                var tags_arr = try field.value.asArray();
                var tags_list: std.ArrayListUnmanaged([]const u8) = .empty;
                var tags_it = tags_arr.iterator();
                while (try tags_it.next()) |tag_val| {
                    try tags_list.append(allocator, try tag_val.asString());
                }
                series.tags = try tags_list.toOwnedSlice(allocator);
            } else {
                // Store unknown fields in extra map - need to dupe the key since it's from the parser buffer
                const key_copy = try allocator.dupe(u8, key);
                try series.extra.put(allocator, key_copy, try field.value.asAny());
            }
        }

        return series;
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
    fn writeAnyValue(jws: anytype, value: AnyValue) !void {
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
    /// A list of timeseries to submit to Datadog
    series: ?[]MetricSeries = null,

    /// Parse a MetricPayload from a zimdjson Value (object)
    pub fn parse(allocator: std.mem.Allocator, value: Value) !MetricPayload {
        var payload = MetricPayload{};

        var obj = try value.asObject();
        var it = obj.iterator();
        while (try it.next()) |field| {
            const key = try field.key.get();

            if (std.mem.eql(u8, key, "series")) {
                var series_arr = try field.value.asArray();
                var series_list: std.ArrayListUnmanaged(MetricSeries) = .empty;
                var series_it = series_arr.iterator();
                while (try series_it.next()) |series_val| {
                    try series_list.append(allocator, try MetricSeries.parse(allocator, series_val));
                }
                payload.series = try series_list.toOwnedSlice(allocator);
            }
        }

        return payload;
    }

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

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"timestamp": 1636629071, "value": 0.7}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const point = try MetricPoint.parse(doc.asValue());

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

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"name": "demobox", "type": "host"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const resource = try MetricResource.parse(doc.asValue());

    try std.testing.expectEqualStrings("demobox", resource.name.?);
    try std.testing.expectEqualStrings("host", resource.type.?);
}

test "MetricSeries - parse basic fields" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}], "tags": ["env:prod", "service:web"]}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.points.?);
    defer allocator.free(series.tags.?);

    try std.testing.expectEqualStrings("system.load.1", series.metric.?);
    try std.testing.expectEqual(@as(i32, 3), series.type.?);
    try std.testing.expectEqual(@as(usize, 1), series.points.?.len);
    try std.testing.expectEqual(@as(usize, 2), series.tags.?.len);
    try std.testing.expectEqualStrings("env:prod", series.tags.?[0]);
}

test "MetricSeries - parse all known fields" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
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

    const doc = try parser.parseFromSlice(allocator, json);
    const series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.points.?);
    defer allocator.free(series.resources.?);
    defer allocator.free(series.tags.?);

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

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "test", "points": [], "unknown_field": "value", "another_extra": 123}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.points.?);
    defer {
        var it = series.extra.keyIterator();
        while (it.next()) |key| {
            allocator.free(key.*);
        }
        series.extra.deinit(allocator);
    }

    try std.testing.expectEqualStrings("test", series.metric.?);
    try std.testing.expectEqual(@as(usize, 2), series.extra.count());
    try std.testing.expect(series.extra.contains("unknown_field"));
    try std.testing.expect(series.extra.contains("another_extra"));
}

test "MetricPayload - parse series array" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{
        \\  "series": [
        \\    {"metric": "system.load.1", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]},
        \\    {"metric": "system.load.5", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.5}]}
        \\  ]
        \\}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const payload = try MetricPayload.parse(allocator, doc.asValue());
    defer {
        for (payload.series.?) |*s| {
            allocator.free(s.points.?);
        }
        allocator.free(payload.series.?);
    }

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

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"metric": "test", "type": 3, "points": [{"timestamp": 1636629071, "value": 0.7}]}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    const series = try MetricSeries.parse(allocator, doc.asValue());
    defer allocator.free(series.points.?);

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

test "MetricSeries - parse empty object" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json = "{}";

    const doc = try parser.parseFromSlice(allocator, json);
    const series = try MetricSeries.parse(allocator, doc.asValue());

    try std.testing.expect(series.metric == null);
    try std.testing.expect(series.type == null);
    try std.testing.expect(series.points == null);
    try std.testing.expect(series.tags == null);
    try std.testing.expectEqual(@as(usize, 0), series.extra.count());
}

test "MetricPayload - parse empty object" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json = "{}";

    const doc = try parser.parseFromSlice(allocator, json);
    const payload = try MetricPayload.parse(allocator, doc.asValue());

    try std.testing.expect(payload.series == null);
}
