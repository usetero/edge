//! Prometheus Exposition Format Line Parser
//!
//! A zero-allocation parser for the Prometheus text exposition format.
//! All returned slices point into the original input buffer.
//!
//! Format specification: https://prometheus.io/docs/instrumenting/exposition_formats/
//!
//! Line types:
//! - Empty lines
//! - Comments: # comment text
//! - HELP metadata: # HELP metric_name description
//! - TYPE metadata: # TYPE metric_name type
//! - Metric samples: metric_name{label="value"} 123.45 1234567890
//!

const std = @import("std");

/// Metric type as declared in TYPE metadata
pub const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,
    untyped,
    unknown,

    pub fn fromString(s: []const u8) MetricType {
        if (std.mem.eql(u8, s, "counter")) return .counter;
        if (std.mem.eql(u8, s, "gauge")) return .gauge;
        if (std.mem.eql(u8, s, "histogram")) return .histogram;
        if (std.mem.eql(u8, s, "summary")) return .summary;
        if (std.mem.eql(u8, s, "untyped")) return .untyped;
        return .unknown;
    }
};

/// A single label key-value pair
pub const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// Zero-allocation iterator over labels in a metric line.
/// All returned slices point into the original input buffer.
pub const LabelIterator = struct {
    raw: []const u8,
    pos: usize,

    pub fn init(raw: []const u8) LabelIterator {
        return .{ .raw = raw, .pos = 0 };
    }

    /// Returns the next label, or null if no more labels.
    /// Handles escaped characters in label values: \\ \" \n
    pub fn next(self: *LabelIterator) ?Label {
        // Skip whitespace and commas
        while (self.pos < self.raw.len) {
            const c = self.raw[self.pos];
            if (c == ' ' or c == ',' or c == '\t') {
                self.pos += 1;
            } else {
                break;
            }
        }

        if (self.pos >= self.raw.len) return null;

        // Parse label name (until '=')
        const name_start = self.pos;
        while (self.pos < self.raw.len and self.raw[self.pos] != '=') {
            self.pos += 1;
        }

        if (self.pos >= self.raw.len) return null;

        const name = self.raw[name_start..self.pos];
        if (name.len == 0) return null;

        // Skip '='
        self.pos += 1;
        if (self.pos >= self.raw.len) return null;

        // Expect opening quote
        if (self.raw[self.pos] != '"') return null;
        self.pos += 1;

        // Parse label value (until unescaped closing quote)
        const value_start = self.pos;
        while (self.pos < self.raw.len) {
            const c = self.raw[self.pos];
            if (c == '\\' and self.pos + 1 < self.raw.len) {
                // Skip escaped character
                self.pos += 2;
            } else if (c == '"') {
                break;
            } else {
                self.pos += 1;
            }
        }

        if (self.pos >= self.raw.len) return null;

        const value = self.raw[value_start..self.pos];

        // Skip closing quote
        self.pos += 1;

        return Label{ .name = name, .value = value };
    }

    /// Reset iterator to beginning
    pub fn reset(self: *LabelIterator) void {
        self.pos = 0;
    }

    /// Find a label by name, returns the value or null
    pub fn find(self: *LabelIterator, name: []const u8) ?[]const u8 {
        self.reset();
        while (self.next()) |label| {
            if (std.mem.eql(u8, label.name, name)) {
                return label.value;
            }
        }
        return null;
    }
};

/// Result of parsing a single line
pub const ParsedLine = union(enum) {
    /// Empty line
    empty: void,

    /// Comment line (# without HELP/TYPE)
    comment: []const u8,

    /// HELP metadata: # HELP metric_name description
    help: struct {
        metric_name: []const u8,
        description: []const u8,
    },

    /// TYPE metadata: # TYPE metric_name type
    type_info: struct {
        metric_name: []const u8,
        metric_type: MetricType,
    },

    /// Metric sample: metric_name{labels} value [timestamp]
    sample: struct {
        metric_name: []const u8,
        labels: LabelIterator,
        value: []const u8,
        timestamp: ?[]const u8,
    },

    /// Parse error - line couldn't be parsed
    parse_error: void,
};

/// Parse a single line of Prometheus exposition format.
/// Returns a ParsedLine union - all slices point into the input buffer.
/// The input should NOT include the trailing newline.
pub fn parseLine(line: []const u8) ParsedLine {
    // Handle empty lines
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) {
        return .{ .empty = {} };
    }

    // Check for comment/metadata lines
    if (trimmed[0] == '#') {
        return parseCommentLine(trimmed);
    }

    // Parse as metric sample
    return parseSampleLine(trimmed);
}

/// Parse a comment, HELP, or TYPE line
fn parseCommentLine(line: []const u8) ParsedLine {
    // Skip the '#'
    var pos: usize = 1;

    // Skip whitespace after #
    while (pos < line.len and (line[pos] == ' ' or line[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= line.len) {
        return .{ .comment = "" };
    }

    const rest = line[pos..];

    // Check for HELP
    if (std.mem.startsWith(u8, rest, "HELP")) {
        return parseHelpLine(rest[4..]);
    }

    // Check for TYPE
    if (std.mem.startsWith(u8, rest, "TYPE")) {
        return parseTypeLine(rest[4..]);
    }

    // Regular comment
    return .{ .comment = rest };
}

/// Parse HELP line: "HELP metric_name description text"
fn parseHelpLine(after_help: []const u8) ParsedLine {
    var pos: usize = 0;

    // Skip whitespace
    while (pos < after_help.len and (after_help[pos] == ' ' or after_help[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= after_help.len) {
        return .{ .parse_error = {} };
    }

    // Parse metric name
    const name_start = pos;
    while (pos < after_help.len and isMetricNameChar(after_help[pos])) {
        pos += 1;
    }

    const metric_name = after_help[name_start..pos];
    if (metric_name.len == 0) {
        return .{ .parse_error = {} };
    }

    // Skip whitespace before description
    while (pos < after_help.len and (after_help[pos] == ' ' or after_help[pos] == '\t')) {
        pos += 1;
    }

    // Rest is the description (may be empty)
    const description = if (pos < after_help.len) after_help[pos..] else "";

    return .{ .help = .{
        .metric_name = metric_name,
        .description = description,
    } };
}

/// Parse TYPE line: "TYPE metric_name type"
fn parseTypeLine(after_type: []const u8) ParsedLine {
    var pos: usize = 0;

    // Skip whitespace
    while (pos < after_type.len and (after_type[pos] == ' ' or after_type[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= after_type.len) {
        return .{ .parse_error = {} };
    }

    // Parse metric name
    const name_start = pos;
    while (pos < after_type.len and isMetricNameChar(after_type[pos])) {
        pos += 1;
    }

    const metric_name = after_type[name_start..pos];
    if (metric_name.len == 0) {
        return .{ .parse_error = {} };
    }

    // Skip whitespace before type
    while (pos < after_type.len and (after_type[pos] == ' ' or after_type[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= after_type.len) {
        return .{ .parse_error = {} };
    }

    // Parse type name
    const type_start = pos;
    while (pos < after_type.len and isMetricNameChar(after_type[pos])) {
        pos += 1;
    }

    const type_str = after_type[type_start..pos];

    return .{ .type_info = .{
        .metric_name = metric_name,
        .metric_type = MetricType.fromString(type_str),
    } };
}

/// Parse a metric sample line: "metric_name{labels} value [timestamp]"
fn parseSampleLine(line: []const u8) ParsedLine {
    var pos: usize = 0;

    // Parse metric name
    const name_start = pos;
    while (pos < line.len and isMetricNameChar(line[pos])) {
        pos += 1;
    }

    const metric_name = line[name_start..pos];
    if (metric_name.len == 0) {
        return .{ .parse_error = {} };
    }

    // Check for labels
    var labels_raw: []const u8 = "";
    if (pos < line.len and line[pos] == '{') {
        pos += 1; // Skip '{'
        const labels_start = pos;

        // Find closing '}'
        var brace_depth: usize = 1;
        while (pos < line.len and brace_depth > 0) {
            const c = line[pos];
            if (c == '\\' and pos + 1 < line.len) {
                pos += 2; // Skip escaped char
            } else if (c == '"') {
                // Skip quoted string
                pos += 1;
                while (pos < line.len and line[pos] != '"') {
                    if (line[pos] == '\\' and pos + 1 < line.len) {
                        pos += 2;
                    } else {
                        pos += 1;
                    }
                }
                if (pos < line.len) pos += 1; // Skip closing quote
            } else if (c == '{') {
                brace_depth += 1;
                pos += 1;
            } else if (c == '}') {
                brace_depth -= 1;
                if (brace_depth > 0) pos += 1;
            } else {
                pos += 1;
            }
        }

        if (brace_depth != 0) {
            return .{ .parse_error = {} };
        }

        labels_raw = line[labels_start..pos];
        pos += 1; // Skip '}'
    }

    // Skip whitespace before value
    while (pos < line.len and (line[pos] == ' ' or line[pos] == '\t')) {
        pos += 1;
    }

    if (pos >= line.len) {
        return .{ .parse_error = {} };
    }

    // Parse value (required)
    const value_start = pos;
    while (pos < line.len and line[pos] != ' ' and line[pos] != '\t') {
        pos += 1;
    }

    const value = line[value_start..pos];
    if (value.len == 0) {
        return .{ .parse_error = {} };
    }

    // Skip whitespace before optional timestamp
    while (pos < line.len and (line[pos] == ' ' or line[pos] == '\t')) {
        pos += 1;
    }

    // Parse optional timestamp
    var timestamp: ?[]const u8 = null;
    if (pos < line.len) {
        const ts_start = pos;
        while (pos < line.len and line[pos] != ' ' and line[pos] != '\t') {
            pos += 1;
        }
        timestamp = line[ts_start..pos];
    }

    return .{ .sample = .{
        .metric_name = metric_name,
        .labels = LabelIterator.init(labels_raw),
        .value = value,
        .timestamp = timestamp,
    } };
}

/// Check if character is valid in a metric/label name
fn isMetricNameChar(c: u8) bool {
    return (c >= 'a' and c <= 'z') or
        (c >= 'A' and c <= 'Z') or
        (c >= '0' and c <= '9') or
        c == '_' or c == ':';
}

// =============================================================================
// Tests
// =============================================================================

test "parseLine - empty lines" {
    try std.testing.expectEqual(ParsedLine{ .empty = {} }, parseLine(""));
    try std.testing.expectEqual(ParsedLine{ .empty = {} }, parseLine("   "));
    try std.testing.expectEqual(ParsedLine{ .empty = {} }, parseLine("\t"));
    try std.testing.expectEqual(ParsedLine{ .empty = {} }, parseLine("  \t  "));
}

test "parseLine - comment lines" {
    const result = parseLine("# this is a comment");
    switch (result) {
        .comment => |c| try std.testing.expectEqualStrings("this is a comment", c),
        else => return error.UnexpectedResult,
    }

    const result2 = parseLine("#");
    switch (result2) {
        .comment => |c| try std.testing.expectEqualStrings("", c),
        else => return error.UnexpectedResult,
    }
}

test "parseLine - HELP lines" {
    const result = parseLine("# HELP http_requests_total Total HTTP requests");
    switch (result) {
        .help => |h| {
            try std.testing.expectEqualStrings("http_requests_total", h.metric_name);
            try std.testing.expectEqualStrings("Total HTTP requests", h.description);
        },
        else => return error.UnexpectedResult,
    }

    // HELP with empty description
    const result2 = parseLine("# HELP metric_name");
    switch (result2) {
        .help => |h| {
            try std.testing.expectEqualStrings("metric_name", h.metric_name);
            try std.testing.expectEqualStrings("", h.description);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - TYPE lines" {
    const result = parseLine("# TYPE http_requests_total counter");
    switch (result) {
        .type_info => |t| {
            try std.testing.expectEqualStrings("http_requests_total", t.metric_name);
            try std.testing.expectEqual(MetricType.counter, t.metric_type);
        },
        else => return error.UnexpectedResult,
    }

    const result2 = parseLine("# TYPE temperature gauge");
    switch (result2) {
        .type_info => |t| {
            try std.testing.expectEqualStrings("temperature", t.metric_name);
            try std.testing.expectEqual(MetricType.gauge, t.metric_type);
        },
        else => return error.UnexpectedResult,
    }

    const result3 = parseLine("# TYPE request_duration histogram");
    switch (result3) {
        .type_info => |t| {
            try std.testing.expectEqual(MetricType.histogram, t.metric_type);
        },
        else => return error.UnexpectedResult,
    }

    const result4 = parseLine("# TYPE rpc_duration summary");
    switch (result4) {
        .type_info => |t| {
            try std.testing.expectEqual(MetricType.summary, t.metric_type);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - simple samples without labels" {
    const result = parseLine("http_requests_total 1234");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("http_requests_total", s.metric_name);
            try std.testing.expectEqualStrings("1234", s.value);
            try std.testing.expect(s.timestamp == null);
        },
        else => return error.UnexpectedResult,
    }

    // With timestamp
    const result2 = parseLine("metric_name 123.45 1678886400000");
    switch (result2) {
        .sample => |s| {
            try std.testing.expectEqualStrings("metric_name", s.metric_name);
            try std.testing.expectEqualStrings("123.45", s.value);
            try std.testing.expectEqualStrings("1678886400000", s.timestamp.?);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - samples with labels" {
    const result = parseLine("http_requests_total{method=\"get\",status=\"200\"} 1027");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("http_requests_total", s.metric_name);
            try std.testing.expectEqualStrings("1027", s.value);

            var labels = s.labels;
            const label1 = labels.next().?;
            try std.testing.expectEqualStrings("method", label1.name);
            try std.testing.expectEqualStrings("get", label1.value);

            const label2 = labels.next().?;
            try std.testing.expectEqualStrings("status", label2.name);
            try std.testing.expectEqualStrings("200", label2.value);

            try std.testing.expect(labels.next() == null);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - samples with empty labels" {
    const result = parseLine("metric_name{} 42");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("metric_name", s.metric_name);
            try std.testing.expectEqualStrings("42", s.value);

            var labels = s.labels;
            try std.testing.expect(labels.next() == null);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - histogram buckets" {
    const result = parseLine("http_request_duration_seconds_bucket{le=\"0.1\"} 24054");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("http_request_duration_seconds_bucket", s.metric_name);
            try std.testing.expectEqualStrings("24054", s.value);

            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("le", label.name);
            try std.testing.expectEqualStrings("0.1", label.value);
        },
        else => return error.UnexpectedResult,
    }

    // +Inf bucket
    const result2 = parseLine("http_request_duration_seconds_bucket{le=\"+Inf\"} 144320");
    switch (result2) {
        .sample => |s| {
            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("+Inf", label.value);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - summary quantiles" {
    const result = parseLine("rpc_duration_seconds{quantile=\"0.99\"} 0.023");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("rpc_duration_seconds", s.metric_name);
            try std.testing.expectEqualStrings("0.023", s.value);

            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("quantile", label.name);
            try std.testing.expectEqualStrings("0.99", label.value);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - special values" {
    // NaN
    const result = parseLine("metric_name NaN");
    switch (result) {
        .sample => |s| try std.testing.expectEqualStrings("NaN", s.value),
        else => return error.UnexpectedResult,
    }

    // +Inf
    const result2 = parseLine("metric_name +Inf");
    switch (result2) {
        .sample => |s| try std.testing.expectEqualStrings("+Inf", s.value),
        else => return error.UnexpectedResult,
    }

    // -Inf
    const result3 = parseLine("metric_name -Inf");
    switch (result3) {
        .sample => |s| try std.testing.expectEqualStrings("-Inf", s.value),
        else => return error.UnexpectedResult,
    }
}

test "parseLine - escaped label values" {
    const result = parseLine("metric{path=\"/foo\\\"bar\"} 1");
    switch (result) {
        .sample => |s| {
            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("path", label.name);
            // The value includes the escape sequence (we don't unescape)
            try std.testing.expectEqualStrings("/foo\\\"bar", label.value);
        },
        else => return error.UnexpectedResult,
    }

    // Escaped backslash
    const result2 = parseLine("metric{path=\"C:\\\\Users\"} 1");
    switch (result2) {
        .sample => |s| {
            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("C:\\\\Users", label.value);
        },
        else => return error.UnexpectedResult,
    }

    // Escaped newline
    const result3 = parseLine("metric{msg=\"line1\\nline2\"} 1");
    switch (result3) {
        .sample => |s| {
            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("line1\\nline2", label.value);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - unicode in label values" {
    const result = parseLine("metric{name=\"日本語\"} 42");
    switch (result) {
        .sample => |s| {
            var labels = s.labels;
            const label = labels.next().?;
            try std.testing.expectEqualStrings("日本語", label.value);
        },
        else => return error.UnexpectedResult,
    }
}

test "parseLine - malformed lines" {
    // Missing value
    try std.testing.expectEqual(ParsedLine{ .parse_error = {} }, parseLine("metric_name"));
    try std.testing.expectEqual(ParsedLine{ .parse_error = {} }, parseLine("metric_name{}"));

    // Unclosed brace
    try std.testing.expectEqual(ParsedLine{ .parse_error = {} }, parseLine("metric{label=\"value\" 123"));

    // Empty TYPE
    try std.testing.expectEqual(ParsedLine{ .parse_error = {} }, parseLine("# TYPE"));

    // Empty HELP
    try std.testing.expectEqual(ParsedLine{ .parse_error = {} }, parseLine("# HELP"));
}

test "parseLine - metric names with colons" {
    const result = parseLine("namespace:subsystem:metric_name 123");
    switch (result) {
        .sample => |s| {
            try std.testing.expectEqualStrings("namespace:subsystem:metric_name", s.metric_name);
        },
        else => return error.UnexpectedResult,
    }
}

test "LabelIterator - find label by name" {
    const result = parseLine("metric{a=\"1\",b=\"2\",c=\"3\"} 42");
    switch (result) {
        .sample => |s| {
            var labels = s.labels;

            try std.testing.expectEqualStrings("1", labels.find("a").?);
            try std.testing.expectEqualStrings("2", labels.find("b").?);
            try std.testing.expectEqualStrings("3", labels.find("c").?);
            try std.testing.expect(labels.find("d") == null);
        },
        else => return error.UnexpectedResult,
    }
}
