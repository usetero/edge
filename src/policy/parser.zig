const std = @import("std");
const proto = @import("proto");

const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const LogMatcher = proto.policy.LogMatcher;
const LogField = proto.policy.LogField;

/// JSON schema for a matcher
const MatcherJson = struct {
    /// Field type: "log_body", "log_severity_text", "log_attribute", "resource_attribute", "scope_attribute"
    field: []const u8,
    /// Key for attribute-based fields (required for *_attribute types)
    key: []const u8 = "",
    /// Match type: "regex", "exact", or "exists"
    match_type: []const u8 = "regex",
    /// Pattern for regex or exact matching
    pattern: []const u8 = "",
    /// Whether to negate the match
    negate: bool = false,
};

/// JSON schema for a policy
const PolicyJson = struct {
    /// Unique identifier for the policy (required)
    id: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
    enabled: bool = true,
    /// Matchers for log policies
    matchers: ?[]MatcherJson = null,
    /// Keep value: "all", "none", "N%", "N/s", "N/m"
    keep: []const u8 = "all",
};

/// JSON schema for a policies-only file
const PoliciesFileJson = struct {
    policies: []PolicyJson,
};

/// Parse policies-only JSON file
pub fn parsePoliciesFile(allocator: std.mem.Allocator, path: []const u8) ![]Policy {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parsePoliciesBytes(allocator, contents);
}

/// Parse policies from JSON bytes
pub fn parsePoliciesBytes(allocator: std.mem.Allocator, json_bytes: []const u8) ![]Policy {
    const parsed = try std.json.parseFromSlice(
        PoliciesFileJson,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();

    const json_policies = parsed.value;
    return parsePolicies(allocator, json_policies.policies);
}

/// Parse policies from JSON array
pub fn parsePolicies(allocator: std.mem.Allocator, json_policies: []PolicyJson) ![]Policy {
    var policies = try allocator.alloc(Policy, json_policies.len);

    for (json_policies, 0..) |json_policy, i| {
        // Allocate and copy strings
        const id = try allocator.dupe(u8, json_policy.id);
        const name = try allocator.dupe(u8, json_policy.name);
        const description = if (json_policy.description) |desc| try allocator.dupe(u8, desc) else &.{};

        // Build log target config
        var log_target: ?LogTarget = null;
        if (json_policy.matchers != null or json_policy.keep.len > 0) {
            // Parse matchers
            var matchers = std.ArrayListUnmanaged(LogMatcher){};
            if (json_policy.matchers) |json_matchers| {
                try matchers.ensureTotalCapacity(allocator, json_matchers.len);
                for (json_matchers) |jm| {
                    const matcher = try parseLogMatcher(allocator, jm);
                    matchers.appendAssumeCapacity(matcher);
                }
            }

            log_target = LogTarget{
                .match = matchers,
                .keep = try allocator.dupe(u8, json_policy.keep),
            };
        }

        policies[i] = Policy{
            .id = id,
            .name = name,
            .description = description,
            .enabled = json_policy.enabled,
            .log = log_target,
        };
    }

    return policies;
}

/// Parse a LogMatcher from JSON
fn parseLogMatcher(allocator: std.mem.Allocator, jm: MatcherJson) !LogMatcher {
    // Parse field type
    const field: LogMatcher.field_union = blk: {
        if (std.mem.eql(u8, jm.field, "log_body")) {
            break :blk .{ .log_field = .LOG_FIELD_BODY };
        } else if (std.mem.eql(u8, jm.field, "log_severity_text")) {
            break :blk .{ .log_field = .LOG_FIELD_SEVERITY_TEXT };
        } else if (std.mem.eql(u8, jm.field, "log_trace_id")) {
            break :blk .{ .log_field = .LOG_FIELD_TRACE_ID };
        } else if (std.mem.eql(u8, jm.field, "log_span_id")) {
            break :blk .{ .log_field = .LOG_FIELD_SPAN_ID };
        } else if (std.mem.eql(u8, jm.field, "log_event_name")) {
            break :blk .{ .log_field = .LOG_FIELD_EVENT_NAME };
        } else if (std.mem.eql(u8, jm.field, "resource_schema_url")) {
            break :blk .{ .log_field = .LOG_FIELD_RESOURCE_SCHEMA_URL };
        } else if (std.mem.eql(u8, jm.field, "scope_schema_url")) {
            break :blk .{ .log_field = .LOG_FIELD_SCOPE_SCHEMA_URL };
        } else if (std.mem.eql(u8, jm.field, "log_attribute")) {
            if (jm.key.len == 0) return error.MissingKey;
            break :blk .{ .log_attribute = try allocator.dupe(u8, jm.key) };
        } else if (std.mem.eql(u8, jm.field, "resource_attribute")) {
            if (jm.key.len == 0) return error.MissingKey;
            break :blk .{ .resource_attribute = try allocator.dupe(u8, jm.key) };
        } else if (std.mem.eql(u8, jm.field, "scope_attribute")) {
            if (jm.key.len == 0) return error.MissingKey;
            break :blk .{ .scope_attribute = try allocator.dupe(u8, jm.key) };
        } else {
            return error.InvalidFieldType;
        }
    };

    // Parse match type
    const match: LogMatcher.match_union = blk: {
        if (std.mem.eql(u8, jm.match_type, "regex")) {
            break :blk .{ .regex = try allocator.dupe(u8, jm.pattern) };
        } else if (std.mem.eql(u8, jm.match_type, "exact")) {
            break :blk .{ .exact = try allocator.dupe(u8, jm.pattern) };
        } else if (std.mem.eql(u8, jm.match_type, "exists")) {
            break :blk .{ .exists = true };
        } else {
            return error.InvalidMatchType;
        }
    };

    return LogMatcher{
        .negate = jm.negate,
        .field = field,
        .match = match,
    };
}

/// Parse keep value - validates format
/// Valid formats: "all", "none", "N%", "N/s", "N/m"
pub fn parseKeepValue(s: []const u8) !void {
    if (s.len == 0 or std.mem.eql(u8, s, "all") or std.mem.eql(u8, s, "none")) {
        return;
    }
    // Check for percentage: "N%"
    if (s.len >= 2 and s[s.len - 1] == '%') {
        const num_str = s[0 .. s.len - 1];
        const pct = std.fmt.parseInt(u8, num_str, 10) catch return error.InvalidKeepValue;
        if (pct > 100) return error.InvalidKeepValue;
        return;
    }
    // Check for rate limit: "N/s" or "N/m"
    if (s.len >= 3 and s[s.len - 2] == '/') {
        const num_str = s[0 .. s.len - 2];
        _ = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidKeepValue;
        if (s[s.len - 1] != 's' and s[s.len - 1] != 'm') {
            return error.InvalidKeepValue;
        }
        return;
    }
    return error.InvalidKeepValue;
}

test "parseKeepValue" {
    try parseKeepValue("all");
    try parseKeepValue("none");
    try parseKeepValue("");
    try parseKeepValue("50%");
    try parseKeepValue("0%");
    try parseKeepValue("100%");
    try parseKeepValue("100/s");
    try parseKeepValue("1000/m");

    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("101%"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("invalid"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("100/x"));
}

test "parseLogMatcher: log_body with regex" {
    const allocator = std.testing.allocator;

    const matcher = try parseLogMatcher(allocator, .{
        .field = "log_body",
        .match_type = "regex",
        .pattern = "test.*",
    });
    defer {
        if (matcher.match) |m| {
            switch (m) {
                .regex => |r| allocator.free(r),
                .exact => |e| allocator.free(e),
                .exists => {},
            }
        }
    }

    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_BODY, matcher.field.?.log_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("test.*", matcher.match.?.regex);
}

test "parseLogMatcher: log_attribute with key" {
    const allocator = std.testing.allocator;

    const matcher = try parseLogMatcher(allocator, .{
        .field = "log_attribute",
        .key = "service.name",
        .match_type = "exact",
        .pattern = "payment-api",
        .negate = true,
    });
    defer {
        if (matcher.field) |f| {
            switch (f) {
                .log_attribute => |k| allocator.free(k),
                .resource_attribute => |k| allocator.free(k),
                .scope_attribute => |k| allocator.free(k),
                .log_field => {},
            }
        }
        if (matcher.match) |m| {
            switch (m) {
                .regex => |r| allocator.free(r),
                .exact => |e| allocator.free(e),
                .exists => {},
            }
        }
    }

    try std.testing.expect(matcher.negate == true);
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expectEqualStrings("service.name", matcher.field.?.log_attribute);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .exact);
    try std.testing.expectEqualStrings("payment-api", matcher.match.?.exact);
}

test "parseLogMatcher: exists match type" {
    const allocator = std.testing.allocator;

    const matcher = try parseLogMatcher(allocator, .{
        .field = "log_attribute",
        .key = "trace_id",
        .match_type = "exists",
    });
    defer {
        if (matcher.field) |f| {
            switch (f) {
                .log_attribute => |k| allocator.free(k),
                .resource_attribute => |k| allocator.free(k),
                .scope_attribute => |k| allocator.free(k),
                .log_field => {},
            }
        }
    }

    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);
}

test "parseLogMatcher: invalid field type" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidFieldType, parseLogMatcher(allocator, .{
        .field = "invalid_field",
        .pattern = "test",
    }));
}

test "parseLogMatcher: missing key for attribute" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.MissingKey, parseLogMatcher(allocator, .{
        .field = "log_attribute",
        .pattern = "test",
    }));
}
