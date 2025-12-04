const std = @import("std");
const proto = @import("proto");

const Policy = proto.policy.Policy;
const FilterAction = proto.policy.FilterAction;
const LogFilterConfig = proto.policy.LogFilterConfig;
const LogMatcher = proto.policy.LogMatcher;

/// JSON schema for a matcher
const MatcherJson = struct {
    match_type: []const u8,
    key: []const u8 = "",
    regex: []const u8,
    negate: bool = false,
};

/// JSON schema for a policy
const PolicyJson = struct {
    /// Unique identifier for the policy (required)
    id: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
    priority: i32 = 0,
    enabled: bool = true,
    // For filter policies
    matchers: ?[]MatcherJson = null,
    action: ?[]const u8 = null,
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

        // Build filter config
        var filter: ?LogFilterConfig = null;
        if (json_policy.matchers != null or json_policy.action != null) {
            // Parse matchers
            var matchers = std.ArrayListUnmanaged(LogMatcher){};
            if (json_policy.matchers) |json_matchers| {
                try matchers.ensureTotalCapacity(allocator, json_matchers.len);
                for (json_matchers) |jm| {
                    const matcher = try parseLogMatcher(allocator, jm);
                    matchers.appendAssumeCapacity(matcher);
                }
            }
            // Parse action
            const action = if (json_policy.action) |a| try parseFilterAction(a) else .FILTER_ACTION_UNSPECIFIED;

            filter = LogFilterConfig{
                .matchers = matchers,
                .action = action,
            };
        }

        policies[i] = Policy{
            .id = id,
            .name = name,
            .description = description,
            .priority = json_policy.priority,
            .enabled = json_policy.enabled,
            .log_filter = filter,
        };
    }

    return policies;
}

/// Parse a LogMatcher from JSON
fn parseLogMatcher(allocator: std.mem.Allocator, jm: MatcherJson) !LogMatcher {
    // Validate match_type before allocating to avoid leaks on error
    const match_case: enum { log_body, log_severity_text, log_attribute, resource_attribute, resource_schema_url, scope_name, scope_version, scope_attribute, scope_schema_url } =
        if (std.mem.eql(u8, jm.match_type, "log_body")) .log_body else if (std.mem.eql(u8, jm.match_type, "log_severity_text")) .log_severity_text else if (std.mem.eql(u8, jm.match_type, "log_attribute")) .log_attribute else if (std.mem.eql(u8, jm.match_type, "resource_attribute")) .resource_attribute else if (std.mem.eql(u8, jm.match_type, "resource_schema_url")) .resource_schema_url else if (std.mem.eql(u8, jm.match_type, "scope_name")) .scope_name else if (std.mem.eql(u8, jm.match_type, "scope_version")) .scope_version else if (std.mem.eql(u8, jm.match_type, "scope_attribute")) .scope_attribute else if (std.mem.eql(u8, jm.match_type, "scope_schema_url")) .scope_schema_url else return error.InvalidMatchType;

    const regex = try allocator.dupe(u8, jm.regex);
    const key = if (jm.key.len > 0) try allocator.dupe(u8, jm.key) else &.{};

    // Map match_type string to the appropriate union variant
    const match: LogMatcher.match_union = switch (match_case) {
        .log_body => .{ .log_body = .{ .regex = regex } },
        .log_severity_text => .{ .log_severity_text = .{ .regex = regex } },
        .log_attribute => .{ .log_attribute = .{ .key = key, .regex = regex } },
        .resource_attribute => .{ .resource_attribute = .{ .key = key, .regex = regex } },
        .resource_schema_url => .{ .resource_schema_url = .{ .regex = regex } },
        .scope_name => .{ .scope_name = .{ .regex = regex } },
        .scope_version => .{ .scope_version = .{ .regex = regex } },
        .scope_attribute => .{ .scope_attribute = .{ .key = key, .regex = regex } },
        .scope_schema_url => .{ .scope_schema_url = .{ .regex = regex } },
    };

    return LogMatcher{
        .negate = jm.negate,
        .match = match,
    };
}

/// Parse FilterAction from string
pub fn parseFilterAction(s: []const u8) !FilterAction {
    if (std.mem.eql(u8, s, "keep")) return .FILTER_ACTION_KEEP;
    if (std.mem.eql(u8, s, "drop")) return .FILTER_ACTION_DROP;
    return error.InvalidAction;
}

test "parseFilterAction" {
    try std.testing.expect(try parseFilterAction("keep") == .FILTER_ACTION_KEEP);
    try std.testing.expect(try parseFilterAction("drop") == .FILTER_ACTION_DROP);
    try std.testing.expectError(error.InvalidAction, parseFilterAction("invalid"));
}

test "parseLogMatcher" {
    const allocator = std.testing.allocator;

    // Test log_body matcher
    const body_matcher = try parseLogMatcher(allocator, .{
        .match_type = "log_body",
        .regex = "test.*",
    });
    defer {
        if (body_matcher.match) |m| {
            switch (m) {
                .log_body => |b| allocator.free(b.regex),
                else => {},
            }
        }
    }
    try std.testing.expect(body_matcher.match != null);
    try std.testing.expect(body_matcher.match.? == .log_body);
    try std.testing.expectEqualStrings("test.*", body_matcher.match.?.log_body.regex);

    // Test log_attribute matcher with key
    const attr_matcher = try parseLogMatcher(allocator, .{
        .match_type = "log_attribute",
        .key = "service.name",
        .regex = "payment.*",
        .negate = true,
    });
    defer {
        if (attr_matcher.match) |m| {
            switch (m) {
                .log_attribute => |a| {
                    allocator.free(a.key);
                    allocator.free(a.regex);
                },
                else => {},
            }
        }
    }
    try std.testing.expect(attr_matcher.negate == true);
    try std.testing.expect(attr_matcher.match.? == .log_attribute);
    try std.testing.expectEqualStrings("service.name", attr_matcher.match.?.log_attribute.key);
    try std.testing.expectEqualStrings("payment.*", attr_matcher.match.?.log_attribute.regex);

    // Test invalid match type
    try std.testing.expectError(error.InvalidMatchType, parseLogMatcher(allocator, .{
        .match_type = "invalid_type",
        .regex = "test",
    }));
}
