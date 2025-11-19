const std = @import("std");
const policy_mod = @import("./policy.zig");
const Policy = policy_mod.Policy;
const TelemetryType = policy_mod.TelemetryType;
const ActionType = policy_mod.ActionType;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Filter manages a collection of policies and evaluates JSON against them
/// Uses MultiArrayList for cache-friendly data layout following DoD principles
pub const FilterEvaluator = struct {
    /// MultiArrayList stores policies in struct-of-arrays layout
    /// This improves cache utilization when scanning policies
    policies: std.MultiArrayList(Policy),

    /// Allocator for managing policy storage
    allocator: std.mem.Allocator,

    /// Initialize a new filter with no policies
    pub fn init(allocator: std.mem.Allocator) FilterEvaluator {
        return .{
            .policies = .{},
            .allocator = allocator,
        };
    }

    /// Deinitialize filter and free all resources
    pub fn deinit(self: *FilterEvaluator) void {
        // Deinit each policy's resources
        for (self.policies.items(.name), self.policies.items(.regexes)) |_, _| {
            // Policy resources would be freed here if they owned memory
        }
        self.policies.deinit(self.allocator);
    }

    /// Add a policy to the filter
    pub fn addPolicy(self: *FilterEvaluator, new_policy: Policy) !void {
        try self.policies.append(self.allocator, new_policy);
    }

    /// Remove all policies from the filter
    pub fn clearPolicies(self: *FilterEvaluator) void {
        self.policies.shrinkRetainingCapacity(0);
    }

    /// Get the number of policies
    pub fn policyCount(self: *const FilterEvaluator) usize {
        return self.policies.len;
    }

    /// Evaluate JSON against all policies for a specific telemetry type
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    pub fn evaluate(
        self: *const FilterEvaluator,
        json_data: []const u8,
        telemetry_type: TelemetryType,
    ) !FilterResult {
        // Data-oriented approach: iterate through struct-of-arrays
        const names = self.policies.items(.name);
        const policy_types = self.policies.items(.policy_type);
        const telemetry_types = self.policies.items(.telemetry_type);
        const regex_lists = self.policies.items(.regexes);
        const actions = self.policies.items(.action);

        // Process policies in order - first match wins
        for (names, policy_types, telemetry_types, regex_lists, actions, 0..) |
            name,
            policy_type,
            policy_telemetry_type,
            regexes,
            action,
            i,
        | {
            _ = name;
            _ = i;

            // Skip policies that don't match the telemetry type
            if (policy_telemetry_type != telemetry_type) {
                continue;
            }

            // Only process filter policies for now
            if (policy_type != .filter) {
                continue;
            }

            // Check if any regex matches the JSON data
            const matches = try self.matchesAnyRegex(json_data, regexes);

            if (matches) {
                // Return the action from the matching policy
                return switch (action) {
                    .keep => FilterResult.keep,
                    .drop => FilterResult.drop,
                };
            }
        }

        // Default to keep if no policies match
        return FilterResult.keep;
    }

    /// Check if JSON data matches any of the provided regex patterns
    /// Simple string matching for now - can be optimized with compiled regexes later
    fn matchesAnyRegex(
        self: *const FilterEvaluator,
        json_data: []const u8,
        patterns: []const []const u8,
    ) !bool {
        _ = self;

        for (patterns) |pattern| {
            // Simple substring matching for now
            // TODO: Replace with proper regex matching when needed for performance
            if (std.mem.indexOf(u8, json_data, pattern)) |_| {
                return true;
            }
        }

        return false;
    }
};

test "Filter.init creates empty filter" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    try std.testing.expectEqual(@as(usize, 0), filter.policyCount());
}

test "Filter.addPolicy increases policy count" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const patterns = [_][]const u8{"error"};
    const test_policy = Policy.init(
        "test",
        .filter,
        .log,
        &patterns,
        policy_mod.Action.init(.drop),
    );

    try filter.addPolicy(test_policy);
    try std.testing.expectEqual(@as(usize, 1), filter.policyCount());
}

test "Filter.clearPolicies removes all policies" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const patterns = [_][]const u8{"error"};
    const test_policy = Policy.init(
        "test",
        .filter,
        .log,
        &patterns,
        policy_mod.Action.init(.drop),
    );

    try filter.addPolicy(test_policy);
    try std.testing.expectEqual(@as(usize, 1), filter.policyCount());

    filter.clearPolicies();
    try std.testing.expectEqual(@as(usize, 0), filter.policyCount());
}

test "Filter.evaluate drops matching JSON" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const patterns = [_][]const u8{"error"};
    const drop_policy = Policy.init(
        "drop-errors",
        .filter,
        .log,
        &patterns,
        policy_mod.Action.init(.drop),
    );

    try filter.addPolicy(drop_policy);

    const json_with_error = "{\"level\":\"error\",\"msg\":\"failed\"}";
    const result = try filter.evaluate(json_with_error, .log);
    try std.testing.expect(result == FilterResult.drop);
}

test "Filter.evaluate keeps non-matching JSON" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const patterns = [_][]const u8{"error"};
    const drop_policy = Policy.init(
        "drop-errors",
        .filter,
        .log,
        &patterns,
        policy_mod.Action.init(.drop),
    );

    try filter.addPolicy(drop_policy);

    const json_without_error = "{\"level\":\"info\",\"msg\":\"success\"}";
    const result = try filter.evaluate(json_without_error, .log);
    try std.testing.expect(result == FilterResult.keep);
}

test "Filter.evaluate respects telemetry type" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const patterns = [_][]const u8{"error"};
    const log_policy = Policy.init(
        "drop-log-errors",
        .filter,
        .log,
        &patterns,
        policy_mod.Action.init(.drop),
    );

    try filter.addPolicy(log_policy);

    const json_with_error = "{\"level\":\"error\",\"msg\":\"failed\"}";

    // Should drop for log type
    const log_result = try filter.evaluate(json_with_error, .log);
    try std.testing.expect(log_result == FilterResult.drop);

    // Should keep for metric type (no matching policy)
    const metric_result = try filter.evaluate(json_with_error, .metric);
    try std.testing.expect(metric_result == FilterResult.keep);
}

test "Filter.evaluate uses first matching policy" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const error_patterns = [_][]const u8{"error"};
    const drop_policy = Policy.init(
        "drop-errors",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.drop),
    );

    const all_patterns = [_][]const u8{"level"};
    const keep_policy = Policy.init(
        "keep-all",
        .filter,
        .log,
        &all_patterns,
        policy_mod.Action.init(.keep),
    );

    // Add drop policy first
    try filter.addPolicy(drop_policy);
    try filter.addPolicy(keep_policy);

    const json = "{\"level\":\"error\",\"msg\":\"failed\"}";
    const result = try filter.evaluate(json, .log);

    // Should use first matching policy (drop)
    try std.testing.expect(result == FilterResult.drop);
}

test "Filter.evaluate defaults to keep when no policies match" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const json = "{\"level\":\"info\",\"msg\":\"test\"}";
    const result = try filter.evaluate(json, .log);

    try std.testing.expect(result == FilterResult.keep);
}

test "Filter.matchesAnyRegex finds substring matches" {
    const filter = FilterEvaluator.init(std.testing.allocator);

    const patterns = [_][]const u8{ "error", "warning", "critical" };

    try std.testing.expect(try filter.matchesAnyRegex("error occurred", &patterns));
    try std.testing.expect(try filter.matchesAnyRegex("warning message", &patterns));
    try std.testing.expect(try filter.matchesAnyRegex("critical failure", &patterns));
    try std.testing.expect(!try filter.matchesAnyRegex("info message", &patterns));
}

test "Filter MultiArrayList layout" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    // Add multiple policies to verify MultiArrayList storage
    const error_patterns = [_][]const u8{"error"};
    const warn_patterns = [_][]const u8{"warn"};
    const info_patterns = [_][]const u8{"info"};

    try filter.addPolicy(Policy.init(
        "policy1",
        .filter,
        .log,
        &error_patterns,
        policy_mod.Action.init(.drop),
    ));

    try filter.addPolicy(Policy.init(
        "policy2",
        .filter,
        .metric,
        &warn_patterns,
        policy_mod.Action.init(.keep),
    ));

    try filter.addPolicy(Policy.init(
        "policy3",
        .filter,
        .span,
        &info_patterns,
        policy_mod.Action.init(.drop),
    ));

    try std.testing.expectEqual(@as(usize, 3), filter.policyCount());

    // Verify we can access struct-of-arrays
    const names = filter.policies.items(.name);
    const telemetry_types = filter.policies.items(.telemetry_type);

    try std.testing.expectEqualStrings("policy1", names[0]);
    try std.testing.expectEqualStrings("policy2", names[1]);
    try std.testing.expectEqualStrings("policy3", names[2]);

    try std.testing.expect(telemetry_types[0] == .log);
    try std.testing.expect(telemetry_types[1] == .metric);
    try std.testing.expect(telemetry_types[2] == .span);
}
