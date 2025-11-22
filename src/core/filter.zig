const std = @import("std");
const policy_pb = @import("../proto/tero/edge/policy/v1.pb.zig");
const Policy = policy_pb.Policy;
const TelemetryType = policy_pb.TelemetryType;
const ActionType = policy_pb.ActionType;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Filter manages a collection of policies and evaluates JSON against them
/// Uses separate MultiArrayList per telemetry type for optimal cache locality
/// Following DoD principles: policies are grouped by access pattern (telemetry type)
pub const FilterEvaluator = struct {
    /// Policies for log telemetry - hot path for log filtering
    log_policies: std.MultiArrayList(Policy),

    /// Policies for metric telemetry - hot path for metric filtering
    metric_policies: std.MultiArrayList(Policy),

    /// Policies for span telemetry - hot path for span filtering
    span_policies: std.MultiArrayList(Policy),

    /// Allocator for managing policy storage
    allocator: std.mem.Allocator,

    /// Initialize a new filter with no policies
    pub fn init(allocator: std.mem.Allocator) FilterEvaluator {
        return .{
            .log_policies = .{},
            .metric_policies = .{},
            .span_policies = .{},
            .allocator = allocator,
        };
    }

    /// Deinitialize filter and free all resources
    pub fn deinit(self: *FilterEvaluator) void {
        self.log_policies.deinit(self.allocator);
        self.metric_policies.deinit(self.allocator);
        self.span_policies.deinit(self.allocator);
    }

    /// Add a policy to the appropriate telemetry-specific list
    pub fn addPolicy(self: *FilterEvaluator, new_policy: Policy) !void {
        switch (new_policy.telemetry_type) {
            .TELEMETRY_TYPE_LOG => try self.log_policies.append(self.allocator, new_policy),
            .TELEMETRY_TYPE_METRIC => try self.metric_policies.append(self.allocator, new_policy),
            .TELEMETRY_TYPE_SPAN => try self.span_policies.append(self.allocator, new_policy),
            else => {}, // Ignore unspecified or unknown types
        }
    }

    /// Remove all policies from all telemetry lists
    pub fn clearPolicies(self: *FilterEvaluator) void {
        self.log_policies.shrinkRetainingCapacity(0);
        self.metric_policies.shrinkRetainingCapacity(0);
        self.span_policies.shrinkRetainingCapacity(0);
    }

    /// Get the total number of policies across all telemetry types
    pub fn policyCount(self: *const FilterEvaluator) usize {
        return self.log_policies.len + self.metric_policies.len + self.span_policies.len;
    }

    /// Evaluate JSON against policies for a specific telemetry type
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// This is optimized: we only iterate through policies of the requested telemetry type
    /// No branching needed to skip irrelevant policies - perfect cache locality
    pub fn evaluate(
        self: *const FilterEvaluator,
        json_data: []const u8,
        telemetry_type: TelemetryType,
    ) !FilterResult {
        // Select the correct policy list based on telemetry type
        // This eliminates the need to check telemetry_type in the inner loop
        const policies = switch (telemetry_type) {
            .TELEMETRY_TYPE_LOG => &self.log_policies,
            .TELEMETRY_TYPE_METRIC => &self.metric_policies,
            .TELEMETRY_TYPE_SPAN => &self.span_policies,
            else => return FilterResult.keep, // Unknown types default to keep
        };

        // Data-oriented approach: iterate through struct-of-arrays
        // All policies in this list are guaranteed to match the telemetry type
        const names = policies.items(.name);
        const policy_types = policies.items(.policy_type);
        const regex_lists = policies.items(.regexes);
        const actions = policies.items(.action);

        // Process policies in order - first match wins
        for (names, policy_types, regex_lists, actions, 0..) |
            name,
            policy_type,
            regexes,
            action,
            i,
        | {
            _ = name;
            _ = i;

            // Only process filter policies for now
            if (policy_type != .POLICY_TYPE_FILTER) {
                continue;
            }

            // Check if any regex matches the JSON data
            const matches = try self.matchesAnyRegex(json_data, regexes.items);

            if (matches) {
                // Return the action from the matching policy
                return switch (action.type) {
                    .ACTION_TYPE_KEEP => FilterResult.keep,
                    .ACTION_TYPE_DROP => FilterResult.drop,
                    else => FilterResult.keep, // Unknown actions default to keep
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

    var regexes = std.ArrayListUnmanaged([]const u8){};
    defer regexes.deinit(std.testing.allocator);
    try regexes.append(std.testing.allocator, "error");

    const test_policy = Policy{
        .name = "test",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };

    try filter.addPolicy(test_policy);
    try std.testing.expectEqual(@as(usize, 1), filter.policyCount());
}

test "Filter.addPolicy routes to correct telemetry list" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var regexes1 = std.ArrayListUnmanaged([]const u8){};
    try regexes1.append(std.testing.allocator, "test");
    var regexes2 = std.ArrayListUnmanaged([]const u8){};
    try regexes2.append(std.testing.allocator, "test");
    var regexes3 = std.ArrayListUnmanaged([]const u8){};
    try regexes3.append(std.testing.allocator, "test");
    var regexes4 = std.ArrayListUnmanaged([]const u8){};
    try regexes4.append(std.testing.allocator, "test");
    defer regexes1.deinit(std.testing.allocator);
    defer regexes2.deinit(std.testing.allocator);
    defer regexes3.deinit(std.testing.allocator);
    defer regexes4.deinit(std.testing.allocator);

    try filter.addPolicy(Policy{ .name = "log1", .policy_type = .POLICY_TYPE_FILTER, .telemetry_type = .TELEMETRY_TYPE_LOG, .regexes = regexes1, .action = .{ .type = .ACTION_TYPE_DROP } });
    try filter.addPolicy(Policy{ .name = "log2", .policy_type = .POLICY_TYPE_FILTER, .telemetry_type = .TELEMETRY_TYPE_LOG, .regexes = regexes2, .action = .{ .type = .ACTION_TYPE_KEEP } });
    try filter.addPolicy(Policy{ .name = "metric1", .policy_type = .POLICY_TYPE_FILTER, .telemetry_type = .TELEMETRY_TYPE_METRIC, .regexes = regexes3, .action = .{ .type = .ACTION_TYPE_DROP } });
    try filter.addPolicy(Policy{ .name = "span1", .policy_type = .POLICY_TYPE_FILTER, .telemetry_type = .TELEMETRY_TYPE_SPAN, .regexes = regexes4, .action = .{ .type = .ACTION_TYPE_KEEP } });

    // Verify policies are in correct lists
    try std.testing.expectEqual(@as(usize, 2), filter.log_policies.len);
    try std.testing.expectEqual(@as(usize, 1), filter.metric_policies.len);
    try std.testing.expectEqual(@as(usize, 1), filter.span_policies.len);
    try std.testing.expectEqual(@as(usize, 4), filter.policyCount());
}

test "Filter.clearPolicies removes all policies" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var regexes = std.ArrayListUnmanaged([]const u8){};
    defer regexes.deinit(std.testing.allocator);
    try regexes.append(std.testing.allocator, "error");

    const test_policy = Policy{
        .name = "test",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };

    try filter.addPolicy(test_policy);
    try std.testing.expectEqual(@as(usize, 1), filter.policyCount());

    filter.clearPolicies();
    try std.testing.expectEqual(@as(usize, 0), filter.policyCount());
}

test "Filter.evaluate drops matching JSON" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var regexes = std.ArrayListUnmanaged([]const u8){};
    defer regexes.deinit(std.testing.allocator);
    try regexes.append(std.testing.allocator, "error");

    const drop_policy = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };

    try filter.addPolicy(drop_policy);

    const json_with_error = "{\"level\":\"error\",\"msg\":\"failed\"}";
    const result = try filter.evaluate(json_with_error, .TELEMETRY_TYPE_LOG);
    try std.testing.expect(result == FilterResult.drop);
}

test "Filter.evaluate keeps non-matching JSON" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var regexes = std.ArrayListUnmanaged([]const u8){};
    defer regexes.deinit(std.testing.allocator);
    try regexes.append(std.testing.allocator, "error");

    const drop_policy = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };

    try filter.addPolicy(drop_policy);

    const json_without_error = "{\"level\":\"info\",\"msg\":\"success\"}";
    const result = try filter.evaluate(json_without_error, .TELEMETRY_TYPE_LOG);
    try std.testing.expect(result == FilterResult.keep);
}

test "Filter.evaluate respects telemetry type isolation" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var regexes = std.ArrayListUnmanaged([]const u8){};
    defer regexes.deinit(std.testing.allocator);
    try regexes.append(std.testing.allocator, "error");

    // Add log policy that drops on "error"
    const log_policy = Policy{
        .name = "drop-log-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };
    try filter.addPolicy(log_policy);

    const json_with_error = "{\"level\":\"error\",\"msg\":\"failed\"}";

    // Should drop for log type (policy exists)
    const log_result = try filter.evaluate(json_with_error, .TELEMETRY_TYPE_LOG);
    try std.testing.expect(log_result == FilterResult.drop);

    // Should keep for metric type (no metric policies, different list)
    const metric_result = try filter.evaluate(json_with_error, .TELEMETRY_TYPE_METRIC);
    try std.testing.expect(metric_result == FilterResult.keep);

    // Should keep for span type (no span policies, different list)
    const span_result = try filter.evaluate(json_with_error, .TELEMETRY_TYPE_SPAN);
    try std.testing.expect(span_result == FilterResult.keep);
}

test "Filter.evaluate uses first matching policy" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    var error_regexes = std.ArrayListUnmanaged([]const u8){};
    defer error_regexes.deinit(std.testing.allocator);
    try error_regexes.append(std.testing.allocator, "error");

    const drop_policy = Policy{
        .name = "drop-errors",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    };

    var all_regexes = std.ArrayListUnmanaged([]const u8){};
    defer all_regexes.deinit(std.testing.allocator);
    try all_regexes.append(std.testing.allocator, "level");

    const keep_policy = Policy{
        .name = "keep-all",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = all_regexes,
        .action = .{ .type = .ACTION_TYPE_KEEP },
    };

    // Add drop policy first
    try filter.addPolicy(drop_policy);
    try filter.addPolicy(keep_policy);

    const json = "{\"level\":\"error\",\"msg\":\"failed\"}";
    const result = try filter.evaluate(json, .TELEMETRY_TYPE_LOG);

    // Should use first matching policy (drop)
    try std.testing.expect(result == FilterResult.drop);
}

test "Filter.evaluate defaults to keep when no policies match" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    const json = "{\"level\":\"info\",\"msg\":\"test\"}";
    const result = try filter.evaluate(json, .TELEMETRY_TYPE_LOG);

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

test "Filter MultiArrayList layout per telemetry type" {
    var filter = FilterEvaluator.init(std.testing.allocator);
    defer filter.deinit();

    // Add multiple policies to verify MultiArrayList storage separation
    var error_regexes = std.ArrayListUnmanaged([]const u8){};
    defer error_regexes.deinit(std.testing.allocator);
    try error_regexes.append(std.testing.allocator, "error");

    var warn_regexes = std.ArrayListUnmanaged([]const u8){};
    defer warn_regexes.deinit(std.testing.allocator);
    try warn_regexes.append(std.testing.allocator, "warn");

    var info_regexes = std.ArrayListUnmanaged([]const u8){};
    defer info_regexes.deinit(std.testing.allocator);
    try info_regexes.append(std.testing.allocator, "info");

    try filter.addPolicy(Policy{
        .name = "log-policy1",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_LOG,
        .regexes = error_regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    });

    try filter.addPolicy(Policy{
        .name = "metric-policy1",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_METRIC,
        .regexes = warn_regexes,
        .action = .{ .type = .ACTION_TYPE_KEEP },
    });

    try filter.addPolicy(Policy{
        .name = "span-policy1",
        .policy_type = .POLICY_TYPE_FILTER,
        .telemetry_type = .TELEMETRY_TYPE_SPAN,
        .regexes = info_regexes,
        .action = .{ .type = .ACTION_TYPE_DROP },
    });

    try std.testing.expectEqual(@as(usize, 3), filter.policyCount());
    try std.testing.expectEqual(@as(usize, 1), filter.log_policies.len);
    try std.testing.expectEqual(@as(usize, 1), filter.metric_policies.len);
    try std.testing.expectEqual(@as(usize, 1), filter.span_policies.len);

    // Verify we can access struct-of-arrays for each telemetry type
    const log_names = filter.log_policies.items(.name);
    const metric_names = filter.metric_policies.items(.name);
    const span_names = filter.span_policies.items(.name);

    try std.testing.expectEqualStrings("log-policy1", log_names[0]);
    try std.testing.expectEqualStrings("metric-policy1", metric_names[0]);
    try std.testing.expectEqualStrings("span-policy1", span_names[0]);
}
