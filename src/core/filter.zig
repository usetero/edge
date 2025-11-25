const std = @import("std");
const proto = @import("proto");
const policy_registry = @import("policy_registry.zig");

const Policy = proto.policy.Policy;
const PolicyType = proto.policy.PolicyType;
const TelemetryType = proto.policy.TelemetryType;
const FilterAction = proto.policy.FilterAction;
const FilterConfig = proto.policy.FilterConfig;
const Matcher = proto.policy.Matcher;
const PolicyRegistry = policy_registry.PolicyRegistry;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Filter evaluates JSON against policies from the centralized registry
/// Uses lock-free snapshot reads for optimal performance
pub const FilterEvaluator = struct {
    /// Reference to centralized policy registry
    registry: *const PolicyRegistry,

    /// Initialize a new filter evaluator with reference to registry
    pub fn init(registry: *const PolicyRegistry) FilterEvaluator {
        return .{
            .registry = registry,
        };
    }

    /// No resources to free - registry is owned elsewhere
    pub fn deinit(self: *FilterEvaluator) void {
        _ = self;
    }

    /// Evaluate JSON against policies for a specific telemetry type
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// Uses lock-free snapshot read for consistent view of policies
    pub fn evaluate(
        self: *const FilterEvaluator,
        json_data: []const u8,
        telemetry_type: TelemetryType,
    ) !FilterResult {
        // Get current policy snapshot (atomic, lock-free)
        const snapshot = self.registry.getSnapshot() orelse return FilterResult.keep;

        // Process policies in priority order - first match wins
        for (snapshot.policies) |policy| {
            // Skip disabled policies
            if (!policy.enabled) continue;

            // Only process LOG_FILTER policies
            if (policy.policy_type != .POLICY_TYPE_LOG_FILTER) continue;

            // Check if policy applies to requested telemetry type
            if (!policyAppliesToType(policy, telemetry_type)) continue;

            // Get filter config
            const config = if (policy.config) |cfg| switch (cfg) {
                .filter => |f| f,
                else => continue,
            } else continue;

            // Check if all matchers match the JSON data
            const matches = self.matchesAllMatchers(json_data, config.matchers.items);

            if (matches) {
                // Return the action from the matching policy
                return switch (config.action) {
                    .FILTER_ACTION_KEEP => FilterResult.keep,
                    .FILTER_ACTION_DROP => FilterResult.drop,
                    else => FilterResult.keep, // Unknown actions default to keep
                };
            }
        }

        // Default to keep if no policies match
        return FilterResult.keep;
    }

    /// Check if all matchers match the JSON data
    /// For now uses simple substring matching - can be enhanced with JSONPath + regex later
    fn matchesAllMatchers(
        self: *const FilterEvaluator,
        json_data: []const u8,
        matchers: []const Matcher,
    ) bool {
        _ = self;

        if (matchers.len == 0) return false;

        for (matchers) |matcher| {
            // Simple substring matching on regex field for now
            // TODO: Implement proper JSONPath extraction + regex matching
            const found = std.mem.indexOf(u8, json_data, matcher.regex) != null;
            const matches = if (matcher.negate) !found else found;

            if (!matches) return false;
        }

        return true;
    }
};

/// Check if a policy applies to a specific telemetry type
fn policyAppliesToType(policy: Policy, telemetry_type: TelemetryType) bool {
    for (policy.telemetry_types.items) |tt| {
        if (tt == telemetry_type) return true;
    }
    return false;
}

test "Filter.matchesAllMatchers finds substring matches" {
    const allocator = std.testing.allocator;

    // Create a dummy registry for testing
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    // Test with simple matchers
    const matchers = [_]Matcher{
        .{ .path = "$.message", .regex = "error" },
    };

    try std.testing.expect(filter.matchesAllMatchers("error occurred", &matchers));
    try std.testing.expect(!filter.matchesAllMatchers("info message", &matchers));
}

test "Filter.matchesAllMatchers with negate" {
    const allocator = std.testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    // Test with negated matcher - match if "debug" is NOT present
    const matchers = [_]Matcher{
        .{ .path = "$.level", .regex = "debug", .negate = true },
    };

    try std.testing.expect(filter.matchesAllMatchers("error occurred", &matchers));
    try std.testing.expect(!filter.matchesAllMatchers("debug message", &matchers));
}
