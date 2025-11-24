const std = @import("std");
const policy_pb = @import("../proto/tero/edge/policy/v1.pb.zig");
const policy_registry = @import("policy_registry.zig");

const Policy = policy_pb.Policy;
const TelemetryType = policy_pb.TelemetryType;
const ActionType = policy_pb.ActionType;
const PolicyRegistry = policy_registry.PolicyRegistry;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Filter evaluates JSON against policies from the centralized registry
/// Uses lock-free snapshot reads for optimal performance
/// Following DoD principles: reads from cache-friendly policy arrays
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
    /// Cache-friendly: only iterates policies of requested telemetry type
    pub fn evaluate(
        self: *const FilterEvaluator,
        json_data: []const u8,
        telemetry_type: TelemetryType,
    ) !FilterResult {
        // Get current policy snapshot (atomic, lock-free)
        const snapshot = self.registry.getSnapshot() orelse return FilterResult.keep;

        // Select policies for requested telemetry type
        const policies = switch (telemetry_type) {
            .TELEMETRY_TYPE_LOG => snapshot.log_policies,
            .TELEMETRY_TYPE_METRIC => snapshot.metric_policies,
            .TELEMETRY_TYPE_SPAN => snapshot.span_policies,
            else => return FilterResult.keep,
        };

        // Process policies in order - first match wins
        for (policies) |policy| {
            // Only process filter policies for now
            if (policy.policy_type != .POLICY_TYPE_FILTER) {
                continue;
            }

            // Check if any regex matches the JSON data
            const matches = try self.matchesAnyRegex(json_data, policy.regexes.items);

            if (matches) {
                // Return the action from the matching policy
                return switch (policy.action.type) {
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

test "Filter.matchesAnyRegex finds substring matches" {
    const allocator = std.testing.allocator;

    // Create a dummy registry for testing
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const patterns = [_][]const u8{ "error", "warning", "critical" };

    try std.testing.expect(try filter.matchesAnyRegex("error occurred", &patterns));
    try std.testing.expect(try filter.matchesAnyRegex("warning message", &patterns));
    try std.testing.expect(try filter.matchesAnyRegex("critical failure", &patterns));
    try std.testing.expect(!try filter.matchesAnyRegex("info message", &patterns));
}

// NOTE: Policy management tests live in policy_registry.zig
// Integration tests for evaluation will be added separately
