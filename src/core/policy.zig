const std = @import("std");

/// Policy type determines what kind of operation to perform
pub const PolicyType = enum {
    filter,
    transform,
    redact,
};

/// Telemetry type specifies what kind of telemetry data this policy applies to
pub const TelemetryType = enum {
    log,
    metric,
    span,
};

/// Action outcome for a policy match
pub const ActionType = enum {
    keep,
    drop,
};

/// Action represents what to do when a policy matches
/// Uses tagged union to support future action types with associated data
pub const Action = union(ActionType) {
    keep: void,
    drop: void,

    pub fn init(action_type: ActionType) Action {
        return switch (action_type) {
            .keep => .{ .keep = {} },
            .drop => .{ .drop = {} },
        };
    }
};

/// Policy represents a filtering/processing rule for telemetry data
/// Designed for use in MultiArrayList for cache-friendly data layout
pub const Policy = struct {
    /// Human-readable name for this policy
    name: []const u8,

    /// Type of policy operation
    policy_type: PolicyType,

    /// Type of telemetry this applies to
    telemetry_type: TelemetryType,

    /// List of regex patterns to match against
    /// Stored as slice of strings - actual regex compilation happens in filter
    regexes: []const []const u8,

    /// Action to take when this policy matches
    action: Action,

    /// Initialize a new policy
    pub fn init(
        name: []const u8,
        policy_type: PolicyType,
        telemetry_type: TelemetryType,
        regexes: []const []const u8,
        action: Action,
    ) Policy {
        return .{
            .name = name,
            .policy_type = policy_type,
            .telemetry_type = telemetry_type,
            .regexes = regexes,
            .action = action,
        };
    }

    /// Deinitialize policy resources
    /// Currently no-op, but provides hook for future resource cleanup
    pub fn deinit(self: *Policy, allocator: std.mem.Allocator) void {
        _ = self;
        _ = allocator;
    }
};

test "Policy.init creates policy correctly" {
    const patterns = [_][]const u8{ "error.*", "warn.*" };
    const policy = Policy.init(
        "test-policy",
        .filter,
        .log,
        &patterns,
        Action.init(.drop),
    );

    try std.testing.expectEqualStrings("test-policy", policy.name);
    try std.testing.expect(policy.policy_type == .filter);
    try std.testing.expect(policy.telemetry_type == .log);
    try std.testing.expectEqual(@as(usize, 2), policy.regexes.len);
    try std.testing.expect(policy.action == .drop);
}

test "Action.init creates correct action types" {
    const keep_action = Action.init(.keep);
    const drop_action = Action.init(.drop);

    try std.testing.expect(keep_action == .keep);
    try std.testing.expect(drop_action == .drop);
}

test "PolicyType enum values" {
    try std.testing.expect(PolicyType.filter != PolicyType.transform);
    try std.testing.expect(PolicyType.transform != PolicyType.redact);
}

test "TelemetryType enum values" {
    try std.testing.expect(TelemetryType.log != TelemetryType.metric);
    try std.testing.expect(TelemetryType.metric != TelemetryType.span);
}
