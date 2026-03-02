const std = @import("std");
const router = @import("../control/router.zig");
const policy_engine = @import("../control/policy_engine.zig");

pub const RequestContext = struct {
    method: []const u8,
    path: []const u8,
};

pub const PrefilterDecision = enum {
    fast_path,
    policy_path,
};

pub const PolicyDecision = struct {
    action: policy_engine.PolicyAction,
    snapshot_version: u64,
};

pub const Pipeline = struct {
    routes: router.Router,
    engine: policy_engine.PolicyEngine,

    pub fn init(allocator: std.mem.Allocator) !Pipeline {
        return .{
            .routes = router.Router.init(),
            .engine = try policy_engine.PolicyEngine.init(allocator),
        };
    }

    pub fn deinit(self: *Pipeline) void {
        self.engine.deinit();
    }

    pub fn classify(self: *const Pipeline, ctx: RequestContext) router.RouteKind {
        return self.routes.match(ctx.method, ctx.path);
    }

    pub fn evaluate(self: *const Pipeline, payload: []const u8) policy_engine.PolicyAction {
        return self.engine.evaluate(payload);
    }

    pub fn prefilter(self: *const Pipeline, route: router.RouteKind, content_type: ?[]const u8) PrefilterDecision {
        if (!self.engine.hasRules()) return .fast_path;
        if (route != .otlp_logs and route != .datadog_logs) return .fast_path;
        const ct = content_type orelse return .policy_path;
        if (std.mem.indexOf(u8, ct, "json") != null) return .policy_path;
        return .fast_path;
    }

    pub fn evaluatePolicy(self: *const Pipeline, payload: []const u8) PolicyDecision {
        const result = self.engine.evaluateWithVersion(payload);
        return .{
            .action = result.action,
            .snapshot_version = result.snapshot_version,
        };
    }
};

test "pipeline classifies OTLP path" {
    var p = try Pipeline.init(std.testing.allocator);
    defer p.deinit();
    try std.testing.expectEqual(.otlp_logs, p.classify(.{ .method = "POST", .path = "/v1/logs" }));
}

test "pipeline prefilter defaults to fast-path without rules" {
    var p = try Pipeline.init(std.testing.allocator);
    defer p.deinit();
    try std.testing.expectEqual(.fast_path, p.prefilter(.otlp_logs, "application/json"));
}

test "pipeline policy path activates for log json when rules exist" {
    var p = try Pipeline.init(std.testing.allocator);
    defer p.deinit();
    try p.engine.apply(.{
        .version = 2,
        .default_action = .keep,
        .rules = &.{
            .{ .contains = "drop", .action = .drop },
        },
    });
    try std.testing.expectEqual(.policy_path, p.prefilter(.otlp_logs, "application/json"));
    const d = p.evaluatePolicy("please drop this");
    try std.testing.expectEqual(.drop, d.action);
    try std.testing.expectEqual(@as(u64, 2), d.snapshot_version);
}
