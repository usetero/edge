const std = @import("std");
const module_types = @import("../modules/module_types.zig");

pub const HttpMethod = module_types.HttpMethod;
pub const RouteKind = module_types.RouteKind;

pub const PrefilterDecision = enum {
    fast_path,
    policy_path,
};

pub fn classifyRoute(path: []const u8, method: HttpMethod) RouteKind {
    if (method == .GET and std.mem.eql(u8, path, "/_health")) return .health;
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/logs")) return .datadog_logs;
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/series")) return .datadog_metrics;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/logs")) return .otlp_logs;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/metrics")) return .otlp_metrics;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/traces")) return .otlp_traces;
    if (method == .GET and (std.mem.eql(u8, path, "/metrics") or std.mem.startsWith(u8, path, "/metrics/"))) return .prometheus_metrics;
    return .passthrough;
}

pub fn prefilter(route_kind: RouteKind, method: HttpMethod, content_type: ?[]const u8) PrefilterDecision {
    if (method != .POST) return .fast_path;

    return switch (route_kind) {
        .datadog_logs, .datadog_metrics, .otlp_logs, .otlp_metrics, .otlp_traces => blk: {
            const ct = content_type orelse "";
            if (ct.len == 0) break :blk .policy_path;
            if (std.mem.indexOf(u8, ct, "json") != null) break :blk .policy_path;
            if (std.mem.indexOf(u8, ct, "protobuf") != null) break :blk .policy_path;
            break :blk .policy_path;
        },
        .passthrough, .prometheus_metrics, .health => .fast_path,
    };
}

test "classifyRoute matches core routes" {
    try std.testing.expectEqual(RouteKind.datadog_logs, classifyRoute("/api/v2/logs", .POST));
    try std.testing.expectEqual(RouteKind.datadog_metrics, classifyRoute("/api/v2/series", .POST));
    try std.testing.expectEqual(RouteKind.otlp_logs, classifyRoute("/v1/logs", .POST));
    try std.testing.expectEqual(RouteKind.prometheus_metrics, classifyRoute("/metrics", .GET));
    try std.testing.expectEqual(RouteKind.health, classifyRoute("/_health", .GET));
    try std.testing.expectEqual(RouteKind.passthrough, classifyRoute("/anything", .GET));
}

test "prefilter policy path for ingest routes" {
    try std.testing.expectEqual(PrefilterDecision.policy_path, prefilter(.datadog_logs, .POST, "application/json"));
    try std.testing.expectEqual(PrefilterDecision.policy_path, prefilter(.otlp_metrics, .POST, "application/x-protobuf"));
    try std.testing.expectEqual(PrefilterDecision.fast_path, prefilter(.prometheus_metrics, .GET, null));
    try std.testing.expectEqual(PrefilterDecision.fast_path, prefilter(.passthrough, .GET, null));
}
