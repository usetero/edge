const std = @import("std");

pub const RouteKind = enum {
    otlp_logs,
    otlp_metrics,
    otlp_traces,
    datadog_logs,
    prometheus_metrics,
    passthrough,
};

pub const Router = struct {
    pub fn init() Router {
        return .{};
    }

    pub fn match(_: *const Router, method: []const u8, path: []const u8) RouteKind {
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/v1/logs")) return .otlp_logs;
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/v1/metrics")) return .otlp_metrics;
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/v1/traces")) return .otlp_traces;
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/api/v2/logs")) return .datadog_logs;
        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/metrics")) return .prometheus_metrics;
        return .passthrough;
    }
};

test "router matches known paths" {
    const r = Router.init();
    try std.testing.expectEqual(.datadog_logs, r.match("POST", "/api/v2/logs"));
    try std.testing.expectEqual(.otlp_metrics, r.match("POST", "/v1/metrics"));
    try std.testing.expectEqual(.passthrough, r.match("GET", "/unknown"));
}
