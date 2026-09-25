//! Distribution composition: which services each distro binary ships, in
//! registration order. Comptime tables — a distro's service set is fixed at
//! build time, so the cost of an unused service is zero bytes (PLAN.md §3).
//!
//! Order matters at the ends: health is always first (never shadowed) and
//! passthrough always last (it owns the wildcard; the router's "last any
//! wins" rule makes order the tiebreaker).
const std = @import("std");
const policy = @import("policy_zig");
const service_mod = @import("../service/service.zig");

pub const ServiceKind = service_mod.ServiceKind;

pub const Distribution = enum {
    edge,
    datadog,
    otlp,
    prometheus,

    pub fn defaultConfigPath(self: Distribution) []const u8 {
        return switch (self) {
            .otlp => "config-otlp.json",
            .prometheus => "config-prometheus.json",
            else => "config.json",
        };
    }
};

pub fn servicesFor(comptime distribution: Distribution) []const ServiceKind {
    return switch (distribution) {
        .edge => &.{ .health, .datadog_logs, .datadog_metrics, .otlp, .prometheus, .passthrough },
        .datadog => &.{ .health, .datadog_logs, .datadog_metrics, .passthrough },
        .otlp => &.{ .health, .otlp, .passthrough },
        .prometheus => &.{ .health, .prometheus, .passthrough },
    };
}

/// The policy stages each distribution reports to the control plane.
pub fn supportedStagesFor(comptime distribution: Distribution) []const policy.proto.policy.PolicyStage {
    return switch (distribution) {
        .edge => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
            .POLICY_STAGE_TRACE_SAMPLING,
        },
        .datadog => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
        },
        .otlp => &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
            .POLICY_STAGE_TRACE_SAMPLING,
        },
        .prometheus => &.{.POLICY_STAGE_METRIC_FILTER},
    };
}

/// Per-service plan-state inputs that come from config. Primitive fields so
/// any config shape (ProxyConfig, LambdaConfig) can feed them.
pub const ServiceOptions = struct {
    prometheus_max_input_bytes: usize = 0,
    prometheus_max_output_bytes: usize = 0,
};

/// Instantiates one service's plan-state. Pure data; the heavier runtime
/// deps (policy registry, event bus, metrics) bind in the connection driver.
pub fn buildService(kind: ServiceKind, options: ServiceOptions) service_mod.Service {
    return switch (kind) {
        .health => .{ .health = .{} },
        .passthrough => .{ .passthrough = .{} },
        .datadog_logs => .{ .datadog_logs = .{} },
        .datadog_metrics => .{ .datadog_metrics = .{} },
        .otlp => .{ .otlp = .{} },
        .prometheus => .{ .prometheus = .{
            .max_input_bytes_per_scrape = options.prometheus_max_input_bytes,
            .max_output_bytes_per_scrape = options.prometheus_max_output_bytes,
        } },
    };
}

const testing = std.testing;

test "prometheus distro defaults to config-prometheus.json" {
    try testing.expectEqualStrings(
        "config-prometheus.json",
        Distribution.prometheus.defaultConfigPath(),
    );
}

test "every distro brackets services with health first and passthrough last" {
    inline for (@typeInfo(Distribution).@"enum".fields) |field| {
        const distribution: Distribution = @enumFromInt(field.value);
        const services = comptime servicesFor(distribution);
        try testing.expectEqual(ServiceKind.health, services[0]);
        try testing.expectEqual(ServiceKind.passthrough, services[services.len - 1]);
        try testing.expect(services.len >= 3);
    }
}

test "edge distro composes all services; focused distros stay focused" {
    const edge = comptime servicesFor(.edge);
    try testing.expectEqual(@as(usize, 6), edge.len);

    const datadog = comptime servicesFor(.datadog);
    for (datadog) |kind| try testing.expect(kind != .otlp and kind != .prometheus);

    const otlp = comptime servicesFor(.otlp);
    for (otlp) |kind| try testing.expect(kind != .datadog_logs and kind != .prometheus);
}

test "buildService wires prometheus scrape budgets from config" {
    const svc = buildService(.prometheus, .{
        .prometheus_max_input_bytes = 2048,
        .prometheus_max_output_bytes = 1024,
    });
    try testing.expectEqual(@as(usize, 2048), svc.prometheus.max_input_bytes_per_scrape);
    try testing.expectEqual(@as(usize, 1024), svc.prometheus.max_output_bytes_per_scrape);
}
