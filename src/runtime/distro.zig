//! Distribution composition: which services each distro binary ships, in
//! registration order. Comptime tables — a distro's service set is fixed at
//! build time, so the cost of an unused service is zero bytes (PLAN.md §3).
//!
//! Order matters at the ends: health is always first (never shadowed) and
//! passthrough always last (it owns the wildcard; the router's "last any
//! wins" rule makes order the tiebreaker).
const std = @import("std");
const mode = @import("mode.zig");
const service_mod = @import("../service/service.zig");
const config_types = @import("../config/types.zig");

pub const ServiceKind = service_mod.ServiceKind;

pub fn servicesFor(comptime distribution: mode.Distribution) []const ServiceKind {
    return switch (distribution) {
        .edge => &.{ .health, .datadog_logs, .datadog_metrics, .otlp, .prometheus, .passthrough },
        .datadog => &.{ .health, .datadog_logs, .datadog_metrics, .passthrough },
        .otlp => &.{ .health, .otlp, .passthrough },
        .prometheus => &.{ .health, .prometheus, .passthrough },
    };
}

/// Instantiates one service's plan-state from frozen config. Pure data; the
/// heavier runtime deps (policy registry, event bus, metrics) bind in the
/// connection driver, not here.
pub fn buildService(kind: ServiceKind, config: *const config_types.ProxyConfig) service_mod.Service {
    return switch (kind) {
        .health => .{ .health = .{} },
        .passthrough => .{ .passthrough = .{} },
        .datadog_logs => .{ .datadog_logs = .{} },
        .datadog_metrics => .{ .datadog_metrics = .{} },
        .otlp => .{ .otlp = .{} },
        .prometheus => .{ .prometheus = .{
            .max_input_bytes_per_scrape = config.prometheus.max_input_bytes_per_scrape,
            .max_output_bytes_per_scrape = config.prometheus.max_output_bytes_per_scrape,
        } },
    };
}

const testing = std.testing;

test "every distro brackets services with health first and passthrough last" {
    inline for (@typeInfo(mode.Distribution).@"enum".fields) |field| {
        const distribution: mode.Distribution = @enumFromInt(field.value);
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
    var config: config_types.ProxyConfig = .{};
    config.prometheus.max_input_bytes_per_scrape = 2048;
    config.prometheus.max_output_bytes_per_scrape = 1024;

    const svc = buildService(.prometheus, &config);
    try testing.expectEqual(@as(usize, 2048), svc.prometheus.max_input_bytes_per_scrape);
    try testing.expectEqual(@as(usize, 1024), svc.prometheus.max_output_bytes_per_scrape);
}
