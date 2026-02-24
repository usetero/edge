//! By convention, root.zig is the root source file when making a library.
const std = @import("std");
const policy_zig = @import("policy_zig");

// =============================================================================
// Public module exports for distributions
// =============================================================================

// Policy package (from policy-zig external dependency)
pub const policy = policy_zig;

// Config modules (non-policy configuration)
pub const config_types = @import("config/types.zig");

// Proxy modules
pub const server = @import("proxy/server.zig");

// Module implementations
pub const proxy_module = @import("modules/proxy_module.zig");
pub const passthrough_module = @import("modules/passthrough_module.zig");
pub const datadog_module = @import("modules/datadog_module.zig");
pub const otlp_module = @import("modules/otlp_module.zig");
pub const health_module = @import("modules/health_module.zig");
pub const prometheus_module = @import("modules/prometheus_module.zig");

// Prometheus module
pub const prometheus = @import("prometheus/root.zig");

// =============================================================================
// Distribution entry points
// =============================================================================

/// Datadog distribution - focused edge proxy for Datadog log ingestion
pub const datadog_distribution = @import("datadog_main.zig");

/// OTLP distribution - focused edge proxy for OpenTelemetry log ingestion
pub const otlp_distribution = @import("otlp_main.zig");

/// Prometheus distribution - focused edge proxy for Prometheus metrics scraping
pub const prometheus_distribution = @import("prometheus_main.zig");

/// Lambda module - for Lambda extension distribution
pub const lambda = @import("lambda/root.zig");

/// Zonfig - comptime configuration with environment overrides
pub const zonfig = @import("zonfig/root.zig");

pub fn bufferedPrint() !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try stdout.flush();
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

// Import modules to include their tests
test {
    _ = @import("config/types.zig");
    _ = @import("modules/proxy_module.zig");
    _ = @import("proxy/compress.zig");
    _ = @import("proxy/router.zig");
    _ = @import("proxy/upstream_client.zig");
    _ = @import("modules/passthrough_module.zig");
    _ = @import("modules/datadog_module.zig");
    _ = @import("modules/datadog_logs_v2.zig");
    _ = @import("modules/otlp_module.zig");
    _ = @import("modules/otlp_attributes.zig");
    _ = @import("modules/otlp_logs.zig");
    _ = @import("modules/health_module.zig");
    _ = @import("prometheus/root.zig");
    _ = @import("modules/prometheus_module.zig");
    _ = @import("lambda/root.zig");
    _ = @import("zonfig/root.zig");
}
