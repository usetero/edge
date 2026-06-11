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

// Core runtime substrate (0.16 rewrite, PLAN.md §5)
pub const core_limits = @import("core/limits.zig");
pub const core_io_select = @import("core/io_select.zig");
pub const core_conn_slab = @import("core/conn_slab.zig");
pub const core_arena_pool = @import("core/arena_pool.zig");
pub const core_lifecycle = @import("core/lifecycle.zig");

// Streaming record pipeline (0.16 rewrite, PLAN.md §6)
pub const pipeline = @import("pipeline/pipeline.zig");
pub const pipeline_encoding = @import("pipeline/encoding.zig");
pub const pipeline_framer = @import("pipeline/framer.zig");
pub const pipeline_compress_buffered = @import("pipeline/compress_buffered.zig");

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
pub const prometheus = @import("signals/prometheus/root.zig");

// =============================================================================
// Distribution entry points
// =============================================================================

/// Datadog distribution - focused edge proxy for Datadog log ingestion
pub const datadog_distribution = @import("datadog_main.zig");

/// OTLP distribution - focused edge proxy for OpenTelemetry log ingestion
pub const otlp_distribution = @import("otlp_main.zig");

/// Prometheus distribution - focused edge proxy for Prometheus metrics scraping
pub const prometheus_distribution = @import("prometheus_main.zig");

/// Tail distribution - focused file log tailing
pub const tail_distribution = @import("edge_tail_main.zig");
pub const tail = @import("tail/mod.zig");

/// Lambda module - for Lambda extension distribution
pub const lambda = @import("lambda/root.zig");

/// Zonfig - comptime configuration with environment overrides
pub const zonfig = @import("zonfig/root.zig");
pub const runtime_pipeline = @import("runtime/pipeline.zig");
pub const io_transport = @import("io/transport.zig");

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
    _ = @import("core/limits.zig");
    _ = @import("core/io_select.zig");
    _ = @import("core/conn_slab.zig");
    _ = @import("core/arena_pool.zig");
    _ = @import("core/lifecycle.zig");
    _ = @import("pipeline/compress_buffered.zig");
    _ = @import("pipeline/encoding.zig");
    _ = @import("pipeline/framer.zig");
    _ = @import("pipeline/pipeline.zig");
    _ = @import("modules/proxy_module.zig");
    _ = @import("proxy/compress.zig");
    _ = @import("proxy/router.zig");
    _ = @import("proxy/upstream_client.zig");
    _ = @import("modules/passthrough_module.zig");
    _ = @import("modules/datadog_module.zig");
    _ = @import("signals/datadog/logs.zig");
    _ = @import("signals/datadog/metrics.zig");
    _ = @import("modules/otlp_module.zig");
    _ = @import("signals/otlp/attributes.zig");
    _ = @import("signals/otlp/logs.zig");
    _ = @import("signals/otlp/metrics.zig");
    _ = @import("signals/otlp/traces.zig");
    _ = @import("modules/health_module.zig");
    _ = @import("service/service.zig");
    _ = @import("http/router.zig");
    _ = @import("runtime/distro.zig");
    _ = @import("signals/prometheus/root.zig");
    _ = @import("modules/prometheus_module.zig");
    _ = @import("runtime/pipeline.zig");
    _ = @import("io/transport.zig");
    _ = @import("lambda/root.zig");
    _ = @import("zonfig/root.zig");
    _ = @import("tail/mod.zig");
}
