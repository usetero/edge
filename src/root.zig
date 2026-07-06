//! By convention, root.zig is the root source file when making a library.
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

// HTTP frontends (PLAN.md §9, PLAN-FRONTEND-SWAP.md): exec is the
// transport-neutral outcome executor shared by every frontend.
pub const frontend_exec = @import("frontend/exec.zig");
pub const frontend_upstream = @import("frontend/upstream.zig");
pub const frontend_select = @import("frontend/select.zig");
pub const frontend_stdio_server = @import("frontend/stdio/server.zig");
pub const frontend_stdio_conn = @import("frontend/stdio/conn.zig");
pub const frontend_httpz_server = @import("frontend/httpz/server.zig");
pub const service_router = @import("service/router.zig");

// Services + distro composition (PLAN.md §8)
pub const service = @import("service/service.zig");
pub const distro = @import("runtime/distro.zig");

// Prometheus signal codecs
pub const prometheus = @import("signals/prometheus/root.zig");

// Shared single-pass JSON span scanning for signal parsers
pub const signals_json_scan = @import("signals/json_scan.zig");

// Datadog log search/filter (exposed for benchmarking)
pub const signals_datadog_logs = @import("signals/datadog/logs.zig");

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
    _ = @import("pipeline/tap.zig");
    _ = @import("signals/json_scan.zig");
    _ = @import("signals/datadog/logs.zig");
    _ = @import("signals/datadog/metrics.zig");
    _ = @import("signals/otlp/attributes.zig");
    _ = @import("signals/otlp/logs.zig");
    _ = @import("signals/otlp/metrics.zig");
    _ = @import("signals/otlp/traces.zig");
    _ = @import("service/service.zig");
    _ = @import("service/router.zig");
    _ = @import("frontend/upstream.zig");
    _ = @import("frontend/exec.zig");
    _ = @import("frontend/stdio/conn.zig");
    // Both frontends compile in every test build regardless of -Dfrontend,
    // so the unselected one can't rot (PLAN-FRONTEND-SWAP.md §6).
    _ = @import("frontend/stdio/server.zig");
    _ = @import("frontend/httpz/server.zig");
    _ = @import("runtime/distro.zig");
    _ = @import("signals/prometheus/root.zig");
    _ = @import("lambda/root.zig");
    _ = @import("zonfig/root.zig");
    _ = @import("tail/mod.zig");
}
