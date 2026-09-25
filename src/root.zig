//! Root of the `edge` library module. The zbench harnesses and lambda_main import it.

pub const policy = @import("policy_zig");
pub const core_limits = @import("core/limits.zig");
pub const codec = @import("codec/root.zig");
pub const pipeline_framer = @import("pipeline/framer.zig");
pub const signals_datadog_logs = @import("signals/datadog/logs.zig");
pub const distro = @import("runtime/distro.zig");
pub const zonfig = @import("zonfig/root.zig");

// Import modules to include their tests
test {
    _ = @import("config/types.zig");
    _ = @import("core/limits.zig");
    _ = @import("core/io_select.zig");
    _ = @import("core/conn_slab.zig");
    _ = @import("core/arena_pool.zig");
    _ = @import("core/lifecycle.zig");
    _ = @import("codec/root.zig");
    _ = @import("pipeline/framer.zig");
    _ = @import("pipeline/pipeline.zig");
    _ = @import("pipeline/tap.zig");
    _ = @import("signals/json_scan.zig");
    _ = @import("signals/stream_io.zig");
    _ = @import("signals/datadog/extras.zig");
    _ = @import("signals/datadog/log_test.zig");
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
    _ = @import("frontend/stdio/deadline_reader.zig");
    _ = @import("frontend/stdio/head_repair.zig");
    // Both frontends compile in every test build regardless of -Dfrontend,
    // so the unselected one can't rot.
    _ = @import("frontend/stdio/server.zig");
    _ = @import("frontend/httpz/server.zig");
    _ = @import("frontend/exchange.zig");
    _ = @import("frontend/paths.zig");
    _ = @import("frontend/endpoints.zig");
    _ = @import("frontend/thread_bufs.zig");
    _ = @import("runtime/distro.zig");
    _ = @import("runtime/extensions.zig");
    _ = @import("signals/prometheus/root.zig");
    _ = @import("lambda/root.zig");
    _ = @import("zonfig/root.zig");
    _ = @import("tail/mod.zig");
}
