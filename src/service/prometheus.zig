//! Prometheus scrape service: the request has no meaningful body — the
//! upstream RESPONSE is the data plane. The driver fetches from the metrics
//! upstream and filters the text exposition line-by-line through policy
//! (signals/prometheus/streaming_filter.zig binds the semantics in Phase 5).
//! Ported from modules/prometheus_module.zig wiring.
const std = @import("std");
const service = @import("service.zig");

pub const routes = [_]service.RoutePattern{
    .exact("/metrics", .{ .get = true }),
    .prefix("/metrics/", .{ .get = true }),
};

pub const Prometheus = struct {
    /// Scrape budgets from config.prometheus (0 = unlimited).
    max_input_bytes_per_scrape: usize = 0,
    max_output_bytes_per_scrape: usize = 0,

    pub fn plan(self: *const Prometheus, _: service.PlanRequest) service.Outcome {
        return .{ .fetch_filtered = .{
            .upstream = .metrics,
            .max_input_bytes = self.max_input_bytes_per_scrape,
            .max_output_bytes = self.max_output_bytes_per_scrape,
        } };
    }
};

test "prometheus plans a filtered fetch with configured budgets" {
    const svc: Prometheus = .{
        .max_input_bytes_per_scrape = 1024,
        .max_output_bytes_per_scrape = 512,
    };
    const outcome = svc.plan(.{ .method = .GET, .path = "/metrics" });
    try std.testing.expectEqual(service.UpstreamChoice.metrics, outcome.fetch_filtered.upstream);
    try std.testing.expectEqual(@as(usize, 1024), outcome.fetch_filtered.max_input_bytes);
    try std.testing.expectEqual(@as(usize, 512), outcome.fetch_filtered.max_output_bytes);
}
