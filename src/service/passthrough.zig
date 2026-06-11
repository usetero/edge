//! Passthrough service: raw bidirectional copy to the default upstream, no
//! evaluation. The wildcard fallback route. Ported from
//! modules/passthrough_module.zig.
const std = @import("std");
const service = @import("service.zig");

pub const routes = [_]service.RoutePattern{
    .any(.all),
};

pub const Passthrough = struct {
    pub fn plan(_: *const Passthrough, _: service.PlanRequest) service.Outcome {
        return .{ .forward_raw = .{ .upstream = .default } };
    }
};

test "passthrough always forwards raw to the default upstream" {
    const svc: Passthrough = .{};
    for ([_]service.HttpMethod{ .GET, .POST, .PUT, .DELETE }) |method| {
        const outcome = svc.plan(.{ .method = method, .path = "/anything/at/all" });
        try std.testing.expectEqual(service.UpstreamChoice.default, outcome.forward_raw.upstream);
    }
}
