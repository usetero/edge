//! Health service: static 200 response, no upstream, no body read.
//! Ported from modules/health_module.zig.
const std = @import("std");
const service = @import("service.zig");

/// Every method, not only GET. The route is what claims the path, so a
/// GET-only route let `HEAD /_health` and `POST /_health` fall through to the
/// wildcard passthrough and travel to the intake. A load balancer configured
/// for HEAD then tested the intake instead of this process, and failed
/// whenever the intake was unreachable.
pub const routes = [_]service.RoutePattern{
    .exact("/_health", .all),
};

pub const Health = struct {
    pub fn plan(_: *const Health, request: service.PlanRequest) service.Outcome {
        // HEAD must work wherever GET does (RFC 9110 §9.3.2). The frontends
        // elide the body for HEAD, so the same outcome serves both.
        return switch (request.method) {
            .GET, .HEAD => .{ .respond = .{
                .status = 200,
                .content_type = "application/json",
                .body = "{\"status\":\"ok\"}",
            } },
            else => .{ .respond = .{
                .status = 405,
                .content_type = "application/json",
                .body = "{\"error\":\"method not allowed\"}",
            } },
        };
    }
};

test "health plans a static 200 with status json" {
    const svc: Health = .{};
    const outcome = svc.plan(.{ .method = .GET, .path = "/_health" });
    try std.testing.expectEqual(@as(u16, 200), outcome.respond.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", outcome.respond.body);
    try std.testing.expectEqualStrings("application/json", outcome.respond.content_type);
}

test "health answers a HEAD probe, which load balancers use" {
    const svc: Health = .{};
    const outcome = svc.plan(.{ .method = .HEAD, .path = "/_health" });
    try std.testing.expectEqual(@as(u16, 200), outcome.respond.status);
}

test "health claims the path for every method, so nothing reaches the intake" {
    const svc: Health = .{};
    for ([_]service.HttpMethod{ .POST, .PUT, .DELETE, .PATCH, .OPTIONS }) |method| {
        const outcome = svc.plan(.{ .method = method, .path = "/_health" });
        try std.testing.expectEqual(@as(u16, 405), outcome.respond.status);
    }
    // The route must admit every method, or the passthrough catches it first.
    try std.testing.expect(routes[0].methods.post);
    try std.testing.expect(routes[0].methods.head);
}
