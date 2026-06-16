//! Health service: static 200 response, no upstream, no body read.
//! Ported from modules/health_module.zig.
const std = @import("std");
const service = @import("service.zig");

pub const routes = [_]service.RoutePattern{
    .exact("/_health", .{ .get = true }),
};

pub const Health = struct {
    pub fn plan(_: *const Health, _: service.PlanRequest) service.Outcome {
        return .{ .respond = .{
            .status = 200,
            .content_type = "application/json",
            .body = "{\"status\":\"ok\"}",
        } };
    }
};

test "health plans a static 200 with status json" {
    const svc: Health = .{};
    const outcome = svc.plan(.{ .method = .GET, .path = "/_health" });
    try std.testing.expectEqual(@as(u16, 200), outcome.respond.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", outcome.respond.body);
    try std.testing.expectEqualStrings("application/json", outcome.respond.content_type);
}
