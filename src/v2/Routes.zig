//! Fixed distribution tables reuse the established pure service contracts.
const std = @import("std");
const service = @import("../service/service.zig");
const distro = @import("../runtime/distro.zig");
const mode = @import("../runtime/mode.zig");

pub const Distribution = mode.Distribution;
pub const Outcome = service.Outcome;
pub const Options = distro.ServiceOptions;
pub const Request = service.PlanRequest;

/// Six routes do not need a heap-allocated hash table. Preserve existing route
/// ordering and method masks; strip the query only for matching, never forwarding.
pub fn plan(distribution: Distribution, request: Request, options: Options) ?Outcome {
    return switch (distribution) {
        inline else => |selected| match(selected, request, options),
    };
}

fn match(comptime distribution: Distribution, request: Request, options: Options) ?Outcome {
    var normalized = request;
    if (std.mem.findScalar(u8, request.path, '?')) |end| normalized.path = request.path[0..end];
    for (distro.servicesFor(distribution)) |kind| {
        const svc = distro.buildService(kind, options);
        for (svc.routes()) |route| {
            if (!route.methods.matches(normalized.method)) continue;
            const matched = switch (route.pattern_type) {
                .exact => std.mem.eql(u8, normalized.path, route.pattern),
                .prefix => std.mem.startsWith(u8, normalized.path, route.pattern),
                .suffix => std.mem.endsWith(u8, normalized.path, route.pattern),
                .any => true,
            };
            if (matched) return svc.plan(normalized);
        }
    }
    return null;
}

/// Unknown methods retain the production router's 404 behavior.
pub fn method(value: []const u8) service.HttpMethod {
    return std.meta.stringToEnum(service.HttpMethod, value) orelse .OTHER;
}

test "v2 routes preserve distribution, query, origin and method boundaries" {
    const testing = std.testing;
    const request: Request = .{ .method = .POST, .path = "/api/v2/logs?api_key=x", .content_type = "application/json" };
    try testing.expectEqual(service.UpstreamChoice.logs, plan(.edge, request, .{}).?.pipe_stream.upstream);
    try testing.expect(plan(.otlp, request, .{}).? == .forward_raw);
    try testing.expect(plan(.edge, .{ .method = .OTHER, .path = "/" }, .{}) == null);
    try testing.expect(plan(.edge, .{ .method = .GET, .path = "/_health?x" }, .{}).? == .respond);
    try testing.expect(plan(.edge, .{ .method = .GET, .path = "/metrics/x" }, .{}).? == .fetch_filtered);
    try testing.expect(plan(.edge, .{ .method = .GET, .path = "/metrics-extra" }, .{}).? == .forward_raw);
}
