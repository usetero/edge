const std = @import("std");
const types = @import("module_types.zig");
const passthrough_mod = @import("passthrough_module.zig");
const datadog_mod = @import("datadog_module.zig");
const otlp_mod = @import("otlp_module.zig");
const health_mod = @import("health_module.zig");
const prometheus_mod = @import("prometheus_module.zig");

pub const ModuleId = types.ModuleId;
pub const HttpMethod = types.HttpMethod;
pub const MethodBitmask = types.MethodBitmask;
pub const RoutePattern = types.RoutePattern;
pub const UpstreamConfig = types.UpstreamConfig;
pub const ModuleConfig = types.ModuleConfig;
pub const ModuleRequest = types.ModuleRequest;
pub const ModuleStreamResult = types.ModuleStreamResult;
pub const ResponseFilter = types.ResponseFilter;

pub const ProxyModule = union(enum) {
    passthrough: *passthrough_mod.PassthroughModule,
    datadog: *datadog_mod.DatadogModule,
    otlp: *otlp_mod.OtlpModule,
    health: *health_mod.HealthModule,
    prometheus: *prometheus_mod.PrometheusModule,

    pub fn init(self: ProxyModule, allocator: std.mem.Allocator, config: ModuleConfig) !void {
        switch (self) {
            inline else => |module| try module.init(allocator, config),
        }
    }

    pub fn processRequestStream(
        self: ProxyModule,
        req: *const ModuleRequest,
        body_reader: *std.Io.Reader,
        body_writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) !ModuleStreamResult {
        return switch (self) {
            inline else => |module| try module.processRequestStream(req, body_reader, body_writer, allocator),
        };
    }

    pub fn deinit(self: ProxyModule) void {
        switch (self) {
            inline else => |module| module.deinit(),
        }
    }

    pub fn createResponseFilter(
        self: ProxyModule,
        inner_writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) !?ResponseFilter {
        return switch (self) {
            .prometheus => |module| try module.createResponseFilter(inner_writer, allocator),
            else => null,
        };
    }
};

pub const ModuleRegistration = struct {
    module: ProxyModule,
    routes: []const RoutePattern,
    upstream_url: []const u8,
    max_path_length: u32 = 2048,
    max_request_body: u32 = 10 * 1024 * 1024,
    max_response_body: u32 = 10 * 1024 * 1024,
    module_data: ?*const anyopaque = null,
};

test "MethodBitmask.matches" {
    const post_only = MethodBitmask{ .post = true };
    try std.testing.expect(post_only.matches(.POST));
    try std.testing.expect(!post_only.matches(.GET));

    const get_post = MethodBitmask{ .get = true, .post = true };
    try std.testing.expect(get_post.matches(.GET));
    try std.testing.expect(get_post.matches(.POST));

    try std.testing.expect(MethodBitmask.all.matches(.DELETE));
}

test "RoutePattern.exact" {
    const route = RoutePattern.exact("/api/v2/logs", .{ .post = true });
    try std.testing.expectEqual(RoutePattern.PatternType.exact, route.pattern_type);
    try std.testing.expectEqualStrings("/api/v2/logs", route.pattern);
}
