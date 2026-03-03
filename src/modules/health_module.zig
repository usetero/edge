const std = @import("std");
const module_types = @import("./module_types.zig");

const ModuleConfig = module_types.ModuleConfig;
const ModuleRequest = module_types.ModuleRequest;
const ModuleStreamResult = module_types.ModuleStreamResult;
const RoutePattern = module_types.RoutePattern;

pub const HealthModule = struct {
    pub fn init(_: *HealthModule, _: std.mem.Allocator, _: ModuleConfig) !void {}

    pub fn processRequestStream(
        _: *HealthModule,
        _: *const ModuleRequest,
        _: *std.Io.Reader,
        _: *std.Io.Writer,
        _: std.mem.Allocator,
    ) !ModuleStreamResult {
        return ModuleStreamResult.respond(200, "{\"status\":\"ok\"}");
    }

    pub fn deinit(_: *HealthModule) void {}
};

pub const routes = [_]RoutePattern{
    RoutePattern.exact("/_health", .{ .get = true }),
};

test "HealthModule returns 200 OK with status json" {
    var module = HealthModule{};

    try module.init(std.testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 8080,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 1024,
        },
        .module_data = null,
    });

    const req = ModuleRequest{
        .method = .GET,
        .path = "/_health",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .headers_ctx = null,
        .get_header_fn = null,
    };
    var in_reader = std.Io.Reader.fixed(&.{});
    var out_buf: [1]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);
    const result = try module.processRequestStream(&req, &in_reader, &out_writer, std.testing.allocator);
    try std.testing.expectEqual(ModuleStreamResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", result.response_body);

    module.deinit();
}
