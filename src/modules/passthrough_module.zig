const std = @import("std");
const module_types = @import("./module_types.zig");

const ModuleConfig = module_types.ModuleConfig;
const ModuleRequest = module_types.ModuleRequest;
const ModuleStreamResult = module_types.ModuleStreamResult;
const RoutePattern = module_types.RoutePattern;
const MethodBitmask = module_types.MethodBitmask;

pub const PassthroughModule = struct {
    pub fn init(_: *PassthroughModule, _: std.mem.Allocator, _: ModuleConfig) !void {}

    pub fn processRequestStream(
        _: *PassthroughModule,
        _: *const ModuleRequest,
        body_reader: *std.Io.Reader,
        body_writer: *std.Io.Writer,
        _: std.mem.Allocator,
    ) !ModuleStreamResult {
        while (true) {
            const n = body_reader.stream(body_writer, .unlimited) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
        }
        return ModuleStreamResult.forwarded();
    }

    pub fn deinit(_: *PassthroughModule) void {}
};

pub const default_routes = [_]RoutePattern{
    RoutePattern.any(MethodBitmask.all),
};

test "PassthroughModule always returns unchanged" {
    var module = PassthroughModule{};

    try module.init(std.testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
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
        .path = "/any/path",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .headers_ctx = null,
        .get_header_fn = null,
    };
    var in_reader = std.Io.Reader.fixed("test body");
    var out_buf: [64]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);
    const result = try module.processRequestStream(&req, &in_reader, &out_writer, std.testing.allocator);
    try std.testing.expectEqual(ModuleStreamResult.Action.forwarded, result.action);
    try std.testing.expectEqualStrings("test body", out_buf[0..out_writer.end]);

    module.deinit();
}
