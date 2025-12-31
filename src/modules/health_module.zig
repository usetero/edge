const std = @import("std");
const proxy_module = @import("./proxy_module.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;

/// Health check module - responds to /_health endpoint
/// Returns 200 OK with JSON body indicating the server is healthy
pub const HealthModule = struct {
    pub fn asProxyModule(self: *HealthModule) ProxyModule {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = ProxyModule.VTable{
        .init = init,
        .processRequest = processRequest,
        .deinit = deinit,
    };

    fn init(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: ModuleConfig,
    ) anyerror!void {
        // Nothing to initialize
    }

    /// Health check - respond immediately with 200 OK
    fn processRequest(
        _: *anyopaque,
        _: *const ModuleRequest,
        _: std.mem.Allocator,
    ) anyerror!ModuleResult {
        return ModuleResult.respond(200, "{\"status\":\"ok\"}");
    }

    fn deinit(_: *anyopaque) void {
        // Nothing to cleanup
    }
};

/// Routes for health check endpoint
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/_health", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

test "HealthModule returns 200 OK with status json" {
    var module = HealthModule{};
    const pm = module.asProxyModule();

    // Initialize (no-op)
    try pm.init(std.testing.allocator, .{
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

    // Process request
    const req = ModuleRequest{
        .method = .GET,
        .path = "/_health",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, std.testing.allocator);
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", result.response_body);

    // Deinit (no-op)
    pm.deinit();
}
