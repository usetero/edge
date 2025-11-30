const std = @import("std");
const proxy_module = @import("../../core/proxy_module.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;

/// Passthrough module - proxies all requests unchanged
/// Used as a fallback/default module for unhandled routes
pub const PassthroughModule = struct {
    /// No state needed - completely stateless
    pub fn asProxyModule(self: *PassthroughModule) ProxyModule {
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

    /// Passthrough - always return unchanged
    fn processRequest(
        _: *anyopaque,
        _: *const ModuleRequest,
        _: std.mem.Allocator,
    ) anyerror!ModuleResult {
        return ModuleResult.unchanged();
    }

    fn deinit(_: *anyopaque) void {
        // Nothing to cleanup
    }
};

/// Default routes - match everything
pub const default_routes = [_]RoutePattern{
    RoutePattern.any(MethodBitmask.all),
};

// =============================================================================
// Tests
// =============================================================================

test "PassthroughModule always returns unchanged" {
    var module = PassthroughModule{};
    const pm = module.asProxyModule();

    // Initialize (no-op)
    try pm.init(std.testing.allocator, .{
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

    // Process request
    const req = ModuleRequest{
        .method = .GET,
        .path = "/any/path",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "test body",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, std.testing.allocator);
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    // Deinit (no-op)
    pm.deinit();
}
