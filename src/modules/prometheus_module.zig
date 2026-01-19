//! Prometheus Module
//!
//! Proxy module for Prometheus metrics scraping.
//! Currently passthrough only - response filtering to be added later.

const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;

const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;

// =============================================================================
// Configuration
// =============================================================================

pub const PrometheusConfig = struct {
    registry: *const PolicyRegistry,
    bus: *EventBus,
    max_bytes_per_scrape: usize = 10 * 1024 * 1024,
};

// =============================================================================
// Module
// =============================================================================

pub const PrometheusModule = struct {
    config: ?*const PrometheusConfig = null,

    pub fn asProxyModule(self: *PrometheusModule) ProxyModule {
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

    fn init(ptr: *anyopaque, _: std.mem.Allocator, module_config: ModuleConfig) anyerror!void {
        const self: *PrometheusModule = @ptrCast(@alignCast(ptr));
        self.config = @ptrCast(@alignCast(module_config.module_data));
    }

    fn processRequest(_: *anyopaque, _: *const ModuleRequest, _: std.mem.Allocator) anyerror!ModuleResult {
        // Passthrough - no request modification
        return ModuleResult.unchanged();
    }

    fn deinit(_: *anyopaque) void {}
};

pub const default_routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
    RoutePattern.prefix("/metrics/", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "PrometheusModule - processRequest returns unchanged" {
    var module = PrometheusModule{};
    const pm = module.asProxyModule();

    try pm.init(testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = null,
    });
    defer pm.deinit();

    const req = ModuleRequest{
        .method = .GET,
        .path = "/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, testing.allocator);
    try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
}
