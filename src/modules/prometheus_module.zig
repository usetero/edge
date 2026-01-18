//! Prometheus Module
//!
//! Proxy module for Prometheus metrics scraping with policy-based filtering.
//!
//! This module acts as a transparent proxy between Prometheus scrapers and
//! application /metrics endpoints. It can filter metrics based on configured
//! policies, dropping or keeping metrics based on name and label patterns.
//!
//! Key features:
//! - Streaming response processing (bounded memory)
//! - Policy-based metric filtering
//! - Per-scrape data limits
//! - Statistics tracking for observability
//!
//! Usage:
//! ```
//! routes:
//!   - path_prefix: /metrics
//!     upstream: http://app:8080
//!     module: prometheus
//!     config:
//!       max_bytes_per_scrape: 10485760  # 10MB
//! ```
//!
//! Note: Response filtering is implemented in Phase 7 via ResponseProcessor.
//! This module currently handles request passthrough.
//!

const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const prometheus = @import("../prometheus/root.zig");
const policy = @import("../policy/root.zig");

const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;
const PolicyRegistry = policy.Registry;

/// Configuration for Prometheus module
pub const PrometheusConfig = struct {
    /// Reference to the policy registry
    registry: *const PolicyRegistry,

    /// Event bus for observability
    bus: *EventBus,

    /// Maximum bytes to process per scrape (data throughput limit)
    max_bytes_per_scrape: usize = 10 * 1024 * 1024, // 10MB default
};

/// Prometheus module - proxies metrics scrapes with optional filtering
pub const PrometheusModule = struct {
    /// Reference to the policy registry
    registry: ?*const PolicyRegistry = null,

    /// Event bus for observability
    bus: ?*EventBus = null,

    /// Configuration reference
    config: ?*const PrometheusConfig = null,

    /// Streaming filter state (initialized per-request, but we keep buffers here)
    filter: ?*prometheus.PolicyStreamingFilter = null,

    /// Return the module as a ProxyModule interface
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
        .processResponseChunk = processResponseChunk,
    };

    fn init(
        ptr: *anyopaque,
        _: std.mem.Allocator,
        module_config: ModuleConfig,
    ) anyerror!void {
        const self: *PrometheusModule = @ptrCast(@alignCast(ptr));

        // Get Prometheus-specific config if provided
        if (module_config.module_data) |data| {
            const prom_config: *const PrometheusConfig = @ptrCast(@alignCast(data));
            self.config = prom_config;
            self.registry = prom_config.registry;
            self.bus = prom_config.bus;
        }
    }

    /// Process incoming request (passthrough for now)
    /// Prometheus scrapes are GET requests - we just pass them through unchanged.
    /// The response filtering happens in the ResponseProcessor (Phase 7).
    fn processRequest(
        _: *anyopaque,
        _: *const ModuleRequest,
        _: std.mem.Allocator,
    ) anyerror!ModuleResult {
        // Passthrough - Prometheus scrapes are GET requests that don't need
        // request body modification. Response filtering is handled separately.
        return ModuleResult.unchanged();
    }

    fn deinit(_: *anyopaque) void {
        // Nothing to clean up - bounded allocator is managed by main
    }

    fn processResponseChunk(
        ptr: *anyopaque,
        chunk: []const u8,
        is_last: bool,
        alloc: std.mem.Allocator,
    ) anyerror![]const u8 {
        const self: *PrometheusModule = @ptrCast(@alignCast(ptr));
        _ = is_last;
        _ = alloc;

        // For now, passthrough - full filtering will be implemented
        // when we integrate the streaming filter with the server's
        // response streaming loop
        _ = self;
        return chunk;
    }

    /// Get max bytes per scrape configuration
    pub fn getMaxBytesPerScrape(self: *const PrometheusModule) usize {
        if (self.config) |cfg| {
            return cfg.max_bytes_per_scrape;
        }
        return 10 * 1024 * 1024; // Default 10MB
    }

    /// Get the policy registry for filtering
    pub fn getRegistry(self: *const PrometheusModule) ?*const PolicyRegistry {
        return self.registry;
    }
};

/// Default routes - match /metrics paths
pub const default_routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
    RoutePattern.prefix("/metrics/", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

test "PrometheusModule - passthrough request" {
    var module = PrometheusModule{};
    const pm = module.asProxyModule();

    // Initialize without config (passthrough mode)
    try pm.init(std.testing.allocator, .{
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

    // Process request - should return unchanged
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

    const result = try pm.processRequest(&req, std.testing.allocator);
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
}

test "PrometheusModule - with config" {
    var module = PrometheusModule{};
    const pm = module.asProxyModule();

    // Create a mock registry (we just need the pointer for now)
    var mock_registry: PolicyRegistry = undefined;

    // Create a mock event bus
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init();

    const config = PrometheusConfig{
        .registry = &mock_registry,
        .bus = noop_bus.eventBus(),
        .max_bytes_per_scrape = 1024 * 1024,
    };

    try pm.init(std.testing.allocator, .{
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
        .module_data = &config,
    });
    defer pm.deinit();

    // Check config getters
    try std.testing.expectEqual(@as(usize, 1024 * 1024), module.getMaxBytesPerScrape());
    try std.testing.expect(module.getRegistry() != null);
}
