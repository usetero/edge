//! Prometheus Module
//!
//! Proxy module for Prometheus metrics scraping with policy-based filtering.
//! Filters response body line-by-line through PolicyStreamingFilter,
//! dropping metrics that don't pass policy evaluation.

const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const prometheus = @import("../prometheus/root.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");
const BoundedAllocator = @import("../bounded_allocator.zig").BoundedAllocator;

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResponse = proxy_module.ModuleResponse;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;

const PolicyStreamingFilter = prometheus.PolicyStreamingFilter;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;

// =============================================================================
// Constants
// =============================================================================

/// Size of line buffer for parsing (max line length)
const LINE_BUFFER_SIZE: usize = 8192;

/// Size of metadata buffer for HELP/TYPE tracking
const METADATA_BUFFER_SIZE: usize = 1296;

// =============================================================================
// Observability Events
// =============================================================================

const PrometheusScrapeCompleted = struct {
    bytes_processed: usize,
    bytes_forwarded: usize,
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    scrape_truncated: bool,
};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for Prometheus module filtering
pub const PrometheusConfig = struct {
    /// Policy registry for metric filtering
    registry: *const PolicyRegistry,

    /// Event bus for observability
    bus: *EventBus,

    /// Optional bounded allocator for memory limit enforcement
    bounded_allocator: ?*BoundedAllocator = null,

    /// Maximum bytes to process per scrape (data throughput limit)
    /// Default: 10MB
    max_bytes_per_scrape: usize = 10 * 1024 * 1024,
};

// =============================================================================
// Module
// =============================================================================

/// Prometheus module - proxy with response filtering
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
        .processResponse = processResponse,
        .deinit = deinit,
    };

    fn init(ptr: *anyopaque, _: std.mem.Allocator, module_config: ModuleConfig) anyerror!void {
        const self: *PrometheusModule = @ptrCast(@alignCast(ptr));
        self.config = @ptrCast(@alignCast(module_config.module_data));
    }

    fn processRequest(_: *anyopaque, _: *const ModuleRequest, _: std.mem.Allocator) anyerror!ModuleResult {
        return ModuleResult.unchanged();
    }

    fn processResponse(ptr: *anyopaque, resp: *const ModuleResponse, allocator: std.mem.Allocator) anyerror!ModuleResult {
        const self: *PrometheusModule = @ptrCast(@alignCast(ptr));

        const config = self.config orelse return ModuleResult.unchanged();

        // Use bounded allocator if configured for memory limit enforcement,
        // otherwise fall back to the provided allocator (typically arena)
        const alloc = if (config.bounded_allocator) |ba|
            ba.allocator()
        else
            allocator;

        // Allocate buffers for filtering
        const line_buffer = try alloc.alloc(u8, LINE_BUFFER_SIZE);
        defer alloc.free(line_buffer);

        const metadata_buffer = try alloc.alloc(u8, METADATA_BUFFER_SIZE);
        defer alloc.free(metadata_buffer);

        // Create filter
        var filter = PolicyStreamingFilter.init(.{
            .line_buffer = line_buffer,
            .metadata_buffer = metadata_buffer,
            .max_scrape_bytes = config.max_bytes_per_scrape,
            .registry = @constCast(config.registry),
            .bus = config.bus,
            .allocator = alloc,
        });

        // Allocate output buffer (same size as input, filtering can only shrink)
        const output_buffer = try alloc.alloc(u8, resp.body.len);
        errdefer alloc.free(output_buffer);

        var output_writer = std.Io.Writer.fixed(output_buffer);

        // Process entire body through filter
        _ = filter.processChunk(resp.body, &output_writer) catch {
            // On error, fail open - return unchanged
            alloc.free(output_buffer);
            return ModuleResult.unchanged();
        };

        // Finish processing (flush any partial line)
        _ = filter.finish(&output_writer) catch {
            alloc.free(output_buffer);
            return ModuleResult.unchanged();
        };

        // Emit stats
        const stats = filter.getStats();
        if (stats.lines_processed > 0) {
            config.bus.info(PrometheusScrapeCompleted{
                .bytes_processed = stats.bytes_processed,
                .bytes_forwarded = stats.bytes_forwarded,
                .lines_processed = stats.lines_processed,
                .lines_dropped = stats.lines_dropped,
                .lines_kept = stats.lines_kept,
                .scrape_truncated = stats.scrape_truncated,
            });
        }

        // Get the filtered output
        const filtered = output_writer.buffered();

        // If nothing was filtered out, return unchanged (avoid copy)
        if (filtered.len == resp.body.len and std.mem.eql(u8, filtered, resp.body)) {
            alloc.free(output_buffer);
            return ModuleResult.unchanged();
        }

        // Return modified body
        return ModuleResult.modified(filtered);
    }

    fn deinit(_: *anyopaque) void {}
};

/// Default routes for /metrics
pub const default_routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
    RoutePattern.prefix("/metrics/", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

fn createTestConfig(allocator: std.mem.Allocator) !struct {
    config: PrometheusConfig,
    registry: *PolicyRegistry,
    bus: *o11y.NoopEventBus,
} {
    const bus = try allocator.create(o11y.NoopEventBus);
    bus.init();

    const registry = try allocator.create(PolicyRegistry);
    registry.* = PolicyRegistry.init(allocator, bus.eventBus());

    return .{
        .config = .{
            .registry = registry,
            .bus = bus.eventBus(),
            .max_bytes_per_scrape = 10 * 1024 * 1024,
        },
        .registry = registry,
        .bus = bus,
    };
}

fn destroyTestConfig(allocator: std.mem.Allocator, registry: *PolicyRegistry, bus: *o11y.NoopEventBus) void {
    registry.deinit();
    allocator.destroy(registry);
    allocator.destroy(bus);
}

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

test "PrometheusModule - processResponse passes through simple metrics" {
    var test_cfg = try createTestConfig(testing.allocator);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

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
        .module_data = @ptrCast(&test_cfg.config),
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

    const body = "http_requests_total 100\nhttp_errors_total 5\n";
    const resp = ModuleResponse{
        .status = 200,
        .body = body,
        .request = &req,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processResponse(&resp, testing.allocator);

    // With no policies, all metrics pass through
    if (result.action == .proxy_modified) {
        try testing.expectEqualStrings(body, result.modified_body);
        testing.allocator.free(@constCast(result.modified_body));
    } else {
        try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
    }
}

test "PrometheusModule - processResponse preserves HELP and TYPE lines" {
    var test_cfg = try createTestConfig(testing.allocator);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

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
        .module_data = @ptrCast(&test_cfg.config),
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

    const body =
        \\# HELP http_requests_total Total HTTP requests
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="get"} 100
        \\
    ;
    const resp = ModuleResponse{
        .status = 200,
        .body = body,
        .request = &req,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processResponse(&resp, testing.allocator);

    if (result.action == .proxy_modified) {
        try testing.expectEqualStrings(body, result.modified_body);
        testing.allocator.free(@constCast(result.modified_body));
    } else {
        try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
    }
}

test "PrometheusModule - processResponse without config returns unchanged" {
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
        .module_data = null, // No config
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

    const resp = ModuleResponse{
        .status = 200,
        .body = "metric 1\n",
        .request = &req,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processResponse(&resp, testing.allocator);
    try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
}

test "PrometheusModule - processResponse handles histogram metrics" {
    var test_cfg = try createTestConfig(testing.allocator);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

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
        .module_data = @ptrCast(&test_cfg.config),
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

    const body =
        \\# HELP http_request_duration_seconds Request duration
        \\# TYPE http_request_duration_seconds histogram
        \\http_request_duration_seconds_bucket{le="0.1"} 100
        \\http_request_duration_seconds_bucket{le="0.5"} 150
        \\http_request_duration_seconds_bucket{le="+Inf"} 200
        \\http_request_duration_seconds_sum 45.5
        \\http_request_duration_seconds_count 200
        \\
    ;
    const resp = ModuleResponse{
        .status = 200,
        .body = body,
        .request = &req,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processResponse(&resp, testing.allocator);

    if (result.action == .proxy_modified) {
        try testing.expectEqualStrings(body, result.modified_body);
        testing.allocator.free(@constCast(result.modified_body));
    } else {
        try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
    }
}
