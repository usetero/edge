const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const policy = @import("../policy/root.zig");
const otlp_logs = @import("./otlp_logs.zig");
const otlp_metrics = @import("./otlp_metrics.zig");
const o11y = @import("../observability/root.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Observability Events
// =============================================================================

const LogsProcessed = struct { dropped: usize, kept: usize };
const LogsProcessingFailed = struct { err: []const u8 };
const MetricsProcessed = struct { dropped: usize, kept: usize };
const MetricsProcessingFailed = struct { err: []const u8 };

/// OTLP module configuration
pub const OtlpConfig = struct {
    /// Reference to the policy registry
    registry: *const PolicyRegistry,
    /// Event bus for observability
    bus: *EventBus,
};

/// OTLP module - handles OpenTelemetry log ingestion with filtering
/// STATELESS, THREAD-SAFE - only reads from registry (which uses lock-free snapshots)
pub const OtlpModule = struct {
    /// Read-only reference to policy registry (set during init)
    registry: *const PolicyRegistry = undefined,
    /// Event bus for observability
    bus: *EventBus = undefined,

    pub fn asProxyModule(self: *OtlpModule) ProxyModule {
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
        ptr: *anyopaque,
        _: std.mem.Allocator,
        config: ModuleConfig,
    ) anyerror!void {
        const self: *OtlpModule = @ptrCast(@alignCast(ptr));

        // Get registry from module_data
        const otlp_config: *const OtlpConfig = @ptrCast(@alignCast(config.module_data orelse
            return error.MissingOtlpConfig));
        self.registry = otlp_config.registry;
        self.bus = otlp_config.bus;
    }

    /// THREAD-SAFE: No shared mutable state, only reads from registry
    fn processRequest(
        ptr: *anyopaque,
        req: *const ModuleRequest,
        allocator: std.mem.Allocator,
    ) anyerror!ModuleResult {
        const self: *OtlpModule = @ptrCast(@alignCast(ptr));

        // Only process POST requests
        if (req.method != .POST) {
            return ModuleResult.unchanged();
        }

        // No body = nothing to process
        if (req.body.len == 0) {
            return ModuleResult.unchanged();
        }

        // Get content type from headers
        const content_type = req.getHeader("content-type") orelse "application/json";

        // Route to appropriate processor based on path
        if (std.mem.endsWith(u8, req.path, "/v1/logs")) {
            return self.processLogs(allocator, req.body, content_type);
        } else if (std.mem.endsWith(u8, req.path, "/v1/metrics")) {
            return self.processMetrics(allocator, req.body, content_type);
        }

        return ModuleResult.unchanged();
    }

    fn processLogs(
        self: *OtlpModule,
        allocator: std.mem.Allocator,
        body: []const u8,
        content_type: []const u8,
    ) !ModuleResult {
        // Process logs through filter
        // FAIL OPEN: If processing fails, pass original through
        const result = otlp_logs.processLogs(
            allocator,
            self.registry,
            self.bus,
            body,
            content_type,
        ) catch |err| {
            self.bus.warn(LogsProcessingFailed{ .err = @errorName(err) });
            return ModuleResult.unchanged();
        };

        self.bus.debug(LogsProcessed{
            .dropped = result.dropped_count,
            .kept = result.original_count - result.dropped_count,
        });

        // If all logs were dropped, return empty response with 200 (OTLP expects this)
        if (result.allDropped()) {
            allocator.free(result.data);
            return ModuleResult.respond(200, "{}");
        }

        // Check if logs were actually modified (any dropped)
        if (!result.wasModified()) {
            // No changes - free allocated memory and return unchanged
            allocator.free(result.data);
            return ModuleResult.unchanged();
        }

        // Logs were modified
        return ModuleResult.modified(result.data);
    }

    fn processMetrics(
        self: *OtlpModule,
        allocator: std.mem.Allocator,
        body: []const u8,
        content_type: []const u8,
    ) !ModuleResult {
        // Process metrics through filter
        // FAIL OPEN: If processing fails, pass original through
        const result = otlp_metrics.processMetrics(
            allocator,
            self.registry,
            self.bus,
            body,
            content_type,
        ) catch |err| {
            self.bus.warn(MetricsProcessingFailed{ .err = @errorName(err) });
            return ModuleResult.unchanged();
        };

        self.bus.debug(MetricsProcessed{
            .dropped = result.dropped_count,
            .kept = result.original_count - result.dropped_count,
        });

        // If all metrics were dropped, return empty response with 200 (OTLP expects this)
        if (result.allDropped()) {
            allocator.free(result.data);
            return ModuleResult.respond(200, "{}");
        }

        // Check if metrics were actually modified (any dropped)
        if (!result.wasModified()) {
            // No changes - free allocated memory and return unchanged
            allocator.free(result.data);
            return ModuleResult.unchanged();
        }

        // Metrics were modified
        return ModuleResult.modified(result.data);
    }

    fn deinit(_: *anyopaque) void {
        // Nothing to cleanup (stateless)
    }
};

/// Routes for OTLP endpoints
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/v1/logs", .{ .post = true }),
    RoutePattern.exact("/v1/metrics", .{ .post = true }),
};

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

test "OtlpModule processes POST requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "localhost",
            .port = 4318,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&otlp_config),
    });

    // Test with POST request and JSON body (OTLP format)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"test"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // With no policies, logs should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    pm.deinit();
}

test "OtlpModule ignores GET requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "localhost",
            .port = 4318,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&otlp_config),
    });

    const req = ModuleRequest{
        .method = .GET,
        .path = "/v1/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "some body",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    pm.deinit();
}

// TODO: Add filtering tests once otlp_logs.zig filtering is implemented
