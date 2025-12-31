const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const policy = @import("../policy/root.zig");
const logs_v2 = @import("./datadog_logs_v2.zig");
const metrics_v2 = @import("./datadog_metrics_v2.zig");
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

/// Datadog module configuration
pub const DatadogConfig = struct {
    /// Reference to the policy registry
    registry: *const PolicyRegistry,
    /// Event bus for observability
    bus: *EventBus,
};

/// Datadog module - handles Datadog log and metric ingestion with filtering
/// STATELESS, THREAD-SAFE - only reads from registry (which uses lock-free snapshots)
pub const DatadogModule = struct {
    /// Read-only reference to policy registry (set during init)
    registry: *const PolicyRegistry = undefined,
    /// Event bus for observability
    bus: *EventBus = undefined,

    pub fn asProxyModule(self: *DatadogModule) ProxyModule {
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
        const self: *DatadogModule = @ptrCast(@alignCast(ptr));

        // Get registry from module_data
        const dd_config: *const DatadogConfig = @ptrCast(@alignCast(config.module_data orelse
            return error.MissingDatadogConfig));
        self.registry = dd_config.registry;
        self.bus = dd_config.bus;
    }

    /// THREAD-SAFE: No shared mutable state, only reads from registry
    fn processRequest(
        ptr: *anyopaque,
        req: *const ModuleRequest,
        allocator: std.mem.Allocator,
    ) anyerror!ModuleResult {
        const self: *DatadogModule = @ptrCast(@alignCast(ptr));

        // Only process POST requests
        if (req.method != .POST) {
            return ModuleResult.unchanged();
        }

        // No body = nothing to process
        if (req.body.len == 0) {
            return ModuleResult.unchanged();
        }

        // Route to appropriate handler based on path
        if (std.mem.eql(u8, req.path, "/api/v2/logs")) {
            return self.processLogs(req, allocator);
        } else if (std.mem.eql(u8, req.path, "/api/v2/series")) {
            return self.processMetrics(req, allocator);
        }

        return ModuleResult.unchanged();
    }

    /// Process logs endpoint
    fn processLogs(self: *DatadogModule, req: *const ModuleRequest, allocator: std.mem.Allocator) !ModuleResult {
        // Get content type from headers
        const content_type = req.getHeader("content-type") orelse "application/json";

        // Process logs through filter
        // FAIL OPEN: If processing fails, pass original through
        const result = logs_v2.processLogs(
            allocator,
            self.registry,
            self.bus,
            req.body,
            content_type,
        ) catch |err| {
            self.bus.warn(LogsProcessingFailed{ .err = @errorName(err) });
            return ModuleResult.unchanged();
        };

        self.bus.debug(LogsProcessed{
            .dropped = result.dropped_count,
            .kept = result.original_count - result.dropped_count,
        });

        // If all logs were dropped, return empty array with 202 (Datadog expects this)
        if (result.allDropped()) {
            allocator.free(result.data);
            return ModuleResult.respond(202, "{}");
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

    /// Process metrics endpoint
    fn processMetrics(self: *DatadogModule, req: *const ModuleRequest, allocator: std.mem.Allocator) !ModuleResult {
        // Get content type from headers
        const content_type = req.getHeader("content-type") orelse "application/json";

        // Process metrics through filter
        // FAIL OPEN: If processing fails, pass original through
        const result = metrics_v2.processMetrics(
            allocator,
            self.registry,
            self.bus,
            req.body,
            content_type,
        ) catch |err| {
            self.bus.warn(MetricsProcessingFailed{ .err = @errorName(err) });
            return ModuleResult.unchanged();
        };

        self.bus.debug(MetricsProcessed{
            .dropped = result.dropped_count,
            .kept = result.original_count - result.dropped_count,
        });

        // If all metrics were dropped, return empty series with 202 (Datadog expects this)
        if (result.allDropped()) {
            allocator.free(result.data);
            return ModuleResult.respond(202, "{\"series\":[]}");
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

/// Routes for Datadog logs endpoint
pub const logs_routes = [_]RoutePattern{
    RoutePattern.exact("/api/v2/logs", .{ .post = true }),
};

/// Routes for Datadog metrics endpoint
pub const metrics_routes = [_]RoutePattern{
    RoutePattern.exact("/api/v2/series", .{ .post = true }),
};

/// All Datadog routes (for backwards compatibility)
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/api/v2/logs", .{ .post = true }),
    RoutePattern.exact("/api/v2/series", .{ .post = true }),
};

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

test "DatadogModule processes POST requests to /api/v2/logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "intake.logs.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    // Test with POST request and JSON body
    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"INFO\", \"message\": \"test\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // With no policies, logs should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    pm.deinit();
}

test "DatadogModule processes POST requests to /api/v2/series" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "api.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    // Test with POST request and JSON body for metrics
    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/series",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1636629071, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // With no policies, metrics should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    pm.deinit();
}

test "DatadogModule ignores GET requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "intake.logs.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    const req = ModuleRequest{
        .method = .GET,
        .path = "/api/v2/logs",
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

test "DatadogModule filters logs with DROP policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for DEBUG logs
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "DEBUG") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "intake.logs.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    // Request with one DEBUG and one ERROR log
    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"DEBUG\", \"message\": \"debug\"}, {\"level\": \"ERROR\", \"message\": \"error\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should be modified (DEBUG filtered out)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "debug") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "error") != null);

    allocator.free(result.modified_body);
    pm.deinit();
}

test "DatadogModule filters metrics with DROP policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-metrics"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^debug\\.") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "api.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    // Request with one debug and one system metric
    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/series",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"debug.internal\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 1.0}]}, {\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should be modified (debug.internal filtered out)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "system.load.1") != null);

    allocator.free(result.modified_body);
    pm.deinit();
}

test "DatadogModule returns 202 when all logs dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy that matches INFO logs (test data uses INFO)
    var drop_all = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_all.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "INFO") },
    });
    defer drop_all.deinit(allocator);

    try registry.updatePolicies(&.{drop_all}, "file-provider", .file);

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "intake.logs.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"INFO\", \"message\": \"test\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should respond immediately with 202
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 202), result.status);

    pm.deinit();
}

test "DatadogModule returns 202 when all metrics dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy that matches the test metric
    var drop_all = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all-metrics"),
        .name = try allocator.dupe(u8, "drop-all-metrics"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false, // drop matching metrics
            },
        },
    };
    try drop_all.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "system") },
    });
    defer drop_all.deinit(allocator);

    try registry.updatePolicies(&.{drop_all}, "file-provider", .file);

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "https",
            .host = "api.datadoghq.com",
            .port = 443,
            .base_path = "",
            .max_request_body = 10 * 1024 * 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&dd_config),
    });

    const req = ModuleRequest{
        .method = .POST,
        .path = "/api/v2/series",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should respond immediately with 202
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 202), result.status);

    pm.deinit();
}
