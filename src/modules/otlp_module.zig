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

// =============================================================================
// Log Filtering Tests
// =============================================================================

test "OtlpModule: DROP policy filters matching logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs with severity "DEBUG"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug-logs"),
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

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    // Request with DEBUG log (should be dropped) and INFO log (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"debug message"},"severityText":"DEBUG"},{"body":{"stringValue":"info message"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should be modified (one log dropped)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);

    // Verify DEBUG log was dropped and INFO log remains
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "DEBUG") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "INFO") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "info message") != null);

    allocator.free(result.modified_body);
}

test "OtlpModule: all logs dropped returns empty response" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all logs
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .exists = true },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

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

    // Should respond with empty response (200 OK with {})
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqualStrings("{}", result.response_body);
}

test "OtlpModule: filter logs by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs from "test-service"
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-test-service"),
        .name = try allocator.dupe(u8, "drop-test-service-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .resource_attribute = try allocator.dupe(u8, "service.name") },
        .match = .{ .regex = try allocator.dupe(u8, "test-service") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    // Request with logs from test-service (should be dropped) and prod-service (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"from test"},"severityText":"INFO"}]}]},{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"prod-service"}}]},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"from prod"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);

    // Verify test-service log was dropped and prod-service log remains
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "from test") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "from prod") != null);

    allocator.free(result.modified_body);
}

// =============================================================================
// Metric Filtering Tests
// =============================================================================

test "OtlpModule: DROP policy filters matching metrics" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for metrics with "debug" in the name
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-debug-metrics"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    // Request with debug metric (should be dropped) and http metric (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"debug.internal"},{"name":"http.requests"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should be modified (one metric dropped)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);

    // Verify debug metric was dropped and http metric remains
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "http.requests") != null);

    allocator.free(result.modified_body);
}

test "OtlpModule: all metrics dropped returns empty response" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .exists = true },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"metric1"},{"name":"metric2"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should respond with empty response (200 OK with {})
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 200), result.status);
    try std.testing.expectEqualStrings("{}", result.response_body);
}

test "OtlpModule: filter metrics by metric type" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const MetricType = proto.policy.MetricType;

    // Create a DROP policy for gauge metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-gauges"),
        .name = try allocator.dupe(u8, "drop-gauge-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = MetricType.METRIC_TYPE_GAUGE },
        .match = .{ .regex = try allocator.dupe(u8, "^gauge$") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    // Request with gauge metric (should be dropped) and sum metric (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"cpu.usage","gauge":{"dataPoints":[{"asDouble":0.5}]}},{"name":"http.requests","sum":{"dataPoints":[{"asInt":"100"}]}}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should be modified (gauge metric dropped)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);

    // Verify gauge metric was dropped and sum metric remains
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "cpu.usage") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "http.requests") != null);

    allocator.free(result.modified_body);
}

test "OtlpModule: metrics route unchanged when no matching policy" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that won't match any metrics
    var drop_policy = proto.policy.Policy{
        .id = try allocator.dupe(u8, "drop-nonexistent"),
        .name = try allocator.dupe(u8, "drop-nonexistent"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "nonexistent_metric_name") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

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
    defer pm.deinit();

    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"http.requests"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);

    // Should pass through unchanged (no metrics matched the policy)
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
}
