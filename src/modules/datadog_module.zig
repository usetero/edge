const std = @import("std");
const module_types = @import("./module_types.zig");
const policy = @import("policy_zig");
const logs_v2 = @import("./datadog_logs_v2.zig");
const metrics_v2 = @import("./datadog_metrics_v2.zig");
const runtime_metrics = @import("../runtime/runtime_metrics.zig");
const o11y = @import("o11y");

const ModuleConfig = module_types.ModuleConfig;
const ModuleRequest = module_types.ModuleRequest;
const ModuleStreamResult = module_types.ModuleStreamResult;
const RoutePattern = module_types.RoutePattern;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;
const RuntimeMetrics = runtime_metrics.RuntimeMetrics;

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
    /// Optional runtime metrics sink
    metrics: ?*RuntimeMetrics = null,
};

/// Datadog module - handles Datadog log and metric ingestion with filtering
/// STATELESS, THREAD-SAFE - only reads from registry (which uses lock-free snapshots)
pub const DatadogModule = struct {
    /// Read-only reference to policy registry (set during init)
    registry: *const PolicyRegistry = undefined,
    /// Event bus for observability
    bus: *EventBus = undefined,
    metrics: ?*RuntimeMetrics = null,

    pub fn init(self: *DatadogModule, _: std.mem.Allocator, config: ModuleConfig) !void {

        // Get registry from module_data
        const dd_config: *const DatadogConfig = @ptrCast(@alignCast(config.module_data orelse
            return error.MissingDatadogConfig));
        self.registry = dd_config.registry;
        self.bus = dd_config.bus;
        self.metrics = dd_config.metrics;
    }

    pub fn processRequestStream(
        self: *DatadogModule,
        req: *const ModuleRequest,
        body_reader: *std.Io.Reader,
        body_writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) !ModuleStreamResult {
        if (req.method != .POST) {
            try streamAll(body_reader, body_writer);
            return ModuleStreamResult.forwarded();
        }

        const content_type = req.getHeader("content-type") orelse "application/json";

        switch (req.route_kind) {
            .datadog_logs => {
                const result = logs_v2.processLogsStream(
                    allocator,
                    self.registry,
                    self.bus,
                    body_reader,
                    body_writer,
                    content_type,
                ) catch |err| {
                    self.bus.warn(LogsProcessingFailed{ .err = @errorName(err) });
                    try streamAll(body_reader, body_writer);
                    return ModuleStreamResult.forwarded();
                };

                self.bus.debug(LogsProcessed{
                    .dropped = result.dropped_count,
                    .kept = result.original_count - result.dropped_count,
                });
                if (self.metrics) |metrics| {
                    metrics.recordPolicyBatch(.datadog_logs, result.original_count, result.dropped_count);
                }

                if (result.allDropped()) {
                    return ModuleStreamResult.respond(202, "{}");
                }
                return ModuleStreamResult.forwarded();
            },
            .datadog_metrics => {
                const result = metrics_v2.processMetricsStream(
                    allocator,
                    self.registry,
                    self.bus,
                    body_reader,
                    body_writer,
                    content_type,
                ) catch |err| {
                    self.bus.warn(MetricsProcessingFailed{ .err = @errorName(err) });
                    try streamAll(body_reader, body_writer);
                    return ModuleStreamResult.forwarded();
                };

                self.bus.debug(MetricsProcessed{
                    .dropped = result.dropped_count,
                    .kept = result.original_count - result.dropped_count,
                });
                if (self.metrics) |metrics| {
                    metrics.recordPolicyBatch(.datadog_metrics, result.original_count, result.dropped_count);
                }

                if (result.allDropped()) {
                    return ModuleStreamResult.respond(202, "{\"errors\":[]}");
                }
                return ModuleStreamResult.forwarded();
            },
            else => {},
        }

        try streamAll(body_reader, body_writer);
        return ModuleStreamResult.forwarded();
    }

    fn streamAll(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
        while (true) {
            const n = reader.stream(writer, .unlimited) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
        }
    }

    pub fn deinit(_: *DatadogModule) void {
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

const ModuleResult = struct {
    action: Action,
    modified_body: []u8 = &.{},
    status: u16 = 200,
    response_body: []const u8 = &.{},

    const Action = enum {
        proxy_unchanged,
        proxy_modified,
        respond_immediately,
    };
};

fn runModuleForTest(
    module: anytype,
    req: *const ModuleRequest,
    allocator: std.mem.Allocator,
) !ModuleResult {
    var in_reader = std.Io.Reader.fixed(req.body);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    errdefer out_writer.deinit();

    const stream_result = try module.processRequestStream(
        req,
        &in_reader,
        &out_writer.writer,
        allocator,
    );

    return switch (stream_result.action) {
        .respond_immediately => blk: {
            out_writer.deinit();
            break :blk .{
                .action = .respond_immediately,
                .status = stream_result.status,
                .response_body = stream_result.response_body,
            };
        },
        .forwarded => blk: {
            const output = try out_writer.toOwnedSlice();
            if (std.mem.eql(u8, output, req.body)) {
                allocator.free(output);
                break :blk .{ .action = .proxy_unchanged };
            }
            break :blk .{
                .action = .proxy_modified,
                .modified_body = output,
            };
        },
    };
}

test "DatadogModule processes POST requests to /api/v2/logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};

    try module.init(allocator, .{
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
        .route_kind = .datadog_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"INFO\", \"message\": \"test\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // With no policies, logs should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    module.deinit();
}

test "DatadogModule processes POST requests to /api/v2/series" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};

    try module.init(allocator, .{
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
        .route_kind = .datadog_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1636629071, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // With no policies, metrics should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    module.deinit();
}

test "DatadogModule ignores GET requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var dd_config = DatadogConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = DatadogModule{};

    try module.init(allocator, .{
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
        .route_kind = .datadog_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "some body",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    module.deinit();
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

    try module.init(allocator, .{
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
        .route_kind = .datadog_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"DEBUG\", \"message\": \"debug\"}, {\"level\": \"ERROR\", \"message\": \"error\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // Should be modified (DEBUG filtered out)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "debug") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "error") != null);

    allocator.free(result.modified_body);
    module.deinit();
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

    try module.init(allocator, .{
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
        .route_kind = .datadog_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"debug.internal\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 1.0}]}, {\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // Should be modified (debug.internal filtered out)
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "debug.internal") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "system.load.1") != null);

    allocator.free(result.modified_body);
    module.deinit();
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

    try module.init(allocator, .{
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
        .route_kind = .datadog_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "[{\"level\": \"INFO\", \"message\": \"test\"}]",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // Should respond immediately with 202
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 202), result.status);

    module.deinit();
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

    try module.init(allocator, .{
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
        .route_kind = .datadog_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "{\"series\": [{\"metric\": \"system.load.1\", \"type\": 3, \"points\": [{\"timestamp\": 1, \"value\": 0.7}]}]}",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // Should respond immediately with 202
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, result.action);
    try std.testing.expectEqual(@as(u16, 202), result.status);

    module.deinit();
}
