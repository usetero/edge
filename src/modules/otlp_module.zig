const std = @import("std");
const module_types = @import("./module_types.zig");
const policy = @import("policy_zig");
const otlp_logs = @import("./otlp_logs.zig");
const otlp_metrics = @import("./otlp_metrics.zig");
const otlp_traces = @import("./otlp_traces.zig");
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
const TracesProcessed = struct { dropped: usize, kept: usize };
const TracesProcessingFailed = struct { err: []const u8 };

/// OTLP module configuration
pub const OtlpConfig = struct {
    /// Reference to the policy registry
    registry: *const PolicyRegistry,
    /// Event bus for observability
    bus: *EventBus,
    /// Optional runtime metrics sink
    metrics: ?*RuntimeMetrics = null,
};

/// OTLP module - handles OpenTelemetry log ingestion with filtering
/// STATELESS, THREAD-SAFE - only reads from registry (which uses lock-free snapshots)
pub const OtlpModule = struct {
    /// Read-only reference to policy registry (set during init)
    registry: *const PolicyRegistry = undefined,
    /// Event bus for observability
    bus: *EventBus = undefined,
    metrics: ?*RuntimeMetrics = null,

    pub fn init(self: *OtlpModule, _: std.mem.Allocator, config: ModuleConfig) !void {

        // Get registry from module_data
        const otlp_config: *const OtlpConfig = @ptrCast(@alignCast(config.module_data orelse
            return error.MissingOtlpConfig));
        self.registry = otlp_config.registry;
        self.bus = otlp_config.bus;
        self.metrics = otlp_config.metrics;
    }

    pub fn processRequestStream(
        self: *OtlpModule,
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
            .otlp_logs => {
                const result = try otlp_logs.processLogsStream(
                    allocator,
                    self.registry,
                    self.bus,
                    body_reader,
                    body_writer,
                    content_type,
                );
                if (self.metrics) |metrics| {
                    metrics.recordPolicyBatch(.otlp_logs, result.original_count, result.dropped_count);
                }
                if (result.allDropped()) return ModuleStreamResult.respond(200, "{}");
                return ModuleStreamResult.forwarded();
            },
            .otlp_metrics => {
                const result = try otlp_metrics.processMetricsStream(
                    allocator,
                    self.registry,
                    self.bus,
                    body_reader,
                    body_writer,
                    content_type,
                );
                if (self.metrics) |metrics| {
                    metrics.recordPolicyBatch(.otlp_metrics, result.original_count, result.dropped_count);
                }
                if (result.allDropped()) return ModuleStreamResult.respond(200, "{}");
                return ModuleStreamResult.forwarded();
            },
            .otlp_traces => {
                const result = try otlp_traces.processTracesStream(
                    allocator,
                    self.registry,
                    self.bus,
                    body_reader,
                    body_writer,
                    content_type,
                );
                if (self.metrics) |metrics| {
                    metrics.recordPolicyBatch(.otlp_traces, result.original_count, result.dropped_count);
                }
                if (result.allDropped()) return ModuleStreamResult.respond(200, "{}");
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

    pub fn deinit(_: *OtlpModule) void {
        // Nothing to cleanup (stateless)
    }
};

/// Routes for OTLP endpoints
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/v1/logs", .{ .post = true }),
    RoutePattern.exact("/v1/metrics", .{ .post = true }),
    RoutePattern.exact("/v1/traces", .{ .post = true }),
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

test "OtlpModule processes POST requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};

    try module.init(allocator, .{
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
        .route_kind = .otlp_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"test"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // With no policies, logs should pass through unchanged
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    module.deinit();
}

test "OtlpModule ignores GET requests" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};

    try module.init(allocator, .{
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
        .route_kind = .otlp_logs,
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

    try module.init(allocator, .{
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
    defer module.deinit();

    // Request with DEBUG log (should be dropped) and INFO log (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .route_kind = .otlp_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"debug message"},"severityText":"DEBUG"},{"body":{"stringValue":"info message"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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

    try module.init(allocator, .{
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
    defer module.deinit();

    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .route_kind = .otlp_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"test"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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
    var attr_path = proto.policy.AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service.name"));
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .resource_attribute = attr_path },
        .match = .{ .regex = try allocator.dupe(u8, "test-service") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};

    try module.init(allocator, .{
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
    defer module.deinit();

    // Request with logs from test-service (should be dropped) and prod-service (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/logs",
        .route_kind = .otlp_logs,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"from test"},"severityText":"INFO"}]}]},{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"prod-service"}}]},"scopeLogs":[{"scope":{},"logRecords":[{"body":{"stringValue":"from prod"},"severityText":"INFO"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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

    try module.init(allocator, .{
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
    defer module.deinit();

    // Request with debug metric (should be dropped) and http metric (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .route_kind = .otlp_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"debug.internal"},{"name":"http.requests"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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

    try module.init(allocator, .{
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
    defer module.deinit();

    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .route_kind = .otlp_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"metric1"},{"name":"metric2"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var otlp_config = OtlpConfig{ .registry = &registry, .bus = noop_bus.eventBus() };

    var module = OtlpModule{};

    try module.init(allocator, .{
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
    defer module.deinit();

    // Request with gauge metric (should be dropped) and sum metric (should be kept)
    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .route_kind = .otlp_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"cpu.usage","gauge":{"dataPoints":[{"asDouble":0.5}]}},{"name":"http.requests","sum":{"dataPoints":[{"asInt":"100"}]}}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

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

    try module.init(allocator, .{
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
    defer module.deinit();

    const req = ModuleRequest{
        .method = .POST,
        .path = "/v1/metrics",
        .route_kind = .otlp_metrics,
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body =
        \\{"resourceMetrics":[{"resource":{},"scopeMetrics":[{"scope":{},"metrics":[{"name":"http.requests"}]}]}]}
        ,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try runModuleForTest(&module, &req, allocator);

    // Stream JSON path may reserialize while preserving semantic content.
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, result.action);
    try std.testing.expect(std.mem.indexOf(u8, result.modified_body, "http.requests") != null);
    allocator.free(result.modified_body);
}
