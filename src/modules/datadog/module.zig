const std = @import("std");
const proxy_module = @import("../../core/proxy_module.zig");
const filter_mod = @import("../../core/filter.zig");
const logs_v2 = @import("logs_v2.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;
const FilterEvaluator = filter_mod.FilterEvaluator;

/// Datadog module configuration
pub const DatadogConfig = struct {
    /// Reference to the filter evaluator
    filter: *const FilterEvaluator,
};

/// Datadog module - handles Datadog log ingestion with filtering
/// STATELESS, THREAD-SAFE - only reads from filter (which uses lock-free snapshots)
pub const DatadogModule = struct {
    /// Read-only reference to filter evaluator (set during init)
    filter: *const FilterEvaluator = undefined,

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

        // Get filter from module_data
        const dd_config: *const DatadogConfig = @ptrCast(@alignCast(config.module_data orelse
            return error.MissingDatadogConfig));
        self.filter = dd_config.filter;
    }

    /// THREAD-SAFE: No shared mutable state, only reads from filter
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

        // Get content type from headers
        const content_type = req.getHeader("content-type") orelse "application/json";

        // Process logs through filter
        // FAIL OPEN: If processing fails, pass original through
        const result = logs_v2.processLogs(
            allocator,
            self.filter,
            req.body,
            content_type,
        ) catch |err| {
            std.log.warn("Failed to process Datadog logs (failing open): {}", .{err});
            return ModuleResult.unchanged();
        };

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

    fn deinit(_: *anyopaque) void {
        // Nothing to cleanup (stateless)
    }
};

/// Routes for Datadog logs endpoint
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/api/v2/logs", .{ .post = true }),
};

// =============================================================================
// Tests
// =============================================================================

const policy_registry = @import("../../core/policy_registry.zig");
const PolicyRegistry = policy_registry.PolicyRegistry;
const proto = @import("proto");

test "DatadogModule processes POST requests" {
    const allocator = std.testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    var dd_config = DatadogConfig{ .filter = &filter };

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

test "DatadogModule ignores GET requests" {
    const allocator = std.testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    var dd_config = DatadogConfig{ .filter = &filter };

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

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create DROP policy for DEBUG logs
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-debug"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try drop_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try drop_policy.config.?.filter.matchers.append(allocator, .{
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    var dd_config = DatadogConfig{ .filter = &filter };

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

test "DatadogModule returns 202 when all logs dropped" {
    const allocator = std.testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create DROP policy that matches everything
    var drop_all = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-all"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try drop_all.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try drop_all.config.?.filter.matchers.append(allocator, .{
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, ""),
    });
    defer drop_all.deinit(allocator);

    try registry.updatePolicies(&.{drop_all}, .file);

    const filter = FilterEvaluator.init(&registry);

    var dd_config = DatadogConfig{ .filter = &filter };

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
