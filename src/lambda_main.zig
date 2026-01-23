//! Lambda Extension Distribution Entry Point
//!
//! A Lambda extension distribution for Datadog telemetry ingestion with filtering.
//! Runs as an external extension, intercepting telemetry from Lambda functions.
//!
//! Architecture:
//! - Main thread: Lambda Extensions API event loop
//! - Background: httpz proxy server (multi-threaded)
//!
//! Features:
//! - Policy-based log/metric filtering
//! - Fail-open behavior
//! - Graceful shutdown within Lambda's deadline
//! - Environment-based configuration (via zonfig)

const std = @import("std");
const builtin = @import("builtin");

const edge = @import("root.zig");
const server_mod = edge.server;
const proxy_module = edge.proxy_module;
const passthrough_mod = edge.passthrough_module;
const datadog_mod = edge.datadog_module;
const health_mod = edge.health_module;
const policy = edge.policy;
const zonfig = edge.zonfig;

const lambda = @import("lambda/root.zig");
const ExtensionClient = lambda.ExtensionClient;

const o11y = @import("observability/root.zig");
const EventBus = o11y.EventBus;
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PassthroughModule = passthrough_mod.PassthroughModule;
const DatadogModule = datadog_mod.DatadogModule;
const DatadogConfig = datadog_mod.DatadogConfig;
const HealthModule = health_mod.HealthModule;

// =============================================================================
// Lambda Configuration
// =============================================================================

/// Lambda extension configuration loaded via zonfig.
/// All fields can be overridden via environment variables with TERO_ prefix.
pub const LambdaConfig = struct {
    // Network
    listen_address: [4]u8 = .{ 127, 0, 0, 1 },
    listen_port: u16 = 8080,

    // Upstream URLs
    upstream_url: []const u8 = "http://localhost",
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,

    // Limits
    max_body_size: u32 = 5 * 1024 * 1024, // 5MB
    max_upstream_retries: u8 = 3,

    // Service metadata
    service: struct {
        name: []const u8 = "tero-edge-lambda",
        namespace: []const u8 = "tero",
        version: []const u8 = "latest",
    } = .{},

    // Policy configuration
    policy: struct {
        /// JSON array of policies to load at startup
        /// Example: TERO_POLICY_STATIC='{"policies":[{"id":"drop-health","name":"Drop health","log":{"match":[{"log_field":"body","regex":"health"}],"keep":"none"}}]}'
        static: ?[]const u8 = null,
        /// HTTP policy provider URL for dynamic updates
        url: ?[]const u8 = null,
        poll_interval: u64 = 60,
        api_key: ?[]const u8 = null,
    } = .{},
};

/// Route std.log through our EventBus adapter
pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = StdLogAdapter.logFn,
};

// =============================================================================
// Observability Events
// =============================================================================

const LambdaExtensionStarting = struct {};
const LambdaExtensionReady = struct { port: u16 };
const LambdaExtensionShutdown = struct { reason: []const u8 };
const LambdaExtensionError = struct { err: []const u8 };
const LambdaInvokeReceived = struct { request_id: []const u8 };
const ProxyServerStarted = struct { port: u16 };
const ProxyServerStopped = struct {};
const ConfigurationLoaded = struct {
    logs_url: []const u8,
    metrics_url: []const u8,
};
const StaticPoliciesLoading = struct {};
const StaticPoliciesLoaded = struct { count: usize };
const StaticPoliciesError = struct { err: []const u8 };

// =============================================================================
// Global State
// =============================================================================

var server_instance: ?*ProxyServer = null;
var global_event_bus: ?*EventBus = null;
var shutdown_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// =============================================================================
// Server Thread
// =============================================================================

const ServerThreadContext = struct {
    proxy: *ProxyServer,
    bus: *EventBus,
};

fn serverThread(ctx: *ServerThreadContext) void {
    ctx.bus.info(ProxyServerStarted{ .port = ctx.proxy.context.listen_port });

    ctx.proxy.listen() catch |err| {
        ctx.bus.err(LambdaExtensionError{ .err = @errorName(err) });
    };

    ctx.bus.info(ProxyServerStopped{});
}

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize observability
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    // Parse log level from environment
    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    // Initialize std.log adapter
    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    global_event_bus = bus;
    defer global_event_bus = null;

    bus.info(LambdaExtensionStarting{});

    // Load configuration via zonfig (env vars with TERO_ prefix, no JSON file)
    const config = zonfig.load(LambdaConfig, allocator, .{ .env_prefix = "TERO" }) catch |err| {
        bus.err(LambdaExtensionError{ .err = @errorName(err) });
        return err;
    };
    defer zonfig.deinit(LambdaConfig, allocator, config);

    // Determine effective URLs
    const logs_url = config.logs_url orelse config.upstream_url;
    const metrics_url = config.metrics_url orelse config.upstream_url;

    bus.info(ConfigurationLoaded{
        .logs_url = logs_url,
        .metrics_url = metrics_url,
    });

    // Generate instance ID
    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "lambda-{d}-{d}", .{
        std.time.milliTimestamp(),
        std.Thread.getCurrentId(),
    });
    const instance_id_copy = try allocator.dupe(u8, instance_id);
    defer allocator.free(instance_id_copy);

    // Build service metadata
    const service_metadata = policy.ServiceMetadata{
        .name = config.service.name,
        .namespace = config.service.namespace,
        .version = config.service.version,
        .instance_id = instance_id_copy,
        .supported_stages = &.{
            .POLICY_STAGE_LOG_FILTER,
            .POLICY_STAGE_LOG_TRANSFORM,
            .POLICY_STAGE_METRIC_FILTER,
        },
    };

    // Create policy registry
    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    // Load static policies from environment variable (TERO_POLICY_STATIC)
    if (config.policy.static) |static_json| {
        bus.info(StaticPoliciesLoading{});

        const policies = policy.parser.parsePoliciesBytes(allocator, static_json) catch |err| {
            bus.err(StaticPoliciesError{ .err = @errorName(err) });
            return err;
        };
        defer {
            for (policies) |*p| {
                p.deinit(allocator);
            }
            allocator.free(policies);
        }

        try registry.updatePolicies(policies, "static", .file);
        bus.info(StaticPoliciesLoaded{ .count = policies.len });
    }

    // Create HTTP policy loader if configured
    var loader: ?*policy.Loader = null;
    defer if (loader) |l| l.deinit();

    if (config.policy.url) |policy_url| {
        // Build headers if API key is set
        var headers_buf: [1]policy.Header = undefined;
        var headers_count: usize = 0;

        var auth_value_buf: [256]u8 = undefined;
        if (config.policy.api_key) |api_key| {
            const auth_value = try std.fmt.bufPrint(&auth_value_buf, "Bearer {s}", .{api_key});
            headers_buf[0] = .{
                .name = "Authorization",
                .value = auth_value,
            };
            headers_count = 1;
        }

        const provider_config = policy.ProviderConfig{
            .id = "lambda-http",
            .type = .http,
            .url = policy_url,
            .poll_interval = config.policy.poll_interval,
            .headers = headers_buf[0..headers_count],
        };

        const providers = [_]policy.ProviderConfig{provider_config};
        loader = try policy.Loader.init(
            allocator,
            bus,
            &registry,
            &providers,
            service_metadata,
        );
        try loader.?.startAsync();
    }

    // Create Datadog module configuration
    var datadog_config = DatadogConfig{
        .registry = &registry,
        .bus = bus,
    };

    // Create modules
    var health_module = HealthModule{};
    var datadog_logs_module = DatadogModule{};
    var datadog_metrics_module = DatadogModule{};
    var passthrough_module = PassthroughModule{};

    // Register modules (order matters - first match wins)
    const module_registrations = [_]ModuleRegistration{
        // Health module - reserved /_health endpoint
        .{
            .module = health_module.asProxyModule(),
            .routes = &health_mod.routes,
            .upstream_url = logs_url,
            .max_request_body = 0,
            .max_response_body = 0,
            .module_data = null,
        },
        // Datadog logs module - handles /api/v2/logs with filtering
        .{
            .module = datadog_logs_module.asProxyModule(),
            .routes = &datadog_mod.logs_routes,
            .upstream_url = logs_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&datadog_config),
        },
        // Datadog metrics module - handles /api/v2/series with filtering
        .{
            .module = datadog_metrics_module.asProxyModule(),
            .routes = &datadog_mod.metrics_routes,
            .upstream_url = metrics_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&datadog_config),
        },
        // Passthrough module - handles all other requests
        .{
            .module = passthrough_module.asProxyModule(),
            .routes = &passthrough_mod.default_routes,
            .upstream_url = logs_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = null,
        },
    };

    // Create proxy server
    var proxy = try ProxyServer.init(
        allocator,
        bus,
        config.listen_address,
        config.listen_port,
        config.max_upstream_retries,
        config.max_body_size,
        &module_registrations,
    );
    defer proxy.deinit();

    server_instance = &proxy;
    defer server_instance = null;

    // Start proxy server in background thread
    var server_ctx = ServerThreadContext{
        .proxy = &proxy,
        .bus = bus,
    };
    const server_thread = try std.Thread.spawn(.{}, serverThread, .{&server_ctx});

    // Initialize Lambda Extensions API client
    var extension = try ExtensionClient.init(allocator, bus, "tero-edge");
    defer extension.deinit();

    // Register with Lambda Extensions API
    try extension.register();

    bus.info(LambdaExtensionReady{ .port = config.listen_port });

    // Event loop - poll for Lambda events
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    while (!shutdown_requested.load(.acquire)) {
        // Reset arena for each event
        _ = arena.reset(.retain_capacity);

        const event = extension.nextEvent(arena.allocator()) catch |err| {
            bus.err(LambdaExtensionError{ .err = @errorName(err) });
            continue;
        };

        switch (event) {
            .invoke => |invoke_event| {
                bus.debug(LambdaInvokeReceived{
                    .request_id = invoke_event.request_id,
                });
                // Proxy server handles requests in background
                // Nothing to do here - just continue polling
            },
            .shutdown => |shutdown_event| {
                bus.info(LambdaExtensionShutdown{
                    .reason = @tagName(shutdown_event.reason),
                });

                // Stop proxy server gracefully
                shutdown_requested.store(true, .release);
                proxy.server.stop();
                break;
            },
        }
    }

    // Wait for server thread to finish
    server_thread.join();

    bus.info(ProxyServerStopped{});
}
