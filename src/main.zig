const std = @import("std");
const builtin = @import("builtin");
const observability = @import("observability/root.zig");
const StdLogAdapter = observability.StdLogAdapter;
const Level = observability.Level;

/// Route std.log through our EventBus adapter
pub const std_options: std.Options = .{
    .log_level = .debug, // Allow all levels through, EventBus will filter
    .logFn = StdLogAdapter.logFn,
};

const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const server_mod = @import("proxy/server.zig");
const proxy_module = @import("core/proxy_module.zig");
const passthrough_mod = @import("modules/passthrough/module.zig");
const datadog_mod = @import("modules/datadog/module.zig");
const policy_registry_mod = @import("./core/policy_registry.zig");
const policy_provider = @import("./core/policy_provider.zig");
const FileProvider = @import("config/providers/file_provider.zig").FileProvider;
const HttpProvider = @import("config/providers/http_provider.zig").HttpProvider;

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PassthroughModule = passthrough_mod.PassthroughModule;
const DatadogModule = datadog_mod.DatadogModule;
const DatadogConfig = datadog_mod.DatadogConfig;

/// Global server instance for signal handler
var server_instance: ?*ProxyServer = null;

/// Global provider lists for signal handler
var global_file_providers: ?*std.ArrayList(*FileProvider) = null;
var global_http_providers: ?*std.ArrayList(*HttpProvider) = null;

/// Signal handler for graceful shutdown
fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    std.log.info("Shutdown signal received, stopping server...", .{});

    // Shutdown all providers first
    if (global_file_providers) |providers| {
        for (providers.items) |provider| {
            provider.shutdown();
        }
    }
    if (global_http_providers) |providers| {
        for (providers.items) |provider| {
            provider.shutdown();
        }
    }

    // Then stop the server
    if (server_instance) |server| {
        server_instance = null;
        server.server.stop();
    }
}

/// Install SIGINT and SIGTERM handlers
fn installShutdownHandlers() void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        std.log.warn("Signal handling not supported on this platform", .{});
        return;
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    std.log.debug("Installed signal handlers for SIGINT and SIGTERM", .{});
}

/// Context for policy update callback
const PolicyCallbackContext = struct {
    registry: *policy_registry_mod.PolicyRegistry,

    fn handleUpdate(context: *anyopaque, update: policy_provider.PolicyUpdate) !void {
        const self: *PolicyCallbackContext = @ptrCast(@alignCast(context));
        try self.registry.updatePolicies(update.policies, update.source);
        std.log.info("Policy registry updated from {s} source with {} policies", .{
            @tagName(update.source),
            update.policies.len,
        });
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize observability with log level from environment
    var stdio_bus: observability.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    // Parse TERO_LOG_LEVEL env var (defaults to info)
    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    // Initialize std.log adapter to route through EventBus
    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name

    const config_path = args.next() orelse "config.json";

    std.log.info("Tero Edge HTTP Proxy starting...", .{});
    std.log.info("Configuration file: {s}", .{config_path});

    // Parse configuration
    const config = try config_parser.parseConfigFile(allocator, config_path);
    defer {
        allocator.free(config.upstream_url);
        allocator.free(config.workspace_id);
        // Free policy providers
        for (config.policy_providers) |provider_config| {
            allocator.free(provider_config.id);
            if (provider_config.path) |path| allocator.free(path);
            if (provider_config.url) |url| allocator.free(url);
        }
        allocator.free(config.policy_providers);
        allocator.destroy(config);
    }

    // Generate service instance ID (UUID-like identifier for this instance's lifetime)
    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "edge-{d}-{d}", .{
        std.time.milliTimestamp(),
        std.Thread.getCurrentId(),
    });
    const instance_id_copy = try allocator.dupe(u8, instance_id);
    defer allocator.free(instance_id_copy);

    // Set the instance_id in service metadata
    config.service.instance_id = instance_id_copy;

    std.log.info("Listen address: {}.{}.{}.{}:{}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
        config.listen_port,
    });
    std.log.info("Upstream URL: {s}", .{config.upstream_url});
    std.log.info("Service: {s}/{s} (instance: {s}, version: {s})", .{
        config.service.namespace,
        config.service.name,
        config.service.instance_id,
        config.service.version,
    });

    // Create centralized policy registry
    var registry = policy_registry_mod.PolicyRegistry.init(allocator, bus);
    defer registry.deinit();

    // Create callback context for policy updates
    var callback_context = PolicyCallbackContext{ .registry = &registry };
    const callback = policy_provider.PolicyCallback{
        .context = @ptrCast(&callback_context),
        .onUpdate = PolicyCallbackContext.handleUpdate,
    };

    // Initialize providers from config (keep pointers for cleanup)
    var file_providers: std.ArrayList(*FileProvider) = .empty;
    defer {
        for (file_providers.items) |provider| {
            provider.deinit();
        }
        file_providers.deinit(allocator);
    }

    var http_providers: std.ArrayList(*HttpProvider) = .empty;
    defer {
        for (http_providers.items) |provider| {
            provider.deinit();
        }
        http_providers.deinit(allocator);
    }

    // Set global provider references for signal handler
    global_file_providers = &file_providers;
    global_http_providers = &http_providers;
    defer {
        global_file_providers = null;
        global_http_providers = null;
    }

    std.log.info("Initializing {} policy provider(s)...", .{config.policy_providers.len});
    for (config.policy_providers) |provider_config| {
        switch (provider_config.type) {
            .file => {
                const path = provider_config.path orelse return error.FileProviderRequiresPath;
                std.log.info("  - File provider: {s}", .{path});

                const file_provider = try FileProvider.init(allocator, bus, path);
                errdefer file_provider.deinit();

                try file_provider.subscribe(callback);
                try file_providers.append(allocator, file_provider);
            },
            .http => {
                const url = provider_config.url orelse return error.HttpProviderRequiresUrl;
                const poll_interval = provider_config.poll_interval orelse 60;
                std.log.info("  - HTTP provider: {s} (poll interval: {}s)", .{ url, poll_interval });

                const http_provider = try HttpProvider.init(
                    allocator,
                    bus,
                    url,
                    poll_interval,
                    config.workspace_id,
                    config.service,
                );
                errdefer http_provider.deinit();

                try http_provider.subscribe(callback);
                try http_providers.append(allocator, http_provider);
            },
        }
    }

    std.log.info("Policy count: {}", .{registry.getPolicyCount()});

    // Install signal handlers
    installShutdownHandlers();

    // Create Datadog module configuration
    var datadog_config = DatadogConfig{
        .registry = &registry,
        .bus = bus,
    };

    // Create modules
    var datadog_module = DatadogModule{};
    var passthrough_module = PassthroughModule{};

    // Register modules (order matters - first match wins)
    const module_registrations = [_]ModuleRegistration{
        // Datadog module - handles /api/v2/logs with filtering
        .{
            .module = datadog_module.asProxyModule(),
            .routes = &datadog_mod.routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&datadog_config),
        },
        // Passthrough module - handles all other requests
        .{
            .module = passthrough_module.asProxyModule(),
            .routes = &passthrough_mod.default_routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = null,
        },
    };

    // Create proxy server with modules
    var proxy = try ProxyServer.init(
        allocator,
        bus,
        config.listen_address,
        config.listen_port,
        &module_registrations,
    );
    defer proxy.deinit();

    // Set global server instance for signal handler
    server_instance = &proxy;
    defer server_instance = null;

    std.log.info("Proxy ready. Waiting for connections...", .{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        std.log.info("To shutdown: kill -s INT {d}", .{std.c.getpid()});
    }

    // Start listening (blocks until server.stop() is called)
    try proxy.listen();

    std.log.info("Server stopped gracefully.", .{});
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
