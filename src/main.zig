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
const proxy_module = @import("modules/proxy_module.zig");
const passthrough_mod = @import("modules/passthrough_module.zig");
const datadog_mod = @import("modules/datadog_module.zig");
const otlp_mod = @import("modules/otlp_module.zig");
const policy = @import("policy/root.zig");

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PassthroughModule = passthrough_mod.PassthroughModule;
const DatadogModule = datadog_mod.DatadogModule;
const DatadogConfig = datadog_mod.DatadogConfig;
const OtlpModule = otlp_mod.OtlpModule;
const OtlpConfig = otlp_mod.OtlpConfig;

/// Global server instance for signal handler
var server_instance: ?*ProxyServer = null;

/// Signal handler for graceful shutdown
fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    std.log.info("Shutdown signal received, stopping server...", .{});

    // Stop the server - this unblocks the main thread
    // Provider cleanup happens in the defer blocks of main()
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

const SourceType = policy.SourceType;

/// Context for policy update callback
const PolicyCallbackContext = struct {
    registry: *policy.Registry,
    source_type: SourceType,

    fn handleUpdate(context: *anyopaque, update: policy.PolicyUpdate) !void {
        const self: *PolicyCallbackContext = @ptrCast(@alignCast(context));
        try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        std.log.info("Policy registry updated from provider '{s}' with {} policies", .{
            update.provider_id,
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
    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    // Storage for PolicyProvider interfaces
    var providers: std.ArrayList(policy.Provider) = .empty;
    defer {
        for (providers.items) |provider| {
            provider.deinit();
        }
        providers.deinit(allocator);
    }

    // Storage for callback contexts (need to persist for lifetime of providers)
    var callback_contexts: std.ArrayList(PolicyCallbackContext) = .empty;
    defer callback_contexts.deinit(allocator);

    std.log.info("Initializing {} policy provider(s)...", .{config.policy_providers.len});
    for (config.policy_providers) |provider_config| {
        switch (provider_config.type) {
            .file => {
                const path = provider_config.path orelse return error.FileProviderRequiresPath;
                std.log.info("  - File provider '{s}': {s}", .{ provider_config.id, path });

                const file_provider = try policy.FileProvider.init(allocator, bus, provider_config.id, path);
                errdefer file_provider.deinit();

                // Create callback context with source type
                try callback_contexts.append(allocator, .{ .registry = &registry, .source_type = .file });
                const callback = policy.PolicyCallback{
                    .context = @ptrCast(&callback_contexts.items[callback_contexts.items.len - 1]),
                    .onUpdate = PolicyCallbackContext.handleUpdate,
                };

                try file_provider.subscribe(callback);

                // Store provider interface for cleanup and registry routing
                const provider_interface = policy.Provider.init(file_provider);
                try providers.append(allocator, provider_interface);
                try registry.registerProvider(&providers.items[providers.items.len - 1]);
            },
            .http => {
                const url = provider_config.url orelse return error.HttpProviderRequiresUrl;
                const poll_interval = provider_config.poll_interval orelse 60;
                std.log.info("  - HTTP provider '{s}': {s} (poll interval: {}s)", .{ provider_config.id, url, poll_interval });

                const http_provider = try policy.HttpProvider.init(
                    allocator,
                    bus,
                    provider_config.id,
                    url,
                    poll_interval,
                    config.workspace_id,
                    config.service,
                );
                errdefer http_provider.deinit();

                // Create callback context with source type
                try callback_contexts.append(allocator, .{ .registry = &registry, .source_type = .http });
                const callback = policy.PolicyCallback{
                    .context = @ptrCast(&callback_contexts.items[callback_contexts.items.len - 1]),
                    .onUpdate = PolicyCallbackContext.handleUpdate,
                };

                try http_provider.subscribe(callback);

                // Store provider interface for cleanup and registry routing
                const provider_interface = policy.Provider.init(http_provider);
                try providers.append(allocator, provider_interface);
                try registry.registerProvider(&providers.items[providers.items.len - 1]);
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

    // Create OTLP module configuration
    var otlp_config = OtlpConfig{
        .registry = &registry,
        .bus = bus,
    };

    // Create modules
    var datadog_module = DatadogModule{};
    var otlp_module = OtlpModule{};
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
        // OTLP module - handles /api/v2/logs with filtering
        .{
            .module = otlp_module.asProxyModule(),
            .routes = &otlp_mod.routes,
            .upstream_url = config.upstream_url,
            .max_request_body = config.max_body_size,
            .max_response_body = config.max_body_size,
            .module_data = @ptrCast(&otlp_config),
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
        config.max_upstream_retries,
        config.max_body_size,
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
