//! Datadog Distribution Entry Point
//!
//! A focused edge proxy distribution for Datadog log ingestion with filtering.
//! Handles /api/v2/logs with policy-based filtering, passes all other requests through.
//!
//! Features:
//! - Policy-based log filtering (DROP/KEEP actions)
//! - Fail-open behavior (errors pass logs through unchanged)
//! - Thread-safe, stateless request processing
//! - Lock-free policy updates via atomic snapshots
//! - Graceful shutdown with signal handling

const std = @import("std");
const builtin = @import("builtin");

const edge = @import("root.zig");
const config_parser = edge.config_parser;
const server_mod = edge.server;
const proxy_module = edge.proxy_module;
const passthrough_mod = edge.passthrough_module;
const datadog_mod = edge.datadog_module;
const policy = edge.policy;

const o11y = @import("observability/root.zig");
const EventBus = o11y.EventBus;
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const ProxyServer = server_mod.ProxyServer;
const ModuleRegistration = proxy_module.ModuleRegistration;
const PassthroughModule = passthrough_mod.PassthroughModule;
const DatadogModule = datadog_mod.DatadogModule;
const DatadogConfig = datadog_mod.DatadogConfig;

/// Route std.log through our EventBus adapter
pub const std_options: std.Options = .{
    .log_level = .debug, // Allow all levels through, EventBus will filter
    .logFn = StdLogAdapter.logFn,
};

// =============================================================================
// Observability Events
// =============================================================================

const ShutdownSignalReceived = struct {};
const SignalHandlersInstalled = struct {};
const SignalHandlingNotSupported = struct { platform: []const u8 };

const PolicyRegistryUpdated = struct {
    provider_id: []const u8,
    policy_count: usize,
};

const ServerStarting = struct {};
const ConfigurationLoaded = struct { path: []const u8 };
const ListenAddressConfigured = struct {
    address: []const u8,
    port: u16,
};
const UpstreamConfigured = struct { url: []const u8 };
const ServiceConfigured = struct {
    namespace: []const u8,
    name: []const u8,
    instance_id: []const u8,
    version: []const u8,
};

const PolicyProvidersInitializing = struct { count: usize };
const FileProviderConfigured = struct { path: []const u8 };
const HttpProviderConfigured = struct {
    url: []const u8,
    poll_interval: u64,
};
const PolicyCountLoaded = struct { count: usize };

const ServerReady = struct {};
const ShutdownHint = struct { pid: c_int };
const ServerStopped = struct {};
const ServerError = struct { message: anyerror };

// =============================================================================
// Global state for signal handlers
// =============================================================================

var server_instance: ?*ProxyServer = null;
var global_event_bus: ?*EventBus = null;

fn handleShutdownSignal(sig: c_int) callconv(.c) void {
    _ = sig;
    if (global_event_bus) |bus| {
        bus.info(ShutdownSignalReceived{});
    }

    // Stop the server - this unblocks the main thread
    // Provider cleanup happens in the defer blocks of main()
    if (server_instance) |server| {
        server_instance = null;
        server.server.stop();
    }
}

fn handleSegfault(sig: c_int, info: *const std.posix.siginfo_t, ctx_ptr: ?*anyopaque) callconv(.c) noreturn {
    _ = sig;
    _ = ctx_ptr;

    std.debug.print("\n=== SEGFAULT ===\n", .{});

    // Get faulting address - field layout differs between Linux and macOS
    const fault_addr: usize = switch (builtin.os.tag) {
        .macos => @intFromPtr(info.addr),
        .linux => @intFromPtr(info.fields.sigfault.addr),
        else => 0,
    };
    std.debug.print("Faulting address: 0x{x}\n", .{fault_addr});
    std.debug.print("Signal code: {d}\n", .{info.code});
    std.debug.print("Stack trace:\n", .{});
    std.debug.dumpCurrentStackTrace(@returnAddress());

    std.posix.abort();
}

fn installShutdownHandlers(bus: *EventBus) void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        bus.warn(SignalHandlingNotSupported{ .platform = @tagName(builtin.os.tag) });
        return;
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdownSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // Install SIGSEGV handler to capture crash info
    const segv_act = std.posix.Sigaction{
        .handler = .{ .sigaction = handleSegfault },
        .mask = std.posix.sigemptyset(),
        .flags = std.posix.SA.SIGINFO,
    };
    std.posix.sigaction(std.posix.SIG.SEGV, &segv_act, null);

    bus.debug(SignalHandlersInstalled{});
}

// =============================================================================
// Policy callback
// =============================================================================

const SourceType = policy.SourceType;

const PolicyCallbackContext = struct {
    registry: *policy.Registry,
    bus: *EventBus,
    source_type: SourceType,

    fn handleUpdate(context: *anyopaque, update: policy.PolicyUpdate) !void {
        const self: *PolicyCallbackContext = @ptrCast(@alignCast(context));
        try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        self.bus.info(PolicyRegistryUpdated{
            .provider_id = update.provider_id,
            .policy_count = update.policies.len,
        });
    }
};

// =============================================================================
// Main entry point
// =============================================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    // var dbg_allo: std.heap.DebugAllocator(.{
    //     .never_unmap = true,
    //     .retain_metadata = true,
    //     .safety = true,
    // }) = .{};
    // defer _ = dbg_allo.deinit();

    // const allocator = dbg_allo.allocator();

    // Initialize observability with log level from environment
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    // Parse TERO_LOG_LEVEL env var (defaults to info)
    bus.setLevel(Level.parseFromEnv("TERO_LOG_LEVEL", .info));

    // Initialize std.log adapter to route through EventBus
    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    // Set global event bus for signal handler
    global_event_bus = bus;
    defer global_event_bus = null;

    // Parse command line arguments
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    _ = args.next(); // Skip program name
    const config_path = args.next() orelse "config.json";

    bus.info(ServerStarting{});
    bus.info(ConfigurationLoaded{ .path = config_path });

    // Parse configuration
    const config = try config_parser.parseConfigFile(allocator, config_path);
    defer {
        allocator.free(config.upstream_url);
        allocator.free(config.workspace_id);
        for (config.policy_providers) |provider_config| {
            allocator.free(provider_config.id);
            if (provider_config.path) |path| allocator.free(path);
            if (provider_config.url) |url| allocator.free(url);
            for (provider_config.headers) |header| {
                allocator.free(header.name);
                allocator.free(header.value);
            }
            if (provider_config.headers.len > 0) {
                allocator.free(provider_config.headers);
            }
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

    // Format listen address for logging
    var addr_buf: [64]u8 = undefined;
    const addr_str = try std.fmt.bufPrint(&addr_buf, "{}.{}.{}.{}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
    });

    bus.info(ListenAddressConfigured{ .address = addr_str, .port = config.listen_port });
    bus.info(UpstreamConfigured{ .url = config.upstream_url });
    bus.info(ServiceConfigured{
        .namespace = config.service.namespace,
        .name = config.service.name,
        .instance_id = config.service.instance_id,
        .version = config.service.version,
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

    bus.info(PolicyProvidersInitializing{ .count = config.policy_providers.len });
    for (config.policy_providers) |provider_config| {
        switch (provider_config.type) {
            .file => {
                const path = provider_config.path orelse return error.FileProviderRequiresPath;
                bus.info(FileProviderConfigured{ .path = path });

                const file_provider = try policy.FileProvider.init(allocator, bus, provider_config.id, path);
                errdefer file_provider.deinit();

                // Create callback context with source type
                try callback_contexts.append(allocator, .{ .registry = &registry, .bus = bus, .source_type = .file });
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
                bus.info(HttpProviderConfigured{ .url = url, .poll_interval = poll_interval });

                const http_provider = try policy.HttpProvider.init(
                    allocator,
                    bus,
                    provider_config.id,
                    url,
                    poll_interval,
                    config.workspace_id,
                    config.service,
                    provider_config.headers,
                );
                errdefer http_provider.deinit();

                // Create callback context with source type
                try callback_contexts.append(allocator, .{ .registry = &registry, .bus = bus, .source_type = .http });
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

    bus.info(PolicyCountLoaded{ .count = registry.getPolicyCount() });

    // Install signal handlers
    installShutdownHandlers(bus);

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
        std.heap.page_allocator,
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

    bus.info(ServerReady{});
    if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
        bus.info(ShutdownHint{ .pid = std.c.getpid() });
    }

    // Start listening (blocks until server.stop() is called)
    proxy.listen() catch |err| {
        bus.err(ServerError{ .message = err });
    };

    bus.info(ServerStopped{});
}
