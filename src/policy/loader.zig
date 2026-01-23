//! Async Policy Loader
//!
//! Provides shared logic for loading policy providers asynchronously,
//! allowing the server to start responding to requests immediately
//! while policies are loaded in the background.
//!
//! ## Usage
//!
//! ```zig
//! var loader = try PolicyLoader.init(allocator, bus, &registry, config.policy_providers);
//! defer loader.deinit();
//!
//! // Start loading providers asynchronously (non-blocking)
//! try loader.startAsync();
//!
//! // Server can now start handling requests...
//!
//! // Optionally wait for initial load to complete
//! loader.waitForInitialLoad();
//! ```

const std = @import("std");
const policy = @import("./root.zig");
const tripwire = @import("../testing/tripwire.zig");

const Registry = policy.Registry;
const Provider = policy.Provider;
const FileProvider = policy.FileProvider;
const HttpProvider = policy.HttpProvider;
const PolicyCallback = policy.PolicyCallback;
const PolicyUpdate = policy.PolicyUpdate;
const SourceType = policy.SourceType;
const ProviderConfig = policy.ProviderConfig;
const ServiceMetadata = policy.ServiceMetadata;

const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyLoaderStarting = struct { provider_count: usize };
const PolicyLoaderReady = struct { loaded_count: usize, failed_count: usize };
const ProviderLoadStarted = struct { provider_id: []const u8, provider_type: []const u8 };
const ProviderLoadCompleted = struct { provider_id: []const u8, policy_count: usize };
const ProviderLoadFailed = struct { provider_id: []const u8, err: []const u8 };
const FileProviderConfigured = struct { path: []const u8 };
const HttpProviderConfigured = struct { url: []const u8, poll_interval: u64 };
const PolicyRegistryUpdated = struct { provider_id: []const u8, policy_count: usize };

// =============================================================================
// Policy Callback Context
// =============================================================================

const CallbackContext = struct {
    registry: *Registry,
    bus: *EventBus,
    source_type: SourceType,

    fn handleUpdate(context: *anyopaque, update: PolicyUpdate) !void {
        const self: *CallbackContext = @ptrCast(@alignCast(context));
        try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        self.bus.info(PolicyRegistryUpdated{
            .provider_id = update.provider_id,
            .policy_count = update.policies.len,
        });
    }
};

// =============================================================================
// Provider State
// =============================================================================

const ProviderState = struct {
    config: ProviderConfig,
    provider: ?Provider = null,
    callback_context: ?CallbackContext = null,
    load_error: ?[]const u8 = null,
    loaded: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

// =============================================================================
// Policy Loader
// =============================================================================

pub const PolicyLoader = struct {
    allocator: std.mem.Allocator,
    bus: *EventBus,
    registry: *Registry,
    service: ServiceMetadata,

    /// Provider states (one per configured provider)
    provider_states: []ProviderState,

    /// Background loading thread
    load_thread: ?std.Thread = null,

    /// Shutdown flag for clean termination
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Signal when initial load is complete
    initial_load_complete: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Tripwire for testing error paths in init
    pub const init_tw = tripwire.module(enum {
        create_loader,
        alloc_states,
    }, error{OutOfMemory});

    /// Initialize the policy loader with provider configurations.
    /// Does not start loading - call `startAsync()` or `loadSync()` to begin.
    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
        registry: *Registry,
        provider_configs: []const ProviderConfig,
        service: ServiceMetadata,
    ) !*PolicyLoader {
        try init_tw.check(.create_loader);
        const self = try allocator.create(PolicyLoader);
        errdefer allocator.destroy(self);

        // Allocate provider states
        try init_tw.check(.alloc_states);
        const states = try allocator.alloc(ProviderState, provider_configs.len);
        errdefer allocator.free(states);

        for (provider_configs, 0..) |config, i| {
            states[i] = .{ .config = config };
        }

        self.* = .{
            .allocator = allocator,
            .bus = bus,
            .registry = registry,
            .service = service,
            .provider_states = states,
        };

        return self;
    }

    /// Start loading providers asynchronously in a background thread.
    /// Returns immediately, allowing the server to start handling requests.
    pub fn startAsync(self: *PolicyLoader) !void {
        self.bus.info(PolicyLoaderStarting{ .provider_count = self.provider_states.len });
        self.load_thread = try std.Thread.spawn(.{}, loadProvidersThread, .{self});
    }

    /// Load all providers synchronously (blocks until complete).
    /// Use this if you need policies loaded before accepting requests.
    pub fn loadSync(self: *PolicyLoader) void {
        self.bus.info(PolicyLoaderStarting{ .provider_count = self.provider_states.len });
        self.loadAllProviders();
    }

    /// Wait for the initial load to complete.
    /// Call this after `startAsync()` if you need to block until ready.
    pub fn waitForInitialLoad(self: *PolicyLoader) void {
        while (!self.initial_load_complete.load(.acquire)) {
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }
    }

    /// Check if initial load is complete (non-blocking).
    pub fn isReady(self: *PolicyLoader) bool {
        return self.initial_load_complete.load(.acquire);
    }

    /// Get the number of successfully loaded providers.
    pub fn getLoadedCount(self: *PolicyLoader) usize {
        var count: usize = 0;
        for (self.provider_states) |state| {
            if (state.loaded.load(.acquire) and state.load_error == null) {
                count += 1;
            }
        }
        return count;
    }

    /// Get the number of providers that failed to load.
    pub fn getFailedCount(self: *PolicyLoader) usize {
        var count: usize = 0;
        for (self.provider_states) |state| {
            if (state.load_error != null) {
                count += 1;
            }
        }
        return count;
    }

    /// Shutdown all providers and clean up resources.
    pub fn deinit(self: *PolicyLoader) void {
        // Signal shutdown
        self.shutdown_flag.store(true, .release);

        // Wait for load thread to finish
        if (self.load_thread) |thread| {
            thread.join();
            self.load_thread = null;
        }

        // Deinit all providers
        for (self.provider_states) |*state| {
            if (state.provider) |provider| {
                provider.deinit();
            }
            if (state.load_error) |err| {
                self.allocator.free(err);
            }
        }

        self.allocator.free(self.provider_states);
        self.allocator.destroy(self);
    }

    // =========================================================================
    // Private Implementation
    // =========================================================================

    fn loadProvidersThread(self: *PolicyLoader) void {
        self.loadAllProviders();
    }

    fn loadAllProviders(self: *PolicyLoader) void {
        var loaded_count: usize = 0;
        var failed_count: usize = 0;

        for (self.provider_states) |*state| {
            if (self.shutdown_flag.load(.acquire)) break;

            self.loadProvider(state) catch |err| {
                const err_str = self.allocator.dupe(u8, @errorName(err)) catch "allocation_failed";
                state.load_error = err_str;
                self.bus.err(ProviderLoadFailed{
                    .provider_id = state.config.id,
                    .err = err_str,
                });
                failed_count += 1;
                continue;
            };

            loaded_count += 1;
        }

        self.initial_load_complete.store(true, .release);
        self.bus.info(PolicyLoaderReady{
            .loaded_count = loaded_count,
            .failed_count = failed_count,
        });
    }

    fn loadProvider(self: *PolicyLoader, state: *ProviderState) !void {
        const config = state.config;
        const provider_type_str = switch (config.type) {
            .file => "file",
            .http => "http",
        };

        self.bus.debug(ProviderLoadStarted{
            .provider_id = config.id,
            .provider_type = provider_type_str,
        });

        switch (config.type) {
            .file => {
                const path = config.path orelse return error.FileProviderRequiresPath;
                self.bus.info(FileProviderConfigured{ .path = path });

                const file_provider = try FileProvider.init(
                    self.allocator,
                    self.bus,
                    config.id,
                    path,
                );
                errdefer file_provider.deinit();

                // Set up callback context
                state.callback_context = .{
                    .registry = self.registry,
                    .bus = self.bus,
                    .source_type = .file,
                };

                const callback = PolicyCallback{
                    .context = @ptrCast(&state.callback_context.?),
                    .onUpdate = CallbackContext.handleUpdate,
                };

                try file_provider.subscribe(callback);

                // Store provider interface
                state.provider = Provider.init(file_provider);
                try self.registry.registerProvider(&state.provider.?);
                state.loaded.store(true, .release);

                self.bus.debug(ProviderLoadCompleted{
                    .provider_id = config.id,
                    .policy_count = self.registry.getPolicyCount(),
                });
            },
            .http => {
                const url = config.url orelse return error.HttpProviderRequiresUrl;
                const poll_interval = config.poll_interval orelse 60;
                self.bus.info(HttpProviderConfigured{ .url = url, .poll_interval = poll_interval });

                const http_provider = try HttpProvider.init(
                    self.allocator,
                    self.bus,
                    config.id,
                    url,
                    poll_interval,
                    self.service,
                    config.headers,
                );
                errdefer http_provider.deinit();

                // Set up callback context
                state.callback_context = .{
                    .registry = self.registry,
                    .bus = self.bus,
                    .source_type = .http,
                };

                const callback = PolicyCallback{
                    .context = @ptrCast(&state.callback_context.?),
                    .onUpdate = CallbackContext.handleUpdate,
                };

                try http_provider.subscribe(callback);

                // Store provider interface
                state.provider = Provider.init(http_provider);
                try self.registry.registerProvider(&state.provider.?);
                state.loaded.store(true, .release);

                self.bus.debug(ProviderLoadCompleted{
                    .provider_id = config.id,
                    .policy_count = self.registry.getPolicyCount(),
                });
            },
        }
    }
};

// =============================================================================
// Tests
// =============================================================================

test "PolicyLoader: init and deinit" {
    const allocator = std.testing.allocator;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    var registry = Registry.init(allocator, bus);
    defer registry.deinit();

    const configs = [_]ProviderConfig{};

    var loader = try PolicyLoader.init(
        allocator,
        bus,
        &registry,
        &configs,
        .{
            .namespace = "test",
            .name = "test-service",
            .instance_id = "test-instance",
            .version = "1.0.0",
        },
    );
    defer loader.deinit();

    try std.testing.expect(!loader.isReady());
    try std.testing.expectEqual(@as(usize, 0), loader.getLoadedCount());
}

// -----------------------------------------------------------------------------
// Tripwire Tests for PolicyLoader.init
// -----------------------------------------------------------------------------

test "PolicyLoader.init: tripwire create_loader fails" {
    const allocator = std.testing.allocator;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    var registry = Registry.init(allocator, bus);
    defer registry.deinit();

    PolicyLoader.init_tw.errorAlways(.create_loader, error.OutOfMemory);
    defer PolicyLoader.init_tw.reset();

    const result = PolicyLoader.init(
        allocator,
        bus,
        &registry,
        &.{},
        .{
            .namespace = "test",
            .name = "test-service",
            .instance_id = "test-instance",
            .version = "1.0.0",
        },
    );

    try std.testing.expectError(error.OutOfMemory, result);
    try PolicyLoader.init_tw.end(.retain);
}

test "PolicyLoader.init: tripwire alloc_states fails" {
    const allocator = std.testing.allocator;

    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    const bus = stdio_bus.eventBus();

    var registry = Registry.init(allocator, bus);
    defer registry.deinit();

    const configs = [_]ProviderConfig{
        .{ .id = "test", .type = .file, .path = "/test.json" },
    };

    PolicyLoader.init_tw.errorAlways(.alloc_states, error.OutOfMemory);
    defer PolicyLoader.init_tw.reset();

    const result = PolicyLoader.init(
        allocator,
        bus,
        &registry,
        &configs,
        .{
            .namespace = "test",
            .name = "test-service",
            .instance_id = "test-instance",
            .version = "1.0.0",
        },
    );

    try std.testing.expectError(error.OutOfMemory, result);
    try PolicyLoader.init_tw.end(.retain);
}
