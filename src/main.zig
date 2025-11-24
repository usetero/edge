const std = @import("std");
const builtin = @import("builtin");
const config_types = @import("config/types.zig");
const config_parser = @import("config/parser.zig");
const httpz_server = @import("proxy/httpz_server.zig");
const filter_mod = @import("core/filter.zig");
const policy_registry_mod = @import("core/policy_registry.zig");
const policy_provider = @import("core/policy_provider.zig");
const FileProvider = @import("config/providers/file_provider.zig").FileProvider;
const HttpProvider = @import("config/providers/http_provider.zig").HttpProvider;

/// Global server instance for signal handler
var server_instance: ?*httpz_server.HttpzProxyServer = null;

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
        // Free policy providers
        for (config.policy_providers) |provider_config| {
            if (provider_config.path) |path| allocator.free(path);
            if (provider_config.url) |url| allocator.free(url);
        }
        allocator.free(config.policy_providers);
        // Free deprecated policies if present
        for (config.policies) |policy| {
            allocator.free(policy.name);
            for (policy.regexes.items) |regex| allocator.free(regex);
            // Cast away const to free the ArrayListUnmanaged
            var regexes_mut = @constCast(&policy.regexes);
            regexes_mut.deinit(allocator);
        }
        allocator.free(config.policies);
        allocator.destroy(config);
    }

    std.log.info("Listen address: {}.{}.{}.{}:{}", .{
        config.listen_address[0],
        config.listen_address[1],
        config.listen_address[2],
        config.listen_address[3],
        config.listen_port,
    });
    std.log.info("Upstream URL: {s}", .{config.upstream_url});

    // Create centralized policy registry
    var registry = policy_registry_mod.PolicyRegistry.init(allocator);
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

                const file_provider = try FileProvider.init(allocator, path);
                errdefer file_provider.deinit();

                try file_provider.subscribe(callback);
                try file_providers.append(allocator, file_provider);
            },
            .http => {
                const url = provider_config.url orelse return error.HttpProviderRequiresUrl;
                const poll_interval = provider_config.poll_interval orelse 60;
                std.log.info("  - HTTP provider: {s} (poll interval: {}s)", .{ url, poll_interval });

                const http_provider = try HttpProvider.init(allocator, url, poll_interval);
                errdefer http_provider.deinit();

                try http_provider.subscribe(callback);
                try http_providers.append(allocator, http_provider);
            },
        }
    }

    std.log.info("Policy count: {}", .{registry.getPolicyCount()});

    // Create filter evaluator with reference to registry
    var filter_evaluator = filter_mod.FilterEvaluator.init(&registry);
    defer filter_evaluator.deinit();

    // Install signal handlers
    installShutdownHandlers();

    // Create httpz proxy server
    var proxy = try httpz_server.HttpzProxyServer.init(
        allocator,
        config,
        &filter_evaluator,
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
