const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const parser = @import("parser.zig");

pub const ConfigManager = struct {
    current: std.atomic.Value(*const types.ProxyConfig),
    allocator: std.mem.Allocator,
    config_path: []const u8,
    watch_thread: ?std.Thread,
    shutdown: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config_path: []const u8) !ConfigManager {
        const initial_config = try parser.parseConfigFile(allocator, config_path);

        const path_copy = try allocator.dupe(u8, config_path);

        return .{
            .current = std.atomic.Value(*const types.ProxyConfig).init(initial_config),
            .allocator = allocator,
            .config_path = path_copy,
            .watch_thread = null,
            .shutdown = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *ConfigManager) void {
        self.shutdown.store(true, .release);

        if (self.watch_thread) |thread| {
            thread.join();
        }

        const config = self.current.load(.acquire);

        // Free policy resources
        for (config.policies) |policy| {
            self.allocator.free(policy.name);
            for (policy.regexes) |regex| {
                self.allocator.free(regex);
            }
            self.allocator.free(policy.regexes);
        }
        self.allocator.free(config.policies);

        // Free the upstream_url string that was allocated in the parser
        self.allocator.free(config.upstream_url);
        self.allocator.destroy(config);
        self.allocator.free(self.config_path);
    }

    pub fn get(self: *const ConfigManager) *const types.ProxyConfig {
        return self.current.load(.acquire);
    }

    pub fn reload(self: *ConfigManager) !void {
        std.log.info("Reloading configuration from {s}...", .{self.config_path});

        const new_config = parser.parseConfigFile(self.allocator, self.config_path) catch |err| {
            std.log.err("Failed to parse new config: {}", .{err});
            return err;
        };

        const old_config = self.current.swap(new_config, .acq_rel);

        // TODO: Defer cleanup after grace period
        // For now, we leak the old config to avoid use-after-free
        // A production implementation would use RCU or ref counting
        _ = old_config;

        std.log.info("Configuration reloaded successfully", .{});
    }

    pub fn startWatching(self: *ConfigManager) !void {
        self.watch_thread = try std.Thread.spawn(.{}, watchLoop, .{self});
    }

    fn watchLoop(self: *ConfigManager) void {
        if (builtin.os.tag == .linux) {
            self.watchLoopLinux() catch |err| {
                std.log.err("Config watcher error: {}", .{err});
            };
        } else if (builtin.os.tag == .macos) {
            self.watchLoopPoll() catch |err| {
                std.log.err("Config watcher error: {}", .{err});
            };
        } else {
            self.watchLoopPoll() catch |err| {
                std.log.err("Config watcher error: {}", .{err});
            };
        }
    }

    fn watchLoopLinux(self: *ConfigManager) !void {
        // For now, use polling as inotify setup is complex
        return self.watchLoopPoll();
    }

    fn watchLoopPoll(self: *ConfigManager) !void {
        var last_mtime: i128 = 0;

        while (!self.shutdown.load(.acquire)) {
            std.Thread.sleep(1 * std.time.ns_per_s); // Check every second

            const file = std.fs.cwd().openFile(self.config_path, .{}) catch continue;
            defer file.close();

            const stat = file.stat() catch continue;

            if (stat.mtime != last_mtime and last_mtime != 0) {
                std.log.info("Config file modified, reloading...", .{});
                self.reload() catch |err| {
                    std.log.err("Failed to reload config: {}", .{err});
                };
            }

            last_mtime = stat.mtime;
        }
    }
};

/// Install signal handler for SIGHUP
pub fn installSignalHandler(config_manager: *ConfigManager) !void {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) {
        return; // Signal handling not supported on this platform
    }

    const Handler = struct {
        var manager: *ConfigManager = undefined;

        fn handleSighup(sig: c_int) callconv(.c) void {
            _ = sig;
            std.log.info("Received SIGHUP, reloading config...", .{});
            manager.reload() catch |err| {
                std.log.err("Failed to reload config: {}", .{err});
            };
        }
    };

    Handler.manager = config_manager;

    const act = std.posix.Sigaction{
        .handler = .{ .handler = Handler.handleSighup },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.HUP, &act, null);
}
