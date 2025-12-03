const std = @import("std");
const builtin = @import("builtin");
const proto = @import("proto");
const policy_provider = @import("../../core/policy_provider.zig");
const policy_source = @import("../../core/policy_source.zig");
const parser = @import("../parser.zig");

const Policy = proto.policy.Policy;
const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;
const SourceType = policy_source.SourceType;

/// File-based policy provider that watches a config file for changes
pub const FileProvider = struct {
    allocator: std.mem.Allocator,
    config_path: []const u8,
    callback: ?PolicyCallback,
    watch_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config_path: []const u8) !*FileProvider {
        const self = try allocator.create(FileProvider);
        errdefer allocator.destroy(self);

        const path_copy = try allocator.dupe(u8, config_path);
        errdefer allocator.free(path_copy);

        self.* = .{
            .allocator = allocator,
            .config_path = path_copy,
            .callback = null,
            .watch_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
        };

        return self;
    }

    pub fn subscribe(self: *FileProvider, callback: PolicyCallback) !void {
        self.callback = callback;

        // Initial load and notify
        try self.loadAndNotify();

        // Start watching for changes
        self.watch_thread = try std.Thread.spawn(.{}, watchLoop, .{self});
    }

    pub fn shutdown(self: *FileProvider) void {
        self.shutdown_flag.store(true, .release);

        if (self.watch_thread) |thread| {
            thread.join();
            self.watch_thread = null;
        }
    }

    pub fn deinit(self: *FileProvider) void {
        // Ensure shutdown is called first
        self.shutdown();

        self.allocator.free(self.config_path);
        self.allocator.destroy(self);
    }

    /// Report an error encountered when applying a policy.
    /// For file provider, this logs to stderr since there's no remote server to report to.
    pub fn recordPolicyError(self: *FileProvider, policy_id: []const u8, error_message: []const u8) void {
        _ = self;
        std.log.err("Policy error [{s}]: {s}", .{ policy_id, error_message });
    }

    fn loadAndNotify(self: *FileProvider) !void {
        std.log.info("Loading policies from file: {s}", .{self.config_path});

        const policies = try parser.parsePoliciesFile(self.allocator, self.config_path);
        defer {
            // Registry duplicates policies, so we must free our parsed copies
            for (policies) |*policy| {
                @constCast(policy).deinit(self.allocator);
            }
            self.allocator.free(policies);
        }

        if (self.callback) |cb| {
            try cb.call(.{
                .policies = policies,
                .source = .file,
            });
        }

        std.log.info("Loaded {} policies from {s}", .{ policies.len, self.config_path });
    }

    fn watchLoop(self: *FileProvider) void {
        if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
            self.watchLoopPoll() catch |err| {
                std.log.err("File watcher error: {}", .{err});
            };
        } else {
            std.log.warn("File watching not supported on this platform", .{});
        }
    }

    fn watchLoopPoll(self: *FileProvider) !void {
        var last_mtime: i128 = 0;

        while (!self.shutdown_flag.load(.acquire)) {
            std.Thread.sleep(1 * std.time.ns_per_s); // Check every second

            const file = std.fs.cwd().openFile(self.config_path, .{}) catch continue;
            defer file.close();

            const stat = file.stat() catch continue;

            if (stat.mtime != last_mtime and last_mtime != 0) {
                std.log.info("Config file modified, reloading policies from {s}", .{self.config_path});
                self.loadAndNotify() catch |err| {
                    std.log.err("Failed to reload policies: {}", .{err});
                };
            }

            last_mtime = stat.mtime;
        }
    }
};
