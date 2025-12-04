const std = @import("std");
const builtin = @import("builtin");
const proto = @import("proto");
const policy_provider = @import("./provider.zig");
const parser = @import("./parser.zig");
const o11y = @import("../observability/root.zig");

const Policy = proto.policy.Policy;
const PolicyCallback = policy_provider.PolicyCallback;
const EventBus = o11y.EventBus;

const Sha256 = std.crypto.hash.sha2.Sha256;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyError = struct { policy_id: []const u8, message: []const u8 };
const PolicyStats = struct { policy_id: []const u8, hits: i64, misses: i64 };
const PoliciesLoading = struct { path: []const u8 };
const PoliciesLoaded = struct { count: usize, path: []const u8 };
const PoliciesUnchanged = struct { hash: []const u8 };
const FileWatcherError = struct { err: []const u8 };
const FileWatcherUnsupported = struct {};
const PolicyReloadFailed = struct { err: []const u8 };

/// File-based policy provider that watches a config file for changes
pub const FileProvider = struct {
    allocator: std.mem.Allocator,
    /// Unique identifier for this provider
    id: []const u8,
    config_path: []const u8,
    callback: ?PolicyCallback,
    watch_thread: ?std.Thread,
    shutdown_flag: std.atomic.Value(bool),
    /// SHA256 hash of the last loaded file contents
    content_hash: ?[Sha256.digest_length]u8,
    /// Event bus for observability
    bus: *EventBus,

    pub fn init(allocator: std.mem.Allocator, bus: *EventBus, id: []const u8, config_path: []const u8) !*FileProvider {
        const self = try allocator.create(FileProvider);
        errdefer allocator.destroy(self);

        const id_copy = try allocator.dupe(u8, id);
        errdefer allocator.free(id_copy);

        const path_copy = try allocator.dupe(u8, config_path);
        errdefer allocator.free(path_copy);

        self.* = .{
            .allocator = allocator,
            .id = id_copy,
            .config_path = path_copy,
            .callback = null,
            .watch_thread = null,
            .shutdown_flag = std.atomic.Value(bool).init(false),
            .content_hash = null,
            .bus = bus,
        };

        return self;
    }

    /// Get the unique identifier for this provider
    pub fn getId(self: *FileProvider) []const u8 {
        return self.id;
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

        self.allocator.free(self.id);
        self.allocator.free(self.config_path);
        self.allocator.destroy(self);
    }

    /// Report an error encountered when applying a policy.
    /// For file provider, this logs to stderr since there's no remote server to report to.
    pub fn recordPolicyError(self: *FileProvider, policy_id: []const u8, error_message: []const u8) void {
        self.bus.err(PolicyError{ .policy_id = policy_id, .message = error_message });
    }

    /// Report statistics about policy hits and misses.
    /// For file provider, this logs to stdout since there's no remote server to report to.
    pub fn recordPolicyStats(self: *FileProvider, policy_id: []const u8, hits: i64, misses: i64) void {
        self.bus.debug(PolicyStats{ .policy_id = policy_id, .hits = hits, .misses = misses });
    }

    fn loadAndNotify(self: *FileProvider) !void {
        self.bus.info(PoliciesLoading{ .path = self.config_path });

        // Read file contents and compute hash
        const file = try std.fs.cwd().openFile(self.config_path, .{});
        defer file.close();

        const contents = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024); // 10MB max
        defer self.allocator.free(contents);

        var new_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(contents, &new_hash, .{});

        // Check if content has changed
        if (self.content_hash) |old_hash| {
            if (std.mem.eql(u8, &old_hash, &new_hash)) {
                self.bus.debug(PoliciesUnchanged{ .hash = &new_hash });
                return;
            }
        }

        // Update stored hash
        self.content_hash = new_hash;

        const policies = try parser.parsePoliciesBytes(self.allocator, contents);
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
                .provider_id = self.id,
            });
        }

        self.bus.info(PoliciesLoaded{ .count = policies.len, .path = self.config_path });
    }

    fn watchLoop(self: *FileProvider) void {
        if (builtin.os.tag == .linux or builtin.os.tag == .macos) {
            self.watchLoopPoll() catch |err| {
                self.bus.err(FileWatcherError{ .err = @errorName(err) });
            };
        } else {
            self.bus.warn(FileWatcherUnsupported{});
        }
    }

    fn watchLoopPoll(self: *FileProvider) !void {
        var last_mtime: i128 = 0;

        while (!self.shutdown_flag.load(.acquire)) {
            std.Thread.sleep(1 * std.time.ns_per_s); // Check every second

            const file = std.fs.cwd().openFile(self.config_path, .{}) catch continue;
            defer file.close();

            const stat = file.stat() catch continue;

            // Only attempt reload if mtime changed (optimization to avoid reading file every second)
            if (stat.mtime != last_mtime) {
                last_mtime = stat.mtime;
                // loadAndNotify will check content hash and skip if unchanged
                self.loadAndNotify() catch |err| {
                    self.bus.err(PolicyReloadFailed{ .err = @errorName(err) });
                };
            }
        }
    }
};
