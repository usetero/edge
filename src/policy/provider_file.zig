const std = @import("std");
const builtin = @import("builtin");
const proto = @import("proto");
const policy_provider = @import("./provider.zig");
const parser = @import("./parser.zig");
const o11y = @import("../observability/root.zig");
const tripwire = @import("../testing/tripwire.zig");

const Policy = proto.policy.Policy;
const PolicyCallback = policy_provider.PolicyCallback;
const EventBus = o11y.EventBus;

const Sha256 = std.crypto.hash.sha2.Sha256;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyError = struct { policy_id: []const u8, message: []const u8 };
const TransformResult = policy_provider.TransformResult;
const PolicyStats = struct {
    policy_id: []const u8,
    hits: i64,
    misses: i64,
    transform_result: TransformResult,
};
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

    /// Tripwire for testing error paths in init
    pub const init_tw = tripwire.module(enum {
        create_provider,
        dupe_id,
        dupe_path,
    }, error{OutOfMemory});

    pub fn init(allocator: std.mem.Allocator, bus: *EventBus, id: []const u8, config_path: []const u8) !*FileProvider {
        try init_tw.check(.create_provider);
        const self = try allocator.create(FileProvider);
        errdefer allocator.destroy(self);

        try init_tw.check(.dupe_id);
        const id_copy = try allocator.dupe(u8, id);
        errdefer allocator.free(id_copy);

        try init_tw.check(.dupe_path);
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

    /// Report statistics about policy hits, misses, and transform results.
    /// For file provider, this logs to stdout since there's no remote server to report to.
    pub fn recordPolicyStats(self: *FileProvider, policy_id: []const u8, hits: i64, misses: i64, transform_result: TransformResult) void {
        self.bus.debug(PolicyStats{ .policy_id = policy_id, .hits = hits, .misses = misses, .transform_result = transform_result });
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

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const Registry = @import("./registry.zig").PolicyRegistry;
const NoopEventBus = o11y.NoopEventBus;

test "FileProvider: init and deinit" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "test-provider",
        "/nonexistent/path/policies.json",
    );
    defer provider.deinit();

    try testing.expectEqualStrings("test-provider", provider.getId());
}

test "FileProvider: subscribe fails when file does not exist" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "test-provider",
        "/nonexistent/path/policies.json",
    );
    defer provider.deinit();

    // Subscribe should fail because file doesn't exist
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.FileNotFound, result);
}

test "FileProvider: subscribe fails with invalid JSON" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    // Create a temporary file with invalid JSON
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("invalid.json", .{});
    try file.writeAll("{ this is not valid json }");
    file.close();

    // Get the full path
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath("invalid.json", &path_buf);

    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "test-provider",
        tmp_path,
    );
    defer provider.deinit();

    // Subscribe should fail because JSON is invalid
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.SyntaxError, result);
}

test "FileProvider: subscribe fails with invalid policy structure" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    // Create a temporary file with valid JSON but invalid policy structure
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("bad_policy.json", .{});
    // Missing required fields like "id"
    try file.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "name": "missing-id-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }]
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath("bad_policy.json", &path_buf);

    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "test-provider",
        tmp_path,
    );
    defer provider.deinit();

    // Subscribe should fail because policy structure is invalid
    const result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });

    try testing.expectError(error.MissingField, result);
}

test "FileProvider: registry remains usable after provider fails to load" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    // Create registry
    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Try to load a provider with a non-existent file
    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "failing-provider",
        "/nonexistent/path/policies.json",
    );
    defer provider.deinit();

    // This should fail
    const subscribe_result = provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });
    try testing.expectError(error.FileNotFound, subscribe_result);

    // Registry should still be usable - no policies loaded
    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());
    try testing.expect(registry.getSnapshot() == null);

    // Now load a valid policy file and verify registry works
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("valid.json", .{});
    try file.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "test-policy",
        \\      "name": "test-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath("valid.json", &path_buf);

    const good_provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "good-provider",
        tmp_path,
    );
    defer good_provider.deinit();

    // Create callback that updates registry
    const CallbackContext = struct {
        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx = CallbackContext{ .registry = &registry };

    try good_provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Registry should now have the policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
}

test "FileProvider: registry retains policies after reload with invalid JSON" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a valid policy file
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("policies.json", .{});
    try file.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "test-policy",
        \\      "name": "test-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath("policies.json", &path_buf);

    const provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "test-provider",
        tmp_path,
    );
    defer provider.deinit();

    // Create callback that updates registry
    const CallbackContext = struct {
        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx = CallbackContext{ .registry = &registry };

    // Subscribe - this should load the valid policy
    try provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Verify the policy was loaded
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Now overwrite the file with invalid JSON
    const file2 = try tmp_dir.dir.createFile("policies.json", .{});
    try file2.writeAll("{ this is not valid json }");
    file2.close();

    // Manually trigger a reload (simulates what the watch loop does)
    // This should fail but not crash
    const reload_result = provider.loadAndNotify();
    try testing.expectError(error.SyntaxError, reload_result);

    // Registry should still have the original policy - reload failure doesn't clear it
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Now overwrite with valid JSON but invalid policy structure (missing "id" field)
    const file2b = try tmp_dir.dir.createFile("policies.json", .{});
    try file2b.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "name": "missing-id-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "test" }]
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file2b.close();

    // Reload should fail due to missing required field
    const reload_result2 = provider.loadAndNotify();
    try testing.expectError(error.MissingField, reload_result2);

    // Registry should still have the original policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
    }

    // Fix the file with valid JSON again
    const file3 = try tmp_dir.dir.createFile("policies.json", .{});
    try file3.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "updated-policy",
        \\      "name": "updated-policy",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "updated" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file3.close();

    // Reload should now succeed
    try provider.loadAndNotify();

    // Registry should now have the updated policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    {
        const snapshot = registry.getSnapshot();
        try testing.expect(snapshot != null);
        try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
        try testing.expectEqualStrings("updated-policy", snapshot.?.policies[0].name);
    }
}

test "FileProvider: multiple providers, one fails, registry has policies from successful one" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = Registry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a valid policy file
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const file = try tmp_dir.dir.createFile("valid.json", .{});
    try file.writeAll(
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "policy-from-valid-provider",
        \\      "name": "policy-from-valid-provider",
        \\      "log": {
        \\        "match": [{ "log_field": "body", "regex": "info" }],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    );
    file.close();

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp_dir.dir.realpath("valid.json", &path_buf);

    // First provider - will fail
    const failing_provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "failing-provider",
        "/nonexistent/policies.json",
    );
    defer failing_provider.deinit();

    const fail_result = failing_provider.subscribe(.{
        .context = undefined,
        .onUpdate = struct {
            fn cb(_: *anyopaque, _: policy_provider.PolicyUpdate) !void {}
        }.cb,
    });
    try testing.expectError(error.FileNotFound, fail_result);

    // Second provider - will succeed
    const good_provider = try FileProvider.init(
        allocator,
        noop_bus.eventBus(),
        "good-provider",
        tmp_path,
    );
    defer good_provider.deinit();

    const CallbackContext = struct {
        registry: *Registry,

        fn handleUpdate(ctx: *anyopaque, update: policy_provider.PolicyUpdate) !void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            try self.registry.updatePolicies(update.policies, update.provider_id, .file);
        }
    };

    var ctx = CallbackContext{ .registry = &registry };

    try good_provider.subscribe(.{
        .context = @ptrCast(&ctx),
        .onUpdate = CallbackContext.handleUpdate,
    });

    // Registry should have policy from the successful provider only
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-from-valid-provider", snapshot.?.policies[0].name);
}

// -----------------------------------------------------------------------------
// Tripwire Tests for FileProvider.init
// -----------------------------------------------------------------------------

test "FileProvider.init: tripwire create_provider fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    FileProvider.init_tw.errorAlways(.create_provider, error.OutOfMemory);
    defer FileProvider.init_tw.reset();

    const result = FileProvider.init(allocator, noop_bus.eventBus(), "test-provider", "/path/to/file.json");
    try testing.expectError(error.OutOfMemory, result);
    try FileProvider.init_tw.end(.retain);
}

test "FileProvider.init: tripwire dupe_id fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    FileProvider.init_tw.errorAlways(.dupe_id, error.OutOfMemory);
    defer FileProvider.init_tw.reset();

    const result = FileProvider.init(allocator, noop_bus.eventBus(), "test-provider", "/path/to/file.json");
    try testing.expectError(error.OutOfMemory, result);
    try FileProvider.init_tw.end(.retain);
}

test "FileProvider.init: tripwire dupe_path fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    FileProvider.init_tw.errorAlways(.dupe_path, error.OutOfMemory);
    defer FileProvider.init_tw.reset();

    const result = FileProvider.init(allocator, noop_bus.eventBus(), "test-provider", "/path/to/file.json");
    try testing.expectError(error.OutOfMemory, result);
    try FileProvider.init_tw.end(.retain);
}
