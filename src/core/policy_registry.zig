const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./policy_source.zig");

const Policy = proto.policy.Policy;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    /// All policies in this snapshot
    policies: []const Policy,

    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const PolicySnapshot) void {
        self.allocator.free(self.policies);
    }

    /// Get a policy by index
    pub fn getPolicy(self: *const PolicySnapshot, idx: u32) ?*const Policy {
        if (idx >= self.policies.len) {
            return null;
        }
        return &self.policies[idx];
    }
};

/// Centralized policy registry with multi-source support
pub const PolicyRegistry = struct {
    // All policies stored together
    policies: std.ArrayListUnmanaged(Policy),

    // Source tracking for deduplication and priority
    // Key: policy name, Value: PolicyMetadata
    policy_sources: std.StringHashMap(PolicyMetadata),

    // Synchronization
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,
    version: std.atomic.Value(u64),

    // Current immutable snapshot for lock-free reads
    current_snapshot: std.atomic.Value(?*const PolicySnapshot),

    pub fn init(allocator: std.mem.Allocator) PolicyRegistry {
        return .{
            .policies = .empty,
            .policy_sources = std.StringHashMap(PolicyMetadata).init(allocator),
            .mutex = .{},
            .allocator = allocator,
            .version = std.atomic.Value(u64).init(0),
            .current_snapshot = std.atomic.Value(?*const PolicySnapshot).init(null),
        };
    }

    pub fn deinit(self: *PolicyRegistry) void {
        // Free all stored policies (we own them via dupe)
        for (self.policies.items) |*policy| {
            policy.deinit(self.allocator);
        }
        self.policies.deinit(self.allocator);

        // Free source tracking keys and hashmap
        var it = self.policy_sources.keyIterator();
        while (it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.policy_sources.deinit();

        // Free current snapshot if exists
        if (self.current_snapshot.load(.acquire)) |snapshot| {
            snapshot.deinit();
            self.allocator.destroy(snapshot);
        }
    }

    /// Update policies from a specific source
    /// Deduplicates by name and applies priority rules
    pub fn updatePolicies(
        self: *PolicyRegistry,
        policies: []const Policy,
        source: SourceType,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Track which policies from this source are in the new set
        var new_policy_names = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = new_policy_names.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            new_policy_names.deinit();
        }

        // Process each incoming policy
        for (policies) |policy| {
            const name_copy = try self.allocator.dupe(u8, policy.name);
            errdefer self.allocator.free(name_copy);

            // Track this name as present in new set
            try new_policy_names.put(name_copy, {});

            // Check if policy already exists
            if (self.policy_sources.get(policy.name)) |existing_meta| {
                // Apply priority rules
                if (existing_meta.shouldReplace(source)) {
                    // Remove old policy and its source tracking
                    self.removePolicyByName(policy.name);
                    if (self.policy_sources.fetchRemove(policy.name)) |kv| {
                        self.allocator.free(kv.key);
                    }

                    // Add new policy
                    try self.addPolicyInternal(policy, source);
                }
                // else: HTTP has priority, keep existing
            } else {
                // New policy, add it
                try self.addPolicyInternal(policy, source);
            }
        }

        // Remove policies from this source that are no longer present
        try self.removeStalePolicies(source, &new_policy_names);

        // Create new immutable snapshot
        try self.createSnapshot();
    }

    /// Add a policy and track its source
    /// Deep copies the policy so the registry owns the memory
    fn addPolicyInternal(
        self: *PolicyRegistry,
        policy: Policy,
        source: SourceType,
    ) !void {
        // Deep copy the policy so we own the memory
        const policy_copy = try policy.dupe(self.allocator);
        try self.policies.append(self.allocator, policy_copy);

        // Track source metadata (name is already copied in policy_copy)
        const name_key = try self.allocator.dupe(u8, policy.name);
        try self.policy_sources.put(name_key, PolicyMetadata.init(source));
    }

    /// Remove a policy by name and free its memory
    fn removePolicyByName(self: *PolicyRegistry, name: []const u8) void {
        for (self.policies.items, 0..) |*policy, i| {
            if (std.mem.eql(u8, policy.name, name)) {
                policy.deinit(self.allocator);
                _ = self.policies.swapRemove(i);
                break;
            }
        }
    }

    /// Remove policies from source that are no longer in the new set
    fn removeStalePolicies(
        self: *PolicyRegistry,
        source: SourceType,
        new_names: *const std.StringHashMap(void),
    ) !void {
        var names_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer names_to_remove.deinit(self.allocator);

        // Find policies from this source not in new set
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            const name = entry.key_ptr.*;
            const metadata = entry.value_ptr.*;

            // Only consider policies from this source
            if (metadata.source != source) continue;

            // If not in new set, mark for removal
            if (!new_names.contains(name)) {
                try names_to_remove.append(self.allocator, name);
            }
        }

        // Remove stale policies
        for (names_to_remove.items) |name| {
            self.removePolicyByName(name);

            // Remove from source tracking
            _ = self.policy_sources.remove(name);
            self.allocator.free(name);
        }
    }

    /// Create immutable snapshot of current policies
    fn createSnapshot(self: *PolicyRegistry) !void {
        const policies_slice = try self.allocator.alloc(Policy, self.policies.items.len);
        errdefer self.allocator.free(policies_slice);

        @memcpy(policies_slice, self.policies.items);

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Create new snapshot
        // TODO: In the future we should do organization and filtering here based
        // on the labels in the policies.
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .policies = policies_slice,
            .version = new_version,
            .allocator = self.allocator,
        };

        // Swap snapshot atomically
        const old_snapshot = self.current_snapshot.swap(snapshot, .acq_rel);

        // Clean up old snapshot (TODO: RCU for grace period)
        if (old_snapshot) |old| {
            old.deinit();
            self.allocator.destroy(old);
        }
    }

    /// Get current policy snapshot (lock-free read)
    pub fn getSnapshot(self: *const PolicyRegistry) ?*const PolicySnapshot {
        return self.current_snapshot.load(.acquire);
    }

    /// Clear all policies from a specific source
    pub fn clearSource(self: *PolicyRegistry, source: SourceType) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var names_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer names_to_remove.deinit(self.allocator);

        // Find all policies from this source
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.source == source) {
                try names_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Remove each policy
        for (names_to_remove.items) |name| {
            self.removePolicyByName(name);
            _ = self.policy_sources.remove(name);
            self.allocator.free(name);
        }

        // Create new snapshot
        try self.createSnapshot();
    }

    /// Get total policy count
    pub fn getPolicyCount(self: *const PolicyRegistry) usize {
        return self.policies.items.len;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const policy_provider = @import("./policy_provider.zig");
const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;

/// Test policy provider that can be configured to emit policies on demand
/// Implements the PolicyProvider interface for integration testing
pub const TestPolicyProvider = struct {
    allocator: std.mem.Allocator,
    source: SourceType,
    policies: std.ArrayListUnmanaged(Policy),
    callbacks: std.ArrayListUnmanaged(PolicyCallback),

    pub fn init(allocator: std.mem.Allocator, source: SourceType) TestPolicyProvider {
        return .{
            .allocator = allocator,
            .source = source,
            .policies = .empty,
            .callbacks = .empty,
        };
    }

    pub fn deinit(self: *TestPolicyProvider) void {
        for (self.policies.items) |*policy| {
            policy.deinit(self.allocator);
        }
        self.policies.deinit(self.allocator);
        self.callbacks.deinit(self.allocator);
    }

    /// Add a policy to the provider's set
    pub fn addPolicy(self: *TestPolicyProvider, policy: Policy) !void {
        const policy_copy = try policy.dupe(self.allocator);
        try self.policies.append(self.allocator, policy_copy);
    }

    /// Remove a policy by name
    pub fn removePolicy(self: *TestPolicyProvider, name: []const u8) void {
        for (self.policies.items, 0..) |*policy, i| {
            if (std.mem.eql(u8, policy.name, name)) {
                policy.deinit(self.allocator);
                _ = self.policies.swapRemove(i);
                return;
            }
        }
    }

    /// Clear all policies
    pub fn clearPolicies(self: *TestPolicyProvider) void {
        for (self.policies.items) |*policy| {
            policy.deinit(self.allocator);
        }
        self.policies.clearRetainingCapacity();
    }

    /// Notify all subscribers of the current policy set
    pub fn notifySubscribers(self: *TestPolicyProvider) !void {
        const update = PolicyUpdate{
            .policies = self.policies.items,
            .source = self.source,
        };
        for (self.callbacks.items) |callback| {
            try callback.call(update);
        }
    }

    /// Subscribe to policy updates (PolicyProvider interface)
    pub fn subscribe(self: *TestPolicyProvider, callback: PolicyCallback) !void {
        try self.callbacks.append(self.allocator, callback);
        // Immediately notify with current policies
        const update = PolicyUpdate{
            .policies = self.policies.items,
            .source = self.source,
        };
        try callback.call(update);
    }

    /// Get as PolicyProvider interface
    pub fn provider(self: *TestPolicyProvider) policy_provider.PolicyProvider {
        return policy_provider.PolicyProvider.init(self);
    }
};

/// Helper to create a test policy with minimal required fields
fn createTestPolicy(
    allocator: std.mem.Allocator,
    name: []const u8,
) !Policy {
    var policy = Policy{
        .name = try allocator.dupe(u8, name),
        .enabled = true,
    };
    _ = &policy;

    return policy;
}

/// Helper to free a test policy created with createTestPolicy
fn freeTestPolicy(allocator: std.mem.Allocator, policy: *Policy) void {
    policy.deinit(allocator);
}

// -----------------------------------------------------------------------------
// Basic Registry Operations Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: init and deinit with no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());
    try testing.expect(registry.getSnapshot() == null);
}

test "PolicyRegistry: add single policy" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, .file);

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("test-policy", snapshot.?.policies[0].name);
}

test "PolicyRegistry: add multiple policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    var policy3 = try createTestPolicy(allocator, "policy-3");
    defer freeTestPolicy(allocator, &policy3);

    try registry.updatePolicies(&.{ policy1, policy2, policy3 }, .file);

    try testing.expectEqual(@as(usize, 3), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
}

test "PolicyRegistry: update existing policy from same source" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add initial policy
    var policy1 = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy1);

    try registry.updatePolicies(&.{policy1}, .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Update with same name
    var policy2 = try createTestPolicy(allocator, "test-policy");
    policy2.priority = 10; // Different priority
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{policy2}, .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(i32, 10), snapshot.?.policies[0].priority);
}

// -----------------------------------------------------------------------------
// Source Priority Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: HTTP source takes priority over file source" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.priority = 1;
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);

    // Try to update with file source (should be ignored)
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.priority = 2;
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Should still have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqual(@as(i32, 1), snapshot.?.policies[0].priority);
}

test "PolicyRegistry: HTTP source can update file source policy" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.priority = 1;
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Update with HTTP source (should replace)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.priority = 2;
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);

    // Should have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqual(@as(i32, 2), snapshot.?.policies[0].priority);
}

test "PolicyRegistry: multiple sources with different policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policies from file source
    var file_policy = try createTestPolicy(allocator, "file-only-policy");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Add policies from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-only-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);

    // Should have both policies
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());
}

// -----------------------------------------------------------------------------
// Stale Policy Removal Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: stale policies are removed when source updates" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add two policies from file source
    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{ policy1, policy2 }, .file);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update with only one policy (policy-2 should be removed)
    try registry.updatePolicies(&.{policy1}, .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-1", snapshot.?.policies[0].name);
}

test "PolicyRegistry: stale removal only affects same source" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update file source with empty set (should only remove file-policy)
    try registry.updatePolicies(&.{}, .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("http-policy", snapshot.?.policies[0].name);
}

test "PolicyRegistry: clearSource removes all policies from source" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policies from both sources
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{file_policy}, .file);
    try registry.updatePolicies(&.{http_policy}, .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Clear file source
    try registry.clearSource(.file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("http-policy", snapshot.?.policies[0].name);
}

// -----------------------------------------------------------------------------
// Snapshot Versioning Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: snapshot version increments on update" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    // First update
    try registry.updatePolicies(&.{policy}, .file);
    const snapshot1 = registry.getSnapshot();
    try testing.expect(snapshot1 != null);
    try testing.expectEqual(@as(u64, 1), snapshot1.?.version);

    // Second update
    try registry.updatePolicies(&.{policy}, .file);
    const snapshot2 = registry.getSnapshot();
    try testing.expect(snapshot2 != null);
    try testing.expectEqual(@as(u64, 2), snapshot2.?.version);

    // Third update
    try registry.updatePolicies(&.{}, .file);
    const snapshot3 = registry.getSnapshot();
    try testing.expect(snapshot3 != null);
    try testing.expectEqual(@as(u64, 3), snapshot3.?.version);
}

test "PolicyRegistry: clearSource increments version" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, .file);
    const version_before = registry.getSnapshot().?.version;

    try registry.clearSource(.file);
    const version_after = registry.getSnapshot().?.version;

    try testing.expect(version_after > version_before);
}

// -----------------------------------------------------------------------------
// TestPolicyProvider Integration Tests
// -----------------------------------------------------------------------------

test "TestPolicyProvider: basic functionality" {
    const allocator = testing.allocator;

    var prov = TestPolicyProvider.init(allocator, .file);
    defer prov.deinit();

    // Add a policy
    var policy = try createTestPolicy(allocator, "provider-policy");
    defer freeTestPolicy(allocator, &policy);

    try prov.addPolicy(policy);
    try testing.expectEqual(@as(usize, 1), prov.policies.items.len);

    // Remove the policy
    prov.removePolicy("provider-policy");
    try testing.expectEqual(@as(usize, 0), prov.policies.items.len);
}

test "TestPolicyProvider: integrates with PolicyRegistry" {
    const allocator = testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var file_provider = TestPolicyProvider.init(allocator, .file);
    defer file_provider.deinit();

    // Add policy to provider
    var policy = try createTestPolicy(allocator, "provider-policy");
    defer freeTestPolicy(allocator, &policy);

    try file_provider.addPolicy(policy);

    // Create callback that updates registry
    const Ctx = struct {
        registry: *PolicyRegistry,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.source);
        }
    };

    var ctx = Ctx{ .registry = &registry };
    const callback = PolicyCallback{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Subscribe - should immediately update registry
    try file_provider.subscribe(callback);

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("provider-policy", snapshot.?.policies[0].name);
}

test "TestPolicyProvider: multiple providers with different sources" {
    const allocator = testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var file_provider = TestPolicyProvider.init(allocator, .file);
    defer file_provider.deinit();

    var http_provider = TestPolicyProvider.init(allocator, .http);
    defer http_provider.deinit();

    // Add policies to providers
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try file_provider.addPolicy(file_policy);
    try http_provider.addPolicy(http_policy);

    // Create callback
    const Ctx = struct {
        registry: *PolicyRegistry,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.source);
        }
    };

    var ctx = Ctx{ .registry = &registry };
    const callback = PolicyCallback{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Subscribe to both providers
    try file_provider.subscribe(callback);
    try http_provider.subscribe(callback);

    // Registry should have both policies
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());
}

test "TestPolicyProvider: notifySubscribers updates registry" {
    const allocator = testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var prov = TestPolicyProvider.init(allocator, .file);
    defer prov.deinit();

    // Create and subscribe callback
    const Ctx = struct {
        registry: *PolicyRegistry,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.source);
        }
    };

    var ctx = Ctx{ .registry = &registry };
    const callback = PolicyCallback{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    try prov.subscribe(callback);
    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());

    // Add policy and notify
    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    try prov.addPolicy(policy1);
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Add another policy and notify
    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try prov.addPolicy(policy2);
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Remove policy and notify
    prov.removePolicy("policy-1");
    try prov.notifySubscribers();

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("policy-2", snapshot.?.policies[0].name);
}

test "TestPolicyProvider: HTTP provider overrides file provider" {
    const allocator = testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var file_provider = TestPolicyProvider.init(allocator, .file);
    defer file_provider.deinit();

    var http_provider = TestPolicyProvider.init(allocator, .http);
    defer http_provider.deinit();

    // Create callback
    const Ctx = struct {
        registry: *PolicyRegistry,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.source);
        }
    };

    var ctx = Ctx{ .registry = &registry };
    const callback = PolicyCallback{
        .context = &ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Add same-named policy to file provider first
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.priority = 1;
    defer freeTestPolicy(allocator, &file_policy);

    try file_provider.addPolicy(file_policy);
    try file_provider.subscribe(callback);

    // Verify file policy is in registry
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        @as(i32, 1),
        registry.getSnapshot().?.policies[0].priority,
    );

    // Add same-named policy to HTTP provider (should override)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.priority = 2;
    defer freeTestPolicy(allocator, &http_policy);

    try http_provider.addPolicy(http_policy);
    try http_provider.subscribe(callback);

    // Verify HTTP policy replaced file policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        @as(i32, 2),
        registry.getSnapshot().?.policies[0].priority,
    );

    // Update file provider - should NOT override HTTP
    file_provider.clearPolicies();
    var file_policy2 = try createTestPolicy(allocator, "shared-policy");
    file_policy2.priority = 3;
    defer freeTestPolicy(allocator, &file_policy2);

    try file_provider.addPolicy(file_policy2);
    try file_provider.notifySubscribers();

    // Should still have HTTP version
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        @as(i32, 2),
        registry.getSnapshot().?.policies[0].priority,
    );
}
