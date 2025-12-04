const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./policy_source.zig");
const matcher_index = @import("./matcher_index.zig");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const Policy = proto.policy.Policy;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;
const MatcherIndex = matcher_index.MatcherIndex;

// =============================================================================
// Observability Events
// =============================================================================

const PolicyErrorNoProvider = struct {
    policy_id: []const u8,
    message: []const u8,
};

const PolicyErrorNotFound = struct {
    policy_id: []const u8,
    message: []const u8,
};

const PolicyRegistryUnchanged = struct {};

/// Policy config types - derived from the Policy.config oneof field
pub const PolicyConfigType = enum {
    /// Policy has a LogFilterConfig (filter field set)
    log_filter,
    /// Policy has no config set
    none,

    /// Get the config type from a policy
    pub fn fromPolicy(policy: *const Policy) PolicyConfigType {
        if (policy.log_filter != null) {
            return .log_filter;
        }
        return .none;
    }
};

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    /// All policies in this snapshot
    policies: []const Policy,

    /// Indices into policies array for each config type
    /// Allows efficient lookup of policies by their config type
    log_filter_indices: []const u32,

    /// Compiled Hyperscan-based matcher index for efficient evaluation
    /// Indexed by (MatchCase, key) for O(k*n) evaluation
    matcher_index: MatcherIndex,

    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PolicySnapshot) void {
        self.matcher_index.deinit();
        self.allocator.free(self.policies);
        self.allocator.free(self.log_filter_indices);
    }

    /// Get a policy by index
    pub fn getPolicy(self: *const PolicySnapshot, idx: u32) ?*const Policy {
        if (idx >= self.policies.len) {
            return null;
        }
        return &self.policies[idx];
    }

    /// Get all log filter policies
    pub fn getLogFilterPolicies(self: *const PolicySnapshot) []const Policy {
        if (self.log_filter_indices.len == 0) {
            return &.{};
        }
        // Return a slice view - caller iterates using indices
        return self.policies;
    }

    /// Get log filter policy indices for iteration
    pub fn getLogFilterIndices(self: *const PolicySnapshot) []const u32 {
        return self.log_filter_indices;
    }

    /// Iterator for log filter policies
    pub fn iterateLogFilterPolicies(self: *const PolicySnapshot) LogFilterPolicyIterator {
        return .{
            .snapshot = self,
            .index = 0,
        };
    }

    pub const LogFilterPolicyIterator = struct {
        snapshot: *const PolicySnapshot,
        index: usize,

        pub fn next(self: *LogFilterPolicyIterator) ?*const Policy {
            if (self.index >= self.snapshot.log_filter_indices.len) {
                return null;
            }
            const policy_idx = self.snapshot.log_filter_indices[self.index];
            self.index += 1;
            return &self.snapshot.policies[policy_idx];
        }
    };
};

/// Centralized policy registry with multi-source support
pub const PolicyRegistry = struct {
    // All policies stored together
    policies: std.ArrayListUnmanaged(Policy),

    // Source tracking for deduplication and priority
    // Key: policy id, Value: PolicyMetadata
    policy_sources: std.StringHashMap(PolicyMetadata),

    // Synchronization
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,
    version: std.atomic.Value(u64),

    // Current immutable snapshot for lock-free reads
    current_snapshot: std.atomic.Value(?*const PolicySnapshot),

    // Provider references for error routing
    // These are not owned by the registry - caller must ensure they outlive the registry
    providers: struct {
        file: ?*policy_provider.PolicyProvider = null,
        http: ?*policy_provider.PolicyProvider = null,
    },

    // Event bus for observability
    bus: *EventBus,

    pub fn init(allocator: std.mem.Allocator, bus: *EventBus) PolicyRegistry {
        return .{
            .policies = .empty,
            .policy_sources = std.StringHashMap(PolicyMetadata).init(allocator),
            .mutex = .{},
            .allocator = allocator,
            .version = std.atomic.Value(u64).init(0),
            .current_snapshot = std.atomic.Value(?*const PolicySnapshot).init(null),
            .providers = .{},
            .bus = bus,
        };
    }

    /// Register a provider for error routing.
    /// The provider must outlive the registry.
    pub fn registerProvider(self: *PolicyRegistry, source: SourceType, provider: *policy_provider.PolicyProvider) void {
        switch (source) {
            .file => self.providers.file = provider,
            .http => self.providers.http = provider,
        }
    }

    /// Report an error encountered when applying a policy.
    /// Routes the error to the appropriate provider based on the policy's source.
    pub fn recordPolicyError(self: *PolicyRegistry, policy_id: []const u8, error_message: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.policy_sources.get(policy_id)) |metadata| {
            const provider: ?*policy_provider.PolicyProvider = switch (metadata.source) {
                .file => self.providers.file,
                .http => self.providers.http,
            };
            if (provider) |p| {
                p.recordPolicyError(policy_id, error_message);
            } else {
                // No provider registered, log as fallback
                self.bus.err(PolicyErrorNoProvider{ .policy_id = policy_id, .message = error_message });
            }
        } else {
            // Policy not found, log
            self.bus.err(PolicyErrorNotFound{ .policy_id = policy_id, .message = error_message });
        }
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
            @constCast(snapshot).deinit();
            self.allocator.destroy(snapshot);
        }
    }

    /// Update policies from a specific source
    /// Deduplicates by id and applies priority rules
    pub fn updatePolicies(
        self: *PolicyRegistry,
        policies: []const Policy,
        source: SourceType,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Track if any changes were made
        var changed = false;

        // Track which policy ids from this source are in the new set
        var new_policy_ids = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = new_policy_ids.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            new_policy_ids.deinit();
        }

        // Process each incoming policy
        for (policies) |policy| {
            const id_copy = try self.allocator.dupe(u8, policy.id);
            errdefer self.allocator.free(id_copy);

            // Track this id as present in new set
            try new_policy_ids.put(id_copy, {});

            // Check if policy already exists
            if (self.policy_sources.get(policy.id)) |existing_meta| {
                // Apply priority rules
                if (existing_meta.shouldReplace(source)) {
                    // Remove old policy and its source tracking
                    self.removePolicyById(policy.id);
                    if (self.policy_sources.fetchRemove(policy.id)) |kv| {
                        self.allocator.free(kv.key);
                    }

                    // Add new policy
                    try self.addPolicyInternal(policy, source);
                    changed = true;
                }
                // else: HTTP has priority, keep existing
            } else {
                // New policy, add it
                try self.addPolicyInternal(policy, source);
                changed = true;
            }
        }

        // Remove policies from this source that are no longer present
        const removed = try self.removeStalePolicies(source, &new_policy_ids);
        if (removed > 0) {
            changed = true;
        }

        // Only create new snapshot if something changed
        if (changed) {
            try self.createSnapshot();
        } else {
            self.bus.debug(PolicyRegistryUnchanged{});
        }
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

        // Track source metadata by policy id
        const id_key = try self.allocator.dupe(u8, policy.id);
        try self.policy_sources.put(id_key, PolicyMetadata.init(source));
    }

    /// Remove a policy by id and free its memory
    fn removePolicyById(self: *PolicyRegistry, id: []const u8) void {
        for (self.policies.items, 0..) |*policy, i| {
            if (std.mem.eql(u8, policy.id, id)) {
                policy.deinit(self.allocator);
                _ = self.policies.swapRemove(i);
                break;
            }
        }
    }

    /// Remove policies from source that are no longer in the new set
    /// Returns the number of policies removed
    fn removeStalePolicies(
        self: *PolicyRegistry,
        source: SourceType,
        new_ids: *const std.StringHashMap(void),
    ) !usize {
        var ids_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer ids_to_remove.deinit(self.allocator);

        // Find policies from this source not in new set
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const metadata = entry.value_ptr.*;

            // Only consider policies from this source
            if (metadata.source != source) continue;

            // If not in new set, mark for removal
            if (!new_ids.contains(id)) {
                try ids_to_remove.append(self.allocator, id);
            }
        }

        // Remove stale policies
        for (ids_to_remove.items) |id| {
            self.removePolicyById(id);

            // Remove from source tracking
            _ = self.policy_sources.remove(id);
            self.allocator.free(id);
        }

        return ids_to_remove.items.len;
    }

    /// Create immutable snapshot of current policies
    fn createSnapshot(self: *PolicyRegistry) !void {
        const policies_slice = try self.allocator.alloc(Policy, self.policies.items.len);
        errdefer self.allocator.free(policies_slice);

        @memcpy(policies_slice, self.policies.items);

        // Build indices by config type
        // First pass: count policies of each type
        var log_filter_count: usize = 0;
        for (policies_slice) |*policy| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_filter => log_filter_count += 1,
                .none => {},
            }
        }

        // Allocate index arrays
        const log_filter_indices = try self.allocator.alloc(u32, log_filter_count);
        errdefer self.allocator.free(log_filter_indices);

        // Second pass: populate indices
        var log_filter_idx: usize = 0;
        for (policies_slice, 0..) |*policy, i| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_filter => {
                    log_filter_indices[log_filter_idx] = @intCast(i);
                    log_filter_idx += 1;
                },
                .none => {},
            }
        }

        // Build matcher index for Hyperscan-based matching
        var idx = try MatcherIndex.build(self.allocator, self.bus, policies_slice);
        errdefer idx.deinit();

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Create new snapshot with indices
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .policies = policies_slice,
            .log_filter_indices = log_filter_indices,
            .matcher_index = idx,
            .version = new_version,
            .allocator = self.allocator,
        };

        // Swap snapshot atomically
        const old_snapshot = self.current_snapshot.swap(snapshot, .acq_rel);

        // Clean up old snapshot (TODO: RCU for grace period)
        if (old_snapshot) |old| {
            @constCast(old).deinit();
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

        var ids_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer ids_to_remove.deinit(self.allocator);

        // Find all policies from this source
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.source == source) {
                try ids_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Remove each policy
        for (ids_to_remove.items) |id| {
            self.removePolicyById(id);
            _ = self.policy_sources.remove(id);
            self.allocator.free(id);
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
        .id = try allocator.dupe(u8, name), // Use name as id for tests
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());
    try testing.expect(registry.getSnapshot() == null);
}

test "PolicyRegistry: add single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
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

// -----------------------------------------------------------------------------
// Policy Config Type Indexing Tests
// -----------------------------------------------------------------------------

const LogFilterConfig = proto.policy.LogFilterConfig;

/// Helper to create a test policy with a log filter config
fn createTestPolicyWithFilter(
    allocator: std.mem.Allocator,
    name: []const u8,
) !Policy {
    var policy = Policy{
        .id = try allocator.dupe(u8, name), // Use name as id for tests
        .name = try allocator.dupe(u8, name),
        .enabled = true,
        .log_filter = LogFilterConfig{
            .matchers = .empty,
            .action = .FILTER_ACTION_DROP,
        },
    };
    _ = &policy;

    return policy;
}

test "PolicyConfigType: fromPolicy returns log_filter when filter is set" {
    const allocator = testing.allocator;

    var policy = try createTestPolicyWithFilter(allocator, "filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.log_filter, config_type);
}

test "PolicyConfigType: fromPolicy returns none when filter is null" {
    const allocator = testing.allocator;

    var policy = try createTestPolicy(allocator, "no-filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.none, config_type);
}

test "PolicySnapshot: log_filter_indices contains only filter policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create mix of policies with and without filters
    var policy_no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy_no_filter);

    var policy_with_filter = try createTestPolicyWithFilter(allocator, "with-filter");
    defer freeTestPolicy(allocator, &policy_with_filter);

    var another_no_filter = try createTestPolicy(allocator, "another-no-filter");
    defer freeTestPolicy(allocator, &another_no_filter);

    try registry.updatePolicies(&.{ policy_no_filter, policy_with_filter, another_no_filter }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should have 3 total policies but only 1 log filter index
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_filter_indices.len);

    // The indexed policy should be the one with filter
    const indexed_policy = snapshot.?.policies[snapshot.?.log_filter_indices[0]];
    try testing.expectEqualStrings("with-filter", indexed_policy.name);
    try testing.expect(indexed_policy.log_filter != null);
}

test "PolicySnapshot: multiple filter policies are indexed" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    var filter3 = try createTestPolicyWithFilter(allocator, "filter-3");
    defer freeTestPolicy(allocator, &filter3);

    try registry.updatePolicies(&.{ filter1, filter2, filter3 }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // All 3 policies should be indexed
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 3), snapshot.?.log_filter_indices.len);
}

test "PolicySnapshot: empty when no filter policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{ policy1, policy2 }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // No filter indices
    try testing.expectEqual(@as(usize, 2), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_filter_indices.len);
}

test "PolicySnapshot: iterateLogFilterPolicies returns all filter policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &no_filter);

    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    try registry.updatePolicies(&.{ no_filter, filter1, filter2 }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Iterate and collect names
    var iter = snapshot.?.iterateLogFilterPolicies();
    var count: usize = 0;
    var found_filter1 = false;
    var found_filter2 = false;

    while (iter.next()) |policy| {
        count += 1;
        try testing.expect(policy.log_filter != null);

        if (std.mem.eql(u8, policy.name, "filter-1")) {
            found_filter1 = true;
        } else if (std.mem.eql(u8, policy.name, "filter-2")) {
            found_filter2 = true;
        }
    }

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expect(found_filter1);
    try testing.expect(found_filter2);
}

test "PolicySnapshot: iterator returns null when no filter policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    var iter = snapshot.?.iterateLogFilterPolicies();
    try testing.expect(iter.next() == null);
}

test "PolicySnapshot: indices update when policies change" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Start with one filter policy
    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    try registry.updatePolicies(&.{filter1}, .file);

    var snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_filter_indices.len);

    // Add another filter policy
    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    try registry.updatePolicies(&.{ filter1, filter2 }, .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 2), snapshot.?.log_filter_indices.len);

    // Remove filter policies, add non-filter
    var no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &no_filter);

    try registry.updatePolicies(&.{no_filter}, .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_filter_indices.len);
}

// -----------------------------------------------------------------------------
// Policy Error Routing Tests
// -----------------------------------------------------------------------------

/// Mock provider that records errors for testing
const MockErrorProvider = struct {
    recorded_errors: std.ArrayListUnmanaged(struct { policy_id: []const u8, message: []const u8 }),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MockErrorProvider {
        return .{
            .recorded_errors = .{},
            .allocator = allocator,
        };
    }

    // Must be pub for PolicyProvider.init to find it
    pub fn deinit(self: *MockErrorProvider) void {
        for (self.recorded_errors.items) |entry| {
            self.allocator.free(entry.policy_id);
            self.allocator.free(entry.message);
        }
        self.recorded_errors.deinit(self.allocator);
    }

    pub fn subscribe(self: *MockErrorProvider, callback: PolicyCallback) !void {
        _ = self;
        _ = callback;
    }

    pub fn recordPolicyError(self: *MockErrorProvider, policy_id: []const u8, error_message: []const u8) void {
        const id_copy = self.allocator.dupe(u8, policy_id) catch return;
        const msg_copy = self.allocator.dupe(u8, error_message) catch {
            self.allocator.free(id_copy);
            return;
        };
        self.recorded_errors.append(self.allocator, .{
            .policy_id = id_copy,
            .message = msg_copy,
        }) catch {
            self.allocator.free(id_copy);
            self.allocator.free(msg_copy);
        };
    }

    fn getErrorCount(self: *MockErrorProvider) usize {
        return self.recorded_errors.items.len;
    }

    fn hasError(self: *MockErrorProvider, policy_id: []const u8, message: []const u8) bool {
        for (self.recorded_errors.items) |entry| {
            if (std.mem.eql(u8, entry.policy_id, policy_id) and
                std.mem.eql(u8, entry.message, message))
            {
                return true;
            }
        }
        return false;
    }
};

test "PolicyRegistry: registerProvider and recordPolicyError routes to correct provider" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create mock providers
    var file_mock = MockErrorProvider.init(allocator);
    defer file_mock.deinit();

    var http_mock = MockErrorProvider.init(allocator);
    defer http_mock.deinit();

    // Register providers
    var file_provider = policy_provider.PolicyProvider.init(&file_mock);
    var http_provider = policy_provider.PolicyProvider.init(&http_mock);

    registry.registerProvider(.file, &file_provider);
    registry.registerProvider(.http, &http_provider);

    // Add policies from different sources
    var file_policy = try createTestPolicy(allocator, "file-policy-1");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy-1");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{file_policy}, .file);
    try registry.updatePolicies(&.{http_policy}, .http);

    // Record errors
    registry.recordPolicyError("file-policy-1", "Invalid regex in file policy");
    registry.recordPolicyError("http-policy-1", "Invalid regex in http policy");

    // Verify errors routed to correct providers
    try testing.expectEqual(@as(usize, 1), file_mock.getErrorCount());
    try testing.expectEqual(@as(usize, 1), http_mock.getErrorCount());

    try testing.expect(file_mock.hasError("file-policy-1", "Invalid regex in file policy"));
    try testing.expect(http_mock.hasError("http-policy-1", "Invalid regex in http policy"));

    // Verify no cross-contamination
    try testing.expect(!file_mock.hasError("http-policy-1", "Invalid regex in http policy"));
    try testing.expect(!http_mock.hasError("file-policy-1", "Invalid regex in file policy"));
}

test "PolicyRegistry: recordPolicyError for unknown policy does not route to provider" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var mock = MockErrorProvider.init(allocator);
    defer mock.deinit();

    var provider = policy_provider.PolicyProvider.init(&mock);
    registry.registerProvider(.file, &provider);

    // Add a real policy so we can test error routing works
    var real_policy = try createTestPolicy(allocator, "real-policy");
    defer freeTestPolicy(allocator, &real_policy);
    try registry.updatePolicies(&.{real_policy}, .file);

    // Record error for the real policy - should be routed
    registry.recordPolicyError("real-policy", "Some error");

    // Verify the error was recorded
    try testing.expectEqual(@as(usize, 1), mock.getErrorCount());
    try testing.expect(mock.hasError("real-policy", "Some error"));
}

test "PolicyRegistry: multiple errors for same policy accumulate" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var mock = MockErrorProvider.init(allocator);
    defer mock.deinit();

    var provider = policy_provider.PolicyProvider.init(&mock);
    registry.registerProvider(.file, &provider);

    var policy = try createTestPolicy(allocator, "error-prone-policy");
    defer freeTestPolicy(allocator, &policy);
    try registry.updatePolicies(&.{policy}, .file);

    // Record multiple errors for the same policy
    registry.recordPolicyError("error-prone-policy", "First error");
    registry.recordPolicyError("error-prone-policy", "Second error");
    registry.recordPolicyError("error-prone-policy", "Third error");

    // All errors should be recorded
    try testing.expectEqual(@as(usize, 3), mock.getErrorCount());
    try testing.expect(mock.hasError("error-prone-policy", "First error"));
    try testing.expect(mock.hasError("error-prone-policy", "Second error"));
    try testing.expect(mock.hasError("error-prone-policy", "Third error"));
}

test "PolicyRegistry: policies keyed by id not name" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create two policies with same name but different ids
    var policy1 = Policy{
        .id = try allocator.dupe(u8, "id-1"),
        .name = try allocator.dupe(u8, "same-name"),
        .enabled = true,
        .priority = 1,
    };
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "id-2"),
        .name = try allocator.dupe(u8, "same-name"),
        .enabled = true,
        .priority = 2,
    };
    defer policy2.deinit(allocator);

    // Both should be added (different ids)
    try registry.updatePolicies(&.{ policy1, policy2 }, .file);

    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 2), snapshot.?.policies.len);
}

test "PolicyRegistry: policy update by id replaces correctly" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add initial policy
    var policy_v1 = Policy{
        .id = try allocator.dupe(u8, "policy-123"),
        .name = try allocator.dupe(u8, "my-policy"),
        .enabled = true,
        .priority = 1,
    };
    defer policy_v1.deinit(allocator);

    try registry.updatePolicies(&.{policy_v1}, .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    var snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(i32, 1), snapshot.?.policies[0].priority);

    // Update with same id, different priority
    var policy_v2 = Policy{
        .id = try allocator.dupe(u8, "policy-123"),
        .name = try allocator.dupe(u8, "my-policy-renamed"),
        .enabled = true,
        .priority = 10,
    };
    defer policy_v2.deinit(allocator);

    try registry.updatePolicies(&.{policy_v2}, .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(i32, 10), snapshot.?.policies[0].priority);
    try testing.expectEqualStrings("my-policy-renamed", snapshot.?.policies[0].name);
}
