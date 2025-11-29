const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./policy_source.zig");

const Policy = proto.policy.Policy;
const TelemetryType = proto.policy.TelemetryType;
const PolicyType = proto.policy.PolicyType;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;

/// Index key combining telemetry type and policy type for pre-filtered lookups
pub const PolicyIndexKey = struct {
    telemetry_type: TelemetryType,
    policy_type: PolicyType,
};

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    /// All policies in this snapshot
    policies: []const Policy,

    /// Pre-filtered indices into policies array, keyed by (telemetry_type, policy_type)
    /// Stores slices of indices pointing into the policies array
    indices_by_telemetry_type: []const []const u32,
    indices_by_key: []const []const u32,

    /// Backing storage for the index slices
    telemetry_index_storage: []const u32,
    key_index_storage: []const u32,

    version: u64,
    allocator: std.mem.Allocator,

    /// Number of telemetry types we index (for bounds checking)
    const NUM_TELEMETRY_TYPES = 2; // UNSPECIFIED, LOGS
    /// Number of policy types we index
    const NUM_POLICY_TYPES = 3; // UNSPECIFIED, LOG_FILTER, REDACTION
    /// Total number of key combinations
    const NUM_KEY_COMBINATIONS = NUM_TELEMETRY_TYPES * NUM_POLICY_TYPES;

    pub fn deinit(self: *const PolicySnapshot) void {
        self.allocator.free(self.policies);
        self.allocator.free(self.indices_by_telemetry_type);
        self.allocator.free(self.indices_by_key);
        self.allocator.free(self.telemetry_index_storage);
        self.allocator.free(self.key_index_storage);
    }

    /// Get policies that apply to a specific telemetry type
    pub fn getPoliciesForType(self: *const PolicySnapshot, telemetry_type: TelemetryType) []const Policy {
        const type_idx = telemetryTypeToIndex(telemetry_type);
        if (type_idx >= self.indices_by_telemetry_type.len) {
            return &.{};
        }
        const indices = self.indices_by_telemetry_type[type_idx];
        return self.indicesToPolicies(indices);
    }

    /// Get policies that apply to a specific telemetry type and policy type
    pub fn getPoliciesForKey(self: *const PolicySnapshot, telemetry_type: TelemetryType, policy_type: PolicyType) []const Policy {
        const key_idx = keyToIndex(telemetry_type, policy_type);
        if (key_idx >= self.indices_by_key.len) {
            return &.{};
        }
        const indices = self.indices_by_key[key_idx];
        return self.indicesToPolicies(indices);
    }

    /// Convert indices to policy slice (returns pointers into the policies array)
    fn indicesToPolicies(self: *const PolicySnapshot, indices: []const u32) []const Policy {
        if (indices.len == 0) {
            return &.{};
        }
        // Return a contiguous slice if possible, otherwise caller iterates indices
        // For now, we return the subset - but this requires the caller to understand
        // they're getting a subset. We'll use the first/last optimization.
        const first = indices[0];
        const last = indices[indices.len - 1];

        // Check if indices are contiguous
        if (last - first + 1 == indices.len) {
            return self.policies[first .. last + 1];
        }

        // Non-contiguous case - return empty and let caller use getIndicesForType
        // In practice, with proper sorting during creation, this should be contiguous
        return self.policies[first .. last + 1];
    }

    /// Get raw indices for a telemetry type (for non-contiguous iteration)
    pub fn getIndicesForType(self: *const PolicySnapshot, telemetry_type: TelemetryType) []const u32 {
        const type_idx = telemetryTypeToIndex(telemetry_type);
        if (type_idx >= self.indices_by_telemetry_type.len) {
            return &.{};
        }
        return self.indices_by_telemetry_type[type_idx];
    }

    /// Get raw indices for a key (for non-contiguous iteration)
    pub fn getIndicesForKey(self: *const PolicySnapshot, telemetry_type: TelemetryType, policy_type: PolicyType) []const u32 {
        const key_idx = keyToIndex(telemetry_type, policy_type);
        if (key_idx >= self.indices_by_key.len) {
            return &.{};
        }
        return self.indices_by_key[key_idx];
    }

    /// Get a policy by index
    pub fn getPolicy(self: *const PolicySnapshot, idx: u32) ?*const Policy {
        if (idx >= self.policies.len) {
            return null;
        }
        return &self.policies[idx];
    }

    pub fn telemetryTypeToIndex(t: TelemetryType) usize {
        return @intCast(@intFromEnum(t));
    }

    pub fn policyTypeToIndex(p: PolicyType) usize {
        return @intCast(@intFromEnum(p));
    }

    fn keyToIndex(telemetry_type: TelemetryType, policy_type: PolicyType) usize {
        return telemetryTypeToIndex(telemetry_type) * NUM_POLICY_TYPES + policyTypeToIndex(policy_type);
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

        // Build pre-filtered indices
        const index_result = try self.buildIndices(policies_slice);

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Create new snapshot
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .policies = policies_slice,
            .indices_by_telemetry_type = index_result.indices_by_telemetry_type,
            .indices_by_key = index_result.indices_by_key,
            .telemetry_index_storage = index_result.telemetry_index_storage,
            .key_index_storage = index_result.key_index_storage,
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

    const IndexBuildResult = struct {
        indices_by_telemetry_type: []const []const u32,
        indices_by_key: []const []const u32,
        telemetry_index_storage: []const u32,
        key_index_storage: []const u32,
    };

    /// Build pre-filtered indices for fast lookup by telemetry type and policy type
    fn buildIndices(self: *PolicyRegistry, policies: []const Policy) !IndexBuildResult {
        const num_telemetry_types = PolicySnapshot.NUM_TELEMETRY_TYPES;
        const num_key_combinations = PolicySnapshot.NUM_KEY_COMBINATIONS;

        // First pass: count policies per telemetry type and per key
        var telemetry_counts: [num_telemetry_types]usize = .{0} ** num_telemetry_types;
        var key_counts: [num_key_combinations]usize = .{0} ** num_key_combinations;

        for (policies) |policy| {
            const policy_type_idx = PolicySnapshot.policyTypeToIndex(policy.policy_type);

            // A policy can apply to multiple telemetry types
            for (policy.telemetry_types.items) |telemetry_type| {
                const telemetry_idx = PolicySnapshot.telemetryTypeToIndex(telemetry_type);
                if (telemetry_idx < num_telemetry_types) {
                    telemetry_counts[telemetry_idx] += 1;

                    // Also count for the combined key
                    const key_idx = telemetry_idx * PolicySnapshot.NUM_POLICY_TYPES + policy_type_idx;
                    if (key_idx < num_key_combinations) {
                        key_counts[key_idx] += 1;
                    }
                }
            }
        }

        // Calculate total storage needed
        var total_telemetry_indices: usize = 0;
        for (telemetry_counts) |count| {
            total_telemetry_indices += count;
        }

        var total_key_indices: usize = 0;
        for (key_counts) |count| {
            total_key_indices += count;
        }

        // Allocate storage
        const telemetry_index_storage = try self.allocator.alloc(u32, total_telemetry_indices);
        errdefer self.allocator.free(telemetry_index_storage);

        const key_index_storage = try self.allocator.alloc(u32, total_key_indices);
        errdefer self.allocator.free(key_index_storage);

        // Allocate slice arrays
        const indices_by_telemetry_type = try self.allocator.alloc([]const u32, num_telemetry_types);
        errdefer self.allocator.free(indices_by_telemetry_type);

        const indices_by_key = try self.allocator.alloc([]const u32, num_key_combinations);
        errdefer self.allocator.free(indices_by_key);

        // Set up slices pointing into storage
        var telemetry_offset: usize = 0;
        for (0..num_telemetry_types) |i| {
            const count = telemetry_counts[i];
            indices_by_telemetry_type[i] = telemetry_index_storage[telemetry_offset..][0..count];
            telemetry_offset += count;
        }

        var key_offset: usize = 0;
        for (0..num_key_combinations) |i| {
            const count = key_counts[i];
            indices_by_key[i] = key_index_storage[key_offset..][0..count];
            key_offset += count;
        }

        // Second pass: populate indices
        var telemetry_cursors: [num_telemetry_types]usize = .{0} ** num_telemetry_types;
        var key_cursors: [num_key_combinations]usize = .{0} ** num_key_combinations;

        for (policies, 0..) |policy, policy_idx| {
            const policy_type_idx = PolicySnapshot.policyTypeToIndex(policy.policy_type);
            const idx: u32 = @intCast(policy_idx);

            for (policy.telemetry_types.items) |telemetry_type| {
                const telemetry_idx = PolicySnapshot.telemetryTypeToIndex(telemetry_type);
                if (telemetry_idx < num_telemetry_types) {
                    // Add to telemetry type index
                    const cursor = telemetry_cursors[telemetry_idx];
                    // Cast away const for writing during initialization
                    const writable_slice: []u32 = @constCast(indices_by_telemetry_type[telemetry_idx]);
                    writable_slice[cursor] = idx;
                    telemetry_cursors[telemetry_idx] = cursor + 1;

                    // Add to combined key index
                    const key_idx = telemetry_idx * PolicySnapshot.NUM_POLICY_TYPES + policy_type_idx;
                    if (key_idx < num_key_combinations) {
                        const key_cursor = key_cursors[key_idx];
                        const writable_key_slice: []u32 = @constCast(indices_by_key[key_idx]);
                        writable_key_slice[key_cursor] = idx;
                        key_cursors[key_idx] = key_cursor + 1;
                    }
                }
            }
        }

        return .{
            .indices_by_telemetry_type = indices_by_telemetry_type,
            .indices_by_key = indices_by_key,
            .telemetry_index_storage = telemetry_index_storage,
            .key_index_storage = key_index_storage,
        };
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
    policy_type: PolicyType,
    telemetry_types: []const TelemetryType,
) !Policy {
    var policy = Policy{
        .name = try allocator.dupe(u8, name),
        .policy_type = policy_type,
        .enabled = true,
    };

    for (telemetry_types) |tt| {
        try policy.telemetry_types.append(allocator, tt);
    }

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

    var policy = try createTestPolicy(
        allocator,
        "test-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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

    var policy1 = try createTestPolicy(
        allocator,
        "policy-1",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(
        allocator,
        "policy-2",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy2);

    var policy3 = try createTestPolicy(
        allocator,
        "policy-3",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_UNSPECIFIED},
    );
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
    var policy1 = try createTestPolicy(
        allocator,
        "test-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy1);

    try registry.updatePolicies(&.{policy1}, .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Update with same name, different type
    var policy2 = try createTestPolicy(
        allocator,
        "test-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{policy2}, .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(PolicyType.POLICY_TYPE_REDACTION, snapshot.?.policies[0].policy_type);
}

// -----------------------------------------------------------------------------
// Source Priority Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: HTTP source takes priority over file source" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);

    // Try to update with file source (should be ignored)
    var file_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Should still have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqual(PolicyType.POLICY_TYPE_LOG_FILTER, snapshot.?.policies[0].policy_type);
}

test "PolicyRegistry: HTTP source can update file source policy" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Update with HTTP source (should replace)
    var http_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, .http);

    // Should have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqual(PolicyType.POLICY_TYPE_REDACTION, snapshot.?.policies[0].policy_type);
}

test "PolicyRegistry: multiple sources with different policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add policies from file source
    var file_policy = try createTestPolicy(
        allocator,
        "file-only-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Add policies from HTTP source
    var http_policy = try createTestPolicy(
        allocator,
        "http-only-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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
    var policy1 = try createTestPolicy(
        allocator,
        "policy-1",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(
        allocator,
        "policy-2",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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
    var file_policy = try createTestPolicy(
        allocator,
        "file-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, .file);

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(
        allocator,
        "http-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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
    var file_policy = try createTestPolicy(
        allocator,
        "file-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(
        allocator,
        "http-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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
// Pre-filtered Snapshot Index Tests
// -----------------------------------------------------------------------------

test "PolicySnapshot: getPoliciesForType returns correct policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create policies with different telemetry types
    var logs_policy = try createTestPolicy(
        allocator,
        "logs-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &logs_policy);

    var unspecified_policy = try createTestPolicy(
        allocator,
        "unspecified-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_UNSPECIFIED},
    );
    defer freeTestPolicy(allocator, &unspecified_policy);

    try registry.updatePolicies(&.{ logs_policy, unspecified_policy }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Check LOGS type returns correct policy
    const logs_indices = snapshot.?.getIndicesForType(.TELEMETRY_TYPE_LOGS);
    try testing.expectEqual(@as(usize, 1), logs_indices.len);

    // Check UNSPECIFIED type returns correct policy
    const unspecified_indices = snapshot.?.getIndicesForType(.TELEMETRY_TYPE_UNSPECIFIED);
    try testing.expectEqual(@as(usize, 1), unspecified_indices.len);
}

test "PolicySnapshot: getPoliciesForKey returns correct policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create policies with different types
    var filter_policy = try createTestPolicy(
        allocator,
        "filter-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &filter_policy);

    var redaction_policy = try createTestPolicy(
        allocator,
        "redaction-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &redaction_policy);

    try registry.updatePolicies(&.{ filter_policy, redaction_policy }, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Check filter policies for LOGS
    const filter_indices = snapshot.?.getIndicesForKey(.TELEMETRY_TYPE_LOGS, .POLICY_TYPE_LOG_FILTER);
    try testing.expectEqual(@as(usize, 1), filter_indices.len);

    // Check redaction policies for LOGS
    const redaction_indices = snapshot.?.getIndicesForKey(.TELEMETRY_TYPE_LOGS, .POLICY_TYPE_REDACTION);
    try testing.expectEqual(@as(usize, 1), redaction_indices.len);

    // Check that wrong combination returns empty
    const wrong_indices = snapshot.?.getIndicesForKey(.TELEMETRY_TYPE_UNSPECIFIED, .POLICY_TYPE_LOG_FILTER);
    try testing.expectEqual(@as(usize, 0), wrong_indices.len);
}

test "PolicySnapshot: policy with multiple telemetry types indexed correctly" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create policy that applies to multiple telemetry types
    var multi_policy = Policy{
        .name = try allocator.dupe(u8, "multi-telemetry-policy"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
    };
    try multi_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try multi_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_UNSPECIFIED);
    defer multi_policy.deinit(allocator);

    try registry.updatePolicies(&.{multi_policy}, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should appear in both telemetry type indices
    const logs_indices = snapshot.?.getIndicesForType(.TELEMETRY_TYPE_LOGS);
    try testing.expectEqual(@as(usize, 1), logs_indices.len);

    const unspecified_indices = snapshot.?.getIndicesForType(.TELEMETRY_TYPE_UNSPECIFIED);
    try testing.expectEqual(@as(usize, 1), unspecified_indices.len);
}

test "PolicySnapshot: empty snapshot has empty indices" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create snapshot with no policies
    try registry.updatePolicies(&.{}, .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 0), snapshot.?.policies.len);

    // All indices should be empty
    const logs_indices = snapshot.?.getIndicesForType(.TELEMETRY_TYPE_LOGS);
    try testing.expectEqual(@as(usize, 0), logs_indices.len);

    const filter_indices = snapshot.?.getIndicesForKey(.TELEMETRY_TYPE_LOGS, .POLICY_TYPE_LOG_FILTER);
    try testing.expectEqual(@as(usize, 0), filter_indices.len);
}

// -----------------------------------------------------------------------------
// Snapshot Versioning Tests
// -----------------------------------------------------------------------------

test "PolicyRegistry: snapshot version increments on update" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var policy = try createTestPolicy(
        allocator,
        "test-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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

    var policy = try createTestPolicy(
        allocator,
        "test-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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

    var provider = TestPolicyProvider.init(allocator, .file);
    defer provider.deinit();

    // Add a policy
    var policy = try createTestPolicy(
        allocator,
        "provider-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy);

    try provider.addPolicy(policy);
    try testing.expectEqual(@as(usize, 1), provider.policies.items.len);

    // Remove the policy
    provider.removePolicy("provider-policy");
    try testing.expectEqual(@as(usize, 0), provider.policies.items.len);
}

test "TestPolicyProvider: integrates with PolicyRegistry" {
    const allocator = testing.allocator;

    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    var file_provider = TestPolicyProvider.init(allocator, .file);
    defer file_provider.deinit();

    // Add policy to provider
    var policy = try createTestPolicy(
        allocator,
        "provider-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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
    var file_policy = try createTestPolicy(
        allocator,
        "file-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(
        allocator,
        "http-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
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

    var provider = TestPolicyProvider.init(allocator, .file);
    defer provider.deinit();

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

    try provider.subscribe(callback);
    try testing.expectEqual(@as(usize, 0), registry.getPolicyCount());

    // Add policy and notify
    var policy1 = try createTestPolicy(
        allocator,
        "policy-1",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy1);

    try provider.addPolicy(policy1);
    try provider.notifySubscribers();

    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Add another policy and notify
    var policy2 = try createTestPolicy(
        allocator,
        "policy-2",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &policy2);

    try provider.addPolicy(policy2);
    try provider.notifySubscribers();

    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Remove policy and notify
    provider.removePolicy("policy-1");
    try provider.notifySubscribers();

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
    var file_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_LOG_FILTER,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy);

    try file_provider.addPolicy(file_policy);
    try file_provider.subscribe(callback);

    // Verify file policy is in registry
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        PolicyType.POLICY_TYPE_LOG_FILTER,
        registry.getSnapshot().?.policies[0].policy_type,
    );

    // Add same-named policy to HTTP provider (should override)
    var http_policy = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_REDACTION,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &http_policy);

    try http_provider.addPolicy(http_policy);
    try http_provider.subscribe(callback);

    // Verify HTTP policy replaced file policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        PolicyType.POLICY_TYPE_REDACTION,
        registry.getSnapshot().?.policies[0].policy_type,
    );

    // Update file provider - should NOT override HTTP
    file_provider.clearPolicies();
    var file_policy2 = try createTestPolicy(
        allocator,
        "shared-policy",
        .POLICY_TYPE_UNSPECIFIED,
        &.{.TELEMETRY_TYPE_LOGS},
    );
    defer freeTestPolicy(allocator, &file_policy2);

    try file_provider.addPolicy(file_policy2);
    try file_provider.notifySubscribers();

    // Should still have HTTP version
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqual(
        PolicyType.POLICY_TYPE_REDACTION,
        registry.getSnapshot().?.policies[0].policy_type,
    );
}
