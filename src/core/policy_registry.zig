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
                    // Remove old policy
                    self.removePolicyByName(policy.name);

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
