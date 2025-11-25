const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./policy_source.zig");

const Policy = proto.policy.Policy;
const TelemetryType = proto.policy.TelemetryType;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    policies: []const Policy,
    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const PolicySnapshot) void {
        self.allocator.free(self.policies);
    }

    /// Get policies that apply to a specific telemetry type
    pub fn getPoliciesForType(self: *const PolicySnapshot, telemetry_type: TelemetryType) []const Policy {
        // Since policies can apply to multiple telemetry types, we need to filter
        // For now, return all policies and let the evaluator filter
        // TODO: Pre-filter during snapshot creation for better performance
        _ = telemetry_type;
        return self.policies;
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
    fn addPolicyInternal(
        self: *PolicyRegistry,
        policy: Policy,
        source: SourceType,
    ) !void {
        try self.policies.append(self.allocator, policy);

        // Track source metadata
        const name_key = try self.allocator.dupe(u8, policy.name);
        try self.policy_sources.put(name_key, PolicyMetadata.init(source));
    }

    /// Remove a policy by name
    fn removePolicyByName(self: *PolicyRegistry, name: []const u8) void {
        for (self.policies.items, 0..) |policy, i| {
            if (std.mem.eql(u8, policy.name, name)) {
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
