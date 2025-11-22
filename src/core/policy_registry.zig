const std = @import("std");
const policy_pb = @import("../proto/tero/edge/policy/v1.pb.zig");
const policy_source = @import("policy_source.zig");

const Policy = policy_pb.Policy;
const TelemetryType = policy_pb.TelemetryType;
const SourceType = policy_source.SourceType;
const PolicyKey = policy_source.PolicyKey;
const PolicyMetadata = policy_source.PolicyMetadata;

/// Immutable snapshot of policies for lock-free reads
/// Following DoD principles: policies grouped by telemetry type for cache locality
pub const PolicySnapshot = struct {
    log_policies: []const Policy,
    metric_policies: []const Policy,
    span_policies: []const Policy,
    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *const PolicySnapshot) void {
        // Free policy slices
        self.allocator.free(self.log_policies);
        self.allocator.free(self.metric_policies);
        self.allocator.free(self.span_policies);
    }
};

/// Centralized policy registry with multi-source support
/// Hot data (policies) optimized for evaluation, cold data (metadata) for updates
pub const PolicyRegistry = struct {
    // HOT DATA: Policies optimized for cache-friendly iteration
    log_policies: std.MultiArrayList(Policy),
    metric_policies: std.MultiArrayList(Policy),
    span_policies: std.MultiArrayList(Policy),

    // COLD DATA: Source tracking for deduplication and priority
    // Key: "name:telemetry_type", Value: PolicyMetadata
    policy_sources: std.StringHashMap(PolicyMetadata),

    // Synchronization
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,
    version: std.atomic.Value(u64),

    // Current immutable snapshot for lock-free reads
    current_snapshot: std.atomic.Value(?*const PolicySnapshot),

    pub fn init(allocator: std.mem.Allocator) PolicyRegistry {
        return .{
            .log_policies = .{},
            .metric_policies = .{},
            .span_policies = .{},
            .policy_sources = std.StringHashMap(PolicyMetadata).init(allocator),
            .mutex = .{},
            .allocator = allocator,
            .version = std.atomic.Value(u64).init(0),
            .current_snapshot = std.atomic.Value(?*const PolicySnapshot).init(null),
        };
    }

    pub fn deinit(self: *PolicyRegistry) void {
        self.log_policies.deinit(self.allocator);
        self.metric_policies.deinit(self.allocator);
        self.span_policies.deinit(self.allocator);

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
    /// Deduplicates by (name, telemetry_type) and applies priority rules
    pub fn updatePolicies(
        self: *PolicyRegistry,
        policies: []const Policy,
        source: SourceType,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Track which policies from this source are in the new set
        var new_policy_keys = std.StringHashMap(void).init(self.allocator);
        defer {
            var it = new_policy_keys.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            new_policy_keys.deinit();
        }

        // Process each incoming policy
        for (policies) |policy| {
            const key = PolicyKey{
                .name = policy.name,
                .telemetry_type = policy.telemetry_type,
            };
            const key_string = try key.toString(self.allocator);
            errdefer self.allocator.free(key_string);

            // Track this key as present in new set
            const new_key_copy = try self.allocator.dupe(u8, key_string);
            try new_policy_keys.put(new_key_copy, {});

            // Check if policy already exists
            if (self.policy_sources.get(key_string)) |existing_meta| {
                // Apply priority rules
                if (existing_meta.shouldReplace(source)) {
                    // Remove old policy
                    try self.removePolicyByKey(key);

                    // Add new policy
                    try self.addPolicyInternal(policy, source, key_string);
                } else {
                    // HTTP has priority, keep existing, free key
                    self.allocator.free(key_string);
                }
            } else {
                // New policy, add it
                try self.addPolicyInternal(policy, source, key_string);
            }
        }

        // Remove policies from this source that are no longer present
        try self.removeStalePolicies(source, &new_policy_keys);

        // Create new immutable snapshot
        try self.createSnapshot();
    }

    /// Add a policy to the appropriate list and track its source
    fn addPolicyInternal(
        self: *PolicyRegistry,
        policy: Policy,
        source: SourceType,
        key_string: []const u8,
    ) !void {
        // Add to appropriate telemetry list
        switch (policy.telemetry_type) {
            .TELEMETRY_TYPE_LOG => try self.log_policies.append(self.allocator, policy),
            .TELEMETRY_TYPE_METRIC => try self.metric_policies.append(self.allocator, policy),
            .TELEMETRY_TYPE_SPAN => try self.span_policies.append(self.allocator, policy),
            else => {}, // Ignore unknown types
        }

        // Track source metadata
        try self.policy_sources.put(key_string, PolicyMetadata.init(source));
    }

    /// Remove a policy by its key from the appropriate list
    fn removePolicyByKey(self: *PolicyRegistry, key: PolicyKey) !void {
        const list = switch (key.telemetry_type) {
            .TELEMETRY_TYPE_LOG => &self.log_policies,
            .TELEMETRY_TYPE_METRIC => &self.metric_policies,
            .TELEMETRY_TYPE_SPAN => &self.span_policies,
            else => return,
        };

        // Find and remove the policy with matching name
        const names = list.items(.name);
        for (names, 0..) |name, i| {
            if (std.mem.eql(u8, name, key.name)) {
                _ = list.swapRemove(i);
                break;
            }
        }
    }

    /// Remove policies from source that are no longer in the new set
    fn removeStalePolicies(
        self: *PolicyRegistry,
        source: SourceType,
        new_keys: *const std.StringHashMap(void),
    ) !void {
        var keys_to_remove: std.ArrayList([]const u8) = .empty;
        defer keys_to_remove.deinit(self.allocator);

        // Find policies from this source not in new set
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            const key_string = entry.key_ptr.*;
            const metadata = entry.value_ptr.*;

            // Only consider policies from this source
            if (metadata.source != source) continue;

            // If not in new set, mark for removal
            if (!new_keys.contains(key_string)) {
                try keys_to_remove.append(self.allocator, key_string);
            }
        }

        // Remove stale policies
        for (keys_to_remove.items) |key_string| {
            const key = try PolicyKey.fromString(self.allocator, key_string);
            defer self.allocator.free(key.name);

            try self.removePolicyByKey(key);

            // Remove from source tracking
            _ = self.policy_sources.remove(key_string);
            self.allocator.free(key_string);
        }
    }

    /// Create immutable snapshot of current policies
    fn createSnapshot(self: *PolicyRegistry) !void {
        // Create slices for each telemetry type
        const log_slice = try self.allocator.alloc(Policy, self.log_policies.len);
        errdefer self.allocator.free(log_slice);

        const metric_slice = try self.allocator.alloc(Policy, self.metric_policies.len);
        errdefer self.allocator.free(metric_slice);

        const span_slice = try self.allocator.alloc(Policy, self.span_policies.len);
        errdefer self.allocator.free(span_slice);

        // Copy policies to slices by accessing fields from MultiArrayList
        const log_data = self.log_policies.slice();
        for (0..self.log_policies.len) |i| {
            log_slice[i] = .{
                .name = log_data.items(.name)[i],
                .policy_type = log_data.items(.policy_type)[i],
                .telemetry_type = log_data.items(.telemetry_type)[i],
                .regexes = log_data.items(.regexes)[i],
                .action = log_data.items(.action)[i],
            };
        }

        const metric_data = self.metric_policies.slice();
        for (0..self.metric_policies.len) |i| {
            metric_slice[i] = .{
                .name = metric_data.items(.name)[i],
                .policy_type = metric_data.items(.policy_type)[i],
                .telemetry_type = metric_data.items(.telemetry_type)[i],
                .regexes = metric_data.items(.regexes)[i],
                .action = metric_data.items(.action)[i],
            };
        }

        const span_data = self.span_policies.slice();
        for (0..self.span_policies.len) |i| {
            span_slice[i] = .{
                .name = span_data.items(.name)[i],
                .policy_type = span_data.items(.policy_type)[i],
                .telemetry_type = span_data.items(.telemetry_type)[i],
                .regexes = span_data.items(.regexes)[i],
                .action = span_data.items(.action)[i],
            };
        }

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Create new snapshot
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .log_policies = log_slice,
            .metric_policies = metric_slice,
            .span_policies = span_slice,
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

        var keys_to_remove: std.ArrayList([]const u8) = .empty;
        defer keys_to_remove.deinit(self.allocator);

        // Find all policies from this source
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.source == source) {
                try keys_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Remove each policy
        for (keys_to_remove.items) |key_string| {
            const key = try PolicyKey.fromString(self.allocator, key_string);
            defer self.allocator.free(key.name);

            try self.removePolicyByKey(key);

            _ = self.policy_sources.remove(key_string);
            self.allocator.free(key_string);
        }

        // Create new snapshot
        try self.createSnapshot();
    }

    /// Get total policy count across all types
    pub fn getPolicyCount(self: *const PolicyRegistry) usize {
        return self.log_policies.len + self.metric_policies.len + self.span_policies.len;
    }

    /// Get source metadata for a specific policy (debug/introspection)
    pub fn getPolicySource(
        self: *const PolicyRegistry,
        key: PolicyKey,
    ) !?PolicyMetadata {
        const key_string = try key.toString(self.allocator);
        defer self.allocator.free(key_string);

        return self.policy_sources.get(key_string);
    }
};
