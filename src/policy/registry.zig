const std = @import("std");
const proto = @import("proto");
const policy_source = @import("./source.zig");
const policy_provider = @import("./provider.zig");
const matcher_index = @import("./matcher_index.zig");
const o11y = @import("../observability/root.zig");
const tripwire = @import("../testing/tripwire.zig");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const Policy = proto.policy.Policy;
const SourceType = policy_source.SourceType;
const PolicyMetadata = policy_source.PolicyMetadata;
const LogMatcherIndex = matcher_index.LogMatcherIndex;
const MetricMatcherIndex = matcher_index.MetricMatcherIndex;
const TraceMatcherIndex = matcher_index.TraceMatcherIndex;

// =============================================================================
// Lock-free Policy Stats
// =============================================================================

/// Atomic counters for policy statistics - lock-free updates
pub const PolicyAtomicStats = struct {
    hits: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    misses: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    // Transform stats (adds, removes, etc.) - less frequent, can batch
    transforms_applied: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    /// Atomically increment hits
    pub inline fn addHit(self: *PolicyAtomicStats) void {
        _ = self.hits.fetchAdd(1, .monotonic);
    }

    /// Atomically increment misses
    pub inline fn addMiss(self: *PolicyAtomicStats) void {
        _ = self.misses.fetchAdd(1, .monotonic);
    }

    /// Atomically increment transforms applied
    pub inline fn addTransform(self: *PolicyAtomicStats, count: i64) void {
        _ = self.transforms_applied.fetchAdd(count, .monotonic);
    }

    /// Read and reset stats atomically (for flushing)
    pub fn readAndReset(self: *PolicyAtomicStats) struct { hits: i64, misses: i64, transforms: i64 } {
        return .{
            .hits = self.hits.swap(0, .monotonic),
            .misses = self.misses.swap(0, .monotonic),
            .transforms = self.transforms_applied.swap(0, .monotonic),
        };
    }
};

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

/// Policy config types - derived from the Policy.target field
pub const PolicyConfigType = enum {
    /// Policy has a LogTarget (target.log)
    log_target,
    /// Policy has a MetricTarget (target.metric)
    metric_target,
    /// Policy has a TraceTarget (target.trace)
    trace_target,
    /// Policy has no config set
    none,

    /// Get the config type from a policy
    pub fn fromPolicy(policy: *const Policy) PolicyConfigType {
        const target = policy.target orelse return .none;
        return switch (target) {
            .log => .log_target,
            .metric => .metric_target,
            .trace => .trace_target,
        };
    }
};

/// Immutable snapshot of policies for lock-free reads
pub const PolicySnapshot = struct {
    /// All policies in this snapshot
    policies: []const Policy,

    /// Indices into policies array for log target policies
    /// Allows efficient lookup of policies by their config type
    log_target_indices: []const u32,

    /// Indices into policies array for metric target policies
    metric_target_indices: []const u32,

    /// Indices into policies array for trace target policies
    trace_target_indices: []const u32,

    /// Compiled Hyperscan-based matcher index for efficient log evaluation
    log_index: LogMatcherIndex,

    /// Compiled Hyperscan-based matcher index for efficient metric evaluation
    metric_index: MetricMatcherIndex,

    /// Compiled Hyperscan-based matcher index for efficient trace evaluation (OTLP only)
    trace_index: TraceMatcherIndex,

    /// Lock-free atomic stats per policy (indexed by policy position)
    /// Mutable even though snapshot is "immutable" - stats are append-only
    policy_stats: []PolicyAtomicStats,

    version: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PolicySnapshot) void {
        self.log_index.deinit();
        self.metric_index.deinit();
        self.trace_index.deinit();
        self.allocator.free(self.policies);
        self.allocator.free(self.log_target_indices);
        self.allocator.free(self.metric_target_indices);
        self.allocator.free(self.trace_target_indices);
        self.allocator.free(self.policy_stats);
    }

    /// Get atomic stats for a policy by index (for lock-free updates)
    pub fn getStats(self: *const PolicySnapshot, idx: u32) ?*PolicyAtomicStats {
        if (idx >= self.policy_stats.len) {
            return null;
        }
        return &self.policy_stats[idx];
    }

    /// Get a policy by index
    pub fn getPolicy(self: *const PolicySnapshot, idx: u32) ?*const Policy {
        if (idx >= self.policies.len) {
            return null;
        }
        return &self.policies[idx];
    }

    /// Get all log target policies
    pub fn getLogTargetPolicies(self: *const PolicySnapshot) []const Policy {
        if (self.log_target_indices.len == 0) {
            return &.{};
        }
        // Return a slice view - caller iterates using indices
        return self.policies;
    }

    /// Get log target policy indices for iteration
    pub fn getLogTargetIndices(self: *const PolicySnapshot) []const u32 {
        return self.log_target_indices;
    }

    /// Get metric target policy indices for iteration
    pub fn getMetricTargetIndices(self: *const PolicySnapshot) []const u32 {
        return self.metric_target_indices;
    }

    /// Iterator for log target policies
    pub fn iterateLogTargetPolicies(self: *const PolicySnapshot) LogTargetPolicyIterator {
        return .{
            .snapshot = self,
            .index = 0,
        };
    }

    /// Iterator for metric target policies
    pub fn iterateMetricTargetPolicies(self: *const PolicySnapshot) MetricTargetPolicyIterator {
        return .{
            .snapshot = self,
            .index = 0,
        };
    }

    pub const LogTargetPolicyIterator = struct {
        snapshot: *const PolicySnapshot,
        index: usize,

        pub fn next(self: *LogTargetPolicyIterator) ?*const Policy {
            if (self.index >= self.snapshot.log_target_indices.len) {
                return null;
            }
            const policy_idx = self.snapshot.log_target_indices[self.index];
            self.index += 1;
            return &self.snapshot.policies[policy_idx];
        }
    };

    pub const MetricTargetPolicyIterator = struct {
        snapshot: *const PolicySnapshot,
        index: usize,

        pub fn next(self: *MetricTargetPolicyIterator) ?*const Policy {
            if (self.index >= self.snapshot.metric_target_indices.len) {
                return null;
            }
            const policy_idx = self.snapshot.metric_target_indices[self.index];
            self.index += 1;
            return &self.snapshot.policies[policy_idx];
        }
    };
};

/// Grace period in nanoseconds before freeing old snapshots.
/// This allows in-flight readers to complete before memory is reclaimed.
const SNAPSHOT_GRACE_PERIOD_NS: u64 = 100 * std.time.ns_per_ms; // 100ms

/// Maximum number of pending snapshots waiting for cleanup.
/// If this limit is reached, we force cleanup of the oldest snapshots.
const MAX_PENDING_SNAPSHOTS: usize = 8;

/// A snapshot pending cleanup after its grace period expires
const PendingSnapshot = struct {
    snapshot: *const PolicySnapshot,
    retire_time: i128, // Timestamp when snapshot was retired
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

    // Snapshots pending cleanup after grace period
    pending_snapshots: std.ArrayListUnmanaged(PendingSnapshot),

    // Provider references for error routing, keyed by provider ID
    // These are not owned by the registry - caller must ensure they outlive the registry
    providers: std.StringHashMapUnmanaged(*policy_provider.PolicyProvider),

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
            .pending_snapshots = .{},
            .providers = .{},
            .bus = bus,
        };
    }

    /// Register a provider for error routing.
    /// The provider must outlive the registry.
    pub fn registerProvider(self: *PolicyRegistry, provider: *policy_provider.PolicyProvider) !void {
        const id = provider.getId();
        const id_copy = try self.allocator.dupe(u8, id);
        errdefer self.allocator.free(id_copy);
        try self.providers.put(self.allocator, id_copy, provider);
    }

    /// Report an error encountered when applying a policy.
    /// Routes the error to the appropriate provider based on the policy's source.
    pub fn recordPolicyError(self: *PolicyRegistry, policy_id: []const u8, error_message: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.policy_sources.get(policy_id)) |metadata| {
            if (self.providers.get(metadata.provider_id)) |provider| {
                provider.recordPolicyError(policy_id, error_message);
            } else {
                // No provider registered, log as fallback
                self.bus.err(PolicyErrorNoProvider{ .policy_id = policy_id, .message = error_message });
            }
        } else {
            // Policy not found, log
            self.bus.err(PolicyErrorNotFound{ .policy_id = policy_id, .message = error_message });
        }
    }

    /// Report statistics about policy hits, misses, and transform results.
    /// Routes the stats to the appropriate provider based on the policy's source.
    pub fn recordPolicyStats(self: *PolicyRegistry, policy_id: []const u8, hits: i64, misses: i64, transform_result: policy_provider.TransformResult) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.policy_sources.get(policy_id)) |metadata| {
            if (self.providers.get(metadata.provider_id)) |provider| {
                provider.recordPolicyStats(policy_id, hits, misses, transform_result);
            }
            // No fallback logging for stats - silent drop if no provider
        }
        // Silent drop if policy not found - stats are best-effort
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

        // Free provider keys
        var prov_it = self.providers.keyIterator();
        while (prov_it.next()) |key| {
            self.allocator.free(key.*);
        }
        self.providers.deinit(self.allocator);

        // Free all pending snapshots (force cleanup, no grace period on shutdown)
        for (self.pending_snapshots.items) |pending| {
            @constCast(pending.snapshot).deinit();
            self.allocator.destroy(pending.snapshot);
        }
        self.pending_snapshots.deinit(self.allocator);

        // Free current snapshot if exists
        // Note: snapshot.policies is a shallow copy of self.policies, so its Policy
        // structs share pointers with the originals we just freed. snapshot.deinit()
        // only frees the array itself and matcher_index, not the policy contents.
        if (self.current_snapshot.load(.acquire)) |snapshot| {
            @constCast(snapshot).deinit();
            self.allocator.destroy(snapshot);
        }
    }

    /// Update policies from a specific provider
    /// Deduplicates by id and applies priority rules based on source_type
    pub fn updatePolicies(
        self: *PolicyRegistry,
        policies: []const Policy,
        provider_id: []const u8,
        source_type: SourceType,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // Track if any changes were made
        var changed = false;

        // Track which policy ids from this provider are in the new set
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
                if (existing_meta.shouldReplace(source_type)) {
                    // Remove old policy and its source tracking
                    self.removePolicyById(policy.id);
                    if (self.policy_sources.fetchRemove(policy.id)) |kv| {
                        self.allocator.free(kv.key);
                    }

                    // Add new policy
                    try self.addPolicyInternal(policy, provider_id, source_type);
                    changed = true;
                }
                // else: higher priority source has priority, keep existing
            } else {
                // New policy, add it
                try self.addPolicyInternal(policy, provider_id, source_type);
                changed = true;
            }
        }

        // Remove policies from this provider that are no longer present
        const removed = try self.removeStalePolicies(provider_id, &new_policy_ids);
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
        provider_id: []const u8,
        source_type: SourceType,
    ) !void {
        // Deep copy the policy so we own the memory
        var policy_copy = try policy.dupe(self.allocator);
        errdefer policy_copy.deinit(self.allocator);

        try self.policies.append(self.allocator, policy_copy);

        // Track source metadata by policy id
        const id_key = try self.allocator.dupe(u8, policy.id);
        errdefer self.allocator.free(id_key);

        try self.policy_sources.put(id_key, PolicyMetadata.init(provider_id, source_type));
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

    /// Remove policies from provider that are no longer in the new set
    /// Returns the number of policies removed
    fn removeStalePolicies(
        self: *PolicyRegistry,
        provider_id: []const u8,
        new_ids: *const std.StringHashMap(void),
    ) !usize {
        var ids_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer ids_to_remove.deinit(self.allocator);

        // Find policies from this provider not in new set
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            const id = entry.key_ptr.*;
            const metadata = entry.value_ptr.*;

            // Only consider policies from this provider
            if (!std.mem.eql(u8, metadata.provider_id, provider_id)) continue;

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

    /// Tripwire for testing error paths in createSnapshot
    pub const snapshot_tw = tripwire.module(enum {
        alloc_policies,
        alloc_log_indices,
        alloc_metric_indices,
        alloc_trace_indices,
        build_log_index,
        build_metric_index,
        build_trace_index,
        alloc_policy_stats,
        create_snapshot,
    }, error{OutOfMemory});

    /// Create immutable snapshot of current policies
    fn createSnapshot(self: *PolicyRegistry) !void {
        try snapshot_tw.check(.alloc_policies);
        const policies_slice = try self.allocator.alloc(Policy, self.policies.items.len);
        errdefer self.allocator.free(policies_slice);

        @memcpy(policies_slice, self.policies.items);

        // Build indices by config type
        // First pass: count policies of each type
        var log_target_count: usize = 0;
        var metric_target_count: usize = 0;
        var trace_target_count: usize = 0;
        for (policies_slice) |*policy| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_target => log_target_count += 1,
                .metric_target => metric_target_count += 1,
                .trace_target => trace_target_count += 1,
                .none => {},
            }
        }

        // Allocate index arrays
        try snapshot_tw.check(.alloc_log_indices);
        const log_target_indices = try self.allocator.alloc(u32, log_target_count);
        errdefer self.allocator.free(log_target_indices);

        try snapshot_tw.check(.alloc_metric_indices);
        const metric_target_indices = try self.allocator.alloc(u32, metric_target_count);
        errdefer self.allocator.free(metric_target_indices);

        try snapshot_tw.check(.alloc_trace_indices);
        const trace_target_indices = try self.allocator.alloc(u32, trace_target_count);
        errdefer self.allocator.free(trace_target_indices);

        // Second pass: populate indices
        var log_target_idx: usize = 0;
        var metric_target_idx: usize = 0;
        var trace_target_idx: usize = 0;
        for (policies_slice, 0..) |*policy, i| {
            const config_type = PolicyConfigType.fromPolicy(policy);
            switch (config_type) {
                .log_target => {
                    log_target_indices[log_target_idx] = @intCast(i);
                    log_target_idx += 1;
                },
                .metric_target => {
                    metric_target_indices[metric_target_idx] = @intCast(i);
                    metric_target_idx += 1;
                },
                .trace_target => {
                    trace_target_indices[trace_target_idx] = @intCast(i);
                    trace_target_idx += 1;
                },
                .none => {},
            }
        }

        // Build matcher indices for Hyperscan-based matching
        try snapshot_tw.check(.build_log_index);
        var log_idx = try LogMatcherIndex.build(self.allocator, self.bus, policies_slice);
        errdefer log_idx.deinit();

        try snapshot_tw.check(.build_metric_index);
        var metric_idx = try MetricMatcherIndex.build(self.allocator, self.bus, policies_slice);
        errdefer metric_idx.deinit();

        try snapshot_tw.check(.build_trace_index);
        var trace_idx = try TraceMatcherIndex.build(self.allocator, self.bus, policies_slice);
        errdefer trace_idx.deinit();

        // Increment version
        const new_version = self.version.load(.monotonic) + 1;
        self.version.store(new_version, .monotonic);

        // Allocate atomic stats array for lock-free per-policy counters
        try snapshot_tw.check(.alloc_policy_stats);
        const policy_stats = try self.allocator.alloc(PolicyAtomicStats, policies_slice.len);
        errdefer self.allocator.free(policy_stats);
        // Initialize all stats to zero (default init does this)
        for (policy_stats) |*stat| {
            stat.* = .{};
        }

        // Create new snapshot with indices
        try snapshot_tw.check(.create_snapshot);
        const snapshot = try self.allocator.create(PolicySnapshot);
        snapshot.* = .{
            .policies = policies_slice,
            .log_target_indices = log_target_indices,
            .metric_target_indices = metric_target_indices,
            .trace_target_indices = trace_target_indices,
            .log_index = log_idx,
            .metric_index = metric_idx,
            .trace_index = trace_idx,
            .policy_stats = policy_stats,
            .version = new_version,
            .allocator = self.allocator,
        };

        // Swap snapshot atomically
        const old_snapshot = self.current_snapshot.swap(snapshot, .acq_rel);

        // Defer cleanup of old snapshot to allow in-flight readers to complete.
        // This implements a simple grace period mechanism to prevent use-after-free.
        if (old_snapshot) |old| {
            const now = std.time.nanoTimestamp();
            try self.pending_snapshots.append(self.allocator, .{
                .snapshot = old,
                .retire_time = now,
            });
        }

        // Clean up snapshots whose grace period has expired
        self.cleanupExpiredSnapshots();
    }

    /// Clean up snapshots whose grace period has expired.
    /// Also forces cleanup if we have too many pending snapshots.
    fn cleanupExpiredSnapshots(self: *PolicyRegistry) void {
        const now = std.time.nanoTimestamp();
        var i: usize = 0;

        while (i < self.pending_snapshots.items.len) {
            const pending = self.pending_snapshots.items[i];
            const elapsed = now - pending.retire_time;
            const grace_expired = elapsed >= SNAPSHOT_GRACE_PERIOD_NS;
            const force_cleanup = self.pending_snapshots.items.len > MAX_PENDING_SNAPSHOTS;

            if (grace_expired or force_cleanup) {
                // Grace period expired or too many pending - free this snapshot
                @constCast(pending.snapshot).deinit();
                self.allocator.destroy(pending.snapshot);
                _ = self.pending_snapshots.swapRemove(i);
                // Don't increment i - swapRemove moved an element into this position
            } else {
                i += 1;
            }
        }
    }

    /// Get current policy snapshot (lock-free read)
    pub fn getSnapshot(self: *const PolicyRegistry) ?*const PolicySnapshot {
        return self.current_snapshot.load(.acquire);
    }

    /// Clear all policies from a specific source
    /// Clear all policies from a specific provider
    pub fn clearProvider(self: *PolicyRegistry, provider_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var ids_to_remove = std.ArrayListUnmanaged([]const u8){};
        defer ids_to_remove.deinit(self.allocator);

        // Find all policies from this provider
        var it = self.policy_sources.iterator();
        while (it.next()) |entry| {
            if (std.mem.eql(u8, entry.value_ptr.provider_id, provider_id)) {
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
const PolicyCallback = policy_provider.PolicyCallback;
const PolicyUpdate = policy_provider.PolicyUpdate;

/// Test policy provider that can be configured to emit policies on demand
/// Implements the PolicyProvider interface for integration testing
pub const TestPolicyProvider = struct {
    allocator: std.mem.Allocator,
    id: []const u8,
    source_type: SourceType,
    policies: std.ArrayListUnmanaged(Policy),
    callbacks: std.ArrayListUnmanaged(PolicyCallback),

    pub fn init(allocator: std.mem.Allocator, id: []const u8, source_type: SourceType) TestPolicyProvider {
        return .{
            .allocator = allocator,
            .id = id,
            .source_type = source_type,
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

    /// Get the unique identifier for this provider
    pub fn getId(self: *TestPolicyProvider) []const u8 {
        return self.id;
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
            .provider_id = self.id,
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
            .provider_id = self.id,
        };
        try callback.call(update);
    }

    /// Record policy errors (no-op for tests)
    pub fn recordPolicyError(self: *TestPolicyProvider, policy_id: []const u8, error_message: []const u8) void {
        _ = self;
        _ = policy_id;
        _ = error_message;
    }

    /// Record policy stats (no-op for tests)
    pub fn recordPolicyStats(self: *TestPolicyProvider, policy_id: []const u8, hits: i64, misses: i64, transform_result: policy_provider.TransformResult) void {
        _ = self;
        _ = policy_id;
        _ = hits;
        _ = misses;
        _ = transform_result;
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

    try registry.updatePolicies(&.{policy}, "file-provider", .file);

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

    try registry.updatePolicies(&.{ policy1, policy2, policy3 }, "file-provider", .file);

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

    try registry.updatePolicies(&.{policy1}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    // Update with same name but different description
    var policy2 = try createTestPolicy(allocator, "test-policy");
    policy2.description = try allocator.dupe(u8, "updated description");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{policy2}, "file-provider", .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("updated description", snapshot.?.policies[0].description);
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
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Try to update with file source (should be ignored)
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Should still have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("http version", snapshot.?.policies[0].description);
}

test "PolicyRegistry: HTTP source can update file source policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Add policy from file source
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version");
    defer freeTestPolicy(allocator, &file_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Update with HTTP source (should replace)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

    // Should have the HTTP version
    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqual(@as(usize, 1), snapshot.?.policies.len);
    try testing.expectEqualStrings("http version", snapshot.?.policies[0].description);
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

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Add policies from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-only-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

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

    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update with only one policy (policy-2 should be removed)
    try registry.updatePolicies(&.{policy1}, "file-provider", .file);
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

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);

    // Add policy from HTTP source
    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Update file source with empty set (should only remove file-policy)
    try registry.updatePolicies(&.{}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);
    try testing.expectEqualStrings("http-policy", snapshot.?.policies[0].name);
}

test "PolicyRegistry: clearProvider removes all policies from provider" {
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

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);
    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());

    // Clear file provider
    try registry.clearProvider("file-provider");
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
    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const snapshot1 = registry.getSnapshot();
    try testing.expect(snapshot1 != null);
    try testing.expectEqual(@as(u64, 1), snapshot1.?.version);

    // Second update
    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const snapshot2 = registry.getSnapshot();
    try testing.expect(snapshot2 != null);
    try testing.expectEqual(@as(u64, 2), snapshot2.?.version);

    // Third update
    try registry.updatePolicies(&.{}, "file-provider", .file);
    const snapshot3 = registry.getSnapshot();
    try testing.expect(snapshot3 != null);
    try testing.expectEqual(@as(u64, 3), snapshot3.?.version);
}

test "PolicyRegistry: clearProvider increments version" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, "file-provider", .file);
    const version_before = registry.getSnapshot().?.version;

    try registry.clearProvider("file-provider");
    const version_after = registry.getSnapshot().?.version;

    try testing.expect(version_after > version_before);
}

// -----------------------------------------------------------------------------
// TestPolicyProvider Integration Tests
// -----------------------------------------------------------------------------

test "TestPolicyProvider: basic functionality" {
    const allocator = testing.allocator;

    var prov = TestPolicyProvider.init(allocator, "file-provider", .file);
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

    var file_provider = TestPolicyProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    // Add policy to provider
    var policy = try createTestPolicy(allocator, "provider-policy");
    defer freeTestPolicy(allocator, &policy);

    try file_provider.addPolicy(policy);

    // Create callback that updates registry
    const Ctx = struct {
        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var ctx = Ctx{ .registry = &registry, .source_type = .file };
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

    var file_provider = TestPolicyProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    var http_provider = TestPolicyProvider.init(allocator, "http-provider", .http);
    defer http_provider.deinit();

    // Add policies to providers
    var file_policy = try createTestPolicy(allocator, "file-policy");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy");
    defer freeTestPolicy(allocator, &http_policy);

    try file_provider.addPolicy(file_policy);
    try http_provider.addPolicy(http_policy);

    // Create callbacks with source types
    const Ctx = struct {
        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var file_ctx = Ctx{ .registry = &registry, .source_type = .file };
    const file_callback = PolicyCallback{
        .context = &file_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    var http_ctx = Ctx{ .registry = &registry, .source_type = .http };
    const http_callback = PolicyCallback{
        .context = &http_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Subscribe to both providers
    try file_provider.subscribe(file_callback);
    try http_provider.subscribe(http_callback);

    // Registry should have both policies
    try testing.expectEqual(@as(usize, 2), registry.getPolicyCount());
}

test "TestPolicyProvider: notifySubscribers updates registry" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var prov = TestPolicyProvider.init(allocator, "file-provider", .file);
    defer prov.deinit();

    // Create and subscribe callback
    const Ctx = struct {
        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var ctx = Ctx{ .registry = &registry, .source_type = .file };
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

    var file_provider = TestPolicyProvider.init(allocator, "file-provider", .file);
    defer file_provider.deinit();

    var http_provider = TestPolicyProvider.init(allocator, "http-provider", .http);
    defer http_provider.deinit();

    // Create callbacks with source types
    const Ctx = struct {
        registry: *PolicyRegistry,
        source_type: SourceType,

        fn onUpdate(ctx_ptr: *anyopaque, update: PolicyUpdate) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));
            try self.registry.updatePolicies(update.policies, update.provider_id, self.source_type);
        }
    };

    var file_ctx = Ctx{ .registry = &registry, .source_type = .file };
    const file_callback = PolicyCallback{
        .context = &file_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    var http_ctx = Ctx{ .registry = &registry, .source_type = .http };
    const http_callback = PolicyCallback{
        .context = &http_ctx,
        .onUpdate = Ctx.onUpdate,
    };

    // Add same-named policy to file provider first
    var file_policy = try createTestPolicy(allocator, "shared-policy");
    file_policy.description = try allocator.dupe(u8, "file version 1");
    defer freeTestPolicy(allocator, &file_policy);

    try file_provider.addPolicy(file_policy);
    try file_provider.subscribe(file_callback);

    // Verify file policy is in registry
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "file version 1",
        registry.getSnapshot().?.policies[0].description,
    );

    // Add same-named policy to HTTP provider (should override)
    var http_policy = try createTestPolicy(allocator, "shared-policy");
    http_policy.description = try allocator.dupe(u8, "http version");
    defer freeTestPolicy(allocator, &http_policy);

    try http_provider.addPolicy(http_policy);
    try http_provider.subscribe(http_callback);

    // Verify HTTP policy replaced file policy
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "http version",
        registry.getSnapshot().?.policies[0].description,
    );

    // Update file provider - should NOT override HTTP
    file_provider.clearPolicies();
    var file_policy2 = try createTestPolicy(allocator, "shared-policy");
    file_policy2.description = try allocator.dupe(u8, "file version 2");
    defer freeTestPolicy(allocator, &file_policy2);

    try file_provider.addPolicy(file_policy2);
    try file_provider.notifySubscribers();

    // Should still have HTTP version
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());
    try testing.expectEqualStrings(
        "http version",
        registry.getSnapshot().?.policies[0].description,
    );
}

// -----------------------------------------------------------------------------
// Policy Config Type Indexing Tests
// -----------------------------------------------------------------------------

const LogTarget = proto.policy.LogTarget;

/// Helper to create a test policy with a log target config
fn createTestPolicyWithFilter(
    allocator: std.mem.Allocator,
    name: []const u8,
) !Policy {
    var policy = Policy{
        .id = try allocator.dupe(u8, name), // Use name as id for tests
        .name = try allocator.dupe(u8, name),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    _ = &policy;

    return policy;
}

test "PolicyConfigType: fromPolicy returns log_target when log is set" {
    const allocator = testing.allocator;

    var policy = try createTestPolicyWithFilter(allocator, "filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.log_target, config_type);
}

test "PolicyConfigType: fromPolicy returns none when log is null" {
    const allocator = testing.allocator;

    var policy = try createTestPolicy(allocator, "no-filter-policy");
    defer freeTestPolicy(allocator, &policy);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.none, config_type);
}

test "PolicySnapshot: log_target_indices contains only log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create mix of policies with and without log targets
    var policy_no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy_no_filter);

    var policy_with_filter = try createTestPolicyWithFilter(allocator, "with-filter");
    defer freeTestPolicy(allocator, &policy_with_filter);

    var another_no_filter = try createTestPolicy(allocator, "another-no-filter");
    defer freeTestPolicy(allocator, &another_no_filter);

    try registry.updatePolicies(&.{ policy_no_filter, policy_with_filter, another_no_filter }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should have 3 total policies but only 1 log target index
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // The indexed policy should be the one with log target
    const indexed_policy = snapshot.?.policies[snapshot.?.log_target_indices[0]];
    try testing.expectEqualStrings("with-filter", indexed_policy.name);
    try testing.expect(indexed_policy.target != null);
}

test "PolicySnapshot: multiple log policies are indexed" {
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

    try registry.updatePolicies(&.{ filter1, filter2, filter3 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // All 3 policies should be indexed
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 3), snapshot.?.log_target_indices.len);
}

test "PolicySnapshot: empty when no log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy1 = try createTestPolicy(allocator, "policy-1");
    defer freeTestPolicy(allocator, &policy1);

    var policy2 = try createTestPolicy(allocator, "policy-2");
    defer freeTestPolicy(allocator, &policy2);

    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // No log target indices
    try testing.expectEqual(@as(usize, 2), snapshot.?.policies.len);
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_target_indices.len);
}

test "PolicySnapshot: iterateLogTargetPolicies returns all log policies" {
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

    try registry.updatePolicies(&.{ no_filter, filter1, filter2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Iterate and collect names
    var iter = snapshot.?.iterateLogTargetPolicies();
    var count: usize = 0;
    var found_filter1 = false;
    var found_filter2 = false;

    while (iter.next()) |policy| {
        count += 1;
        try testing.expect(policy.target != null);

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

test "PolicySnapshot: iterator returns null when no log policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var policy = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &policy);

    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    var iter = snapshot.?.iterateLogTargetPolicies();
    try testing.expect(iter.next() == null);
}

test "PolicySnapshot: indices update when policies change" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Start with one log policy
    var filter1 = try createTestPolicyWithFilter(allocator, "filter-1");
    defer freeTestPolicy(allocator, &filter1);

    try registry.updatePolicies(&.{filter1}, "file-provider", .file);

    var snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // Add another log policy
    var filter2 = try createTestPolicyWithFilter(allocator, "filter-2");
    defer freeTestPolicy(allocator, &filter2);

    try registry.updatePolicies(&.{ filter1, filter2 }, "file-provider", .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 2), snapshot.?.log_target_indices.len);

    // Remove log policies, add non-log
    var no_filter = try createTestPolicy(allocator, "no-filter");
    defer freeTestPolicy(allocator, &no_filter);

    try registry.updatePolicies(&.{no_filter}, "file-provider", .file);

    snapshot = registry.getSnapshot();
    try testing.expectEqual(@as(usize, 0), snapshot.?.log_target_indices.len);
}

// -----------------------------------------------------------------------------
// Policy Error Routing Tests
// -----------------------------------------------------------------------------

/// Mock provider that records errors for testing
const MockErrorProvider = struct {
    recorded_errors: std.ArrayListUnmanaged(struct { policy_id: []const u8, message: []const u8 }),
    allocator: std.mem.Allocator,
    id: []const u8,

    fn init(allocator: std.mem.Allocator, id: []const u8) MockErrorProvider {
        return .{
            .recorded_errors = .{},
            .allocator = allocator,
            .id = id,
        };
    }

    pub fn getId(self: *MockErrorProvider) []const u8 {
        return self.id;
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

    pub fn recordPolicyStats(self: *MockErrorProvider, policy_id: []const u8, hits: i64, misses: i64, transform_result: policy_provider.TransformResult) void {
        // No-op for mock - stats tracking not needed for error tests
        _ = self;
        _ = policy_id;
        _ = hits;
        _ = misses;
        _ = transform_result;
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
    var file_mock = MockErrorProvider.init(allocator, "file-provider");
    defer file_mock.deinit();

    var http_mock = MockErrorProvider.init(allocator, "http-provider");
    defer http_mock.deinit();

    // Register providers
    var file_provider = policy_provider.PolicyProvider.init(&file_mock);
    var http_provider = policy_provider.PolicyProvider.init(&http_mock);

    try registry.registerProvider(&file_provider);
    try registry.registerProvider(&http_provider);

    // Add policies from different sources
    var file_policy = try createTestPolicy(allocator, "file-policy-1");
    defer freeTestPolicy(allocator, &file_policy);

    var http_policy = try createTestPolicy(allocator, "http-policy-1");
    defer freeTestPolicy(allocator, &http_policy);

    try registry.updatePolicies(&.{file_policy}, "file-provider", .file);
    try registry.updatePolicies(&.{http_policy}, "http-provider", .http);

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

    var mock = MockErrorProvider.init(allocator, "file-provider");
    defer mock.deinit();

    var provider = policy_provider.PolicyProvider.init(&mock);
    try registry.registerProvider(&provider);

    // Add a real policy so we can test error routing works
    var real_policy = try createTestPolicy(allocator, "real-policy");
    defer freeTestPolicy(allocator, &real_policy);
    try registry.updatePolicies(&.{real_policy}, "file-provider", .file);

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

    var mock = MockErrorProvider.init(allocator, "file-provider");
    defer mock.deinit();

    var provider = policy_provider.PolicyProvider.init(&mock);
    try registry.registerProvider(&provider);

    var policy = try createTestPolicy(allocator, "error-prone-policy");
    defer freeTestPolicy(allocator, &policy);
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

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
    };
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "id-2"),
        .name = try allocator.dupe(u8, "same-name"),
        .enabled = true,
    };
    defer policy2.deinit(allocator);

    // Both should be added (different ids)
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

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
        .description = try allocator.dupe(u8, "version 1"),
    };
    defer policy_v1.deinit(allocator);

    try registry.updatePolicies(&.{policy_v1}, "file-provider", .file);
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    var snapshot = registry.getSnapshot();
    try testing.expectEqualStrings("version 1", snapshot.?.policies[0].description);

    // Update with same id, different description
    var policy_v2 = Policy{
        .id = try allocator.dupe(u8, "policy-123"),
        .name = try allocator.dupe(u8, "my-policy-renamed"),
        .enabled = true,
        .description = try allocator.dupe(u8, "version 2"),
    };
    defer policy_v2.deinit(allocator);

    try registry.updatePolicies(&.{policy_v2}, "file-provider", .file);

    // Should still have 1 policy, but updated
    try testing.expectEqual(@as(usize, 1), registry.getPolicyCount());

    snapshot = registry.getSnapshot();
    try testing.expectEqualStrings("version 2", snapshot.?.policies[0].description);
    try testing.expectEqualStrings("my-policy-renamed", snapshot.?.policies[0].name);
}

// -----------------------------------------------------------------------------
// Metric Policy Tests
// -----------------------------------------------------------------------------

const MetricTarget = proto.policy.MetricTarget;

test "PolicyConfigType: fromPolicy returns metric_target when metric is set" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy"),
        .name = try allocator.dupe(u8, "metric-policy"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer policy.deinit(allocator);

    const config_type = PolicyConfigType.fromPolicy(&policy);
    try testing.expectEqual(PolicyConfigType.metric_target, config_type);
}

test "PolicySnapshot: metric_target_indices contains only metric policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a log policy
    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy"),
        .name = try allocator.dupe(u8, "log-policy"),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    defer log_policy.deinit(allocator);

    // Create a metric policy
    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy"),
        .name = try allocator.dupe(u8, "metric-policy"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer metric_policy.deinit(allocator);

    // Create a policy with no target
    var no_target_policy = try createTestPolicy(allocator, "no-target");
    defer freeTestPolicy(allocator, &no_target_policy);

    // Add all policies
    try registry.updatePolicies(&.{ log_policy, metric_policy, no_target_policy }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Should have 3 policies total
    try testing.expectEqual(@as(usize, 3), snapshot.?.policies.len);

    // Should have 1 log policy indexed
    try testing.expectEqual(@as(usize, 1), snapshot.?.log_target_indices.len);

    // Should have 1 metric policy indexed
    try testing.expectEqual(@as(usize, 1), snapshot.?.metric_target_indices.len);

    // Verify the log policy is correct
    const log_policy_idx = snapshot.?.log_target_indices[0];
    try testing.expectEqualStrings("log-policy", snapshot.?.policies[log_policy_idx].name);

    // Verify the metric policy is correct
    const metric_policy_idx = snapshot.?.metric_target_indices[0];
    try testing.expectEqualStrings("metric-policy", snapshot.?.policies[metric_policy_idx].name);
}

test "PolicySnapshot: iterateMetricTargetPolicies iterates only metric policies" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create two metric policies
    var metric_policy1 = Policy{
        .id = try allocator.dupe(u8, "metric-1"),
        .name = try allocator.dupe(u8, "metric-1"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = true,
        } },
    };
    defer metric_policy1.deinit(allocator);

    var metric_policy2 = Policy{
        .id = try allocator.dupe(u8, "metric-2"),
        .name = try allocator.dupe(u8, "metric-2"),
        .enabled = true,
        .target = .{ .metric = MetricTarget{
            .match = .empty,
            .keep = false,
        } },
    };
    defer metric_policy2.deinit(allocator);

    // Create a log policy (should not be in metric iteration)
    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy"),
        .name = try allocator.dupe(u8, "log-policy"),
        .enabled = true,
        .target = .{ .log = LogTarget{
            .match = .empty,
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    defer log_policy.deinit(allocator);

    try registry.updatePolicies(&.{ metric_policy1, log_policy, metric_policy2 }, "file-provider", .file);

    const snapshot = registry.getSnapshot();
    try testing.expect(snapshot != null);

    // Iterate metric policies
    var iter = snapshot.?.iterateMetricTargetPolicies();
    var count: usize = 0;
    var found_metric1 = false;
    var found_metric2 = false;

    while (iter.next()) |policy| {
        count += 1;
        try testing.expect(policy.target != null);

        if (std.mem.eql(u8, policy.name, "metric-1")) {
            found_metric1 = true;
        } else if (std.mem.eql(u8, policy.name, "metric-2")) {
            found_metric2 = true;
        }
    }

    try testing.expectEqual(@as(usize, 2), count);
    try testing.expect(found_metric1);
    try testing.expect(found_metric2);
}

// -----------------------------------------------------------------------------
// Tripwire Tests for createSnapshot
// -----------------------------------------------------------------------------

test "PolicyRegistry.createSnapshot: tripwire alloc_policies fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.alloc_policies, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire alloc_log_indices fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.alloc_log_indices, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire alloc_metric_indices fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.alloc_metric_indices, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire alloc_trace_indices fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.alloc_trace_indices, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire build_log_index fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.build_log_index, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire build_metric_index fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.build_metric_index, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire build_trace_index fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.build_trace_index, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire alloc_policy_stats fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.alloc_policy_stats, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}

test "PolicyRegistry.createSnapshot: tripwire create_snapshot fails" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    PolicyRegistry.snapshot_tw.errorAlways(.create_snapshot, error.OutOfMemory);
    defer PolicyRegistry.snapshot_tw.reset();

    var policy = try createTestPolicy(allocator, "test-policy");
    defer freeTestPolicy(allocator, &policy);

    const result = registry.updatePolicies(&.{policy}, "file-provider", .file);
    try testing.expectError(error.OutOfMemory, result);
    try PolicyRegistry.snapshot_tw.end(.retain);
}
