//! Policy Engine - Hyperscan-based policy evaluation
//!
//! This module provides efficient policy evaluation using an inverted index
//! of Hyperscan databases. Instead of iterating through policies and checking
//! matchers, we:
//!
//! 1. Iterate through matcher keys (MatchCase, attribute_key)
//! 2. Scan field values against pre-compiled Hyperscan databases
//! 3. Aggregate match counts per policy using O(1) array operations
//! 4. Select the highest priority policy where all matchers matched
//!
//! ## Policy Stages
//!
//! Policies now contain both filter and transform stages:
//! 1. **Filter Stage**: Determines keep/drop based on `keep` field
//! 2. **Transform Stage**: Applies modifications (redact, remove, rename, add)
//!
//! The engine evaluates the filter stage first. If the decision is to drop,
//! evaluation stops early. Otherwise, matched policies are returned for
//! transform processing.
//!
//! ## Performance Characteristics
//!
//! - O(k * n) where k = number of unique matcher keys, n = input text length
//! - O(1) per-pattern match aggregation using numeric policy indices
//! - Independent of the number of policies or patterns per key
//! - Lock-free reads from atomic snapshot pointer

const std = @import("std");
const proto = @import("proto");
const matcher_index = @import("./matcher_index.zig");
const policy_mod = @import("./root.zig");
const policy_types = @import("./types.zig");
const log_transform = @import("./log_transform.zig");
const sampler_mod = @import("./sampler.zig");
const rate_limiter_mod = @import("./rate_limiter.zig");

const o11y = @import("../observability/root.zig");
const NoopEventBus = o11y.NoopEventBus;
const EventBus = o11y.EventBus;

const LogMatcher = proto.policy.LogMatcher;

const KeepValue = matcher_index.KeepValue;
const PolicyIndex = matcher_index.PolicyIndex;
const PolicyInfo = matcher_index.PolicyInfo;
const MAX_POLICIES = matcher_index.MAX_POLICIES;
const Sampler = sampler_mod.Sampler;
const RateLimiter = rate_limiter_mod.RateLimiter;

const MatcherDatabase = matcher_index.MatcherDatabase;
pub const PolicyRegistry = policy_mod.Registry;
pub const PolicySnapshot = policy_mod.Snapshot;

// Re-export types for callers
pub const FieldRef = policy_types.FieldRef;
pub const MetricFieldRef = policy_types.MetricFieldRef;
pub const LogFieldAccessor = policy_types.LogFieldAccessor;
pub const LogFieldMutator = policy_types.LogFieldMutator;
pub const MetricFieldAccessor = policy_types.MetricFieldAccessor;
pub const MetricFieldMutator = policy_types.MetricFieldMutator;
pub const MutateOp = policy_types.MutateOp;
pub const MetricMutateOp = policy_types.MetricMutateOp;
pub const TelemetryType = policy_types.TelemetryType;

// Proto types
const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const MetricTarget = proto.policy.MetricTarget;

/// Maximum number of pattern matches to track per scan
pub const MAX_MATCHES_PER_SCAN: usize = 256;

/// Helper to extract the log target from a policy (handles target union)
pub fn getLogTarget(policy: *const Policy) ?*const LogTarget {
    const target_ptr = &(policy.target orelse return null);
    return switch (target_ptr.*) {
        .log => |*log| log,
        .metric => null,
    };
}

/// Helper to extract the metric target from a policy (handles target union)
pub fn getMetricTarget(policy: *const Policy) ?*const MetricTarget {
    const target_ptr = &(policy.target orelse return null);
    return switch (target_ptr.*) {
        .log => null,
        .metric => |*metric| metric,
    };
}

// =============================================================================
// FilterDecision - Result of filter stage evaluation
// =============================================================================

/// Decision from the filter stage of policy evaluation
pub const FilterDecision = enum {
    /// Keep the telemetry (explicitly matched a keep policy)
    keep,
    /// Drop the telemetry (matched a drop policy)
    drop,
    /// No policy matched - default behavior (keep)
    unset,

    /// Returns true if telemetry should continue to next stage
    pub fn shouldContinue(self: FilterDecision) bool {
        return self != .drop;
    }
};

// =============================================================================
// PolicyResult - Complete evaluation result
// =============================================================================

/// Result of policy evaluation containing filter decision and matched policies
pub const PolicyResult = struct {
    /// The filter decision (keep/drop/unset)
    decision: FilterDecision,
    /// IDs of policies that matched (for transform stage lookup)
    /// Only populated when decision is keep or unset
    matched_policy_ids: []const []const u8,
    /// Whether any transformations were applied to the telemetry
    /// Callers should use this to determine if re-encoding is needed
    was_transformed: bool = false,

    /// Empty result for dropped telemetry
    pub const dropped = PolicyResult{
        .decision = .drop,
        .matched_policy_ids = &.{},
        .was_transformed = false,
    };

    /// Default result when no policies match
    pub const unmatched = PolicyResult{
        .decision = .unset,
        .matched_policy_ids = &.{},
        .was_transformed = false,
    };
};

// =============================================================================
// Comptime Type Helpers - Select types based on telemetry type
// =============================================================================

/// Returns the field reference type for the given telemetry type
fn FieldRefType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => FieldRef,
        .metric => MetricFieldRef,
    };
}

/// Returns the field accessor function type for the given telemetry type
fn FieldAccessorType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogFieldAccessor,
        .metric => MetricFieldAccessor,
    };
}

/// Returns the field mutator function type for the given telemetry type
fn FieldMutatorType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogFieldMutator,
        .metric => MetricFieldMutator,
    };
}

// =============================================================================
// Observability Events
// =============================================================================

const EvaluateEmpty = struct {};
const EvaluateStart = struct { matcher_key_count: usize, policy_count: usize };
const MatcherKeyFieldNotPresent = struct {
    telemetry_type: TelemetryType,
    field: MatcherFieldRef,
};
const MatcherKeyFieldValue = struct {
    telemetry_type: TelemetryType,
    field: MatcherFieldRef,
    value: []const u8,
};
const MatcherFieldRef = union(TelemetryType) {
    log: FieldRef,
    metric: MetricFieldRef,
};
const MatcherKeyNoDatabase = struct {};
const ScanResult = struct { positive_count: usize, negated_count: usize };
const PolicyFullMatch = struct { policy_index: PolicyIndex, policy_id: []const u8 };
const PolicyNegationFailed = struct { policy_index: PolicyIndex };
const EvaluateResult = struct { decision: FilterDecision, matched_count: usize };
const TransformApplied = struct {
    policy_id: []const u8,
    removes: usize,
    redacts: usize,
    renames: usize,
    adds: usize,
};

// =============================================================================
// PolicyEngine - Main evaluation engine
// =============================================================================

/// Policy engine that evaluates telemetry against policies using Hyperscan.
/// Uses an inverted index for O(k*n) evaluation regardless of policy count.
///
/// The engine runs two stages:
/// 1. Filter stage: Determines keep/drop decision
/// 2. Transform stage: Returns matched policies for modification (caller handles)
pub const PolicyEngine = struct {
    /// Event bus for observability
    bus: *EventBus,
    /// Policy registry for getting snapshots and recording stats/errors
    registry: *PolicyRegistry,

    const Self = @This();

    pub fn init(bus: *EventBus, registry: *PolicyRegistry) Self {
        return .{
            .bus = bus,
            .registry = registry,
        };
    }

    /// Evaluate telemetry against all policies in the current snapshot.
    ///
    /// Returns a PolicyResult containing:
    /// - The filter decision (keep/drop/unset)
    /// - List of matched policy IDs (for transform stage lookup)
    ///
    /// A policy "fully matches" when:
    /// - All positive matchers have their patterns found in the field value
    /// - No negated matchers have their patterns found in the field value
    ///
    /// Thread-safe: uses only stack-allocated buffers for match aggregation.
    /// Automatically gets the current snapshot from the registry.
    ///
    /// The `policy_id_buf` parameter is used to store matched policy IDs.
    /// Caller provides the buffer to avoid allocation.
    ///
    /// If `field_mutator` is provided, transforms from matched policies will be applied.
    /// Pass null to skip transform application.
    ///
    /// If `byte_counter` is provided, bytes before/after each transform will be measured
    /// and recorded in policy stats. Pass null to skip byte tracking.
    ///
    /// Full policy evaluation with filter decision, matched policy IDs, and optional transforms.
    /// Returns PolicyResult containing the filter decision and list of matched policy IDs.
    /// If field_mutator is provided, transforms are applied to matched policies.
    /// Result of scanning all matcher keys against field values
    const ScanState = struct {
        match_counts: [MAX_MATCHES_PER_SCAN]u16,
        active_policies: [MAX_MATCHES_PER_SCAN]PolicyIndex,
        is_active: [MAX_MATCHES_PER_SCAN]bool,
        active_count: usize,
    };

    /// Result of finding matching policies from scan state
    const MatchState = struct {
        matched_indices: [MAX_MATCHES_PER_SCAN]PolicyIndex,
        matched_policies: [MAX_MATCHES_PER_SCAN]PolicyInfo,
        matched_decisions: [MAX_MATCHES_PER_SCAN]FilterDecision,
        matched_count: usize,
        decision: FilterDecision,
    };

    pub fn evaluate(
        self: *const Self,
        comptime T: TelemetryType,
        ctx: *anyopaque,
        field_accessor: FieldAccessorType(T),
        field_mutator: ?FieldMutatorType(T),
        policy_id_buf: [][]const u8,
    ) PolicyResult {
        // Get current snapshot from registry (lock-free)
        const snapshot = self.registry.getSnapshot() orelse {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        };

        // Select the appropriate index based on telemetry type (compile-time dispatch)
        const index = switch (T) {
            .log => &snapshot.log_index,
            .metric => &snapshot.metric_index,
        };

        if (index.isEmpty()) {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        }

        self.bus.debug(EvaluateStart{ .matcher_key_count = index.getMatcherKeys().len, .policy_count = index.getPolicyCount() });

        // Phase 1: Scan all matcher keys and compute match counts
        var scan_state = self.scanMatcherKeys(T, ctx, field_accessor, index);

        // Phase 2: Find matching policies and determine decision
        // Use context pointer as hash input for deterministic sampling
        const hash_input = @intFromPtr(ctx);
        const match_state = self.findMatchingPolicies(T, index, &scan_state, policy_id_buf, hash_input);

        self.bus.debug(EvaluateResult{ .decision = match_state.decision, .matched_count = match_state.matched_count });

        // Record hit/miss stats using lock-free atomics
        self.recordMatchedPolicyStats(snapshot, &match_state);

        if (match_state.decision == .drop) {
            return PolicyResult.dropped;
        }

        // Phase 3: Apply transforms (log only) and record stats
        var was_transformed = false;
        if (T == .log) {
            if (field_mutator) |mutator| {
                for (0..match_state.matched_count) |i| {
                    const policy_index = match_state.matched_indices[i];
                    const result = self.applyLogTransforms(
                        ctx,
                        field_accessor,
                        mutator,
                        snapshot,
                        policy_index,
                        policy_id_buf[i],
                    );
                    if (result.totalApplied() > 0) {
                        was_transformed = true;
                        // Record transform stats using lock-free atomics
                        if (snapshot.getStats(policy_index)) |stats| {
                            stats.addTransform(@intCast(result.totalApplied()));
                        }
                    }
                }
            }
        }

        return PolicyResult{
            .decision = match_state.decision,
            .matched_policy_ids = policy_id_buf[0..match_state.matched_count],
            .was_transformed = was_transformed,
        };
    }

    /// Scan all matcher keys and compute match counts for each policy.
    /// Returns state needed for determining which policies matched.
    inline fn scanMatcherKeys(
        self: *const Self,
        comptime T: TelemetryType,
        ctx: *anyopaque,
        field_accessor: FieldAccessorType(T),
        index: *const matcher_index.MatcherIndexType(T),
    ) ScanState {
        var state = ScanState{
            .match_counts = undefined,
            .active_policies = undefined,
            .is_active = undefined,
            .active_count = 0,
        };
        @memset(&state.match_counts, 0);
        @memset(&state.is_active, false);

        // Initialize match counts for policies with negated patterns
        // No telemetry type filtering needed - index only contains policies of type T
        for (index.getPoliciesWithNegation()) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;
            state.match_counts[policy_index] = policy_info.negated_count;
            state.is_active[policy_index] = true;
            state.active_policies[state.active_count] = policy_index;
            state.active_count += 1;
        }

        var result_buf: [MAX_MATCHES_PER_SCAN]u32 = undefined;

        // Iterate type-specific matcher keys - no runtime type filtering needed
        for (index.getMatcherKeys()) |matcher_key| {
            const field_ref = matcher_key.field;

            const value = field_accessor(ctx, field_ref) orelse {
                self.bus.debug(MatcherKeyFieldNotPresent{
                    .telemetry_type = T,
                    .field = if (T == .log) .{ .log = field_ref } else .{ .metric = field_ref },
                });
                continue;
            };

            self.bus.debug(MatcherKeyFieldValue{
                .telemetry_type = T,
                .field = if (T == .log) .{ .log = field_ref } else .{ .metric = field_ref },
                .value = if (value.len > 100) value[0..100] else value,
            });

            const db = index.getDatabase(matcher_key) orelse {
                self.bus.debug(MatcherKeyNoDatabase{});
                continue;
            };

            // Scan positive patterns - increment match counts
            const positive_result = db.scanPositive(value, &result_buf);
            for (positive_result.matches()) |pattern_id| {
                if (pattern_id < db.positive_patterns.len) {
                    const meta = db.positive_patterns[pattern_id];
                    state.match_counts[meta.policy_index] += 1;
                    if (!state.is_active[meta.policy_index]) {
                        state.is_active[meta.policy_index] = true;
                        state.active_policies[state.active_count] = meta.policy_index;
                        state.active_count += 1;
                    }
                }
            }

            // Scan negated patterns - decrement match counts
            const negated_result = db.scanNegated(value, &result_buf);
            for (negated_result.matches()) |pattern_id| {
                if (pattern_id < db.negated_patterns.len) {
                    const meta = db.negated_patterns[pattern_id];
                    state.match_counts[meta.policy_index] -= 1;
                    if (!state.is_active[meta.policy_index]) {
                        state.is_active[meta.policy_index] = true;
                        state.active_policies[state.active_count] = meta.policy_index;
                        state.active_count += 1;
                    }
                    self.bus.debug(PolicyNegationFailed{ .policy_index = meta.policy_index });
                }
            }

            self.bus.debug(ScanResult{ .positive_count = positive_result.count, .negated_count = negated_result.count });
        }

        return state;
    }

    /// Find all matching policies, apply sampling/rate limiting, and determine final decision.
    /// Drop always beats keep: if any policy returns drop, final decision is drop.
    inline fn findMatchingPolicies(
        self: *const Self,
        comptime T: TelemetryType,
        index: *const matcher_index.MatcherIndexType(T),
        scan_state: *const ScanState,
        policy_id_buf: [][]const u8,
        hash_input: u64,
    ) MatchState {
        var state = MatchState{
            .matched_indices = undefined,
            .matched_policies = undefined,
            .matched_decisions = undefined,
            .matched_count = 0,
            .decision = .unset,
        };

        for (scan_state.active_policies[0..scan_state.active_count]) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;

            if (!policy_info.enabled) continue;

            if (scan_state.match_counts[policy_index] == policy_info.required_match_count) {
                self.bus.debug(PolicyFullMatch{ .policy_index = policy_info.index, .policy_id = policy_info.id });

                // Apply sampling/rate limiting to get this policy's decision
                const decision = applyKeepValue(policy_info, hash_input);

                if (state.matched_count < policy_id_buf.len) {
                    policy_id_buf[state.matched_count] = policy_info.id;
                    state.matched_indices[state.matched_count] = policy_index;
                    state.matched_policies[state.matched_count] = policy_info;
                    state.matched_decisions[state.matched_count] = decision;
                    state.matched_count += 1;
                }

                // Update final decision: drop beats keep, keep beats unset
                if (decision == .drop) {
                    state.decision = .drop;
                } else if (decision == .keep and state.decision == .unset) {
                    state.decision = .keep;
                }
            }
        }

        return state;
    }

    /// Apply transforms to log context for a matched policy.
    /// Returns the transform result for stats recording.
    inline fn applyLogTransforms(
        self: *const Self,
        ctx: *anyopaque,
        field_accessor: LogFieldAccessor,
        field_mutator: LogFieldMutator,
        snapshot: *const PolicySnapshot,
        policy_index: PolicyIndex,
        policy_id: []const u8,
    ) log_transform.TransformResult {
        const policy = snapshot.getPolicy(policy_index) orelse return .{};
        const log_target = getLogTarget(policy) orelse return .{};
        const transform = log_target.transform orelse return .{};

        const result = log_transform.applyTransforms(&transform, ctx, field_accessor, field_mutator);

        if (result.totalApplied() > 0) {
            self.bus.debug(TransformApplied{
                .policy_id = policy_id,
                .removes = result.removes_applied,
                .redacts = result.redacts_applied,
                .renames = result.renames_applied,
                .adds = result.adds_applied,
            });
        }

        return result;
    }

    /// Record stats for all matched policies using lock-free atomics.
    /// Hit if policy's decision matches final decision, miss otherwise.
    inline fn recordMatchedPolicyStats(
        self: *const Self,
        snapshot: *const PolicySnapshot,
        match_state: *const MatchState,
    ) void {
        _ = self; // Observability bus not used for stats currently
        for (0..match_state.matched_count) |i| {
            const policy_index = match_state.matched_indices[i];
            const policy_decision = match_state.matched_decisions[i];

            if (snapshot.getStats(policy_index)) |stats| {
                if (policy_decision == match_state.decision) {
                    stats.addHit();
                } else {
                    stats.addMiss();
                }
            }
        }
    }

    /// Apply policy's keep value with sampling/rate limiting to get decision.
    /// - none: always drop
    /// - all: always keep
    /// - percentage: hash-based deterministic sampling
    /// - per_second/per_minute: uses the policy's RateLimiter
    fn applyKeepValue(policy_info: PolicyInfo, hash_input: u64) FilterDecision {
        return switch (policy_info.keep) {
            .none => .drop,
            .all => .keep,
            .percentage => |pct| {
                const sampler = Sampler{ .percentage = pct };
                return if (sampler.shouldKeep(hash_input)) .keep else .drop;
            },
            .per_second, .per_minute => {
                if (policy_info.rate_limiter) |rl| {
                    return if (rl.shouldKeep()) .keep else .drop;
                }
                return .keep; // No rate limiter configured, default to keep
            },
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const SourceType = policy_mod.SourceType;
const LogField = proto.policy.LogField;

/// Test context for unit tests - simple struct with known fields
const TestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    env: ?[]const u8 = null,

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const TestLogContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.level,
                else => null,
            },
            .log_attribute => |key| {
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                if (std.mem.eql(u8, key, "env")) return self.env;
                return null;
            },
            .resource_attribute, .scope_attribute => null,
        };
    }
};

test "PolicyEngine: empty registry returns unset" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log = TestLogContext{ .message = "hello" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "PolicyEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Matching log should be dropped
    var error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
    // Dropped results don't include policy IDs (no transform needed)
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);

    // Non-matching log should be unset (no policy matched)
    var info_log = TestLogContext{ .message = "all good" };
    const result2 = engine.evaluate(.log, &info_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "PolicyEngine: single policy keep match returns policy ID" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Matching log should be kept with policy ID returned
    var error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("policy-1", result.matched_policy_ids[0]);
}

test "PolicyEngine: multiple matchers AND logic" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Two matchers - both must match
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Both match - dropped
    var payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &payment_error, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Only message matches - unset
    var other_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &other_error, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Only service matches - unset
    var payment_info = TestLogContext{ .message = "request completed", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &payment_info, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: negated matcher" {
    const allocator = testing.allocator;

    // Drop logs that do NOT contain "important"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "important") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Non-important log should be dropped (negate: pattern NOT found = success)
    var boring = TestLogContext{ .message = "just a regular log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &boring, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Important log should be unset (negate: pattern found = failure, no match)
    var important = TestLogContext{ .message = "this is important data" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &important, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: mixed negated and non-negated matchers" {
    const allocator = testing.allocator;

    // Drop errors that are NOT from production
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-prod-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Must contain "error"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    // Must NOT be from production
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
        .match = .{ .regex = try allocator.dupe(u8, "prod") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Error from staging - dropped (error matches, prod not found = both conditions satisfied)
    var staging_error = TestLogContext{ .message = "an error occurred", .env = "staging" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &staging_error, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Error from production - unset (error matches, but prod IS found = negation failed)
    var prod_error = TestLogContext{ .message = "an error occurred", .env = "production" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &prod_error, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Non-error from staging - unset (error doesn't match)
    var staging_info = TestLogContext{ .message = "all good", .env = "staging" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &staging_info, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: most restrictive wins - drop beats keep" {
    const allocator = testing.allocator;

    // Policy that keeps errors
    var keep_policy = Policy{
        .id = try allocator.dupe(u8, "keep-errors"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy.deinit(allocator);

    // Policy that drops errors from payment service (more specific AND more restrictive)
    var drop_policy = Policy{
        .id = try allocator.dupe(u8, "drop-payment-errors"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Error from payment - both policies match, most restrictive (DROP) wins
    var payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &payment_error, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Error from auth - only keep_policy matches (KEEP)
    var auth_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    const result = engine.evaluate(.log, &auth_error, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
}

test "PolicyEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // Disabled!
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Would match but policy is disabled - unset
    var error_log = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-error-pattern"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Regex pattern: matches "error" or "Error" case-insensitive with (?i)
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "^.*rror") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Various error formats should match
    var error1 = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error1, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    var error2 = TestLogContext{ .message = "Error: something went wrong" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error2, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Non-matching should be unset
    var info = TestLogContext{ .message = "everything is fine" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &info, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: missing field with negated matcher succeeds" {
    const allocator = testing.allocator;

    // Drop logs where service attribute does NOT contain "critical"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "^critical-s.*$") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No service attribute = pattern cannot be found = negation succeeds = dropped
    var no_service = TestLogContext{ .message = "hello" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &no_service, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Service without "critical" = negation succeeds = dropped
    var non_critical = TestLogContext{ .message = "hello", .service = "normal-service" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &non_critical, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Service with "critical" = negation fails = unset
    var critical = TestLogContext{ .message = "hello", .service = "critical-service" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &critical, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: multiple policies with different matcher keys" {
    const allocator = testing.allocator;

    // Policy 1: Drop based on log_body
    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    // Policy 2: Drop based on log_attribute
    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-debug-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matches policy1
    var error_log = TestLogContext{ .message = "an error occurred", .service = "payment" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Matches policy2
    var debug_log = TestLogContext{ .message = "all good", .service = "debug-service" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &debug_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Matches neither
    var normal_log = TestLogContext{ .message = "all good", .service = "payment" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &normal_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: evaluate with null mutator" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Test evaluate with null mutator returns full PolicyResult
    var error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    var info_log = TestLogContext{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &info_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "FilterDecision: shouldContinue" {
    try testing.expect(FilterDecision.keep.shouldContinue());
    try testing.expect(FilterDecision.unset.shouldContinue());
    try testing.expect(!FilterDecision.drop.shouldContinue());
}

// =============================================================================
// Edge case tests for active policy tracking optimization
// =============================================================================

test "PolicyEngine: all policies positive only - none start active" {
    // Edge case: No policies have negated patterns, so policies_with_negation is empty.
    // Policies should only become active when positive patterns match.
    const allocator = testing.allocator;

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-warning"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No match - no policies become active
    var normal = TestLogContext{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &normal, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Match policy1 only
    var error_log = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Match policy2 only
    var warning_log = TestLogContext{ .message = "warning issued" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &warning_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: all policies negated only - all start active" {
    // Edge case: All policies have only negated patterns.
    // All policies start active and match if their negated patterns don't match.
    const allocator = testing.allocator;

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "important") },
        .negate = true,
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
        .negate = true,
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Neither "important" nor "critical" - both policies match
    var boring = TestLogContext{ .message = "just a normal log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &boring, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "important" - policy1 fails, policy2 still matches
    var important = TestLogContext{ .message = "important data here" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &important, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "critical" - policy1 still matches, policy2 fails
    var critical = TestLogContext{ .message = "critical issue" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &critical, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains both - both policies fail
    var both = TestLogContext{ .message = "important and critical" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &both, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: mix of positive-only and negated policies" {
    // Edge case: Some policies have negated patterns (start active), others don't.
    // Verifies both paths work correctly together.
    const allocator = testing.allocator;

    // Policy with only positive pattern
    var positive_policy = Policy{
        .id = try allocator.dupe(u8, "positive-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try positive_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer positive_policy.deinit(allocator);

    // Policy with only negated pattern
    var negated_policy = Policy{
        .id = try allocator.dupe(u8, "negated-policy"),
        .name = try allocator.dupe(u8, "drop-non-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try negated_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
        .negate = true,
    });
    defer negated_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ positive_policy, negated_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // No "error", no "debug" - negated policy matches (drops)
    var normal = TestLogContext{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &normal, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "error", no "debug" - both policies match
    var error_log = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "debug" - negated policy fails, positive policy doesn't match
    var debug_log = TestLogContext{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &debug_log, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains both "error" and "debug" - positive matches, negated fails
    var error_debug = TestLogContext{ .message = "error in debug mode" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_debug, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: multiple negated patterns same policy" {
    // Edge case: Policy with multiple negated patterns - all must "pass" (not match)
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-special"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    // Must NOT contain "skip" AND must NOT contain "ignore"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "skip") },
        .negate = true,
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "ignore") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Neither word - both negations pass - policy matches
    var normal = TestLogContext{ .message = "normal message" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &normal, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "skip" - first negation fails - policy doesn't match
    var skip = TestLogContext{ .message = "skip this one" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &skip, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains "ignore" - second negation fails - policy doesn't match
    var ignore = TestLogContext{ .message = "ignore this" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &ignore, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Contains both - both negations fail - policy doesn't match
    var both = TestLogContext{ .message = "skip and ignore" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &both, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "PolicyEngine: policy becomes active via positive then fails via negated" {
    // Edge case: Policy has both positive and negated patterns.
    // Positive matches first (becomes active), then negated also matches (fails).
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors-not-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    // Must contain "error" AND must NOT contain "debug"
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Has "error", no "debug" - positive matches, negation passes - policy matches
    var error_only = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.log, &error_only, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Has both "error" and "debug" - positive matches but negation fails
    // required_match_count = 2 (1 positive + 1 negated)
    // match_counts starts at 1 (negated_count)
    // positive match: +1 -> 2
    // negated match: -1 -> 1
    // Final: 1 != 2 - policy doesn't match
    var error_debug = TestLogContext{ .message = "debug error message" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &error_debug, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Has "debug" but no "error" - positive doesn't match, negation fails
    // match_counts starts at 1, negated match: -1 -> 0, final: 0 != 2
    var debug_only = TestLogContext{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &debug_only, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);

    // Has neither - positive doesn't match, negation passes
    // match_counts stays at 1 (negated_count), final: 1 != 2
    var neither = TestLogContext{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.log, &neither, TestLogContext.fieldAccessor, null, &policy_id_buf).decision);
}

// =============================================================================
// Tests for evaluate() with transforms
// =============================================================================

/// Mutable test context that supports both FieldAccessor and FieldMutator
const MutableTestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    env: ?[]const u8 = null,

    // Dynamic attributes stored in a hash map
    attributes: std.StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MutableTestLogContext {
        return .{
            .attributes = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MutableTestLogContext) void {
        var it = self.attributes.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.attributes.deinit();
    }

    pub fn setAttribute(self: *MutableTestLogContext, key: []const u8, value: []const u8) !void {
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);

        const gop = try self.attributes.getOrPut(key);
        if (gop.found_existing) {
            self.allocator.free(gop.value_ptr.*);
            gop.value_ptr.* = value_copy;
        } else {
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = value_copy;
        }
    }

    pub fn removeAttribute(self: *MutableTestLogContext, key: []const u8) bool {
        if (self.attributes.fetchRemove(key)) |removed| {
            self.allocator.free(removed.key);
            self.allocator.free(removed.value);
            return true;
        }
        return false;
    }

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: FieldRef) ?[]const u8 {
        const self: *const MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => self.message,
                .LOG_FIELD_SEVERITY_TEXT => self.level,
                else => null,
            },
            .log_attribute => |key| {
                // Check fixed fields first
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                if (std.mem.eql(u8, key, "env")) return self.env;
                // Check dynamic attributes
                return self.attributes.get(key);
            },
            .resource_attribute, .scope_attribute => null,
        };
    }

    pub fn fieldMutator(ctx_ptr: *anyopaque, op: policy_types.MutateOp) bool {
        const self: *MutableTestLogContext = @ptrCast(@alignCast(ctx_ptr));
        switch (op) {
            .remove => |field| {
                switch (field) {
                    .log_attribute => |key| {
                        // Handle fixed fields
                        if (std.mem.eql(u8, key, "service")) {
                            if (self.service != null) {
                                self.service = null;
                                return true;
                            }
                            return false;
                        }
                        if (std.mem.eql(u8, key, "env")) {
                            if (self.env != null) {
                                self.env = null;
                                return true;
                            }
                            return false;
                        }
                        // Handle dynamic attributes
                        return self.removeAttribute(key);
                    },
                    else => return false,
                }
            },
            .set => |s| {
                switch (s.field) {
                    .log_attribute => |key| {
                        // For fixed fields, just update the pointer
                        if (std.mem.eql(u8, key, "service")) {
                            self.service = s.value;
                            return true;
                        }
                        if (std.mem.eql(u8, key, "env")) {
                            self.env = s.value;
                            return true;
                        }
                        // For dynamic attributes, store a copy
                        self.setAttribute(key, s.value) catch return false;
                        return true;
                    },
                    else => return false,
                }
            },
            .rename => |r| {
                switch (r.from) {
                    .log_attribute => |from_key| {
                        // Get the source value
                        var value: ?[]const u8 = null;
                        if (std.mem.eql(u8, from_key, "service")) {
                            value = self.service;
                            if (value != null) self.service = null;
                        } else if (std.mem.eql(u8, from_key, "env")) {
                            value = self.env;
                            if (value != null) self.env = null;
                        } else {
                            if (self.attributes.get(from_key)) |v| {
                                value = v;
                                _ = self.removeAttribute(from_key);
                            }
                        }

                        if (value == null) return false;

                        // Set the target
                        self.setAttribute(r.to, value.?) catch return false;
                        return true;
                    },
                    else => return false,
                }
            },
        }
    }
};

test "evaluate: policy with keep=all and no transform" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.service = "payment-api";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("keep-policy", result.matched_policy_ids[0]);
    // No transform, so context unchanged
    try testing.expectEqualStrings("payment-api", ctx.service.?);
}

test "evaluate: policy with keep=all and remove transform" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "transform-policy"),
        .name = try allocator.dupe(u8, "remove-env"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.service = "payment-api";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have removed 'env'
    try testing.expect(ctx.env == null);
    // Other fields unchanged
    try testing.expectEqualStrings("payment-api", ctx.service.?);
}

test "evaluate: policy with keep=all and redact transform" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .replacement = try allocator.dupe(u8, "[REDACTED]"),
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "redact-policy"),
        .name = try allocator.dupe(u8, "redact-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "sensitive") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "sensitive data here";
    ctx.service = "secret-service";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have redacted 'service'
    try testing.expectEqualStrings("[REDACTED]", ctx.service.?);
}

test "evaluate: policy with keep=all and add transform" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "processed") },
        .value = try allocator.dupe(u8, "true"),
        .upsert = true,
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "add-policy"),
        .name = try allocator.dupe(u8, "add-processed"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should have added 'processed'
    try testing.expectEqualStrings("true", ctx.attributes.get("processed").?);
}

test "evaluate: policy with no keep (drop) skips transform" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{
            .log = .{
                .keep = try allocator.dupe(u8, "none"),
                .transform = transform, // Transform should NOT be applied for drops
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);
    // Transform should NOT have been applied (log is dropped)
    try testing.expectEqualStrings("production", ctx.env.?);
}

test "evaluate: multiple policies with different transforms" {
    const allocator = testing.allocator;

    // Policy 1: matches "error", adds tag
    var transform1 = proto.policy.LogTransform{};
    try transform1.add.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "error_tag") },
        .value = try allocator.dupe(u8, "true"),
        .upsert = true,
    });

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "tag-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform1,
        } },
    };
    try policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });

    // Policy 2: matches "payment", removes env
    var transform2 = proto.policy.LogTransform{};
    try transform2.remove.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
    });

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "clean-payment"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform2,
        } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });

    defer policy1.deinit(allocator);
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ policy1, policy2 }, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches BOTH policies
    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "payment error occurred";
    ctx.service = "payment-api";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 2), result.matched_policy_ids.len);

    // Both transforms should have been applied
    try testing.expectEqualStrings("true", ctx.attributes.get("error_tag").?);
    try testing.expect(ctx.env == null);
}

test "evaluate: policy with unset keep applies transform" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.add.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "tagged") },
        .value = try allocator.dupe(u8, "yes"),
        .upsert = true,
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "unset-policy"),
        .name = try allocator.dupe(u8, "tag-only"),
        .enabled = true,
        .target = .{
            .log = .{
                // keep is null (unset) - should still apply transforms
                .transform = transform,
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "info") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "info log message";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    // When keep is not specified, it defaults to "all" which means keep
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("yes", ctx.attributes.get("tagged").?);
}

test "evaluate: null mutator skips transforms" {
    const allocator = testing.allocator;

    var transform = proto.policy.LogTransform{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
    });

    var policy = Policy{
        .id = try allocator.dupe(u8, "transform-policy"),
        .name = try allocator.dupe(u8, "remove-env"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    // Pass null for mutator - transforms should be skipped
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // Transform should NOT have been applied (null mutator)
    try testing.expectEqualStrings("production", ctx.env.?);
}

test "evaluate: policy without transform field" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "no-transform"),
        .name = try allocator.dupe(u8, "just-keep"),
        .enabled = true,
        .target = .{
            .log = .{
                .keep = try allocator.dupe(u8, "all"),
                // No transform field
            },
        },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var ctx = MutableTestLogContext.init(allocator);
    defer ctx.deinit();
    ctx.message = "an error occurred";
    ctx.env = "production";

    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    // No transform, env unchanged
    try testing.expectEqualStrings("production", ctx.env.?);
}

test "evaluate: mixed keep and drop policies - only keep applies transforms" {
    const allocator = testing.allocator;

    // Policy 1: drop errors (no transform should apply)
    var drop_transform = proto.policy.LogTransform{};
    try drop_transform.add.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "dropped") },
        .value = try allocator.dupe(u8, "should-not-appear"),
        .upsert = true,
    });

    var drop_policy = Policy{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
            .transform = drop_transform,
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });

    // Policy 2: keep errors with transform
    var keep_transform = proto.policy.LogTransform{};
    try keep_transform.add.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "kept") },
        .value = try allocator.dupe(u8, "yes"),
        .upsert = true,
    });

    var keep_policy = Policy{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = keep_transform,
        } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });

    defer drop_policy.deinit(allocator);
    defer keep_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ drop_policy, keep_policy }, "test", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Test 1: Log matches only drop policy
    {
        var ctx = MutableTestLogContext.init(allocator);
        defer ctx.deinit();
        ctx.message = "debug message";

        var policy_id_buf: [16][]const u8 = undefined;
        const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

        try testing.expectEqual(FilterDecision.drop, result.decision);
        // Transform should NOT be applied for drop
        try testing.expect(ctx.attributes.get("dropped") == null);
    }

    // Test 2: Log matches only keep policy
    {
        var ctx = MutableTestLogContext.init(allocator);
        defer ctx.deinit();
        ctx.message = "error occurred";

        var policy_id_buf: [16][]const u8 = undefined;
        const result = engine.evaluate(.log, &ctx, MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

        try testing.expectEqual(FilterDecision.keep, result.decision);
        // Transform should be applied for keep
        try testing.expectEqualStrings("yes", ctx.attributes.get("kept").?);
    }
}

// =============================================================================
// Stats Recording Tests
// =============================================================================

const policy_provider = @import("./provider.zig");

/// Test provider that tracks recordPolicyStats calls
const StatsTrackingProvider = struct {
    allocator: std.mem.Allocator,
    stats_calls: std.ArrayListUnmanaged(StatsCall),

    const StatsCall = struct {
        policy_id: []const u8,
        hits: i64,
        misses: i64,
        transform_result: log_transform.TransformResult,
    };

    pub fn init(allocator: std.mem.Allocator) StatsTrackingProvider {
        return .{
            .allocator = allocator,
            .stats_calls = .{},
        };
    }

    pub fn deinit(self: *StatsTrackingProvider) void {
        for (self.stats_calls.items) |call| {
            self.allocator.free(call.policy_id);
        }
        self.stats_calls.deinit(self.allocator);
    }

    pub fn getId(self: *StatsTrackingProvider) []const u8 {
        _ = self;
        return "stats-tracking-provider";
    }

    pub fn subscribe(self: *StatsTrackingProvider, callback: policy_mod.PolicyCallback) !void {
        _ = self;
        _ = callback;
    }

    pub fn recordPolicyError(self: *StatsTrackingProvider, policy_id: []const u8, error_message: []const u8) void {
        _ = self;
        _ = policy_id;
        _ = error_message;
    }

    pub fn recordPolicyStats(self: *StatsTrackingProvider, policy_id: []const u8, hits: i64, misses: i64, transform_result: log_transform.TransformResult) void {
        const id_copy = self.allocator.dupe(u8, policy_id) catch return;
        self.stats_calls.append(self.allocator, .{
            .policy_id = id_copy,
            .hits = hits,
            .misses = misses,
            .transform_result = transform_result,
        }) catch {
            self.allocator.free(id_copy);
        };
    }

    pub fn provider(self: *StatsTrackingProvider) policy_provider.PolicyProvider {
        return policy_provider.PolicyProvider.init(self);
    }

    /// Find stats for a given policy ID
    pub fn getStats(self: *const StatsTrackingProvider, policy_id: []const u8) ?StatsCall {
        for (self.stats_calls.items) |call| {
            if (std.mem.eql(u8, call.policy_id, policy_id)) {
                return call;
            }
        }
        return null;
    }

    /// Count total stats calls
    pub fn callCount(self: *const StatsTrackingProvider) usize {
        return self.stats_calls.items.len;
    }
};

test "PolicyEngine stats: all DROP policies get hits" {
    const allocator = testing.allocator;

    // Two DROP policies that both match
    var drop_policy1 = Policy{
        .id = try allocator.dupe(u8, "drop-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer drop_policy1.deinit(allocator);

    var drop_policy2 = Policy{
        .id = try allocator.dupe(u8, "drop-2"),
        .name = try allocator.dupe(u8, "drop-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer drop_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ drop_policy1, drop_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both DROP policies
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Both policies should get hits via lock-free atomic stats on snapshot
    const snapshot = registry.getSnapshot().?;

    // Policy 0 (drop-1) should have 1 hit
    const stats0 = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats0.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats0.misses.load(.monotonic));

    // Policy 1 (drop-2) should have 1 hit
    const stats1 = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), stats1.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats1.misses.load(.monotonic));
}

test "PolicyEngine stats: all KEEP policies get hits" {
    const allocator = testing.allocator;

    // Two KEEP policies that both match
    var keep_policy1 = Policy{
        .id = try allocator.dupe(u8, "keep-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy1.deinit(allocator);

    var keep_policy2 = Policy{
        .id = try allocator.dupe(u8, "keep-2"),
        .name = try allocator.dupe(u8, "keep-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer keep_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both KEEP policies
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);

    // Both policies should get hits via lock-free atomic stats on snapshot
    const snapshot = registry.getSnapshot().?;

    // Policy 0 (keep-1) should have 1 hit
    const stats0 = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats0.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats0.misses.load(.monotonic));

    // Policy 1 (keep-2) should have 1 hit
    const stats1 = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), stats1.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats1.misses.load(.monotonic));
}

test "PolicyEngine stats: mixed KEEP and DROP - DROP gets hits, KEEP gets misses" {
    const allocator = testing.allocator;

    // One KEEP and one DROP policy that both match
    var keep_policy = Policy{
        .id = try allocator.dupe(u8, "keep-policy"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy.deinit(allocator);

    var drop_policy = Policy{
        .id = try allocator.dupe(u8, "drop-policy"),
        .name = try allocator.dupe(u8, "drop-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches both policies (KEEP and DROP)
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Both policies should have stats recorded via lock-free atomics
    const snapshot = registry.getSnapshot().?;

    // KEEP policy (index 0) gets miss (its decision differs from final decision)
    const keep_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 0), keep_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep_stats.misses.load(.monotonic));

    // DROP policy (index 1) gets hit (its decision matches final decision)
    const drop_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 1), drop_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), drop_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: single policy match gets hit" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "single-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // Single policy should get a hit via lock-free atomic stats
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

test "PolicyEngine stats: multiple KEEPs and DROPs - all DROPs get hits, all KEEPs get misses" {
    const allocator = testing.allocator;

    // Two KEEP policies
    var keep_policy1 = Policy{
        .id = try allocator.dupe(u8, "keep-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy1.deinit(allocator);

    var keep_policy2 = Policy{
        .id = try allocator.dupe(u8, "keep-2"),
        .name = try allocator.dupe(u8, "keep-critical"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try keep_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "critical") },
    });
    defer keep_policy2.deinit(allocator);

    // Two DROP policies
    var drop_policy1 = Policy{
        .id = try allocator.dupe(u8, "drop-1"),
        .name = try allocator.dupe(u8, "drop-warning"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy1.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer drop_policy1.deinit(allocator);

    var drop_policy2 = Policy{
        .id = try allocator.dupe(u8, "drop-2"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2, drop_policy1, drop_policy2 }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log matches all 4 policies (2 KEEP, 2 DROP)
    var test_log = TestLogContext{ .message = "critical error with warning and debug info" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // All 4 policies should have stats recorded via lock-free atomics
    const snapshot = registry.getSnapshot().?;

    // Both KEEP policies (index 0,1) get misses (their decision differs from final decision)
    const keep1_stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 0), keep1_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep1_stats.misses.load(.monotonic));

    const keep2_stats = snapshot.getStats(1).?;
    try testing.expectEqual(@as(i64, 0), keep2_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 1), keep2_stats.misses.load(.monotonic));

    // Both DROP policies (index 2,3) get hits (their decision matches final decision)
    const drop1_stats = snapshot.getStats(2).?;
    try testing.expectEqual(@as(i64, 1), drop1_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), drop1_stats.misses.load(.monotonic));

    const drop2_stats = snapshot.getStats(3).?;
    try testing.expectEqual(@as(i64, 1), drop2_stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), drop2_stats.misses.load(.monotonic));
}

test "PolicyEngine stats: no match records no stats" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "no-match-policy"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Log doesn't match the policy
    var test_log = TestLogContext{ .message = "all good here" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // No stats should be recorded - policy should have 0 hits and 0 misses
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 0), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

// =============================================================================
// Metric Policy Tests
// =============================================================================

const MetricField = proto.policy.MetricField;
const MetricMatcher = proto.policy.MetricMatcher;

/// Test context for metric unit tests - simple struct with known fields
const TestMetricContext = struct {
    name: ?[]const u8 = null,
    description: ?[]const u8 = null,
    unit: ?[]const u8 = null,
    scope_name: ?[]const u8 = null,
    datapoint_attributes: ?std.StringHashMap([]const u8) = null,
    resource_attributes: ?std.StringHashMap([]const u8) = null,

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
        const self: *const TestMetricContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (field) {
            .metric_field => |mf| switch (mf) {
                .METRIC_FIELD_NAME => self.name,
                .METRIC_FIELD_DESCRIPTION => self.description,
                .METRIC_FIELD_UNIT => self.unit,
                .METRIC_FIELD_SCOPE_NAME => self.scope_name,
                else => null,
            },
            .datapoint_attribute => |key| {
                if (self.datapoint_attributes) |attrs| {
                    return attrs.get(key);
                }
                return null;
            },
            .resource_attribute => |key| {
                if (self.resource_attributes) |attrs| {
                    return attrs.get(key);
                }
                return null;
            },
            .scope_attribute => null,
            .metric_type => null, // Test context doesn't track metric type
            .aggregation_temporality => null, // Test context doesn't track temporality
        };
    }
};

test "MetricPolicyEngine: empty registry returns unset" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_metric = TestMetricContext{ .name = "http_requests_total" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    // Verify the registry has the policy
    const snapshot = registry.getSnapshot().?;
    try testing.expectEqual(@as(usize, 1), snapshot.policies.len);

    // Verify the metric index has the matcher key
    const index = &snapshot.metric_index;
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    // Verify we can get the database for the metric key
    const db = index.getDatabase(.{ .field = .{ .metric_field = .METRIC_FIELD_NAME } });
    try testing.expect(db != null);

    // Test that scanning works directly
    var result_buf: [256]u32 = undefined;
    const scan_result = db.?.scanPositive("debug_memory_usage", &result_buf);
    try testing.expect(scan_result.count > 0); // Pattern should match

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matching metric should be dropped
    var debug_metric = TestMetricContext{ .name = "debug_memory_usage" };
    const result = engine.evaluate(.metric, &debug_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Non-matching metric should pass
    var normal_metric = TestMetricContext{ .name = "http_requests_total" };
    const result2 = engine.evaluate(.metric, &normal_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: single policy keep match returns policy ID" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-keep"),
        .name = try allocator.dupe(u8, "keep-important-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = true,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    var test_metric = TestMetricContext{ .name = "http_requests_total" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
    try testing.expectEqualStrings("metric-policy-keep", result.matched_policy_ids[0]);
}

test "MetricPolicyEngine: multiple matchers AND logic" {
    const allocator = testing.allocator;

    // Policy requires BOTH metric name AND unit to match
    // Use anchored regex patterns to ensure exact matching
    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-and"),
        .name = try allocator.dupe(u8, "drop-slow-requests"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^request_duration$") },
    });
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_UNIT },
        .match = .{ .regex = try allocator.dupe(u8, "^seconds$") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Both match - should drop
    var both_match = TestMetricContext{ .name = "request_duration", .unit = "seconds" };
    const result1 = engine.evaluate(.metric, &both_match, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Only name matches - should pass (unit "milliseconds" doesn't match "^seconds$")
    var name_only = TestMetricContext{ .name = "request_duration", .unit = "milliseconds" };
    const result2 = engine.evaluate(.metric, &name_only, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);

    // Only unit matches - should pass (name "response_size" doesn't match "^request_duration$")
    var unit_only = TestMetricContext{ .name = "response_size", .unit = "seconds" };
    const result3 = engine.evaluate(.metric, &unit_only, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result3.decision);
}

test "MetricPolicyEngine: negated matcher" {
    const allocator = testing.allocator;

    // Keep metrics that do NOT have "internal" in the name
    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-negate"),
        .name = try allocator.dupe(u8, "drop-internal-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "internal_.*") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Internal metric matches pattern, negation fails -> policy doesn't match -> passes
    var internal_metric = TestMetricContext{ .name = "internal_queue_size" };
    const result1 = engine.evaluate(.metric, &internal_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result1.decision);

    // Non-internal metric doesn't match pattern, negation succeeds -> policy matches -> drops
    var public_metric = TestMetricContext{ .name = "http_requests_total" };
    const result2 = engine.evaluate(.metric, &public_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result2.decision);
}

test "MetricPolicyEngine: datapoint attribute matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-dp-attr"),
        .name = try allocator.dupe(u8, "drop-error-status"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try allocator.dupe(u8, "status_code") },
        .match = .{ .regex = try allocator.dupe(u8, "5[0-9][0-9]") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric with 500 status should be dropped
    var dp_attrs = std.StringHashMap([]const u8).init(allocator);
    defer dp_attrs.deinit();
    try dp_attrs.put("status_code", "503");

    var error_metric = TestMetricContext{
        .name = "http_response",
        .datapoint_attributes = dp_attrs,
    };
    const result1 = engine.evaluate(.metric, &error_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Metric with 200 status should pass
    var ok_attrs = std.StringHashMap([]const u8).init(allocator);
    defer ok_attrs.deinit();
    try ok_attrs.put("status_code", "200");

    var ok_metric = TestMetricContext{
        .name = "http_response",
        .datapoint_attributes = ok_attrs,
    };
    const result2 = engine.evaluate(.metric, &ok_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: resource attribute matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-res-attr"),
        .name = try allocator.dupe(u8, "drop-test-env"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .resource_attribute = try allocator.dupe(u8, "deployment.environment") },
        .match = .{ .regex = try allocator.dupe(u8, "test|staging") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric from test environment should be dropped
    var test_attrs = std.StringHashMap([]const u8).init(allocator);
    defer test_attrs.deinit();
    try test_attrs.put("deployment.environment", "test");

    var test_metric = TestMetricContext{
        .name = "http_requests_total",
        .resource_attributes = test_attrs,
    };
    const result1 = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Metric from production environment should pass
    var prod_attrs = std.StringHashMap([]const u8).init(allocator);
    defer prod_attrs.deinit();
    try prod_attrs.put("deployment.environment", "production");

    var prod_metric = TestMetricContext{
        .name = "http_requests_total",
        .resource_attributes = prod_attrs,
    };
    const result2 = engine.evaluate(.metric, &prod_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "MetricPolicyEngine: log policies don't affect metrics" {
    const allocator = testing.allocator;

    // Create a log policy that would match if applied to metrics
    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy-only"),
        .name = try allocator.dupe(u8, "drop-error-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{log_policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Metric evaluation should not be affected by log policies
    var test_metric = TestMetricContext{ .name = "error_count" };
    const result = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: metric policies don't affect logs" {
    const allocator = testing.allocator;

    // Create a metric policy
    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-only"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer metric_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{metric_policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Log evaluation should not be affected by metric policies
    var test_log = TestLogContext{ .message = "debug_info: something happened" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "MetricPolicyEngine: most restrictive wins - drop beats keep" {
    const allocator = testing.allocator;

    // Keep policy for all http metrics
    var keep_policy = Policy{
        .id = try allocator.dupe(u8, "metric-keep-http"),
        .name = try allocator.dupe(u8, "keep-http-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = true,
        } },
    };
    try keep_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_.*") },
    });
    defer keep_policy.deinit(allocator);

    // Drop policy for error metrics
    var drop_policy = Policy{
        .id = try allocator.dupe(u8, "metric-drop-errors"),
        .name = try allocator.dupe(u8, "drop-error-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try drop_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_errors") },
    });
    defer drop_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // http_errors matches both policies - drop should win
    var error_metric = TestMetricContext{ .name = "http_errors" };
    const result1 = engine.evaluate(.metric, &error_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // http_requests matches only keep policy
    var requests_metric = TestMetricContext{ .name = "http_requests_total" };
    const result2 = engine.evaluate(.metric, &requests_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result2.decision);
}

test "MetricPolicyEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-disabled"),
        .name = try allocator.dupe(u8, "disabled-drop-policy"),
        .enabled = false, // Disabled!
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, ".+") }, // Match any non-empty name
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Even though the pattern matches, the disabled policy should be skipped
    var test_metric = TestMetricContext{ .name = "any_metric_name" };
    const result = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
}

test "MetricPolicyEngine: mixed log and metric policies" {
    const allocator = testing.allocator;

    // Metric drop policy
    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-drop"),
        .name = try allocator.dupe(u8, "drop-debug-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "debug_.*") },
    });
    defer metric_policy.deinit(allocator);

    // Log drop policy
    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-drop"),
        .name = try allocator.dupe(u8, "drop-debug-logs"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "DEBUG:.*") },
    });
    defer log_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{ metric_policy, log_policy }, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Debug metric should be dropped by metric policy
    var debug_metric = TestMetricContext{ .name = "debug_memory" };
    const result1 = engine.evaluate(.metric, &debug_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result1.decision);

    // Debug log should be dropped by log policy
    var debug_log = TestLogContext{ .message = "DEBUG: test message" };
    const result2 = engine.evaluate(.log, &debug_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result2.decision);

    // Non-debug metric should pass
    var normal_metric = TestMetricContext{ .name = "http_requests" };
    const result3 = engine.evaluate(.metric, &normal_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result3.decision);

    // Non-debug log should pass
    var normal_log = TestLogContext{ .message = "INFO: test message" };
    const result4 = engine.evaluate(.log, &normal_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result4.decision);
}

test "MetricPolicyEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-regex"),
        .name = try allocator.dupe(u8, "drop-by-regex"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match any metric starting with "internal_" or ending with "_debug"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "(^internal_|_debug$)") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matches: starts with internal_
    var m1 = TestMetricContext{ .name = "internal_queue_size" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.metric, &m1, TestMetricContext.fieldAccessor, null, &policy_id_buf).decision);

    // Matches: ends with _debug
    var m2 = TestMetricContext{ .name = "http_latency_debug" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluate(.metric, &m2, TestMetricContext.fieldAccessor, null, &policy_id_buf).decision);

    // Does not match
    var m3 = TestMetricContext{ .name = "http_requests_total" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluate(.metric, &m3, TestMetricContext.fieldAccessor, null, &policy_id_buf).decision);
}

test "MetricPolicyEngine: stats recording for matched policies" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-stats-test"),
        .name = try allocator.dupe(u8, "drop-test-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "test_.*") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Matching metric - should record stats
    var test_metric = TestMetricContext{ .name = "test_counter" };
    const result = engine.evaluate(.metric, &test_metric, TestMetricContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Verify stats were recorded via lock-free atomics
    const snapshot = registry.getSnapshot().?;
    const stats = snapshot.getStats(0).?;
    try testing.expectEqual(@as(i64, 1), stats.hits.load(.monotonic));
    try testing.expectEqual(@as(i64, 0), stats.misses.load(.monotonic));
}

// =============================================================================
// Sampling and Rate Limiting Tests
// =============================================================================

test "PolicyEngine: percentage sampling - 0% drops all" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-0-percent"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "0%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 0% sampling should drop all matching logs
    var test_log = TestLogContext{ .message = "test message" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
}

test "PolicyEngine: percentage sampling - 100% keeps all" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-100-percent"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "100%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 100% sampling should keep all matching logs
    var test_log = TestLogContext{ .message = "test message" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
}

test "PolicyEngine: percentage sampling - deterministic per context" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-50-percent"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Same context should produce same decision (deterministic)
    var test_log = TestLogContext{ .message = "test message" };
    const result1 = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    const result2 = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(result1.decision, result2.decision);
}

test "PolicyEngine: rate limiting - respects limit" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-5-per-second"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "5/s"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // First 5 should be kept
    var kept_count: u32 = 0;
    for (0..10) |_| {
        var test_log = TestLogContext{ .message = "test message" };
        const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
        if (result.decision == .keep) {
            kept_count += 1;
        }
    }

    // Should keep exactly 5 (rate limit)
    try testing.expectEqual(@as(u32, 5), kept_count);
}

test "PolicyEngine: rate limiting per minute" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-3-per-minute"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "3/m"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // First 3 should be kept
    var kept_count: u32 = 0;
    for (0..10) |_| {
        var test_log = TestLogContext{ .message = "test message" };
        const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
        if (result.decision == .keep) {
            kept_count += 1;
        }
    }

    // Should keep exactly 3 (rate limit per minute)
    try testing.expectEqual(@as(u32, 3), kept_count);
}

test "PolicyEngine: rate limiting with zero limit drops all" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "rate-limit-0"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "0/s"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // 0/s rate limit should drop all
    var test_log = TestLogContext{ .message = "test message" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
}

test "PolicyEngine: sampling does not affect non-matching logs" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "sample-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "50%"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "specific_pattern") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&.{policy}, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);
    var policy_id_buf: [16][]const u8 = undefined;

    // Non-matching log should return unset (not affected by sampling)
    var test_log = TestLogContext{ .message = "different message" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result.decision);
}

test "PolicyEngine: more matching policies than policy_id_buf capacity" {
    // When more policies match than fit in policy_id_buf, the engine should:
    // 1. Still compute the correct final decision (including from policies beyond buffer)
    // 2. Only return as many policy IDs as fit in the buffer
    // 3. Not crash or have undefined behavior
    const allocator = testing.allocator;

    // Create 5 KEEP policies that all match, but we'll only provide a buffer for 2
    var policies: [5]Policy = undefined;
    for (&policies, 0..) |*p, i| {
        var id_buf: [16]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "policy-{d}", .{i}) catch unreachable;

        p.* = Policy{
            .id = try allocator.dupe(u8, id),
            .name = try allocator.dupe(u8, id),
            .enabled = true,
            .target = .{ .log = .{
                .keep = try allocator.dupe(u8, "all"),
            } },
        };
        // All policies match on "test" in body
        try p.target.?.log.match.append(allocator, .{
            .field = .{ .log_field = .LOG_FIELD_BODY },
            .match = .{ .regex = try allocator.dupe(u8, "test") },
        });
    }
    defer for (&policies) |*p| p.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.updatePolicies(&policies, "file-provider", .file);

    const engine = PolicyEngine.init(noop_bus.eventBus(), &registry);

    // Buffer only fits 2 policy IDs, but 5 policies will match
    var small_policy_id_buf: [2][]const u8 = undefined;

    var test_log = TestLogContext{ .message = "test message" };
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &small_policy_id_buf);

    // Decision should be KEEP (all 5 policies want to keep)
    try testing.expectEqual(FilterDecision.keep, result.decision);

    // Only 2 policy IDs returned (buffer capacity), even though 5 matched
    try testing.expectEqual(@as(usize, 2), result.matched_policy_ids.len);
}
