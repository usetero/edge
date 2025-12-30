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

const o11y = @import("../observability/root.zig");
const NoopEventBus = o11y.NoopEventBus;
const EventBus = o11y.EventBus;

const LogMatcher = proto.policy.LogMatcher;

const KeepValue = matcher_index.KeepValue;
const PolicyIndex = matcher_index.PolicyIndex;
const MAX_POLICIES = matcher_index.MAX_POLICIES;

const MatcherIndex = matcher_index.MatcherIndex;
const MatcherKey = matcher_index.MatcherKey;
const MatcherDatabase = matcher_index.MatcherDatabase;
const PolicyInfo = matcher_index.PolicyInfo;
const PatternMeta = matcher_index.PatternMeta;
pub const PolicyRegistry = policy_mod.Registry;
pub const PolicySnapshot = policy_mod.Snapshot;

// Re-export types for callers
pub const FieldRef = policy_types.FieldRef;
pub const FieldMutator = policy_types.FieldMutator;
pub const MutateOp = policy_types.MutateOp;
pub const TelemetryType = policy_types.TelemetryType;

// Proto types
const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const MetricTarget = proto.policy.MetricTarget;

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

    /// Empty result for dropped telemetry
    pub const dropped = PolicyResult{
        .decision = .drop,
        .matched_policy_ids = &.{},
    };

    /// Default result when no policies match
    pub const unmatched = PolicyResult{
        .decision = .unset,
        .matched_policy_ids = &.{},
    };
};

// Re-export FilterResult for backwards compatibility during migration
pub const FilterResult = FilterDecision;

// =============================================================================
// FieldAccessor - Interface for accessing field values
// =============================================================================

/// Field accessor function type.
/// Given a FieldRef, returns the field value as a string slice, or null if not found.
/// This type is shared with log_transform for both filtering and transform operations.
pub const FieldAccessor = *const fn (ctx: *const anyopaque, field: FieldRef) ?[]const u8;

// =============================================================================
// Observability Events
// =============================================================================

const EvaluateEmpty = struct {};
const EvaluateStart = struct { matcher_key_count: usize, policy_count: usize };
const MatcherKeyFieldNotPresent = struct { field: FieldRef };
const MatcherKeyFieldValue = struct { field: FieldRef, value: []const u8 };
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
    /// Allocator for temporary match aggregation buffers
    allocator: std.mem.Allocator,
    /// Event bus for observability
    bus: *EventBus,
    /// Policy registry for getting snapshots and recording stats/errors
    registry: *PolicyRegistry,

    const Self = @This();

    /// Maximum number of pattern matches to track per scan
    const MAX_MATCHES_PER_SCAN: usize = 256;

    pub fn init(allocator: std.mem.Allocator, bus: *EventBus, registry: *PolicyRegistry) Self {
        return .{
            .allocator = allocator,
            .bus = bus,
            .registry = registry,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to free currently
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
        match_counts: [MAX_POLICIES]u16,
        active_policies: [MAX_POLICIES]PolicyIndex,
        is_active: [MAX_POLICIES]bool,
        active_count: usize,
    };

    /// Result of finding matching policies from scan state
    const MatchState = struct {
        matched_indices: [MAX_POLICIES]PolicyIndex,
        matched_keep_values: [MAX_POLICIES]KeepValue,
        matched_count: usize,
        best_decision: FilterDecision,
        has_keep_policy: bool,
        has_drop_policy: bool,

        inline fn hasMixedDecisions(self: *const MatchState) bool {
            return self.has_keep_policy and self.has_drop_policy;
        }
    };

    pub fn evaluate(
        self: *const Self,
        telemetry_type: TelemetryType,
        ctx: *anyopaque,
        field_accessor: FieldAccessor,
        field_mutator: ?FieldMutator,
        policy_id_buf: [][]const u8,
    ) PolicyResult {
        // Get current snapshot from registry (lock-free)
        const snapshot = self.registry.getSnapshot() orelse {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        };

        // Currently only log telemetry type uses Hyperscan matcher index
        // Metric matching will be implemented separately
        if (telemetry_type != .log) {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        }

        const index = &snapshot.matcher_index;

        if (index.isEmpty()) {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        }

        self.bus.debug(EvaluateStart{ .matcher_key_count = index.getMatcherKeys().len, .policy_count = index.getPolicyCount() });

        // Phase 1: Scan all matcher keys and compute match counts
        var scan_state = self.scanMatcherKeys(ctx, field_accessor, index);

        // Phase 2: Find matching policies and determine decision
        var match_state = self.findMatchingPolicies(index, &scan_state, policy_id_buf);

        self.bus.debug(EvaluateResult{ .decision = match_state.best_decision, .matched_count = match_state.matched_count });

        // Phase 3: Handle drop case (record stats, return early)
        if (match_state.best_decision == .drop) {
            self.recordDropStats(policy_id_buf, &match_state);
            return PolicyResult.dropped;
        }

        // Phase 4: Apply transforms and record stats for keep case
        self.applyTransformsAndRecordStats(ctx, field_accessor, field_mutator, snapshot, policy_id_buf, &match_state);

        return PolicyResult{
            .decision = match_state.best_decision,
            .matched_policy_ids = policy_id_buf[0..match_state.matched_count],
        };
    }

    /// Scan all matcher keys and compute match counts for each policy.
    /// Returns state needed for determining which policies matched.
    inline fn scanMatcherKeys(
        self: *const Self,
        ctx: *anyopaque,
        field_accessor: FieldAccessor,
        index: *const MatcherIndex,
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
        for (index.getPoliciesWithNegation()) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;
            state.match_counts[policy_index] = policy_info.negated_count;
            state.is_active[policy_index] = true;
            state.active_policies[state.active_count] = policy_index;
            state.active_count += 1;
        }

        var result_buf: [MAX_MATCHES_PER_SCAN]u32 = undefined;

        for (index.getMatcherKeys()) |matcher_key| {
            // Currently only log telemetry uses this path
            // Skip metric keys when evaluating log telemetry
            const field_ref = switch (matcher_key) {
                .log => |k| k.field,
                .metric => continue, // Skip metric keys for now - metric evaluation handled separately
            };

            const value = field_accessor(ctx, field_ref) orelse {
                self.bus.debug(MatcherKeyFieldNotPresent{ .field = field_ref });
                continue;
            };

            self.bus.debug(MatcherKeyFieldValue{
                .field = field_ref,
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

    /// Find all matching policies from active set and determine best decision.
    inline fn findMatchingPolicies(
        self: *const Self,
        index: *const MatcherIndex,
        scan_state: *const ScanState,
        policy_id_buf: [][]const u8,
    ) MatchState {
        var state = MatchState{
            .matched_indices = undefined,
            .matched_keep_values = undefined,
            .matched_count = 0,
            .best_decision = .unset,
            .has_keep_policy = false,
            .has_drop_policy = false,
        };
        var best_keep: ?KeepValue = null;

        for (scan_state.active_policies[0..scan_state.active_count]) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;

            if (!policy_info.enabled) continue;

            if (scan_state.match_counts[policy_index] == policy_info.required_match_count) {
                self.bus.debug(PolicyFullMatch{ .policy_index = policy_info.index, .policy_id = policy_info.id });

                if (state.matched_count < policy_id_buf.len) {
                    policy_id_buf[state.matched_count] = policy_info.id;
                    state.matched_indices[state.matched_count] = policy_index;
                    state.matched_keep_values[state.matched_count] = policy_info.keep;
                    state.matched_count += 1;

                    const decision = keepToDecision(policy_info.keep);
                    if (decision == .keep) {
                        state.has_keep_policy = true;
                    } else if (decision == .drop) {
                        state.has_drop_policy = true;
                    }
                }

                if (best_keep == null or policy_info.keep.isMoreRestrictiveThan(best_keep.?)) {
                    best_keep = policy_info.keep;
                    state.best_decision = keepToDecision(policy_info.keep);
                }
            }
        }

        return state;
    }

    /// Record stats for all matched policies when decision is drop.
    inline fn recordDropStats(
        self: *const Self,
        policy_id_buf: [][]const u8,
        match_state: *const MatchState,
    ) void {
        if (match_state.matched_count == 0) return;

        const empty_transform_result = log_transform.TransformResult{};

        for (0..match_state.matched_count) |i| {
            const policy_id = policy_id_buf[i];
            const keep_value = match_state.matched_keep_values[i];
            const policy_decision = keepToDecision(keep_value);

            if (match_state.hasMixedDecisions()) {
                if (policy_decision == .keep) {
                    self.registry.recordPolicyStats(policy_id, 1, 0, empty_transform_result);
                } else {
                    self.registry.recordPolicyStats(policy_id, 0, 1, empty_transform_result);
                }
            } else {
                self.registry.recordPolicyStats(policy_id, 1, 0, empty_transform_result);
            }
        }
    }

    /// Apply transforms for each matched policy and record stats.
    inline fn applyTransformsAndRecordStats(
        self: *const Self,
        ctx: *anyopaque,
        field_accessor: FieldAccessor,
        field_mutator: ?FieldMutator,
        snapshot: *const PolicySnapshot,
        policy_id_buf: [][]const u8,
        match_state: *const MatchState,
    ) void {
        for (0..match_state.matched_count) |i| {
            const policy_id = policy_id_buf[i];
            const policy_index = match_state.matched_indices[i];
            const keep_value = match_state.matched_keep_values[i];
            const policy_decision = keepToDecision(keep_value);

            var transform_result = log_transform.TransformResult{};
            if (field_mutator) |mutator| {
                if (snapshot.getPolicy(policy_index)) |policy| {
                    if (getLogTarget(policy)) |log_target| {
                        if (log_target.transform) |transform| {
                            transform_result = log_transform.applyTransforms(&transform, ctx, field_accessor, mutator);
                        }
                    }
                }
            }

            if (transform_result.totalApplied() > 0) {
                self.bus.debug(TransformApplied{
                    .policy_id = policy_id,
                    .removes = transform_result.removes_applied,
                    .redacts = transform_result.redacts_applied,
                    .renames = transform_result.renames_applied,
                    .adds = transform_result.adds_applied,
                });
            }

            if (match_state.hasMixedDecisions()) {
                if (policy_decision == .keep) {
                    self.registry.recordPolicyStats(policy_id, 1, 0, transform_result);
                } else {
                    self.registry.recordPolicyStats(policy_id, 0, 1, transform_result);
                }
            } else {
                self.registry.recordPolicyStats(policy_id, 1, 0, transform_result);
            }
        }
    }

    /// Convert KeepValue to FilterDecision
    fn keepToDecision(keep: KeepValue) FilterDecision {
        return switch (keep) {
            .none => .drop,
            .all => .keep,
            // For percentage and rate limits, we keep for now (sampling not implemented)
            .percentage, .per_second, .per_minute => .keep,
        };
    }
};

// Backwards compatibility alias
pub const FilterEngine = PolicyEngine;

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);
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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{ drop_policy1, drop_policy2 }, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    // Log matches both DROP policies
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Both policies should get hits (all same action)
    try testing.expectEqual(@as(usize, 2), stats_provider.callCount());

    const stats1 = stats_provider.getStats("drop-1").?;
    try testing.expectEqual(@as(i64, 1), stats1.hits);
    try testing.expectEqual(@as(i64, 0), stats1.misses);

    const stats2 = stats_provider.getStats("drop-2").?;
    try testing.expectEqual(@as(i64, 1), stats2.hits);
    try testing.expectEqual(@as(i64, 0), stats2.misses);
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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2 }, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    // Log matches both KEEP policies
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    try testing.expectEqual(FilterDecision.keep, result.decision);

    // Both policies should get hits (all same action)
    try testing.expectEqual(@as(usize, 2), stats_provider.callCount());

    const stats1 = stats_provider.getStats("keep-1").?;
    try testing.expectEqual(@as(i64, 1), stats1.hits);
    try testing.expectEqual(@as(i64, 0), stats1.misses);

    const stats2 = stats_provider.getStats("keep-2").?;
    try testing.expectEqual(@as(i64, 1), stats2.hits);
    try testing.expectEqual(@as(i64, 0), stats2.misses);
}

test "PolicyEngine stats: mixed KEEP and DROP - KEEP gets hits, DROP gets misses" {
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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{ keep_policy, drop_policy }, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    // Log matches both policies (KEEP and DROP)
    var test_log = TestLogContext{ .message = "critical error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // Both policies should have stats recorded
    try testing.expectEqual(@as(usize, 2), stats_provider.callCount());

    // KEEP policy gets hit (it matched)
    const keep_stats = stats_provider.getStats("keep-policy").?;
    try testing.expectEqual(@as(i64, 1), keep_stats.hits);
    try testing.expectEqual(@as(i64, 0), keep_stats.misses);

    // DROP policy gets miss (KEEP was also present)
    const drop_stats = stats_provider.getStats("drop-policy").?;
    try testing.expectEqual(@as(i64, 0), drop_stats.hits);
    try testing.expectEqual(@as(i64, 1), drop_stats.misses);
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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{policy}, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    var test_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // Single policy should get a hit
    try testing.expectEqual(@as(usize, 1), stats_provider.callCount());
    const stats = stats_provider.getStats("single-policy").?;
    try testing.expectEqual(@as(i64, 1), stats.hits);
    try testing.expectEqual(@as(i64, 0), stats.misses);
}

test "PolicyEngine stats: multiple KEEPs and DROPs - all KEEPs get hits, all DROPs get misses" {
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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{ keep_policy1, keep_policy2, drop_policy1, drop_policy2 }, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    // Log matches all 4 policies (2 KEEP, 2 DROP)
    var test_log = TestLogContext{ .message = "critical error with warning and debug info" };
    var policy_id_buf: [16][]const u8 = undefined;
    const result = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // DROP wins (most restrictive)
    try testing.expectEqual(FilterDecision.drop, result.decision);

    // All 4 policies should have stats recorded
    try testing.expectEqual(@as(usize, 4), stats_provider.callCount());

    // Both KEEP policies get hits
    const keep1_stats = stats_provider.getStats("keep-1").?;
    try testing.expectEqual(@as(i64, 1), keep1_stats.hits);
    try testing.expectEqual(@as(i64, 0), keep1_stats.misses);

    const keep2_stats = stats_provider.getStats("keep-2").?;
    try testing.expectEqual(@as(i64, 1), keep2_stats.hits);
    try testing.expectEqual(@as(i64, 0), keep2_stats.misses);

    // Both DROP policies get misses (because KEEP policies were also present)
    const drop1_stats = stats_provider.getStats("drop-1").?;
    try testing.expectEqual(@as(i64, 0), drop1_stats.hits);
    try testing.expectEqual(@as(i64, 1), drop1_stats.misses);

    const drop2_stats = stats_provider.getStats("drop-2").?;
    try testing.expectEqual(@as(i64, 0), drop2_stats.hits);
    try testing.expectEqual(@as(i64, 1), drop2_stats.misses);
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

    var stats_provider = StatsTrackingProvider.init(allocator);
    defer stats_provider.deinit();
    var provider_iface = stats_provider.provider();

    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try registry.registerProvider(&provider_iface);
    try registry.updatePolicies(&.{policy}, "stats-tracking-provider", .file);

    const engine = PolicyEngine.init(allocator, noop_bus.eventBus(), &registry);

    // Log doesn't match the policy
    var test_log = TestLogContext{ .message = "all good here" };
    var policy_id_buf: [16][]const u8 = undefined;
    _ = engine.evaluate(.log, &test_log, TestLogContext.fieldAccessor, null, &policy_id_buf);

    // No stats should be recorded
    try testing.expectEqual(@as(usize, 0), stats_provider.callCount());
}
