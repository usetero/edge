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
const matcher_index = @import("../hyperscan/matcher_index.zig");
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
    pub fn evaluate(
        self: *const Self,
        ctx: *anyopaque,
        field_accessor: FieldAccessor,
        field_mutator: ?FieldMutator,
        policy_id_buf: [][]const u8,
    ) PolicyResult {
        const result = self.evaluateFilter(ctx, field_accessor, policy_id_buf);
        if (!result.decision.shouldContinue()) {
            return result;
        }

        // Apply transforms if mutator provided
        if (field_mutator) |mutator| {
            const snapshot = self.registry.getSnapshot() orelse return result;

            // For each matched policy, apply its transforms
            for (result.matched_policy_ids) |policy_id| {
                // Find policy by ID in snapshot
                for (snapshot.policies) |*policy| {
                    if (std.mem.eql(u8, policy.id, policy_id)) {
                        const log_target = policy.log orelse continue;
                        const transform = log_target.transform orelse continue;
                        _ = log_transform.applyTransforms(&transform, ctx, field_accessor, mutator);
                        break;
                    }
                }
            }
        }

        return result;
    }

    /// Full policy evaluation with filter decision and matched policy IDs.
    /// Returns PolicyResult containing the filter decision and list of matched policy IDs.
    pub fn evaluateFilter(
        self: *const Self,
        ctx: *const anyopaque,
        field_accessor: FieldAccessor,
        policy_id_buf: [][]const u8,
    ) PolicyResult {
        // Get current snapshot from registry (lock-free)
        const snapshot = self.registry.getSnapshot() orelse {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        };

        const index = &snapshot.matcher_index;

        if (index.isEmpty()) {
            self.bus.debug(EvaluateEmpty{});
            return PolicyResult.unmatched;
        }

        const policy_count = index.getPolicyCount();
        self.bus.debug(EvaluateStart{ .matcher_key_count = index.getMatcherKeys().len, .policy_count = policy_count });

        // Stack-allocated arrays for O(1) per-policy operations
        // Initialize match_counts[i] = negated_count[i] (assume all negated patterns pass)
        // Positive matches increment, negated matches decrement
        // Policy matches when match_counts[i] == required_match_count[i]
        var match_counts: [MAX_POLICIES]u16 = std.mem.zeroes([MAX_POLICIES]u16);

        // Track which policies had any match activity
        var active_policies: [MAX_POLICIES]PolicyIndex = undefined;
        var active_count: usize = 0;
        var is_active: [MAX_POLICIES]bool = std.mem.zeroes([MAX_POLICIES]bool);

        // Initialize match counts and mark policies with negated patterns as active
        // Uses precomputed list from index build time - no iteration over all policies
        for (index.getPoliciesWithNegation()) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;
            match_counts[policy_index] = policy_info.negated_count;
            is_active[policy_index] = true;
            active_policies[active_count] = policy_index;
            active_count += 1;
        }

        // Buffer for scan results
        var result_buf: [MAX_MATCHES_PER_SCAN]u32 = undefined;

        // Iterate through all matcher keys
        for (index.getMatcherKeys()) |matcher_key| {
            // Get field value for this key
            const field_ref = matcher_key.field;
            const value = field_accessor(ctx, field_ref) orelse {
                // Field not present - negated matchers succeed (already counted)
                // Positive matchers fail (no match possible)
                self.bus.debug(MatcherKeyFieldNotPresent{ .field = field_ref });
                continue;
            };

            self.bus.debug(MatcherKeyFieldValue{
                .field = field_ref,
                .value = if (value.len > 100) value[0..100] else value,
            });

            // Get database for this key
            const db = index.getDatabase(matcher_key) orelse {
                self.bus.debug(MatcherKeyNoDatabase{});
                continue;
            };

            // Scan positive patterns - increment match counts
            const positive_result = db.scanPositive(value, &result_buf);
            for (positive_result.matches()) |pattern_id| {
                if (pattern_id < db.positive_patterns.len) {
                    const meta = db.positive_patterns[pattern_id];
                    match_counts[meta.policy_index] += 1;
                    if (!is_active[meta.policy_index]) {
                        is_active[meta.policy_index] = true;
                        active_policies[active_count] = meta.policy_index;
                        active_count += 1;
                    }
                }
            }

            // Scan negated patterns - decrement match counts (negated pattern matched = failed)
            const negated_result = db.scanNegated(value, &result_buf);
            for (negated_result.matches()) |pattern_id| {
                if (pattern_id < db.negated_patterns.len) {
                    const meta = db.negated_patterns[pattern_id];
                    match_counts[meta.policy_index] -= 1;
                    if (!is_active[meta.policy_index]) {
                        is_active[meta.policy_index] = true;
                        active_policies[active_count] = meta.policy_index;
                        active_count += 1;
                    }
                    self.bus.debug(PolicyNegationFailed{ .policy_index = meta.policy_index });
                }
            }

            self.bus.debug(ScanResult{ .positive_count = positive_result.count, .negated_count = negated_result.count });
        }

        // Find all matching policies from active set
        var matched_count: usize = 0;
        var best_keep: ?KeepValue = null;
        var best_decision: FilterDecision = .unset;

        for (active_policies[0..active_count]) |policy_index| {
            const policy_info = index.getPolicyByIndex(policy_index) orelse continue;

            // Skip disabled policies
            if (!policy_info.enabled) continue;

            // Policy matches when count equals required
            if (match_counts[policy_index] == policy_info.required_match_count) {
                self.bus.debug(PolicyFullMatch{ .policy_index = policy_info.index, .policy_id = policy_info.id });

                // Add to matched list if buffer has space
                if (matched_count < policy_id_buf.len) {
                    policy_id_buf[matched_count] = policy_info.id;
                    matched_count += 1;
                }

                // Update best decision based on priority
                if (best_keep == null or policy_info.keep.isMoreRestrictiveThan(best_keep.?)) {
                    best_keep = policy_info.keep;
                    best_decision = keepToDecision(policy_info.keep);
                }
            }
        }

        self.bus.debug(EvaluateResult{ .decision = best_decision, .matched_count = matched_count });

        // Record policy stats for the winning policy (most restrictive)
        if (matched_count > 0) {
            self.registry.recordPolicyStats(policy_id_buf[0], 1, 0);
        }

        // If drop, return early with empty result (no transform needed)
        if (best_decision == .drop) {
            return PolicyResult.dropped;
        }

        // Return keep/unset with matched policy IDs for transform stage
        return PolicyResult{
            .decision = best_decision,
            .matched_policy_ids = policy_id_buf[0..matched_count],
        };
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
const Policy = proto.policy.Policy;
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

    const test_log = TestLogContext{ .message = "hello" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluateFilter(&test_log, TestLogContext.fieldAccessor, &policy_id_buf);

    try testing.expectEqual(FilterDecision.unset, result.decision);
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);
}

test "PolicyEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf);
    try testing.expectEqual(FilterDecision.drop, result.decision);
    // Dropped results don't include policy IDs (no transform needed)
    try testing.expectEqual(@as(usize, 0), result.matched_policy_ids.len);

    // Non-matching log should be unset (no policy matched)
    const info_log = TestLogContext{ .message = "all good" };
    const result2 = engine.evaluateFilter(&info_log, TestLogContext.fieldAccessor, &policy_id_buf);
    try testing.expectEqual(FilterDecision.unset, result2.decision);
}

test "PolicyEngine: single policy keep match returns policy ID" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [16][]const u8 = undefined;

    const result = engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    // Two matchers - both must match
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.log.?.match.append(allocator, .{
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
    const payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&payment_error, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Only message matches - unset
    const other_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&other_error, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Only service matches - unset
    const payment_info = TestLogContext{ .message = "request completed", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&payment_info, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: negated matcher" {
    const allocator = testing.allocator;

    // Drop logs that do NOT contain "important"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const boring = TestLogContext{ .message = "just a regular log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&boring, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Important log should be unset (negate: pattern found = failure, no match)
    const important = TestLogContext{ .message = "this is important data" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&important, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: mixed negated and non-negated matchers" {
    const allocator = testing.allocator;

    // Drop errors that are NOT from production
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-prod-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    // Must contain "error"
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    // Must NOT be from production
    try policy.log.?.match.append(allocator, .{
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
    const staging_error = TestLogContext{ .message = "an error occurred", .env = "staging" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&staging_error, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Error from production - unset (error matches, but prod IS found = negation failed)
    const prod_error = TestLogContext{ .message = "an error occurred", .env = "production" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&prod_error, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Non-error from staging - unset (error doesn't match)
    const staging_info = TestLogContext{ .message = "all good", .env = "staging" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&staging_info, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: most restrictive wins - drop beats keep" {
    const allocator = testing.allocator;

    // Policy that keeps errors
    var keep_policy = Policy{
        .id = try allocator.dupe(u8, "keep-errors"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
        },
    };
    try keep_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer keep_policy.deinit(allocator);

    // Policy that drops errors from payment service (more specific AND more restrictive)
    var drop_policy = Policy{
        .id = try allocator.dupe(u8, "drop-payment-errors"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try drop_policy.log.?.match.append(allocator, .{
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
    const payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&payment_error, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Error from auth - only keep_policy matches (KEEP)
    const auth_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    const result = engine.evaluateFilter(&auth_error, TestLogContext.fieldAccessor, &policy_id_buf);
    try testing.expectEqual(FilterDecision.keep, result.decision);
    try testing.expectEqual(@as(usize, 1), result.matched_policy_ids.len);
}

test "PolicyEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // Disabled!
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const error_log = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-error-pattern"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    // Regex pattern: matches "error" or "Error" case-insensitive with (?i)
    try policy.log.?.match.append(allocator, .{
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
    const error1 = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error1, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    const error2 = TestLogContext{ .message = "Error: something went wrong" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error2, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Non-matching should be unset
    const info = TestLogContext{ .message = "everything is fine" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&info, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: missing field with negated matcher succeeds" {
    const allocator = testing.allocator;

    // Drop logs where service attribute does NOT contain "critical"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const no_service = TestLogContext{ .message = "hello" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&no_service, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Service without "critical" = negation succeeds = dropped
    const non_critical = TestLogContext{ .message = "hello", .service = "normal-service" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&non_critical, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Service with "critical" = negation fails = unset
    const critical = TestLogContext{ .message = "hello", .service = "critical-service" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&critical, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: multiple policies with different matcher keys" {
    const allocator = testing.allocator;

    // Policy 1: Drop based on log_body
    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy1.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    // Policy 2: Drop based on log_attribute
    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-debug-service"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy2.log.?.match.append(allocator, .{
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
    const error_log = TestLogContext{ .message = "an error occurred", .service = "payment" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Matches policy2
    const debug_log = TestLogContext{ .message = "all good", .service = "debug-service" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&debug_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Matches neither
    const normal_log = TestLogContext{ .message = "all good", .service = "payment" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&normal_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: evaluateFilter backwards compatibility" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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

    // Test evaluateFilter returns full PolicyResult
    const error_log = TestLogContext{ .message = "an error occurred" };
    var policy_id_buf: [MAX_POLICIES][]const u8 = undefined;
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    const info_log = TestLogContext{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&info_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);
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
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try policy1.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-warning"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try policy2.log.?.match.append(allocator, .{
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
    const normal = TestLogContext{ .message = "all good" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&normal, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Match policy1 only
    const error_log = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Match policy2 only
    const warning_log = TestLogContext{ .message = "warning issued" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&warning_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: all policies negated only - all start active" {
    // Edge case: All policies have only negated patterns.
    // All policies start active and match if their negated patterns don't match.
    const allocator = testing.allocator;

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try policy1.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "important") },
        .negate = true,
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try policy2.log.?.match.append(allocator, .{
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
    const boring = TestLogContext{ .message = "just a normal log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&boring, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "important" - policy1 fails, policy2 still matches
    const important = TestLogContext{ .message = "important data here" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&important, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "critical" - policy1 still matches, policy2 fails
    const critical = TestLogContext{ .message = "critical issue" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&critical, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains both - both policies fail
    const both = TestLogContext{ .message = "important and critical" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&both, TestLogContext.fieldAccessor, &policy_id_buf).decision);
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
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try positive_policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer positive_policy.deinit(allocator);

    // Policy with only negated pattern
    var negated_policy = Policy{
        .id = try allocator.dupe(u8, "negated-policy"),
        .name = try allocator.dupe(u8, "drop-non-debug"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    try negated_policy.log.?.match.append(allocator, .{
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
    const normal = TestLogContext{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&normal, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "error", no "debug" - both policies match
    const error_log = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "debug" - negated policy fails, positive policy doesn't match
    const debug_log = TestLogContext{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&debug_log, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains both "error" and "debug" - positive matches, negated fails
    const error_debug = TestLogContext{ .message = "error in debug mode" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_debug, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: multiple negated patterns same policy" {
    // Edge case: Policy with multiple negated patterns - all must "pass" (not match)
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-special"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    // Must NOT contain "skip" AND must NOT contain "ignore"
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "skip") },
        .negate = true,
    });
    try policy.log.?.match.append(allocator, .{
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
    const normal = TestLogContext{ .message = "normal message" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&normal, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "skip" - first negation fails - policy doesn't match
    const skip = TestLogContext{ .message = "skip this one" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&skip, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains "ignore" - second negation fails - policy doesn't match
    const ignore = TestLogContext{ .message = "ignore this" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&ignore, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Contains both - both negations fail - policy doesn't match
    const both = TestLogContext{ .message = "skip and ignore" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&both, TestLogContext.fieldAccessor, &policy_id_buf).decision);
}

test "PolicyEngine: policy becomes active via positive then fails via negated" {
    // Edge case: Policy has both positive and negated patterns.
    // Positive matches first (becomes active), then negated also matches (fails).
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors-not-debug"),
        .enabled = true,
        .log = .{ .keep = try allocator.dupe(u8, "none") },
    };
    // Must contain "error" AND must NOT contain "debug"
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.log.?.match.append(allocator, .{
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
    const error_only = TestLogContext{ .message = "error occurred" };
    try testing.expectEqual(FilterDecision.drop, engine.evaluateFilter(&error_only, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Has both "error" and "debug" - positive matches but negation fails
    // required_match_count = 2 (1 positive + 1 negated)
    // match_counts starts at 1 (negated_count)
    // positive match: +1 -> 2
    // negated match: -1 -> 1
    // Final: 1 != 2 - policy doesn't match
    const error_debug = TestLogContext{ .message = "debug error message" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&error_debug, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Has "debug" but no "error" - positive doesn't match, negation fails
    // match_counts starts at 1, negated match: -1 -> 0, final: 0 != 2
    const debug_only = TestLogContext{ .message = "debug info" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&debug_only, TestLogContext.fieldAccessor, &policy_id_buf).decision);

    // Has neither - positive doesn't match, negation passes
    // match_counts stays at 1 (negated_count), final: 1 != 2
    const neither = TestLogContext{ .message = "normal log" };
    try testing.expectEqual(FilterDecision.unset, engine.evaluateFilter(&neither, TestLogContext.fieldAccessor, &policy_id_buf).decision);
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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
            .transform = transform, // Transform should NOT be applied for drops
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform1,
        },
    };
    try policy1.log.?.match.append(allocator, .{
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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform2,
        },
    };
    try policy2.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            // keep is null (unset) - should still apply transforms
            .transform = transform,
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, null, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            // No transform field
        },
    };
    try policy.log.?.match.append(allocator, .{
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
    const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
            .transform = drop_transform,
        },
    };
    try drop_policy.log.?.match.append(allocator, .{
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
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = keep_transform,
        },
    };
    try keep_policy.log.?.match.append(allocator, .{
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
        const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

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
        const result = engine.evaluate(@ptrCast(&ctx), MutableTestLogContext.fieldAccessor, MutableTestLogContext.fieldMutator, &policy_id_buf);

        try testing.expectEqual(FilterDecision.keep, result.decision);
        // Transform should be applied for keep
        try testing.expectEqualStrings("yes", ctx.attributes.get("kept").?);
    }
}
