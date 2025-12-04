//! Filter Engine - Hyperscan-based policy evaluation
//!
//! This module provides efficient policy evaluation using an inverted index
//! of Hyperscan databases. Instead of iterating through policies and checking
//! matchers, we:
//!
//! 1. Iterate through matcher keys (MatchCase, attribute_key)
//! 2. Scan field values against pre-compiled Hyperscan databases
//! 3. Aggregate match counts per policy
//! 4. Select the highest priority policy where all matchers matched
//!
//! ## Performance Characteristics
//!
//! - O(k * n) where k = number of unique matcher keys, n = input text length
//! - Independent of the number of policies or patterns per key
//! - Lock-free reads from atomic snapshot pointer

const std = @import("std");
const proto = @import("proto");
const matcher_index = @import("matcher_index.zig");
const o11y = @import("../observability/root.zig");
const NoopEventBus = o11y.NoopEventBus;

const log = std.log.scoped(.filter_engine);

const FilterAction = proto.policy.FilterAction;
const LogMatcher = proto.policy.LogMatcher;

const MatcherIndex = matcher_index.MatcherIndex;
const MatcherKey = matcher_index.MatcherKey;
const MatcherDatabase = matcher_index.MatcherDatabase;
const PolicyInfo = matcher_index.PolicyInfo;
const PatternMeta = matcher_index.PatternMeta;
pub const MatchCase = matcher_index.MatchCase;

// =============================================================================
// FilterResult - Evaluation outcome
// =============================================================================

/// Result of filter evaluation
pub const FilterResult = enum {
    /// Keep the data (forward/process)
    keep,
    /// Drop the data (filter out)
    drop,
};

// =============================================================================
// FieldAccessor - Interface for accessing field values
// =============================================================================

/// Field accessor function type.
/// Given a MatchCase and key, returns the field value as a string slice, or null if not found.
pub const FieldAccessor = *const fn (ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8;

// =============================================================================
// FilterEngine - Main evaluation engine
// =============================================================================

/// Filter engine that evaluates data against policies using Hyperscan.
/// Uses an inverted index for O(k*n) evaluation regardless of policy count.
pub const FilterEngine = struct {
    /// Allocator for temporary match aggregation buffers
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Maximum number of pattern matches to track per scan
    const MAX_MATCHES_PER_SCAN: usize = 256;

    /// Maximum number of policies to track matches for
    const MAX_POLICIES: usize = 1024;

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
        // No resources to free currently
    }

    /// Evaluate data against all policies in the index.
    ///
    /// Returns the action of the highest priority fully-matching policy,
    /// or FilterResult.keep if no policies match.
    ///
    /// A policy "fully matches" when:
    /// - All non-negated matchers have their patterns found in the field value
    /// - All negated matchers have their patterns NOT found in the field value
    ///
    /// Thread-safe: uses only stack-allocated buffers for match aggregation.
    pub fn evaluate(
        self: *const Self,
        index: *const MatcherIndex,
        ctx: *const anyopaque,
        field_accessor: FieldAccessor,
    ) FilterResult {
        _ = self;

        if (index.isEmpty()) {
            log.debug("evaluate: index is empty, returning keep", .{});
            return .keep;
        }

        log.debug("evaluate: checking {d} matcher keys", .{index.getMatcherKeys().len});

        // Stack-allocated match count tracking
        // Maps policy_id hash -> (match_count, policy_id_ptr)
        var match_counts: [MAX_POLICIES]MatchCountEntry = undefined;
        var match_count_len: usize = 0;

        // Track which negated matchers have been "hit" (pattern found, which is a failure for negation)
        var negation_failures: [MAX_POLICIES]NegationFailure = undefined;
        var negation_failure_len: usize = 0;

        // Buffer for scan results
        var result_buf: [MAX_MATCHES_PER_SCAN]u32 = undefined;

        // Iterate through all matcher keys
        for (index.getMatcherKeys()) |matcher_key| {
            // Get field value for this key
            const value = field_accessor(ctx, matcher_key.match_case, matcher_key.key) orelse {
                // Field not present - handle negated matchers specially
                // For negated matchers, missing field means pattern cannot be found = success
                // We don't need to do anything here because negated matchers default to "succeeded"
                // (only failures are tracked)
                log.debug("  matcher_key match_case={any} key='{s}': field not present", .{ matcher_key.match_case, matcher_key.key });
                continue;
            };

            log.debug("  matcher_key match_case={any} key='{s}': value='{s}'", .{ matcher_key.match_case, matcher_key.key, if (value.len > 100) value[0..100] else value });

            // Get database for this key
            const db = index.getDatabase(matcher_key) orelse {
                log.debug("    no database found for this key", .{});
                continue;
            };

            // Scan the value
            const scan_result = db.scan(value, &result_buf);
            log.debug("    scan returned {d} matches", .{scan_result.count});

            // Process matches
            for (scan_result.matches()) |pattern_id| {
                if (pattern_id >= db.patterns.len) continue;

                const meta = db.patterns[pattern_id];

                if (meta.negate) {
                    // Pattern found for a negated matcher = FAILURE
                    // Record this so we know this policy's negated matcher failed
                    log.debug("    pattern_id={d} policy='{s}' NEGATION FAILURE (pattern found but negate=true)", .{ pattern_id, meta.policy_id });
                    if (negation_failure_len < MAX_POLICIES) {
                        negation_failures[negation_failure_len] = .{
                            .policy_id = meta.policy_id,
                            .matcher_index = meta.matcher_index,
                        };
                        negation_failure_len += 1;
                    }
                } else {
                    // Pattern found for a non-negated matcher = SUCCESS
                    // Increment match count for this policy
                    log.debug("    pattern_id={d} policy='{s}' MATCH (incrementing count)", .{ pattern_id, meta.policy_id });
                    incrementMatchCount(&match_counts, &match_count_len, meta.policy_id);
                }
            }
        }

        // Log match counts
        log.debug("Match counts ({d} policies with matches):", .{match_count_len});
        for (match_counts[0..match_count_len]) |entry| {
            const policy_info = index.getPolicy(entry.policy_id);
            if (policy_info) |info| {
                log.debug("  policy='{s}' matches={d} required={d} (negated={d})", .{ entry.policy_id, entry.count, info.regex_matcher_count - @as(u32, @intCast(info.negated_matchers.items.len)), info.negated_matchers.items.len });
            } else {
                log.debug("  policy='{s}' matches={d} (policy info not found!)", .{ entry.policy_id, entry.count });
            }
        }

        // Find the best matching policy
        const result = findBestMatch(index, &match_counts, match_count_len, &negation_failures, negation_failure_len);
        log.debug("evaluate result: {any}", .{result});
        return result;
    }

    /// Match count tracking entry
    const MatchCountEntry = struct {
        policy_id: []const u8,
        count: u32,
    };

    /// Negation failure tracking
    const NegationFailure = struct {
        policy_id: []const u8,
        matcher_index: u32,
    };

    /// Increment the match count for a policy
    fn incrementMatchCount(
        entries: *[MAX_POLICIES]MatchCountEntry,
        len: *usize,
        policy_id: []const u8,
    ) void {
        // Look for existing entry
        for (entries[0..len.*]) |*entry| {
            if (std.mem.eql(u8, entry.policy_id, policy_id)) {
                entry.count += 1;
                return;
            }
        }

        // Add new entry
        if (len.* < MAX_POLICIES) {
            entries[len.*] = .{
                .policy_id = policy_id,
                .count = 1,
            };
            len.* += 1;
        }
    }

    /// Find the best matching policy given match counts and negation failures
    fn findBestMatch(
        index: *const MatcherIndex,
        match_counts: *const [MAX_POLICIES]MatchCountEntry,
        match_count_len: usize,
        negation_failures: *const [MAX_POLICIES]NegationFailure,
        negation_failure_len: usize,
    ) FilterResult {
        var best_priority: ?i32 = null;
        var best_action: FilterResult = .keep;

        // Check each policy with matches
        for (match_counts[0..match_count_len]) |entry| {
            const policy_info = index.getPolicy(entry.policy_id) orelse continue;

            // Skip disabled policies
            if (!policy_info.enabled) continue;

            // Count how many negated matchers this policy has
            const negated_count = policy_info.negated_matchers.items.len;

            // For the policy to match:
            // 1. Non-negated match count must equal (total matchers - negated matchers)
            const expected_non_negated = policy_info.regex_matcher_count - @as(u32, @intCast(negated_count));
            if (entry.count != expected_non_negated) continue;

            // 2. No negated matchers should have failed (pattern found when it shouldn't be)
            var negation_failed = false;
            for (negation_failures[0..negation_failure_len]) |failure| {
                if (std.mem.eql(u8, failure.policy_id, entry.policy_id)) {
                    negation_failed = true;
                    break;
                }
            }
            if (negation_failed) continue;

            // Policy fully matches! Check if it's the best priority
            if (best_priority == null or policy_info.priority > best_priority.?) {
                best_priority = policy_info.priority;
                best_action = actionToResult(policy_info.action);
            }
        }

        // Also check policies that only have negated matchers (no positive matches needed)
        // These are policies where ALL matchers are negated
        var policies_it = index.policies.iterator();
        while (policies_it.next()) |kv| {
            const policy_info = kv.value_ptr.*;

            // Skip disabled
            if (!policy_info.enabled) continue;

            // Check if ALL matchers are negated (no non-negated matches required)
            const negated_count = policy_info.negated_matchers.items.len;
            if (negated_count != policy_info.regex_matcher_count) continue;

            // All matchers are negated - check that none of them failed
            var negation_failed = false;
            for (negation_failures[0..negation_failure_len]) |failure| {
                if (std.mem.eql(u8, failure.policy_id, policy_info.id)) {
                    negation_failed = true;
                    break;
                }
            }
            if (negation_failed) continue;

            // This all-negated policy matches! Check priority
            if (best_priority == null or policy_info.priority > best_priority.?) {
                best_priority = policy_info.priority;
                best_action = actionToResult(policy_info.action);
            }
        }

        return best_action;
    }

    /// Convert proto FilterAction to FilterResult
    fn actionToResult(action: FilterAction) FilterResult {
        return switch (action) {
            .FILTER_ACTION_DROP => .drop,
            .FILTER_ACTION_KEEP => .keep,
            else => .keep,
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;
const Policy = proto.policy.Policy;

/// Test context for unit tests - simple struct with known fields
const TestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,
    env: ?[]const u8 = null,

    pub fn fieldAccessor(ctx_ptr: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8 {
        const self: *const TestLogContext = @ptrCast(@alignCast(ctx_ptr));
        return switch (match_case) {
            .log_body => self.message,
            .log_severity_text => self.level,
            .log_attribute => {
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                if (std.mem.eql(u8, key, "env")) return self.env;
                return null;
            },
            else => null,
        };
    }
};

test "FilterEngine: empty index returns keep" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    const test_log = TestLogContext{ .message = "hello" };
    const result = engine.evaluate(&index, @ptrCast(&test_log), TestLogContext.fieldAccessor);

    try testing.expectEqual(FilterResult.keep, result);
}

test "FilterEngine: single policy drop match" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Matching log should be dropped
    const error_log = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&error_log), TestLogContext.fieldAccessor));

    // Non-matching log should be kept
    const info_log = TestLogContext{ .message = "all good" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&info_log), TestLogContext.fieldAccessor));
}

test "FilterEngine: single policy keep match" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Matching log should be kept
    const error_log = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "FilterEngine: multiple matchers AND logic" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-payment-errors"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    // Two matchers - both must match
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Both match - dropped
    const payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&payment_error), TestLogContext.fieldAccessor));

    // Only message matches - kept
    const other_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&other_error), TestLogContext.fieldAccessor));

    // Only service matches - kept
    const payment_info = TestLogContext{ .message = "request completed", .service = "payment-api" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&payment_info), TestLogContext.fieldAccessor));
}

test "FilterEngine: negated matcher" {
    const allocator = testing.allocator;

    // Drop logs that do NOT contain "important"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "important") } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Non-important log should be dropped (negate: pattern NOT found = success)
    const boring = TestLogContext{ .message = "just a regular log" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&boring), TestLogContext.fieldAccessor));

    // Important log should be kept (negate: pattern found = failure)
    const important = TestLogContext{ .message = "this is important data" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&important), TestLogContext.fieldAccessor));
}

test "FilterEngine: mixed negated and non-negated matchers" {
    const allocator = testing.allocator;

    // Drop errors that are NOT from production
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-prod-errors"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    // Must contain "error"
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    // Must NOT be from production
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "env"),
            .regex = try allocator.dupe(u8, "prod"),
        } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Error from staging - dropped (error matches, prod not found = both conditions satisfied)
    const staging_error = TestLogContext{ .message = "an error occurred", .env = "staging" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&staging_error), TestLogContext.fieldAccessor));

    // Error from production - kept (error matches, but prod IS found = negation failed)
    const prod_error = TestLogContext{ .message = "an error occurred", .env = "production" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&prod_error), TestLogContext.fieldAccessor));

    // Non-error from staging - kept (error doesn't match)
    const staging_info = TestLogContext{ .message = "all good", .env = "staging" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&staging_info), TestLogContext.fieldAccessor));
}

test "FilterEngine: priority ordering - higher priority wins" {
    const allocator = testing.allocator;

    // Low priority: drop errors
    var low_priority = Policy{
        .id = try allocator.dupe(u8, "low-priority"),
        .name = try allocator.dupe(u8, "low-priority"),
        .enabled = true,
        .priority = 1,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try low_priority.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer low_priority.deinit(allocator);

    // High priority: keep errors from payment service
    var high_priority = Policy{
        .id = try allocator.dupe(u8, "high-priority"),
        .name = try allocator.dupe(u8, "high-priority"),
        .enabled = true,
        .priority = 100,
        .log_filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try high_priority.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    try high_priority.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    defer high_priority.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{ low_priority, high_priority }, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Error from payment - both policies match, high priority wins (KEEP)
    const payment_error = TestLogContext{ .message = "an error occurred", .service = "payment-api" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&payment_error), TestLogContext.fieldAccessor));

    // Error from auth - only low priority matches (DROP)
    const auth_error = TestLogContext{ .message = "an error occurred", .service = "auth-api" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&auth_error), TestLogContext.fieldAccessor));
}

test "FilterEngine: disabled policies are skipped" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // Disabled!
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Would match but policy is disabled - kept
    const error_log = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "FilterEngine: regex pattern matching" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-error-pattern"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    // Regex pattern: matches "error" or "Error" case-insensitive with (?i)
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "^.*rror") } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Various error formats should match
    const error1 = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&error1), TestLogContext.fieldAccessor));

    const error2 = TestLogContext{ .message = "Error: something went wrong" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&error2), TestLogContext.fieldAccessor));

    // Non-matching should be kept
    const info = TestLogContext{ .message = "everything is fine" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&info), TestLogContext.fieldAccessor));
}

test "FilterEngine: missing field with negated matcher succeeds" {
    const allocator = testing.allocator;

    // Drop logs where service attribute does NOT contain "critical"
    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-non-critical"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "^critical-s.*$"),
        } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{policy}, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // No service attribute = pattern cannot be found = negation succeeds = dropped
    const no_service = TestLogContext{ .message = "hello" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&no_service), TestLogContext.fieldAccessor));

    // Service without "critical" = negation succeeds = dropped
    const non_critical = TestLogContext{ .message = "hello", .service = "normal-service" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&non_critical), TestLogContext.fieldAccessor));

    // Service with "critical" = negation fails = kept
    const critical = TestLogContext{ .message = "hello", .service = "critical-service" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&critical), TestLogContext.fieldAccessor));
}

test "FilterEngine: multiple policies with different matcher keys" {
    const allocator = testing.allocator;

    // Policy 1: Drop based on log_body
    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy1.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy1.deinit(allocator);

    // Policy 2: Drop based on log_attribute
    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "drop-debug-service"),
        .enabled = true,
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy2.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "debug"),
        } },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, &.{ policy1, policy2 }, noop_bus.eventBus());
    defer index.deinit();

    const engine = FilterEngine.init(allocator);

    // Matches policy1
    const error_log = TestLogContext{ .message = "an error occurred", .service = "payment" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&error_log), TestLogContext.fieldAccessor));

    // Matches policy2
    const debug_log = TestLogContext{ .message = "all good", .service = "debug-service" };
    try testing.expectEqual(FilterResult.drop, engine.evaluate(&index, @ptrCast(&debug_log), TestLogContext.fieldAccessor));

    // Matches neither
    const normal_log = TestLogContext{ .message = "all good", .service = "payment" };
    try testing.expectEqual(FilterResult.keep, engine.evaluate(&index, @ptrCast(&normal_log), TestLogContext.fieldAccessor));
}
