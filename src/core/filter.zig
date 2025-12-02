const std = @import("std");
const proto = @import("proto");
const policy_registry = @import("policy_registry.zig");

const Policy = proto.policy.Policy;
const PolicyType = proto.policy.PolicyType;
const TelemetryType = proto.policy.TelemetryType;
const FilterAction = proto.policy.FilterAction;
const FilterConfig = proto.policy.FilterConfig;
const Matcher = proto.policy.Matcher;
const MatchType = proto.policy.MatchType;
const PolicyRegistry = policy_registry.PolicyRegistry;
const PolicySnapshot = policy_registry.PolicySnapshot;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Field accessor function type
/// Given a MatchType and key, returns the field value as a string slice, or null if not found
pub const FieldAccessor = *const fn (ctx: *const anyopaque, match_type: MatchType, key: []const u8) ?[]const u8;

/// Filter evaluates data against policies from the centralized registry
/// Uses lock-free snapshot reads for optimal performance
pub const FilterEvaluator = struct {
    /// Reference to centralized policy registry
    registry: *const PolicyRegistry,

    /// Initialize a new filter evaluator with reference to registry
    pub fn init(registry: *const PolicyRegistry) FilterEvaluator {
        return .{
            .registry = registry,
        };
    }

    /// No resources to free - registry is owned elsewhere
    pub fn deinit(self: *FilterEvaluator) void {
        _ = self;
    }

    /// Evaluate data against policies for a specific telemetry type using a field accessor
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// Uses lock-free snapshot read for consistent view of policies
    /// Uses pre-filtered indices for O(1) lookup of relevant policies
    ///
    /// The field_accessor function is called to retrieve field values from the data.
    /// The ctx pointer is passed through to the accessor for accessing the actual data structure.
    pub fn evaluate(
        self: *const FilterEvaluator,
        ctx: *const anyopaque,
        field_accessor: FieldAccessor,
        telemetry_type: TelemetryType,
    ) FilterResult {
        // Get current policy snapshot (atomic, lock-free)
        const snapshot = self.registry.getSnapshot() orelse return FilterResult.keep;

        // Use pre-filtered index to get only LOG_FILTER policies for this telemetry type
        const policy_indices = snapshot.getIndicesForKey(telemetry_type, .POLICY_TYPE_LOG_FILTER);

        // No policies to evaluate
        if (policy_indices.len == 0) return FilterResult.keep;

        // Process policies in priority order - first match wins
        for (policy_indices) |idx| {
            const policy = snapshot.getPolicy(idx) orelse continue;

            // Skip disabled policies
            if (!policy.enabled) continue;

            // Get filter config
            const config = if (policy.config) |cfg| switch (cfg) {
                .filter => |f| f,
                else => continue,
            } else continue;

            // Check if all matchers match the data
            const matches = matchesAllMatchers(ctx, field_accessor, config.matchers.items);

            if (matches) {
                // Return the action from the matching policy
                return switch (config.action) {
                    .FILTER_ACTION_KEEP => FilterResult.keep,
                    .FILTER_ACTION_DROP => FilterResult.drop,
                    else => FilterResult.keep, // Unknown actions default to keep
                };
            }
        }

        // Default to keep if no policies match
        return FilterResult.keep;
    }
};

/// Check if all matchers match using the field accessor
/// All matchers must match for the overall result to be true (AND logic)
fn matchesAllMatchers(
    ctx: *const anyopaque,
    field_accessor: FieldAccessor,
    matchers: []const Matcher,
) bool {
    if (matchers.len == 0) return false;

    for (matchers) |matcher| {
        const match_result = matchSingleMatcher(ctx, field_accessor, matcher);
        if (!match_result) return false;
    }

    return true;
}

/// Check if a single matcher matches using the field accessor
/// Returns true if the matcher matches (considering negate flag)
fn matchSingleMatcher(ctx: *const anyopaque, field_accessor: FieldAccessor, matcher: Matcher) bool {
    std.debug.print("Matching {any} {s} with {s}\n", .{ matcher.match_type, matcher.key, matcher.regex });
    // Get the field value using the accessor
    const value = field_accessor(ctx, matcher.match_type, matcher.key);

    // Check if the value matches the pattern
    const found = if (value) |v|
        matchesPattern(v, matcher.regex)
    else
        false;

    // Apply negate flag
    return if (matcher.negate) !found else found;
}

/// Check if a value matches a pattern (substring match for now)
/// The pattern is treated as a literal substring to find
fn matchesPattern(value: []const u8, pattern: []const u8) bool {
    if (pattern.len == 0) return true; // Empty pattern matches everything
    return std.mem.indexOf(u8, value, pattern) != null;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test context for unit tests - simple struct with known fields
const TestLogContext = struct {
    level: ?[]const u8 = null,
    message: ?[]const u8 = null,
    service: ?[]const u8 = null,
    ddtags: ?[]const u8 = null,

    fn fieldAccessor(ctx: *const anyopaque, match_type: MatchType, key: []const u8) ?[]const u8 {
        const self: *const TestLogContext = @ptrCast(@alignCast(ctx));
        return switch (match_type) {
            .MATCH_TYPE_LOG_BODY => self.message,
            .MATCH_TYPE_LOG_SEVERITY_TEXT => self.level,
            .MATCH_TYPE_LOG_ATTRIBUTE => {
                if (std.mem.eql(u8, key, "service")) return self.service;
                if (std.mem.eql(u8, key, "ddtags")) return self.ddtags;
                if (std.mem.eql(u8, key, "message")) return self.message;
                return null;
            },
            else => null,
        };
    }
};

test "matchSingleMatcher matches field value" {
    const log = TestLogContext{
        .level = "ERROR",
        .message = "error occurred",
    };

    // Match on message field containing "error"
    const matcher = Matcher{ .match_type = .MATCH_TYPE_LOG_BODY, .regex = "error" };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // No match when pattern not found
    const no_match = Matcher{ .match_type = .MATCH_TYPE_LOG_BODY, .regex = "warning" };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with negate" {
    const log = TestLogContext{
        .level = "INFO",
        .message = "all good",
    };

    // Negated match - true if "ERROR" is NOT in level
    const matcher = Matcher{ .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT, .regex = "ERROR", .negate = true };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // Negated match - false if "INFO" IS in level
    const no_match = Matcher{ .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT, .regex = "INFO", .negate = true };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with log attribute" {
    const log = TestLogContext{
        .service = "payment-api",
        .level = "ERROR",
        .message = "failed",
    };

    // Match log attribute (service field)
    const matcher = Matcher{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "service", .regex = "payment" };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // No match for non-existent service
    const no_match = Matcher{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "service", .regex = "auth" };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with non-existent field" {
    const log = TestLogContext{
        .message = "hello",
    };

    // Non-existent attribute returns null, so no match
    const matcher = Matcher{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "nonexistent", .regex = "hello" };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // With negate, non-existent field means "pattern not found" = true
    const negated = Matcher{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "nonexistent", .regex = "hello", .negate = true };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, negated));
}

test "matchesAllMatchers with multiple matchers (AND logic)" {
    const log = TestLogContext{
        .level = "ERROR",
        .service = "payment",
        .message = "transaction failed",
    };

    // All matchers must match
    const matchers_all_match = [_]Matcher{
        .{ .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT, .regex = "ERROR" },
        .{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "service", .regex = "payment" },
    };
    try testing.expect(matchesAllMatchers(@ptrCast(&log), TestLogContext.fieldAccessor, &matchers_all_match));

    // One matcher fails = overall false
    const matchers_one_fails = [_]Matcher{
        .{ .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT, .regex = "ERROR" },
        .{ .match_type = .MATCH_TYPE_LOG_ATTRIBUTE, .key = "service", .regex = "auth" }, // doesn't match
    };
    try testing.expect(!matchesAllMatchers(@ptrCast(&log), TestLogContext.fieldAccessor, &matchers_one_fails));
}

test "matchesAllMatchers with empty matchers returns false" {
    const log = TestLogContext{
        .message = "test",
    };

    const empty_matchers = [_]Matcher{};
    try testing.expect(!matchesAllMatchers(@ptrCast(&log), TestLogContext.fieldAccessor, &empty_matchers));
}

test "FilterEvaluator.evaluate with LOG_FILTER policy drops matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a DROP policy for debug logs
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-debug"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try drop_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try drop_policy.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT,
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Debug log should be dropped
    const debug_log = TestLogContext{ .level = "DEBUG", .message = "verbose info" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&debug_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));

    // Error log should be kept (doesn't match)
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate with LOG_FILTER policy keeps matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a KEEP policy for error logs
    var keep_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "keep-errors"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_KEEP,
            },
        },
    };
    try keep_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try keep_policy.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT,
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer keep_policy.deinit(allocator);

    try registry.updatePolicies(&.{keep_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log matches KEEP policy
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate returns keep when no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const log = TestLogContext{ .level = "INFO", .message = "test" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate skips disabled policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a disabled DROP policy
    var disabled_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "disabled-drop"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = false, // disabled!
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try disabled_policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try disabled_policy.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT,
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer disabled_policy.deinit(allocator);

    try registry.updatePolicies(&.{disabled_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log would match, but policy is disabled, so keep
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate with Datadog log format" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop logs from staging environment
    var drop_staging = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-staging"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try drop_staging.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try drop_staging.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_ATTRIBUTE,
        .key = try allocator.dupe(u8, "ddtags"),
        .regex = try allocator.dupe(u8, "env:staging"),
    });
    defer drop_staging.deinit(allocator);

    try registry.updatePolicies(&.{drop_staging}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Staging log should be dropped
    const staging_log = TestLogContext{
        .ddtags = "env:staging,version:5.1",
        .message = "request completed",
        .service = "payment",
    };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&staging_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));

    // Production log should be kept
    const prod_log = TestLogContext{
        .ddtags = "env:production,version:5.1",
        .message = "request completed",
        .service = "payment",
    };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&prod_log), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate with multiple matchers (AND logic)" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop DEBUG logs from payment service only
    var policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-payment-debug"),
        .policy_type = .POLICY_TYPE_LOG_FILTER,
        .enabled = true,
        .config = .{
            .filter = .{
                .action = .FILTER_ACTION_DROP,
            },
        },
    };
    try policy.telemetry_types.append(allocator, .TELEMETRY_TYPE_LOGS);
    try policy.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_SEVERITY_TEXT,
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    try policy.config.?.filter.matchers.append(allocator, .{
        .match_type = .MATCH_TYPE_LOG_ATTRIBUTE,
        .key = try allocator.dupe(u8, "service"),
        .regex = try allocator.dupe(u8, "payment"),
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // DEBUG from payment = dropped
    const payment_debug = TestLogContext{ .level = "DEBUG", .service = "payment", .message = "processing" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&payment_debug), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));

    // DEBUG from auth = kept (service doesn't match)
    const auth_debug = TestLogContext{ .level = "DEBUG", .service = "auth", .message = "login attempt" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&auth_debug), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));

    // ERROR from payment = kept (level doesn't match)
    const payment_error = TestLogContext{ .level = "ERROR", .service = "payment", .message = "failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&payment_error), TestLogContext.fieldAccessor, .TELEMETRY_TYPE_LOGS));
}
