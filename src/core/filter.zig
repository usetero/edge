const std = @import("std");
const proto = @import("proto");
const policy_registry = @import("policy_registry.zig");
const regex_index = @import("regex_index.zig");

const Policy = proto.policy.Policy;
const PolicyType = proto.policy.PolicyType;
const FilterAction = proto.policy.FilterAction;
const LogFilterConfig = proto.policy.LogFilterConfig;
const LogMatcher = proto.policy.LogMatcher;
pub const MatchCase = LogMatcher._match_case;
const PolicyRegistry = policy_registry.PolicyRegistry;
const PolicySnapshot = policy_registry.PolicySnapshot;
const CompiledRegexIndex = regex_index.CompiledRegexIndex;
const RegexDatabase = regex_index.RegexDatabase;
const PatternInfo = regex_index.PatternInfo;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Field accessor function type
/// Given a MatchCase and key, returns the field value as a string slice, or null if not found
pub const FieldAccessor = *const fn (ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8;

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

    /// Evaluate data against log filter policies using Hyperscan-accelerated regex matching
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// Uses lock-free snapshot read for consistent view of policies.
    /// Uses the compiled regex index from the snapshot for O(n) scanning
    /// where n is the input size, regardless of number of patterns.
    ///
    /// The field_accessor function is called to retrieve field values from the data.
    /// The ctx pointer is passed through to the accessor for accessing the actual data structure.
    pub fn evaluate(
        self: *const FilterEvaluator,
        ctx: *const anyopaque,
        field_accessor: FieldAccessor,
    ) FilterResult {
        // Get current policy snapshot (atomic, lock-free)
        const snapshot = self.registry.getSnapshot() orelse return FilterResult.keep;
        const policies = snapshot.getLogFilterPolicies();
        const regex_idx = &snapshot.compiled_regex_index;

        // Process policies in order - first fully matching policy wins
        for (snapshot.log_filter_indices) |policy_idx| {
            const policy = &policies[policy_idx];

            // Skip disabled policies
            if (!policy.enabled) continue;

            const filter_config = policy.filter orelse continue;

            // Check if all matchers match using Hyperscan
            const all_match = checkAllMatchersWithHyperscan(
                ctx,
                field_accessor,
                regex_idx,
                filter_config.matchers.items,
            );

            if (all_match) {
                return switch (filter_config.action) {
                    .FILTER_ACTION_KEEP => FilterResult.keep,
                    .FILTER_ACTION_DROP => FilterResult.drop,
                    else => FilterResult.keep,
                };
            }
        }

        // Default to keep if no policies match
        return FilterResult.keep;
    }
};

/// Check if all matchers match using Hyperscan-accelerated regex matching
/// All matchers must match for the overall result to be true (AND logic)
fn checkAllMatchersWithHyperscan(
    ctx: *const anyopaque,
    field_accessor: FieldAccessor,
    regex_idx: *const CompiledRegexIndex,
    matchers: []const LogMatcher,
) bool {
    if (matchers.len == 0) return false;

    for (matchers) |matcher| {
        const match_result = matchSingleMatcherWithHyperscan(ctx, field_accessor, regex_idx, matcher);
        if (!match_result) return false;
    }

    return true;
}

/// Check if a single matcher matches using Hyperscan
/// Uses the compiled regex database for the match type
fn matchSingleMatcherWithHyperscan(
    ctx: *const anyopaque,
    field_accessor: FieldAccessor,
    regex_idx: *const CompiledRegexIndex,
    matcher: LogMatcher,
) bool {
    const match = matcher.match orelse return false;

    // Extract the match case, key, and regex
    const match_case: MatchCase = match;
    const key: []const u8 = switch (match) {
        .resource_attribute => |m| m.key,
        .scope_attribute => |m| m.key,
        .log_attribute => |m| m.key,
        else => "",
    };

    // Get the field value using the accessor
    const value = field_accessor(ctx, match_case, key) orelse {
        // No value found - if negate is true, this is a match (pattern not in non-existent field)
        return matcher.negate;
    };

    // Get the appropriate Hyperscan database
    const db: ?*const RegexDatabase = if (key.len > 0)
        regex_idx.getKeyedDatabase(match_case, key)
    else
        regex_idx.getSimpleDatabase(match_case);

    // If no database for this match type, fall back to substring matching
    if (db == null) {
        std.log.info("No database found for match type: {any}", .{match_case});
        return matchSingleMatcher(ctx, field_accessor, matcher);
    }

    // Scan the value with Hyperscan
    const scan_result = regex_index.scanValue(db.?, value);

    // Apply negate flag
    // If negate=true: we want TRUE when the pattern is NOT found
    // If negate=false: we want TRUE when the pattern IS found
    return if (matcher.negate) !scan_result.matched else scan_result.matched;
}

/// Check if a single matcher matches using the field accessor
/// Returns true if the matcher matches (considering negate flag)
fn matchSingleMatcher(ctx: *const anyopaque, field_accessor: FieldAccessor, matcher: LogMatcher) bool {
    const match = matcher.match orelse return false;

    // Extract the match case, key, and regex based on the union variant
    const match_case: MatchCase = match;
    const key: []const u8, const regex: []const u8 = switch (match) {
        .resource_schema_url => |m| .{ "", m.regex },
        .resource_attribute => |m| .{ m.key, m.regex },
        .scope_schema_url => |m| .{ "", m.regex },
        .scope_name => |m| .{ "", m.regex },
        .scope_version => |m| .{ "", m.regex },
        .scope_attribute => |m| .{ m.key, m.regex },
        .log_body => |m| .{ "", m.regex },
        .log_severity_text => |m| .{ "", m.regex },
        .log_severity_number => return false, // Not supported yet (uses min/max, not regex)
        .log_attribute => |m| .{ m.key, m.regex },
    };

    // Get the field value using the accessor
    const value = field_accessor(ctx, match_case, key);

    // Check if the value matches the pattern
    const found = if (value) |v|
        matchesPattern(v, regex)
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

    fn fieldAccessor(ctx: *const anyopaque, match_case: MatchCase, key: []const u8) ?[]const u8 {
        const self: *const TestLogContext = @ptrCast(@alignCast(ctx));
        return switch (match_case) {
            .log_body => self.message,
            .log_severity_text => self.level,
            .log_attribute => {
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
    const matcher = LogMatcher{ .match = .{ .log_body = .{ .regex = "error" } } };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // No match when pattern not found
    const no_match = LogMatcher{ .match = .{ .log_body = .{ .regex = "warning" } } };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with negate" {
    const log = TestLogContext{
        .level = "INFO",
        .message = "all good",
    };

    // Negated match - true if "ERROR" is NOT in level
    const matcher = LogMatcher{ .match = .{ .log_severity_text = .{ .regex = "ERROR" } }, .negate = true };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // Negated match - false if "INFO" IS in level
    const no_match = LogMatcher{ .match = .{ .log_severity_text = .{ .regex = "INFO" } }, .negate = true };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with log attribute" {
    const log = TestLogContext{
        .service = "payment-api",
        .level = "ERROR",
        .message = "failed",
    };

    // Match log attribute (service field)
    const matcher = LogMatcher{ .match = .{ .log_attribute = .{ .key = "service", .regex = "payment" } } };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // No match for non-existent service
    const no_match = LogMatcher{ .match = .{ .log_attribute = .{ .key = "service", .regex = "auth" } } };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, no_match));
}

test "matchSingleMatcher with non-existent field" {
    const log = TestLogContext{
        .message = "hello",
    };

    // Non-existent attribute returns null, so no match
    const matcher = LogMatcher{ .match = .{ .log_attribute = .{ .key = "nonexistent", .regex = "hello" } } };
    try testing.expect(!matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, matcher));

    // With negate, non-existent field means "pattern not found" = true
    const negated = LogMatcher{ .match = .{ .log_attribute = .{ .key = "nonexistent", .regex = "hello" } }, .negate = true };
    try testing.expect(matchSingleMatcher(@ptrCast(&log), TestLogContext.fieldAccessor, negated));
}

test "FilterEvaluator.evaluate with LOG_FILTER policy drops matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a DROP policy for debug logs
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "DEBUG") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Debug log should be dropped
    const debug_log = TestLogContext{ .level = "DEBUG", .message = "verbose info" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&debug_log), TestLogContext.fieldAccessor));

    // Error log should be kept (doesn't match)
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "FilterEvaluator.evaluate with LOG_FILTER policy keeps matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a KEEP policy for error logs
    var keep_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try keep_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer keep_policy.deinit(allocator);

    try registry.updatePolicies(&.{keep_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log matches KEEP policy
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "FilterEvaluator.evaluate returns keep when no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const log = TestLogContext{ .level = "INFO", .message = "test" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&log), TestLogContext.fieldAccessor));
}

test "FilterEvaluator.evaluate skips disabled policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a disabled DROP policy
    var disabled_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // disabled!
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try disabled_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer disabled_policy.deinit(allocator);

    try registry.updatePolicies(&.{disabled_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log would match, but policy is disabled, so keep
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "FilterEvaluator.evaluate with Datadog log format" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop logs from staging environment
    var drop_staging = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-staging"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_staging.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "ddtags"),
            .regex = try allocator.dupe(u8, "env:staging"),
        } },
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
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&staging_log), TestLogContext.fieldAccessor));

    // Production log should be kept
    const prod_log = TestLogContext{
        .ddtags = "env:production,version:5.1",
        .message = "request completed",
        .service = "payment",
    };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&prod_log), TestLogContext.fieldAccessor));
}

test "FilterEvaluator.evaluate with multiple matchers (AND logic)" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop DEBUG logs from payment service only
    var policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-payment-debug"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "DEBUG") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // DEBUG from payment = dropped
    const payment_debug = TestLogContext{ .level = "DEBUG", .service = "payment", .message = "processing" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&payment_debug), TestLogContext.fieldAccessor));

    // DEBUG from auth = kept (service doesn't match)
    const auth_debug = TestLogContext{ .level = "DEBUG", .service = "auth", .message = "login attempt" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&auth_debug), TestLogContext.fieldAccessor));

    // ERROR from payment = kept (level doesn't match)
    const payment_error = TestLogContext{ .level = "ERROR", .service = "payment", .message = "failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&payment_error), TestLogContext.fieldAccessor));
}

// =============================================================================
// Hyperscan-based Evaluation Tests
// =============================================================================

test "evaluateWithHyperscan: drops matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a DROP policy for error logs
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log should be dropped
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));

    // Info log should be kept
    const info_log = TestLogContext{ .level = "INFO", .message = "all good" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&info_log), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: keeps matching logs" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a KEEP policy for error logs
    var keep_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "keep-errors"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try keep_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer keep_policy.deinit(allocator);

    try registry.updatePolicies(&.{keep_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log matches KEEP policy
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: returns keep when no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const log = TestLogContext{ .level = "INFO", .message = "test" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&log), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: with log_attribute matches" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop logs from payment service
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-payment"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Payment service log should be dropped
    const payment_log = TestLogContext{ .service = "payment-api", .message = "processing" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&payment_log), TestLogContext.fieldAccessor));

    // Auth service log should be kept
    const auth_log = TestLogContext{ .service = "auth-api", .message = "login" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&auth_log), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: with negate flag" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop logs that do NOT contain "important"
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-non-important"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "important") } },
        .negate = true,
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Non-important log should be dropped (negate: pattern NOT found = match)
    const boring_log = TestLogContext{ .message = "just a boring message" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&boring_log), TestLogContext.fieldAccessor));

    // Important log should be kept (negate: pattern found = no match)
    const important_log = TestLogContext{ .message = "this is important data" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&important_log), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: multiple matchers AND logic" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop DEBUG logs from payment service only
    var policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-payment-debug"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "DEBUG") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // DEBUG from payment = dropped (both matchers match)
    const payment_debug = TestLogContext{ .level = "DEBUG", .service = "payment", .message = "processing" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&payment_debug), TestLogContext.fieldAccessor));

    // DEBUG from auth = kept (service doesn't match)
    const auth_debug = TestLogContext{ .level = "DEBUG", .service = "auth", .message = "login attempt" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&auth_debug), TestLogContext.fieldAccessor));

    // ERROR from payment = kept (level doesn't match)
    const payment_error = TestLogContext{ .level = "ERROR", .service = "payment", .message = "failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&payment_error), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: regex pattern matching" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Drop logs matching error pattern with regex
    var drop_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "drop-error-pattern"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try drop_policy.filter.?.matchers.append(allocator, .{
        // Regex pattern: matches "error" or "Error" or "ERROR"
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "[Ee]rror") } },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Various error messages should be dropped
    const error1 = TestLogContext{ .message = "an error occurred" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&error1), TestLogContext.fieldAccessor));

    const error2 = TestLogContext{ .message = "Error: something went wrong" };
    try testing.expectEqual(FilterResult.drop, filter.evaluate(@ptrCast(&error2), TestLogContext.fieldAccessor));

    // Non-error message should be kept
    const info = TestLogContext{ .message = "everything is fine" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&info), TestLogContext.fieldAccessor));
}

test "evaluateWithHyperscan: skips disabled policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Create a disabled DROP policy
    var disabled_policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "disabled-drop"),
        .enabled = false, // disabled!
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try disabled_policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer disabled_policy.deinit(allocator);

    try registry.updatePolicies(&.{disabled_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log would match, but policy is disabled, so keep
    const error_log = TestLogContext{ .level = "ERROR", .message = "something failed" };
    try testing.expectEqual(FilterResult.keep, filter.evaluate(@ptrCast(&error_log), TestLogContext.fieldAccessor));
}
