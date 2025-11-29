const std = @import("std");
const proto = @import("proto");
const policy_registry = @import("policy_registry.zig");
const jsonpath = @import("jsonpath.zig");

const Policy = proto.policy.Policy;
const PolicyType = proto.policy.PolicyType;
const TelemetryType = proto.policy.TelemetryType;
const FilterAction = proto.policy.FilterAction;
const FilterConfig = proto.policy.FilterConfig;
const Matcher = proto.policy.Matcher;
const PolicyRegistry = policy_registry.PolicyRegistry;
const PolicySnapshot = policy_registry.PolicySnapshot;
const JsonDoc = jsonpath.JsonDoc;

/// FilterResult indicates whether to keep or drop the data
pub const FilterResult = enum {
    keep,
    drop,
};

/// Filter evaluates JSON against policies from the centralized registry
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

    /// Evaluate JSON against policies for a specific telemetry type
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// Uses lock-free snapshot read for consistent view of policies
    /// Uses pre-filtered indices for O(1) lookup of relevant policies
    pub fn evaluate(
        self: *const FilterEvaluator,
        json_data: []const u8,
        telemetry_type: TelemetryType,
    ) FilterResult {
        // Get current policy snapshot (atomic, lock-free)
        const snapshot = self.registry.getSnapshot() orelse return FilterResult.keep;

        // Use pre-filtered index to get only LOG_FILTER policies for this telemetry type
        const policy_indices = snapshot.getIndicesForKey(telemetry_type, .POLICY_TYPE_LOG_FILTER);

        // No policies to evaluate
        if (policy_indices.len == 0) return FilterResult.keep;

        // Parse JSON document once for all policy evaluations
        const doc = JsonDoc.parse(json_data) catch {
            // If JSON parsing fails, default to keep (fail-open)
            return FilterResult.keep;
        };
        defer doc.deinit();

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

            // Check if all matchers match the JSON data
            const matches = self.matchesAllMatchers(doc, config.matchers.items);

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

    /// Evaluate a pre-parsed JSON document against policies for a specific telemetry type
    /// Returns FilterResult.keep or FilterResult.drop based on first matching policy
    /// If no policies match, defaults to FilterResult.keep
    ///
    /// This method is more efficient when you already have a parsed JsonDoc,
    /// avoiding redundant parsing when processing multiple logs from an array.
    pub fn evaluateJson(
        self: *const FilterEvaluator,
        doc: JsonDoc,
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

            // Check if all matchers match the JSON data
            const matches = self.matchesAllMatchers(doc, config.matchers.items);

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

    /// Check if all matchers match the JSON document
    /// Uses JSONPath to extract values and substring matching on the regex field
    /// All matchers must match for the overall result to be true (AND logic)
    fn matchesAllMatchers(
        self: *const FilterEvaluator,
        doc: JsonDoc,
        matchers: []const Matcher,
    ) bool {
        _ = self;

        if (matchers.len == 0) return false;

        for (matchers) |matcher| {
            const match_result = matchSingleMatcher(doc, matcher);
            if (!match_result) return false;
        }

        return true;
    }

    /// Check if a single matcher matches the JSON document
    /// Returns true if the matcher matches (considering negate flag)
    fn matchSingleMatcher(doc: JsonDoc, matcher: Matcher) bool {
        // If path is empty, fall back to matching against entire JSON (not supported with parsed doc)
        if (matcher.path.len == 0) return false;

        // Convert path to null-terminated string for C API
        var path_buf: [512]u8 = undefined;
        const path_z = toNullTerminated(matcher.path, &path_buf) orelse return false;

        // Query the JSON document with the JSONPath
        const result = doc.query(path_z) catch {
            // Query failed - treat as no match
            return if (matcher.negate) true else false;
        };
        defer result.deinit();

        // Check if any of the extracted values match the pattern
        const found = blk: {
            if (result.count() == 0) break :blk false;

            // Check each result value for a match
            var iter = result.iterator();
            while (iter.next()) |value| {
                if (matchesPattern(value, matcher.regex)) {
                    break :blk true;
                }
            }
            break :blk false;
        };

        // Apply negate flag
        return if (matcher.negate) !found else found;
    }

    /// Convert a slice to a null-terminated string in the provided buffer
    fn toNullTerminated(s: []const u8, buf: *[512]u8) ?[:0]const u8 {
        if (s.len >= buf.len) return null;
        @memcpy(buf[0..s.len], s);
        buf[s.len] = 0;
        return buf[0..s.len :0];
    }

    /// Check if a value matches a pattern (substring match for now)
    /// The pattern is treated as a literal substring to find
    fn matchesPattern(value: []const u8, pattern: []const u8) bool {
        if (pattern.len == 0) return true; // Empty pattern matches everything
        return std.mem.indexOf(u8, value, pattern) != null;
    }
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "FilterEvaluator.matchSingleMatcher extracts JSONPath and matches" {
    const json_str =
        \\{"message": "error occurred", "level": "ERROR"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Match on message field containing "error"
    const matcher = Matcher{ .path = "$.message", .regex = "error" };
    try testing.expect(FilterEvaluator.matchSingleMatcher(doc, matcher));

    // No match when pattern not found
    const no_match = Matcher{ .path = "$.message", .regex = "warning" };
    try testing.expect(!FilterEvaluator.matchSingleMatcher(doc, no_match));
}

test "FilterEvaluator.matchSingleMatcher with negate" {
    const json_str =
        \\{"level": "INFO", "message": "all good"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Negated match - true if "ERROR" is NOT in level
    const matcher = Matcher{ .path = "$.level", .regex = "ERROR", .negate = true };
    try testing.expect(FilterEvaluator.matchSingleMatcher(doc, matcher));

    // Negated match - false if "INFO" IS in level
    const no_match = Matcher{ .path = "$.level", .regex = "INFO", .negate = true };
    try testing.expect(!FilterEvaluator.matchSingleMatcher(doc, no_match));
}

test "FilterEvaluator.matchSingleMatcher with nested path" {
    const json_str =
        \\{"resource": {"attributes": {"service.name": "payment-api"}}}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Match nested field
    const matcher = Matcher{ .path = "$.resource.attributes['service.name']", .regex = "payment" };
    try testing.expect(FilterEvaluator.matchSingleMatcher(doc, matcher));
}

test "FilterEvaluator.matchSingleMatcher with array wildcard" {
    const json_str =
        \\{"logs": [{"level": "INFO"}, {"level": "ERROR"}, {"level": "DEBUG"}]}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Match if any log has ERROR level
    const matcher = Matcher{ .path = "$.logs[*].level", .regex = "ERROR" };
    try testing.expect(FilterEvaluator.matchSingleMatcher(doc, matcher));

    // No match for FATAL (not present)
    const no_match = Matcher{ .path = "$.logs[*].level", .regex = "FATAL" };
    try testing.expect(!FilterEvaluator.matchSingleMatcher(doc, no_match));
}

test "FilterEvaluator.matchSingleMatcher with non-existent path" {
    const json_str =
        \\{"message": "hello"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // Non-existent path returns no results, so no match
    const matcher = Matcher{ .path = "$.nonexistent", .regex = "hello" };
    try testing.expect(!FilterEvaluator.matchSingleMatcher(doc, matcher));

    // With negate, non-existent path means "pattern not found" = true
    const negated = Matcher{ .path = "$.nonexistent", .regex = "hello", .negate = true };
    try testing.expect(FilterEvaluator.matchSingleMatcher(doc, negated));
}

test "FilterEvaluator.matchesAllMatchers with multiple matchers (AND logic)" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const json_str =
        \\{"level": "ERROR", "service": "payment", "message": "transaction failed"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    // All matchers must match
    const matchers_all_match = [_]Matcher{
        .{ .path = "$.level", .regex = "ERROR" },
        .{ .path = "$.service", .regex = "payment" },
    };
    try testing.expect(filter.matchesAllMatchers(doc, &matchers_all_match));

    // One matcher fails = overall false
    const matchers_one_fails = [_]Matcher{
        .{ .path = "$.level", .regex = "ERROR" },
        .{ .path = "$.service", .regex = "auth" }, // doesn't match
    };
    try testing.expect(!filter.matchesAllMatchers(doc, &matchers_one_fails));
}

test "FilterEvaluator.matchesAllMatchers with empty matchers returns false" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const json_str =
        \\{"message": "test"}
    ;
    const doc = try JsonDoc.parse(json_str);
    defer doc.deinit();

    const empty_matchers = [_]Matcher{};
    try testing.expect(!filter.matchesAllMatchers(doc, &empty_matchers));
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Debug log should be dropped
    const debug_log =
        \\{"level": "DEBUG", "message": "verbose info"}
    ;
    try testing.expectEqual(FilterResult.drop, filter.evaluate(debug_log, .TELEMETRY_TYPE_LOGS));

    // Error log should be kept (doesn't match)
    const error_log =
        \\{"level": "ERROR", "message": "something failed"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(error_log, .TELEMETRY_TYPE_LOGS));
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer keep_policy.deinit(allocator);

    try registry.updatePolicies(&.{keep_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log matches KEEP policy
    const error_log =
        \\{"level": "ERROR", "message": "something failed"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(error_log, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate returns keep when no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const log =
        \\{"level": "INFO", "message": "test"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(log, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluate returns keep on invalid JSON (fail-open)" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    // Add a policy so we actually try to parse
    var policy = proto.policy.Policy{
        .name = try allocator.dupe(u8, "test-policy"),
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Invalid JSON should fail-open (return keep)
    const invalid_json = "{ not valid json }";
    try testing.expectEqual(FilterResult.keep, filter.evaluate(invalid_json, .TELEMETRY_TYPE_LOGS));
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer disabled_policy.deinit(allocator);

    try registry.updatePolicies(&.{disabled_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log would match, but policy is disabled, so keep
    const error_log =
        \\{"level": "ERROR", "message": "something failed"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(error_log, .TELEMETRY_TYPE_LOGS));
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
        .path = try allocator.dupe(u8, "$.ddtags"),
        .regex = try allocator.dupe(u8, "env:staging"),
    });
    defer drop_staging.deinit(allocator);

    try registry.updatePolicies(&.{drop_staging}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Staging log should be dropped
    const staging_log =
        \\{"ddsource": "nginx", "ddtags": "env:staging,version:5.1", "hostname": "i-012345678", "message": "request completed", "service": "payment"}
    ;
    try testing.expectEqual(FilterResult.drop, filter.evaluate(staging_log, .TELEMETRY_TYPE_LOGS));

    // Production log should be kept
    const prod_log =
        \\{"ddsource": "nginx", "ddtags": "env:production,version:5.1", "hostname": "i-987654321", "message": "request completed", "service": "payment"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(prod_log, .TELEMETRY_TYPE_LOGS));
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    try policy.config.?.filter.matchers.append(allocator, .{
        .path = try allocator.dupe(u8, "$.service"),
        .regex = try allocator.dupe(u8, "payment"),
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // DEBUG from payment = dropped
    const payment_debug =
        \\{"level": "DEBUG", "service": "payment", "message": "processing"}
    ;
    try testing.expectEqual(FilterResult.drop, filter.evaluate(payment_debug, .TELEMETRY_TYPE_LOGS));

    // DEBUG from auth = kept (service doesn't match)
    const auth_debug =
        \\{"level": "DEBUG", "service": "auth", "message": "login attempt"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(auth_debug, .TELEMETRY_TYPE_LOGS));

    // ERROR from payment = kept (level doesn't match)
    const payment_error =
        \\{"level": "ERROR", "service": "payment", "message": "failed"}
    ;
    try testing.expectEqual(FilterResult.keep, filter.evaluate(payment_error, .TELEMETRY_TYPE_LOGS));
}

// =============================================================================
// Tests for evaluateJson (pre-parsed JsonDoc)
// =============================================================================

test "FilterEvaluator.evaluateJson with LOG_FILTER policy drops matching logs" {
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Debug log should be dropped
    const debug_log =
        \\{"level": "DEBUG", "message": "verbose info"}
    ;
    const debug_doc = try JsonDoc.parse(debug_log);
    defer debug_doc.deinit();
    try testing.expectEqual(FilterResult.drop, filter.evaluateJson(debug_doc, .TELEMETRY_TYPE_LOGS));

    // Error log should be kept (doesn't match)
    const error_log =
        \\{"level": "ERROR", "message": "something failed"}
    ;
    const error_doc = try JsonDoc.parse(error_log);
    defer error_doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(error_doc, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluateJson returns keep when no policies" {
    const allocator = testing.allocator;
    var registry = PolicyRegistry.init(allocator);
    defer registry.deinit();

    const filter = FilterEvaluator.init(&registry);

    const log =
        \\{"level": "INFO", "message": "test"}
    ;
    const doc = try JsonDoc.parse(log);
    defer doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(doc, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluateJson skips disabled policies" {
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "ERROR"),
    });
    defer disabled_policy.deinit(allocator);

    try registry.updatePolicies(&.{disabled_policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Error log would match, but policy is disabled, so keep
    const error_log =
        \\{"level": "ERROR", "message": "something failed"}
    ;
    const doc = try JsonDoc.parse(error_log);
    defer doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(doc, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluateJson with Datadog log format" {
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
        .path = try allocator.dupe(u8, "$.ddtags"),
        .regex = try allocator.dupe(u8, "env:staging"),
    });
    defer drop_staging.deinit(allocator);

    try registry.updatePolicies(&.{drop_staging}, .file);

    const filter = FilterEvaluator.init(&registry);

    // Staging log should be dropped
    const staging_log =
        \\{"ddsource": "nginx", "ddtags": "env:staging,version:5.1", "hostname": "i-012345678", "message": "request completed", "service": "payment"}
    ;
    const staging_doc = try JsonDoc.parse(staging_log);
    defer staging_doc.deinit();
    try testing.expectEqual(FilterResult.drop, filter.evaluateJson(staging_doc, .TELEMETRY_TYPE_LOGS));

    // Production log should be kept
    const prod_log =
        \\{"ddsource": "nginx", "ddtags": "env:production,version:5.1", "hostname": "i-987654321", "message": "request completed", "service": "payment"}
    ;
    const prod_doc = try JsonDoc.parse(prod_log);
    defer prod_doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(prod_doc, .TELEMETRY_TYPE_LOGS));
}

test "FilterEvaluator.evaluateJson with multiple matchers (AND logic)" {
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
        .path = try allocator.dupe(u8, "$.level"),
        .regex = try allocator.dupe(u8, "DEBUG"),
    });
    try policy.config.?.filter.matchers.append(allocator, .{
        .path = try allocator.dupe(u8, "$.service"),
        .regex = try allocator.dupe(u8, "payment"),
    });
    defer policy.deinit(allocator);

    try registry.updatePolicies(&.{policy}, .file);

    const filter = FilterEvaluator.init(&registry);

    // DEBUG from payment = dropped
    const payment_debug =
        \\{"level": "DEBUG", "service": "payment", "message": "processing"}
    ;
    const payment_debug_doc = try JsonDoc.parse(payment_debug);
    defer payment_debug_doc.deinit();
    try testing.expectEqual(FilterResult.drop, filter.evaluateJson(payment_debug_doc, .TELEMETRY_TYPE_LOGS));

    // DEBUG from auth = kept (service doesn't match)
    const auth_debug =
        \\{"level": "DEBUG", "service": "auth", "message": "login attempt"}
    ;
    const auth_debug_doc = try JsonDoc.parse(auth_debug);
    defer auth_debug_doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(auth_debug_doc, .TELEMETRY_TYPE_LOGS));

    // ERROR from payment = kept (level doesn't match)
    const payment_error =
        \\{"level": "ERROR", "service": "payment", "message": "failed"}
    ;
    const payment_error_doc = try JsonDoc.parse(payment_error);
    defer payment_error_doc.deinit();
    try testing.expectEqual(FilterResult.keep, filter.evaluateJson(payment_error_doc, .TELEMETRY_TYPE_LOGS));
}
