//! Compiled Regex Index using Hyperscan/Vectorscan
//!
//! This module provides high-performance multi-pattern regex matching by compiling
//! all policy regexes into Hyperscan databases, grouped by match type.
//!
//! ## Architecture
//!
//! Patterns are grouped by their match type since each type accesses a different field:
//! - Simple types (log_body, log_severity_text, etc.): One DB per type
//! - Keyed types (log_attribute, resource_attribute): One DB per (type, key) pair
//!
//! Each compiled database maps Hyperscan pattern IDs back to (policy_index, matcher_index)
//! so we can determine which policy matched.

const std = @import("std");
const proto = @import("proto");
const hyperscan = @import("../hyperscan/hyperscan.zig");

const Policy = proto.policy.Policy;
const LogMatcher = proto.policy.LogMatcher;
const LogFilterConfig = proto.policy.LogFilterConfig;

pub const MatchCase = LogMatcher._match_case;

/// Information about a pattern in the Hyperscan database
/// Maps from Hyperscan pattern ID back to the policy/matcher that defined it
pub const PatternInfo = struct {
    /// Index into the policies array
    policy_index: u32,
    /// Index into the policy's matchers array
    matcher_index: u32,
    /// Whether this matcher has negate=true
    negate: bool,
    /// The filter action for this policy (cached for quick access)
    action: proto.policy.FilterAction,
};

/// A compiled Hyperscan database with pattern mapping
pub const RegexDatabase = struct {
    /// The compiled Hyperscan database
    db: hyperscan.Database,
    /// Scratch space for scanning (one per DB, can be cloned for threads)
    scratch: hyperscan.Scratch,
    /// Maps Hyperscan pattern ID -> PatternInfo
    pattern_infos: []const PatternInfo,
    /// Allocator used for pattern_infos
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RegexDatabase) void {
        self.scratch.deinit();
        self.db.deinit();
        self.allocator.free(self.pattern_infos);
    }
};

/// Key for attribute-based match types
/// Used to group patterns by (match_type, attribute_key)
pub const AttributeKey = struct {
    match_case: MatchCase,
    key: []const u8,

    pub fn hash(self: AttributeKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&self.match_case));
        h.update(self.key);
        return h.final();
    }

    pub fn eql(a: AttributeKey, b: AttributeKey) bool {
        return a.match_case == b.match_case and std.mem.eql(u8, a.key, b.key);
    }
};

/// Context for attribute key hashing
pub const AttributeKeyContext = struct {
    pub fn hash(_: AttributeKeyContext, key: AttributeKey) u64 {
        return key.hash();
    }

    pub fn eql(_: AttributeKeyContext, a: AttributeKey, b: AttributeKey) bool {
        return a.eql(b);
    }
};

/// Compiled regex index for efficient multi-pattern matching
///
/// Groups patterns by match type since each type accesses a different data field.
/// At scan time, extract the field value and scan against the appropriate database.
pub const CompiledRegexIndex = struct {
    allocator: std.mem.Allocator,

    /// Databases for simple (non-keyed) match types
    /// Index by MatchCase enum value
    simple_databases: [simple_match_case_count]?*RegexDatabase,

    /// Databases for keyed match types (log_attribute, resource_attribute, scope_attribute)
    /// Key is (match_case, attribute_key)
    keyed_databases: std.HashMap(AttributeKey, *RegexDatabase, AttributeKeyContext, std.hash_map.default_max_load_percentage),

    /// Storage for duped attribute keys (owned by this struct)
    key_storage: std.ArrayListUnmanaged([]const u8),

    const Self = @This();

    // Match cases that don't have a key field
    const simple_match_cases = [_]MatchCase{
        .resource_schema_url,
        .scope_schema_url,
        .scope_name,
        .scope_version,
        .log_body,
        .log_severity_text,
        // Note: log_severity_number uses min/max, not regex - excluded
    };
    const simple_match_case_count = @typeInfo(MatchCase).@"enum".fields.len;

    // Match cases that have a key field
    const keyed_match_cases = [_]MatchCase{
        .resource_attribute,
        .scope_attribute,
        .log_attribute,
    };

    fn isKeyedMatchCase(match_case: MatchCase) bool {
        return switch (match_case) {
            .resource_attribute, .scope_attribute, .log_attribute => true,
            else => false,
        };
    }

    /// Build a compiled regex index from a slice of policies
    pub fn build(
        allocator: std.mem.Allocator,
        policies: []const Policy,
    ) !Self {
        var self = Self{
            .allocator = allocator,
            .simple_databases = [_]?*RegexDatabase{null} ** simple_match_case_count,
            .keyed_databases = std.HashMap(AttributeKey, *RegexDatabase, AttributeKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .key_storage = .empty,
        };
        errdefer self.deinit();

        // Collect all patterns grouped by match type
        var simple_patterns: [simple_match_case_count]std.ArrayListUnmanaged(PatternCollector) = undefined;
        for (&simple_patterns) |*list| {
            list.* = .empty;
        }
        defer for (&simple_patterns) |*list| {
            list.deinit(allocator);
        };

        var keyed_patterns = std.HashMap(AttributeKey, std.ArrayListUnmanaged(PatternCollector), AttributeKeyContext, std.hash_map.default_max_load_percentage).init(allocator);
        defer {
            var it = keyed_patterns.valueIterator();
            while (it.next()) |list| {
                list.deinit(allocator);
            }
            keyed_patterns.deinit();
        }

        // First pass: collect all patterns
        for (policies, 0..) |*policy, policy_idx| {
            const filter_config = policy.filter orelse continue;

            for (filter_config.matchers.items, 0..) |matcher, matcher_idx| {
                const match = matcher.match orelse continue;

                const match_case: MatchCase = match;
                const regex = getRegexFromMatch(match) orelse continue;

                // Skip empty regexes
                if (regex.len == 0) continue;

                const collector = PatternCollector{
                    .regex = regex,
                    .info = .{
                        .policy_index = @intCast(policy_idx),
                        .matcher_index = @intCast(matcher_idx),
                        .negate = matcher.negate,
                        .action = filter_config.action,
                    },
                };

                if (isKeyedMatchCase(match_case)) {
                    const key = getKeyFromMatch(match) orelse "";

                    // Check if we already have this key stored
                    const attr_key_lookup = AttributeKey{ .match_case = match_case, .key = key };
                    const gop = try keyed_patterns.getOrPut(attr_key_lookup);
                    if (!gop.found_existing) {
                        // First time seeing this key - dupe and store it
                        const key_copy = try allocator.dupe(u8, key);
                        try self.key_storage.append(allocator, key_copy);
                        // Update the key in the map to point to our owned copy
                        gop.key_ptr.key = key_copy;
                        gop.value_ptr.* = .empty;
                    }
                    try gop.value_ptr.append(allocator, collector);
                } else {
                    try simple_patterns[@intFromEnum(match_case)].append(allocator, collector);
                }
            }
        }

        // Second pass: compile databases for each group
        for (simple_patterns, 0..) |patterns_list, match_case_idx| {
            if (patterns_list.items.len == 0) continue;

            const db = try compilePatterns(allocator, patterns_list.items);
            self.simple_databases[match_case_idx] = db;
        }

        var keyed_it = keyed_patterns.iterator();
        while (keyed_it.next()) |entry| {
            const patterns_list = entry.value_ptr;
            if (patterns_list.items.len == 0) continue;

            const db = try compilePatterns(allocator, patterns_list.items);
            try self.keyed_databases.put(entry.key_ptr.*, db);
        }

        return self;
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        // Free simple databases
        for (&self.simple_databases) |*db_opt| {
            if (db_opt.*) |db| {
                db.*.deinit();
                self.allocator.destroy(db);
                db_opt.* = null;
            }
        }

        // Free keyed databases
        var keyed_it = self.keyed_databases.iterator();
        while (keyed_it.next()) |entry| {
            const db = entry.value_ptr.*;
            db.deinit();
            self.allocator.destroy(db);
        }
        self.keyed_databases.deinit();

        // Free key storage
        for (self.key_storage.items) |key| {
            self.allocator.free(key);
        }
        self.key_storage.deinit(self.allocator);
    }

    /// Get the database for a simple (non-keyed) match case
    pub fn getSimpleDatabase(self: *const Self, match_case: MatchCase) ?*const RegexDatabase {
        return self.simple_databases[@intFromEnum(match_case)];
    }

    /// Get the database for a keyed match case (attribute matches)
    pub fn getKeyedDatabase(self: *const Self, match_case: MatchCase, key: []const u8) ?*const RegexDatabase {
        const attr_key = AttributeKey{ .match_case = match_case, .key = key };
        return self.keyed_databases.get(attr_key);
    }

    /// Check if there are any compiled patterns
    pub fn isEmpty(self: *const Self) bool {
        for (self.simple_databases) |db_opt| {
            if (db_opt != null) return false;
        }
        return self.keyed_databases.count() == 0;
    }

    /// Get count of compiled databases
    pub fn getDatabaseCount(self: *const Self) usize {
        var count: usize = 0;
        for (self.simple_databases) |db_opt| {
            if (db_opt != null) count += 1;
        }
        return count + self.keyed_databases.count();
    }
};

/// Temporary struct for collecting patterns before compilation
const PatternCollector = struct {
    regex: []const u8,
    info: PatternInfo,
};

/// Extract the regex string from a match union
fn getRegexFromMatch(match: LogMatcher.match_union) ?[]const u8 {
    return switch (match) {
        .resource_schema_url => |m| m.regex,
        .resource_attribute => |m| m.regex,
        .scope_schema_url => |m| m.regex,
        .scope_name => |m| m.regex,
        .scope_version => |m| m.regex,
        .scope_attribute => |m| m.regex,
        .log_body => |m| m.regex,
        .log_severity_text => |m| m.regex,
        .log_severity_number => null, // Uses min/max, not regex
        .log_attribute => |m| m.regex,
    };
}

/// Extract the key from a keyed match union
fn getKeyFromMatch(match: LogMatcher.match_union) ?[]const u8 {
    return switch (match) {
        .resource_attribute => |m| m.key,
        .scope_attribute => |m| m.key,
        .log_attribute => |m| m.key,
        else => null,
    };
}

/// Compile a list of patterns into a Hyperscan database
fn compilePatterns(
    allocator: std.mem.Allocator,
    collectors: []const PatternCollector,
) !*RegexDatabase {
    // Build pattern array for Hyperscan
    const patterns = try allocator.alloc(hyperscan.Pattern, collectors.len);
    defer allocator.free(patterns);

    const pattern_infos = try allocator.alloc(PatternInfo, collectors.len);
    errdefer allocator.free(pattern_infos);

    for (collectors, 0..) |collector, i| {
        patterns[i] = .{
            .expression = collector.regex,
            .id = @intCast(i),
            .flags = .{}, // Default flags
        };
        pattern_infos[i] = collector.info;
    }

    // Compile with Hyperscan
    var db = try hyperscan.Database.compileMulti(allocator, patterns, .{});
    errdefer db.deinit();

    // Allocate scratch
    var scratch = try hyperscan.Scratch.init(&db);
    errdefer scratch.deinit();

    // Create the database struct
    const regex_db = try allocator.create(RegexDatabase);
    regex_db.* = .{
        .db = db,
        .scratch = scratch,
        .pattern_infos = pattern_infos,
        .allocator = allocator,
    };

    return regex_db;
}

// =============================================================================
// Scan Result Types
// =============================================================================

/// Result of scanning a value against the regex index
pub const ScanResult = struct {
    /// Whether a match was found
    matched: bool,
    /// The pattern info for the first match (if any)
    pattern_info: ?PatternInfo,
};

/// Scan a value against a regex database
/// Returns the first match found (for short-circuit evaluation)
pub fn scanValue(
    db: *const RegexDatabase,
    value: []const u8,
) ScanResult {
    var result = ScanResult{
        .matched = false,
        .pattern_info = null,
    };

    // Use Hyperscan's matches() for quick check, or scan for details
    var scanner = db.db.scan(@constCast(&db.scratch), value);
    if (scanner.next()) |match| {
        result.matched = true;
        result.pattern_info = db.pattern_infos[match.id];
    }

    return result;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "CompiledRegexIndex: build empty index" {
    const allocator = testing.allocator;

    var index = try CompiledRegexIndex.build(allocator, &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());
}

test "CompiledRegexIndex: build with single log_body pattern" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    // Should have a database for log_body
    const db = index.getSimpleDatabase(.log_body);
    try testing.expect(db != null);
    try testing.expectEqual(@as(usize, 1), db.?.pattern_infos.len);

    // Other types should be null
    try testing.expect(index.getSimpleDatabase(.log_severity_text) == null);
}

test "CompiledRegexIndex: build with multiple match types" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "multi-match"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());
    try testing.expect(index.getSimpleDatabase(.log_body) != null);
    try testing.expect(index.getSimpleDatabase(.log_severity_text) != null);
}

test "CompiledRegexIndex: build with log_attribute (keyed)" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "attr-policy"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "env"),
            .regex = try allocator.dupe(u8, "staging"),
        } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    // Should have 2 keyed databases (one per key)
    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());

    // Can look up by key
    const service_db = index.getKeyedDatabase(.log_attribute, "service");
    try testing.expect(service_db != null);

    const env_db = index.getKeyedDatabase(.log_attribute, "env");
    try testing.expect(env_db != null);

    // Non-existent key returns null
    try testing.expect(index.getKeyedDatabase(.log_attribute, "nonexistent") == null);
}

test "CompiledRegexIndex: multiple policies same match type" {
    const allocator = testing.allocator;

    var policy1 = Policy{
        .name = try allocator.dupe(u8, "policy-1"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy1.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .name = try allocator.dupe(u8, "policy-2"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try policy2.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "warning") } },
    });
    defer policy2.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{ policy1, policy2 });
    defer index.deinit();

    // Both patterns in same database
    const db = index.getSimpleDatabase(.log_body);
    try testing.expect(db != null);
    try testing.expectEqual(@as(usize, 2), db.?.pattern_infos.len);

    // Check pattern info mapping
    try testing.expectEqual(@as(u32, 0), db.?.pattern_infos[0].policy_index);
    try testing.expectEqual(@as(u32, 1), db.?.pattern_infos[1].policy_index);
    try testing.expectEqual(proto.policy.FilterAction.FILTER_ACTION_DROP, db.?.pattern_infos[0].action);
    try testing.expectEqual(proto.policy.FilterAction.FILTER_ACTION_KEEP, db.?.pattern_infos[1].action);
}

test "CompiledRegexIndex: negate flag preserved" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "negate-policy"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "success") } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    const db = index.getSimpleDatabase(.log_body);
    try testing.expect(db != null);
    try testing.expect(db.?.pattern_infos[0].negate);
}

test "CompiledRegexIndex: scan matches value" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "scan-test"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    const db = index.getSimpleDatabase(.log_body).?;

    // Should match
    const result1 = scanValue(db, "an error occurred");
    try testing.expect(result1.matched);
    try testing.expect(result1.pattern_info != null);
    try testing.expectEqual(@as(u32, 0), result1.pattern_info.?.policy_index);

    // Should not match
    const result2 = scanValue(db, "all good");
    try testing.expect(!result2.matched);
    try testing.expect(result2.pattern_info == null);
}

test "CompiledRegexIndex: scan with multiple patterns" {
    const allocator = testing.allocator;

    var policy1 = Policy{
        .name = try allocator.dupe(u8, "error-policy"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy1.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .name = try allocator.dupe(u8, "warn-policy"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try policy2.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "warning") } },
    });
    defer policy2.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{ policy1, policy2 });
    defer index.deinit();

    const db = index.getSimpleDatabase(.log_body).?;

    // Match first pattern
    const result1 = scanValue(db, "error happened");
    try testing.expect(result1.matched);
    try testing.expectEqual(@as(u32, 0), result1.pattern_info.?.policy_index);

    // Match second pattern
    const result2 = scanValue(db, "warning issued");
    try testing.expect(result2.matched);
    try testing.expectEqual(@as(u32, 1), result2.pattern_info.?.policy_index);

    // No match
    const result3 = scanValue(db, "info message");
    try testing.expect(!result3.matched);
}

test "CompiledRegexIndex: all simple match types" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "all-types"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };

    // Add a matcher for each simple type
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .resource_schema_url = .{ .regex = try allocator.dupe(u8, "schema") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .scope_schema_url = .{ .regex = try allocator.dupe(u8, "scope_schema") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .scope_name = .{ .regex = try allocator.dupe(u8, "scope_name") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .scope_version = .{ .regex = try allocator.dupe(u8, "v1") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "body") } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_text = .{ .regex = try allocator.dupe(u8, "ERROR") } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    // Should have 6 databases (one per simple type)
    try testing.expectEqual(@as(usize, 6), index.getDatabaseCount());

    try testing.expect(index.getSimpleDatabase(.resource_schema_url) != null);
    try testing.expect(index.getSimpleDatabase(.scope_schema_url) != null);
    try testing.expect(index.getSimpleDatabase(.scope_name) != null);
    try testing.expect(index.getSimpleDatabase(.scope_version) != null);
    try testing.expect(index.getSimpleDatabase(.log_body) != null);
    try testing.expect(index.getSimpleDatabase(.log_severity_text) != null);

    // log_severity_number uses min/max not regex, so no DB
    try testing.expect(index.getSimpleDatabase(.log_severity_number) == null);
}

test "CompiledRegexIndex: all keyed match types" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "keyed-types"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };

    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .resource_attribute = .{
            .key = try allocator.dupe(u8, "service.name"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .scope_attribute = .{
            .key = try allocator.dupe(u8, "library"),
            .regex = try allocator.dupe(u8, "opentelemetry"),
        } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "user_id"),
            .regex = try allocator.dupe(u8, "admin"),
        } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    // Should have 3 keyed databases
    try testing.expectEqual(@as(usize, 3), index.getDatabaseCount());

    try testing.expect(index.getKeyedDatabase(.resource_attribute, "service.name") != null);
    try testing.expect(index.getKeyedDatabase(.scope_attribute, "library") != null);
    try testing.expect(index.getKeyedDatabase(.log_attribute, "user_id") != null);
}

test "CompiledRegexIndex: same key different match types" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "same-key"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };

    // Same key "name" but different match types
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .resource_attribute = .{
            .key = try allocator.dupe(u8, "name"),
            .regex = try allocator.dupe(u8, "resource"),
        } },
    });
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "name"),
            .regex = try allocator.dupe(u8, "log"),
        } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    // Should have 2 separate databases (keyed by match_case + key)
    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());

    const resource_db = index.getKeyedDatabase(.resource_attribute, "name");
    const log_db = index.getKeyedDatabase(.log_attribute, "name");

    try testing.expect(resource_db != null);
    try testing.expect(log_db != null);
    try testing.expect(resource_db != log_db); // Different databases
}

test "CompiledRegexIndex: policies without filter config ignored" {
    const allocator = testing.allocator;

    var policy_no_filter = Policy{
        .name = try allocator.dupe(u8, "no-filter"),
        .enabled = true,
        .filter = null, // No filter config
    };
    defer policy_no_filter.deinit(allocator);

    var policy_with_filter = Policy{
        .name = try allocator.dupe(u8, "with-filter"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy_with_filter.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "test") } },
    });
    defer policy_with_filter.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{ policy_no_filter, policy_with_filter });
    defer index.deinit();

    // Only one database from the policy with filter
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    const db = index.getSimpleDatabase(.log_body);
    try testing.expect(db != null);
    // Pattern should reference policy index 1 (the one with filter)
    try testing.expectEqual(@as(u32, 1), db.?.pattern_infos[0].policy_index);
}

test "CompiledRegexIndex: empty regex patterns skipped" {
    const allocator = testing.allocator;

    var policy = Policy{
        .name = try allocator.dupe(u8, "empty-regex"),
        .enabled = true,
        .filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    // Empty regex
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "") } },
    });
    // Non-empty regex
    try policy.filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "valid") } },
    });
    defer policy.deinit(allocator);

    var index = try CompiledRegexIndex.build(allocator, &.{policy});
    defer index.deinit();

    const db = index.getSimpleDatabase(.log_body);
    try testing.expect(db != null);
    // Only the non-empty pattern should be compiled
    try testing.expectEqual(@as(usize, 1), db.?.pattern_infos.len);
    try testing.expectEqual(@as(u32, 1), db.?.pattern_infos[0].matcher_index);
}
