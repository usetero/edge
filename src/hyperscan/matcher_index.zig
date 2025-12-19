//! Matcher Index - Inverted index for efficient policy matching
//!
//! This module compiles policies into Hyperscan databases indexed by (MatchCase, Key).
//! At evaluation time, we scan each field value against its corresponding database
//! and aggregate matches to determine which policies fully match.
//!
//! ## Architecture
//!
//! 1. **MatcherKey**: Identifies a unique (MatchCase, attribute_key) tuple
//! 2. **MatcherDatabase**: Compiled Hyperscan DBs for one MatcherKey (positive + negated)
//! 3. **MatcherIndex**: Collection of all databases + policy metadata for match aggregation
//!
//! ## Performance Optimizations
//!
//! - **Numeric policy indices**: O(1) array lookups instead of string hash lookups
//! - **Separate positive/negated databases**: Clean separation, no per-pattern negate flag
//! - **Dense policy array**: Cache-friendly iteration over matched policies

const std = @import("std");
const proto = @import("proto");
const hyperscan = @import("./hyperscan.zig");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Observability Events
// =============================================================================

// Info-level events
const MatcherIndexBuildStarted = struct { policy_count: usize };
const MatcherIndexBuildCompleted = struct { database_count: usize, matcher_key_count: usize, policy_count: usize };

// Debug-level events for MatcherDatabase.scan
const ScanMatched = struct { pattern_count: usize, value_len: usize, value_preview: []const u8, is_negated: bool };
const ScanMatchDetail = struct { pattern_id: u32, policy_index: PolicyIndex };
const ScanError = struct { err: []const u8 };

// Debug-level events for MatcherIndex.build
const ProcessingPolicy = struct { id: []const u8, name: []const u8, enabled: bool, index: PolicyIndex };
const SkippingPolicyNoFilter = struct { id: []const u8 };
const PolicyMatcherCount = struct { id: []const u8, matcher_count: usize, keep: []const u8 };
const MatcherNullField = struct { matcher_idx: usize };
const MatcherNullMatch = struct { matcher_idx: usize };
const MatcherEmptyRegex = struct { matcher_idx: usize };
const MatcherDetail = struct { matcher_idx: usize, match_case: MatchCase, key: []const u8, regex: []const u8, negate: bool };
const PolicyStored = struct { id: []const u8, index: PolicyIndex, required_matches: u16, negated_count: u16 };
const CompilingDatabase = struct { match_case: MatchCase, key: []const u8, positive_count: usize, negated_count: usize };

const Policy = proto.policy.Policy;
const LogMatcher = proto.policy.LogMatcher;
const LogTarget = proto.policy.LogTarget;
const LogField = proto.policy.LogField;

// =============================================================================
// Policy Index - Numeric identifier for O(1) lookups
// =============================================================================

/// Numeric policy index for efficient array-based lookups at runtime.
/// Supports up to 65,535 policies which is more than sufficient.
pub const PolicyIndex = u16;

/// Maximum number of policies supported
pub const MAX_POLICIES: usize = 4096; // Practical limit for stack-allocated bitsets

// =============================================================================
// MatchCase - Field type being matched
// =============================================================================

/// MatchCase represents the type of field being matched.
/// This is derived from the LogMatcher.field oneof.
pub const MatchCase = enum {
    // Simple log fields (from LogField enum)
    log_body,
    log_severity_text,
    log_trace_id,
    log_span_id,
    log_event_name,
    resource_schema_url,
    scope_schema_url,

    // Keyed attribute fields
    log_attribute,
    resource_attribute,
    scope_attribute,

    /// Convert from proto LogMatcher.field_union to MatchCase
    pub fn fromFieldUnion(field: LogMatcher.field_union) MatchCase {
        return switch (field) {
            .log_field => |lf| switch (lf) {
                .LOG_FIELD_BODY => .log_body,
                .LOG_FIELD_SEVERITY_TEXT => .log_severity_text,
                .LOG_FIELD_TRACE_ID => .log_trace_id,
                .LOG_FIELD_SPAN_ID => .log_span_id,
                .LOG_FIELD_EVENT_NAME => .log_event_name,
                .LOG_FIELD_RESOURCE_SCHEMA_URL => .resource_schema_url,
                .LOG_FIELD_SCOPE_SCHEMA_URL => .scope_schema_url,
                else => .log_body, // Default for unspecified
            },
            .log_attribute => .log_attribute,
            .resource_attribute => .resource_attribute,
            .scope_attribute => .scope_attribute,
        };
    }
};

// =============================================================================
// MatcherKey - Index key for databases
// =============================================================================

/// Key for indexing Hyperscan databases.
/// Combines match type and attribute key (empty for non-keyed types).
pub const MatcherKey = struct {
    match_case: MatchCase,
    key: []const u8, // Empty string for non-keyed types like log_body

    const Self = @This();

    pub fn hash(self: Self) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&self.match_case));
        h.update(self.key);
        return h.final();
    }

    pub fn eql(a: Self, b: Self) bool {
        return a.match_case == b.match_case and std.mem.eql(u8, a.key, b.key);
    }

    /// Check if this match case requires a key (attribute-based matches)
    pub fn isKeyed(match_case: MatchCase) bool {
        return switch (match_case) {
            .resource_attribute, .scope_attribute, .log_attribute => true,
            else => false,
        };
    }
};

/// Hash context for MatcherKey in hash maps
pub const MatcherKeyContext = struct {
    pub fn hash(_: MatcherKeyContext, key: MatcherKey) u64 {
        return key.hash();
    }

    pub fn eql(_: MatcherKeyContext, a: MatcherKey, b: MatcherKey) bool {
        return a.eql(b);
    }
};

// =============================================================================
// PatternMeta - Metadata for each pattern in a database
// =============================================================================

/// Metadata for a pattern in the Hyperscan database.
/// Maps Hyperscan pattern ID back to policy information.
pub const PatternMeta = struct {
    /// Numeric index of the policy (for O(1) array lookups)
    policy_index: PolicyIndex,
};

// =============================================================================
// KeepValue - Parsed keep configuration
// =============================================================================

/// Parsed keep value from policy
/// Priority order (most restrictive first): none > percentage > all > rate_limit
pub const KeepValue = union(enum) {
    /// Keep all logs (default)
    all,
    /// Drop all logs
    none,
    /// Keep a percentage of logs (0-100)
    percentage: u8,
    /// Rate limit: keep N logs per second
    per_second: u32,
    /// Rate limit: keep N logs per minute
    per_minute: u32,

    /// Parse a keep string into a KeepValue
    /// Valid formats: "all", "none", "N%", "N/s", "N/m"
    pub fn parse(s: []const u8) KeepValue {
        if (s.len == 0 or std.mem.eql(u8, s, "all")) {
            return .all;
        }
        if (std.mem.eql(u8, s, "none")) {
            return .none;
        }
        // Check for percentage: "N%"
        if (s.len >= 2 and s[s.len - 1] == '%') {
            const num_str = s[0 .. s.len - 1];
            const pct = std.fmt.parseInt(u8, num_str, 10) catch return .all;
            if (pct > 100) return .all;
            return .{ .percentage = pct };
        }
        // Check for rate limit: "N/s" or "N/m"
        if (s.len >= 3 and s[s.len - 2] == '/') {
            const num_str = s[0 .. s.len - 2];
            const rate = std.fmt.parseInt(u32, num_str, 10) catch return .all;
            return switch (s[s.len - 1]) {
                's' => .{ .per_second = rate },
                'm' => .{ .per_minute = rate },
                else => .all,
            };
        }
        return .all;
    }

    /// Compare two KeepValues for restrictiveness.
    /// Returns true if self is more restrictive than other.
    /// Order: none > percentage (lower %) > all > rate limits
    pub fn isMoreRestrictiveThan(self: KeepValue, other: KeepValue) bool {
        const self_rank = self.restrictiveness();
        const other_rank = other.restrictiveness();
        if (self_rank != other_rank) {
            return self_rank < other_rank; // Lower rank = more restrictive
        }
        // Same category - compare values
        return switch (self) {
            .percentage => |p| switch (other) {
                .percentage => |op| p < op, // Lower percentage is more restrictive
                else => false,
            },
            else => false,
        };
    }

    /// Get restrictiveness rank (lower = more restrictive)
    fn restrictiveness(self: KeepValue) u8 {
        return switch (self) {
            .none => 0,
            .percentage => 1,
            .all => 2,
            .per_second, .per_minute => 3, // Rate limits are least restrictive in priority
        };
    }
};

// =============================================================================
// PolicyInfo - Policy metadata for match aggregation
// =============================================================================

/// Policy information needed for match aggregation and action determination.
pub const PolicyInfo = struct {
    /// Policy ID (for reporting/debugging)
    id: []const u8,
    /// Numeric index for O(1) array lookups
    index: PolicyIndex,
    /// Number of positive (non-negated) matchers that must match
    required_match_count: u16,
    /// Keep value parsed from policy (determines what to do when matched)
    keep: KeepValue,
    /// Whether policy is enabled
    enabled: bool,
    /// Whether this policy has only negated matchers (no positive matches required)
    all_negated: bool,
};

// =============================================================================
// MatcherDatabase - Compiled Hyperscan DBs for one MatcherKey
// =============================================================================

/// A compiled Hyperscan database pair for a specific MatcherKey.
/// Contains separate databases for positive and negated patterns.
pub const MatcherDatabase = struct {
    /// The compiled Hyperscan database for positive patterns (must match)
    positive_db: ?hyperscan.Database,
    /// The compiled Hyperscan database for negated patterns (must NOT match)
    negated_db: ?hyperscan.Database,
    /// Scratch space for scanning - protected by mutex
    scratch: ?hyperscan.Scratch,
    /// Mutex for thread-safe scratch access
    mutex: std.Thread.Mutex,
    /// Maps Hyperscan pattern ID -> PolicyIndex for positive patterns
    positive_patterns: []const PatternMeta,
    /// Maps Hyperscan pattern ID -> PolicyIndex for negated patterns
    negated_patterns: []const PatternMeta,
    /// Allocator used for patterns arrays
    allocator: std.mem.Allocator,
    /// Event bus for observability
    bus: *EventBus,

    const Self = @This();

    /// Scan a value against positive patterns.
    /// Returns matching pattern IDs in result_buf.
    pub fn scanPositive(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        return self.scanDb(self.positive_db, self.positive_patterns, value, result_buf, false);
    }

    /// Scan a value against negated patterns.
    /// Returns matching pattern IDs in result_buf (these are failures - pattern should NOT have matched).
    pub fn scanNegated(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        return self.scanDb(self.negated_db, self.negated_patterns, value, result_buf, true);
    }

    fn scanDb(self: *Self, db: ?hyperscan.Database, patterns: []const PatternMeta, value: []const u8, result_buf: []u32, is_negated: bool) ScanResult {
        const database = db orelse return ScanResult{ .count = 0, .buf = result_buf };
        const scratch = &(self.scratch orelse return ScanResult{ .count = 0, .buf = result_buf });

        self.mutex.lock();
        defer self.mutex.unlock();

        var result = ScanResult{ .count = 0, .buf = result_buf };

        _ = database.scanWithCallback(scratch, value, &result, scanCallback) catch |err| {
            self.bus.warn(ScanError{ .err = @errorName(err) });
            return result;
        };

        if (result.count > 0) {
            self.bus.debug(ScanMatched{
                .pattern_count = result.count,
                .value_len = value.len,
                .value_preview = if (value.len > 100) value[0..100] else value,
                .is_negated = is_negated,
            });
            for (result.matches()) |pattern_id| {
                if (pattern_id < patterns.len) {
                    const meta = patterns[pattern_id];
                    self.bus.debug(ScanMatchDetail{ .pattern_id = pattern_id, .policy_index = meta.policy_index });
                }
            }
        }

        return result;
    }

    fn scanCallback(ctx: *ScanResult, match: hyperscan.Match) bool {
        if (ctx.count < ctx.buf.len) {
            ctx.buf[ctx.count] = match.id;
            ctx.count += 1;
            return true; // Continue scanning
        }
        return false; // Buffer full, stop
    }

    pub fn deinit(self: *Self) void {
        if (self.scratch) |*s| s.deinit();
        if (self.positive_db) |*db| db.deinit();
        if (self.negated_db) |*db| db.deinit();
        self.allocator.free(self.positive_patterns);
        self.allocator.free(self.negated_patterns);
    }
};

/// Result of scanning a value
pub const ScanResult = struct {
    count: usize,
    buf: []u32,

    pub fn matches(self: ScanResult) []const u32 {
        return self.buf[0..self.count];
    }
};

// =============================================================================
// MatcherIndex - The complete compiled index
// =============================================================================

/// The compiled matcher index containing all databases and policy metadata.
/// Built from a set of policies, used for efficient evaluation.
pub const MatcherIndex = struct {
    allocator: std.mem.Allocator,

    /// Maps MatcherKey -> MatcherDatabase
    databases: std.HashMap(MatcherKey, *MatcherDatabase, MatcherKeyContext, std.hash_map.default_max_load_percentage),

    /// Dense array of policy info indexed by PolicyIndex
    /// Enables O(1) lookups during evaluation
    policies: []PolicyInfo,

    /// All unique matcher keys (for iteration during evaluation)
    matcher_keys: []MatcherKey,

    /// Storage for duped keys (owned strings)
    key_storage: std.ArrayListUnmanaged([]const u8),

    /// Storage for duped policy IDs (owned strings)
    policy_id_storage: std.ArrayListUnmanaged([]const u8),

    /// Event bus for observability
    bus: *EventBus,

    const Self = @This();

    /// Build a MatcherIndex from a slice of policies.
    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var self = Self{
            .allocator = allocator,
            .databases = std.HashMap(MatcherKey, *MatcherDatabase, MatcherKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .policies = &.{},
            .matcher_keys = &.{},
            .key_storage = .{},
            .policy_id_storage = .{},
            .bus = bus,
        };
        errdefer self.deinit();

        // Temporary storage for collecting patterns per MatcherKey
        const PatternsPerKey = struct {
            positive: std.ArrayListUnmanaged(PatternCollector),
            negated: std.ArrayListUnmanaged(PatternCollector),
        };

        var patterns_by_key = std.HashMap(
            MatcherKey,
            PatternsPerKey,
            MatcherKeyContext,
            std.hash_map.default_max_load_percentage,
        ).init(allocator);
        defer {
            var it = patterns_by_key.valueIterator();
            while (it.next()) |patterns| {
                patterns.positive.deinit(allocator);
                patterns.negated.deinit(allocator);
            }
            patterns_by_key.deinit();
        }

        // Temporary list for building policy info
        var policy_info_list = std.ArrayListUnmanaged(PolicyInfo){};
        defer policy_info_list.deinit(allocator);

        // First pass: collect patterns and build policy info
        var policy_index: PolicyIndex = 0;
        for (policies_slice) |*policy| {
            const log_target = policy.log orelse {
                bus.debug(SkippingPolicyNoFilter{ .id = policy.id });
                continue;
            };

            bus.debug(ProcessingPolicy{ .id = policy.id, .name = policy.name, .enabled = policy.enabled, .index = policy_index });

            // Count matchers
            var positive_count: u16 = 0;
            var negated_count: u16 = 0;

            bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = log_target.match.items.len, .keep = log_target.keep });

            for (log_target.match.items, 0..) |matcher, matcher_idx| {
                // Get field type from matcher
                const field = matcher.field orelse {
                    bus.debug(MatcherNullField{ .matcher_idx = matcher_idx });
                    continue;
                };

                const match_case = MatchCase.fromFieldUnion(field);

                // Get match type - we only support regex for hyperscan
                const match_union = matcher.match orelse {
                    bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
                    continue;
                };

                // Extract regex from match union (only regex type is supported for hyperscan)
                const regex: []const u8 = switch (match_union) {
                    .regex => |r| r,
                    .exact => |e| e, // Treat exact as literal regex
                    .exists => continue, // exists doesn't use regex matching
                };

                if (regex.len == 0) {
                    bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
                    continue;
                }

                // Get key for attribute-based matchers
                const raw_key = getKeyFromField(field) orelse "";
                const matcher_key = MatcherKey{ .match_case = match_case, .key = raw_key };

                bus.debug(MatcherDetail{ .matcher_idx = matcher_idx, .match_case = match_case, .key = raw_key, .regex = regex, .negate = matcher.negate });

                // Track counts
                if (matcher.negate) {
                    negated_count += 1;
                } else {
                    positive_count += 1;
                }

                // Add to patterns collection
                const gop = try patterns_by_key.getOrPut(matcher_key);
                if (!gop.found_existing) {
                    // First time seeing this key - dupe it if needed
                    if (raw_key.len > 0) {
                        const key_copy = try allocator.dupe(u8, raw_key);
                        try self.key_storage.append(allocator, key_copy);
                        gop.key_ptr.key = key_copy;
                    }
                    gop.value_ptr.* = .{
                        .positive = .{},
                        .negated = .{},
                    };
                }

                const collector = PatternCollector{
                    .policy_index = policy_index,
                    .regex = regex,
                };

                if (matcher.negate) {
                    try gop.value_ptr.negated.append(allocator, collector);
                } else {
                    try gop.value_ptr.positive.append(allocator, collector);
                }
            }

            // Store policy info
            const policy_id_copy = try allocator.dupe(u8, policy.id);
            try self.policy_id_storage.append(allocator, policy_id_copy);

            try policy_info_list.append(allocator, .{
                .id = policy_id_copy,
                .index = policy_index,
                .required_match_count = positive_count,
                .keep = KeepValue.parse(log_target.keep),
                .enabled = policy.enabled,
                .all_negated = positive_count == 0 and negated_count > 0,
            });

            bus.debug(PolicyStored{ .id = policy.id, .index = policy_index, .required_matches = positive_count, .negated_count = negated_count });

            policy_index += 1;
        }

        // Copy policy info to owned slice
        self.policies = try allocator.dupe(PolicyInfo, policy_info_list.items);

        // Second pass: compile databases for each MatcherKey
        var keys_list = std.ArrayListUnmanaged(MatcherKey){};
        defer keys_list.deinit(allocator);

        var key_it = patterns_by_key.iterator();
        while (key_it.next()) |entry| {
            const matcher_key = entry.key_ptr.*;
            const patterns = entry.value_ptr.*;

            if (patterns.positive.items.len == 0 and patterns.negated.items.len == 0) continue;

            bus.debug(CompilingDatabase{
                .match_case = matcher_key.match_case,
                .key = matcher_key.key,
                .positive_count = patterns.positive.items.len,
                .negated_count = patterns.negated.items.len,
            });

            const db = try compileDatabase(allocator, bus, patterns.positive.items, patterns.negated.items);
            try self.databases.put(matcher_key, db);
            try keys_list.append(allocator, matcher_key);
        }

        // Store matcher keys for iteration
        self.matcher_keys = try allocator.dupe(MatcherKey, keys_list.items);

        span.completed(MatcherIndexBuildCompleted{
            .database_count = self.databases.count(),
            .matcher_key_count = self.matcher_keys.len,
            .policy_count = self.policies.len,
        });

        return self;
    }

    /// Get the database for a MatcherKey, or null if none exists.
    pub fn getDatabase(self: *const Self, key: MatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    /// Get policy info by index (O(1) array lookup).
    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    /// Get policy info by ID (O(n) search - use for debugging only).
    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    /// Get all matcher keys for iteration during evaluation.
    pub fn getMatcherKeys(self: *const Self) []const MatcherKey {
        return self.matcher_keys;
    }

    /// Get all policies for iteration.
    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    /// Check if the index is empty (no databases compiled).
    pub fn isEmpty(self: *const Self) bool {
        return self.databases.count() == 0;
    }

    /// Get count of compiled databases.
    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    /// Get count of policies.
    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        // Free databases
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        // Free policies array
        self.allocator.free(self.policies);

        // Free matcher keys array
        self.allocator.free(self.matcher_keys);

        // Free key storage
        for (self.key_storage.items) |key| {
            self.allocator.free(key);
        }
        self.key_storage.deinit(self.allocator);

        // Free policy ID storage
        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// Helper functions
// =============================================================================

/// Extract the key from a field union (for keyed attribute types)
fn getKeyFromField(field: LogMatcher.field_union) ?[]const u8 {
    return switch (field) {
        .log_attribute => |key| key,
        .resource_attribute => |key| key,
        .scope_attribute => |key| key,
        .log_field => null, // Simple fields don't have keys
    };
}

/// Pattern collector for building databases
const PatternCollector = struct {
    policy_index: PolicyIndex,
    regex: []const u8,
};

/// Compile positive and negated patterns into a MatcherDatabase
fn compileDatabase(
    allocator: std.mem.Allocator,
    bus: *EventBus,
    positive_collectors: []const PatternCollector,
    negated_collectors: []const PatternCollector,
) !*MatcherDatabase {
    var positive_db: ?hyperscan.Database = null;
    var negated_db: ?hyperscan.Database = null;
    var scratch: ?hyperscan.Scratch = null;

    errdefer {
        if (scratch) |*s| s.deinit();
        if (positive_db) |*db| db.deinit();
        if (negated_db) |*db| db.deinit();
    }

    // Compile positive patterns
    var positive_patterns: []PatternMeta = &.{};
    if (positive_collectors.len > 0) {
        const hs_patterns = try allocator.alloc(hyperscan.Pattern, positive_collectors.len);
        defer allocator.free(hs_patterns);

        positive_patterns = try allocator.alloc(PatternMeta, positive_collectors.len);
        errdefer allocator.free(positive_patterns);

        for (positive_collectors, 0..) |collector, i| {
            hs_patterns[i] = .{
                .expression = collector.regex,
                .id = @intCast(i),
                .flags = .{},
            };
            positive_patterns[i] = .{ .policy_index = collector.policy_index };
        }

        positive_db = try hyperscan.Database.compileMulti(allocator, hs_patterns, .{});
    }

    // Compile negated patterns
    var negated_patterns: []PatternMeta = &.{};
    if (negated_collectors.len > 0) {
        const hs_patterns = try allocator.alloc(hyperscan.Pattern, negated_collectors.len);
        defer allocator.free(hs_patterns);

        negated_patterns = try allocator.alloc(PatternMeta, negated_collectors.len);
        errdefer allocator.free(negated_patterns);

        for (negated_collectors, 0..) |collector, i| {
            hs_patterns[i] = .{
                .expression = collector.regex,
                .id = @intCast(i),
                .flags = .{},
            };
            negated_patterns[i] = .{ .policy_index = collector.policy_index };
        }

        negated_db = try hyperscan.Database.compileMulti(allocator, hs_patterns, .{});
    }

    // Allocate scratch for whichever database exists
    if (positive_db) |*db| {
        scratch = try hyperscan.Scratch.init(db);
        if (negated_db) |*ndb| {
            // Extend scratch for negated db
            _ = try hyperscan.Scratch.init(ndb);
        }
    } else if (negated_db) |*db| {
        scratch = try hyperscan.Scratch.init(db);
    }

    // Create the database struct
    const matcher_db = try allocator.create(MatcherDatabase);
    matcher_db.* = .{
        .positive_db = positive_db,
        .negated_db = negated_db,
        .scratch = scratch,
        .mutex = .{},
        .positive_patterns = positive_patterns,
        .negated_patterns = negated_patterns,
        .allocator = allocator,
        .bus = bus,
    };

    return matcher_db;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "MatcherKey: hash and equality" {
    const key1 = MatcherKey{ .match_case = .log_body, .key = "" };
    const key2 = MatcherKey{ .match_case = .log_body, .key = "" };
    const key3 = MatcherKey{ .match_case = .log_severity_text, .key = "" };
    const key4 = MatcherKey{ .match_case = .log_attribute, .key = "service" };
    const key5 = MatcherKey{ .match_case = .log_attribute, .key = "service" };
    const key6 = MatcherKey{ .match_case = .log_attribute, .key = "env" };

    // Same keys should be equal
    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));

    // Different keys should not be equal
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));

    // Hash should be consistent
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());
}

test "MatcherKey: isKeyed" {
    try testing.expect(!MatcherKey.isKeyed(.log_body));
    try testing.expect(!MatcherKey.isKeyed(.log_severity_text));
    try testing.expect(!MatcherKey.isKeyed(.resource_schema_url));
    try testing.expect(MatcherKey.isKeyed(.log_attribute));
    try testing.expect(MatcherKey.isKeyed(.resource_attribute));
    try testing.expect(MatcherKey.isKeyed(.scope_attribute));
}

test "KeepValue: parse" {
    // Test basic values
    try testing.expectEqual(KeepValue.all, KeepValue.parse("all"));
    try testing.expectEqual(KeepValue.all, KeepValue.parse(""));
    try testing.expectEqual(KeepValue.none, KeepValue.parse("none"));

    // Test percentages
    try testing.expectEqual(KeepValue{ .percentage = 50 }, KeepValue.parse("50%"));
    try testing.expectEqual(KeepValue{ .percentage = 0 }, KeepValue.parse("0%"));
    try testing.expectEqual(KeepValue{ .percentage = 100 }, KeepValue.parse("100%"));

    // Test rate limits
    try testing.expectEqual(KeepValue{ .per_second = 100 }, KeepValue.parse("100/s"));
    try testing.expectEqual(KeepValue{ .per_minute = 1000 }, KeepValue.parse("1000/m"));

    // Invalid values default to all
    try testing.expectEqual(KeepValue.all, KeepValue.parse("invalid"));
    try testing.expectEqual(KeepValue.all, KeepValue.parse("101%")); // > 100
}

test "KeepValue: restrictiveness comparison" {
    const none: KeepValue = .none;
    const all: KeepValue = .all;
    const pct50: KeepValue = .{ .percentage = 50 };
    const pct10: KeepValue = .{ .percentage = 10 };
    const rate100: KeepValue = .{ .per_second = 100 };

    // none is most restrictive
    try testing.expect(none.isMoreRestrictiveThan(all));
    try testing.expect(none.isMoreRestrictiveThan(pct50));

    // percentage is more restrictive than all
    try testing.expect(pct50.isMoreRestrictiveThan(all));
    try testing.expect(pct10.isMoreRestrictiveThan(pct50));

    // all is more restrictive than rate limits
    try testing.expect(all.isMoreRestrictiveThan(rate100));

    // Same restrictiveness
    try testing.expect(!all.isMoreRestrictiveThan(all));
    try testing.expect(!none.isMoreRestrictiveThan(none));
}

test "MatcherIndex: build empty" {
    const allocator = testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 0), index.getPolicyCount());
}

test "MatcherIndex: build with single policy" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // Check policy info by index
    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
    try testing.expect(policy_info.?.enabled);
    try testing.expect(!policy_info.?.all_negated);

    // Check policy info by ID
    const policy_info_by_id = index.getPolicy("policy-1");
    try testing.expect(policy_info_by_id != null);
    try testing.expectEqualStrings("policy-1", policy_info_by_id.?.id);

    // Check database exists for log_body
    const db = index.getDatabase(.{ .match_case = .log_body, .key = "" });
    try testing.expect(db != null);
    try testing.expect(db.?.positive_db != null);
    try testing.expect(db.?.negated_db == null);
}

test "MatcherIndex: build with keyed matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
        .match = .{ .regex = try allocator.dupe(u8, "prod") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // Should have 2 databases (one per key)
    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());

    // Check databases exist
    try testing.expect(index.getDatabase(.{ .match_case = .log_attribute, .key = "service" }) != null);
    try testing.expect(index.getDatabase(.{ .match_case = .log_attribute, .key = "env" }) != null);
    try testing.expect(index.getDatabase(.{ .match_case = .log_attribute, .key = "other" }) == null);
}

test "MatcherIndex: multiple policies same matcher key" {
    const allocator = testing.allocator;

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "policy-1"),
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

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "policy-2"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "all"),
        },
    };
    try policy2.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{ policy1, policy2 });
    defer index.deinit();

    // Should have 1 database with 2 patterns
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 2), index.getPolicyCount());

    const db = index.getDatabase(.{ .match_case = .log_body, .key = "" });
    try testing.expect(db != null);
    try testing.expectEqual(@as(usize, 2), db.?.positive_patterns.len);
}

test "MatcherIndex: negated matcher creates negated database" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 0), policy_info.?.required_match_count);
    try testing.expect(policy_info.?.all_negated);

    // Check database has negated patterns
    const db = index.getDatabase(.{ .match_case = .log_body, .key = "" });
    try testing.expect(db != null);
    try testing.expect(db.?.positive_db == null);
    try testing.expect(db.?.negated_db != null);
    try testing.expectEqual(@as(usize, 1), db.?.negated_patterns.len);
}

test "MatcherIndex: mixed positive and negated matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    // Positive matcher
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    // Negated matcher on same field
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "ignore") },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
    try testing.expect(!policy_info.?.all_negated);

    // Check database has both positive and negated
    const db = index.getDatabase(.{ .match_case = .log_body, .key = "" });
    try testing.expect(db != null);
    try testing.expect(db.?.positive_db != null);
    try testing.expect(db.?.negated_db != null);
    try testing.expectEqual(@as(usize, 1), db.?.positive_patterns.len);
    try testing.expectEqual(@as(usize, 1), db.?.negated_patterns.len);
}

test "MatcherIndex: scan database" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    var db = index.getDatabase(.{ .match_case = .log_body, .key = "" }).?;

    // Scan matching value
    var result_buf: [16]u32 = undefined;
    var result = db.scanPositive("an error occurred", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Scan non-matching value
    result = db.scanPositive("all good", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    // Scan value matching both patterns
    result = db.scanPositive("error and warning", &result_buf);
    try testing.expectEqual(@as(usize, 2), result.count);
}

test "MatcherIndex: exists matcher excluded from regex matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log = .{
            .keep = try allocator.dupe(u8, "none"),
        },
    };
    // Add a regex matcher
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    // Add an exists matcher (should be excluded from hyperscan index)
    try policy.log.?.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "trace_id") },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // Only 1 database (for log_body, exists matcher is not indexed)
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    // required_match_count should be 1 (excludes exists)
    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
}
