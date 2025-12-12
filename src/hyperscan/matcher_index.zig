//! Matcher Index - Inverted index for efficient policy matching
//!
//! This module compiles policies into Hyperscan databases indexed by (MatchCase, Key).
//! At evaluation time, we scan each field value against its corresponding database
//! and aggregate matches to determine which policies fully match.
//!
//! ## Architecture
//!
//! 1. **MatcherKey**: Identifies a unique (MatchCase, attribute_key) tuple
//! 2. **MatcherDatabase**: Compiled Hyperscan DB for one MatcherKey, patterns map to policy IDs
//! 3. **MatcherIndex**: Collection of all databases + policy metadata for match aggregation

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
const MatcherIndexBuildCompleted = struct { database_count: usize, matcher_key_count: usize };

// Debug-level events for MatcherDatabase.scan
const ScanMatched = struct { pattern_count: usize, value_len: usize, value_preview: []const u8 };
const ScanMatchDetail = struct { pattern_id: u32, policy_id: []const u8, negate: bool };
const ScanError = struct { err: []const u8 };

// Debug-level events for MatcherIndex.build
const ProcessingPolicy = struct { id: []const u8, name: []const u8, enabled: bool };
const SkippingPolicyNoFilter = struct { id: []const u8 };
const PolicyMatcherCount = struct { id: []const u8, matcher_count: usize, action: proto.policy.FilterAction };
const MatcherNullMatch = struct { matcher_idx: usize };
const MatcherSeverityNumber = struct { matcher_idx: usize };
const MatcherNoRegex = struct { matcher_idx: usize };
const MatcherEmptyRegex = struct { matcher_idx: usize };
const MatcherDetail = struct { matcher_idx: usize, match_case: MatchCase, key: []const u8, regex: []const u8, negate: bool };
const PolicyStored = struct { id: []const u8, regex_matcher_count: u32, negated_matcher_count: usize };
const CompilingDatabase = struct { match_case: MatchCase, key: []const u8, pattern_count: usize };
const CompilingDatabasePattern = struct { idx: usize, policy_id: []const u8, regex: []const u8, negate: bool };

const Policy = proto.policy.Policy;
const LogMatcher = proto.policy.LogMatcher;
const FilterAction = proto.policy.FilterAction;

pub const MatchCase = LogMatcher._match_case;

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
    /// Policy ID this pattern belongs to
    policy_id: []const u8,
    /// Index of this matcher within the policy's matchers list
    matcher_index: u32,
    /// Whether this is a negated matcher (pattern must NOT match)
    negate: bool,
};

// =============================================================================
// PolicyInfo - Policy metadata for match aggregation
// =============================================================================

/// Policy information needed for match aggregation and action determination.
pub const PolicyInfo = struct {
    /// Policy ID
    id: []const u8,
    /// Total number of regex matchers in this policy (excludes severity_number)
    regex_matcher_count: u32,
    /// Filter action to take when policy matches
    action: FilterAction,
    /// Policy priority (higher = more important)
    priority: i32,
    /// Whether policy is enabled
    enabled: bool,
    /// Negated matchers info: maps MatcherKey -> list of matcher indices
    /// Used to track which negated patterns need to NOT match
    negated_matchers: std.ArrayListUnmanaged(NegatedMatcherInfo),

    pub const NegatedMatcherInfo = struct {
        matcher_key: MatcherKey,
        matcher_index: u32,
    };
};

// =============================================================================
// MatcherDatabase - Compiled Hyperscan DB for one MatcherKey
// =============================================================================

/// A compiled Hyperscan database for a specific MatcherKey.
/// Contains all patterns from all policies that match on this (MatchCase, Key).
pub const MatcherDatabase = struct {
    /// The compiled Hyperscan database
    db: hyperscan.Database,
    /// Pool of scratch spaces for concurrent scanning
    scratch_pool: ScratchPool,
    /// Maps Hyperscan pattern ID -> PatternMeta
    patterns: []const PatternMeta,
    /// Allocator used for patterns array
    allocator: std.mem.Allocator,
    /// Event bus for observability
    bus: *EventBus,

    const Self = @This();

    /// Number of scratch spaces in the pool (allows this many concurrent scans)
    const SCRATCH_POOL_SIZE = 8;

    /// Pool of scratch spaces with lightweight locking
    const ScratchPool = struct {
        scratches: [SCRATCH_POOL_SIZE]hyperscan.Scratch,
        /// Bitset tracking which scratches are available (1 = available)
        available: std.atomic.Value(u8),
        /// Fallback mutex for when pool is exhausted
        fallback_scratch: hyperscan.Scratch,
        fallback_mutex: std.Thread.Mutex,

        fn init(db: *hyperscan.Database) !ScratchPool {
            var pool: ScratchPool = .{
                .scratches = undefined,
                .available = std.atomic.Value(u8).init(0xFF), // All 8 bits set = all available
                .fallback_scratch = undefined,
                .fallback_mutex = .{},
            };

            // Initialize pool scratches
            for (&pool.scratches, 0..) |*scratch, i| {
                scratch.* = hyperscan.Scratch.init(db) catch |err| {
                    // Clean up already allocated scratches
                    for (pool.scratches[0..i]) |*s| s.deinit();
                    return err;
                };
            }

            // Initialize fallback scratch
            pool.fallback_scratch = try hyperscan.Scratch.init(db);

            return pool;
        }

        fn deinit(self: *ScratchPool) void {
            for (&self.scratches) |*scratch| {
                scratch.deinit();
            }
            self.fallback_scratch.deinit();
        }

        /// Acquire a scratch space. Returns index and pointer, or null to use fallback.
        fn acquire(self: *ScratchPool) ?struct { index: u3, scratch: *hyperscan.Scratch } {
            while (true) {
                const current = self.available.load(.acquire);
                if (current == 0) return null; // Pool exhausted, use fallback

                // Find first available slot
                const index: u3 = @intCast(@ctz(current));
                const mask = @as(u8, 1) << index;
                const new = current & ~mask;

                // Try to claim it
                if (self.available.cmpxchgWeak(current, new, .acq_rel, .acquire)) |_| {
                    // CAS failed, retry
                    continue;
                }

                return .{ .index = index, .scratch = &self.scratches[index] };
            }
        }

        /// Release a scratch space back to the pool
        fn release(self: *ScratchPool, index: u3) void {
            const mask = @as(u8, 1) << index;
            _ = self.available.fetchOr(mask, .release);
        }
    };

    /// Scan a value and return all matching pattern IDs.
    /// Thread-safe: uses a pool of scratch spaces for concurrent access.
    pub fn scan(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        var result = ScanResult{ .count = 0, .buf = result_buf };

        // Try to get a scratch from the pool
        if (self.scratch_pool.acquire()) |acquired| {
            defer self.scratch_pool.release(acquired.index);
            self.doScan(acquired.scratch, value, &result);
        } else {
            // Pool exhausted, fall back to mutex-protected scratch
            self.scratch_pool.fallback_mutex.lock();
            defer self.scratch_pool.fallback_mutex.unlock();
            self.doScan(&self.scratch_pool.fallback_scratch, value, &result);
        }

        return result;
    }

    fn doScan(self: *Self, scratch: *hyperscan.Scratch, value: []const u8, result: *ScanResult) void {
        _ = self.db.scanWithCallback(scratch, value, result, scanCallback) catch |err| {
            self.bus.warn(ScanError{ .err = @errorName(err) });
            return;
        };

        if (result.count > 0) {
            self.bus.debug(ScanMatched{
                .pattern_count = result.count,
                .value_len = value.len,
                .value_preview = if (value.len > 100) value[0..100] else value,
            });
            for (result.matches()) |pattern_id| {
                if (pattern_id < self.patterns.len) {
                    const meta = self.patterns[pattern_id];
                    self.bus.debug(ScanMatchDetail{ .pattern_id = pattern_id, .policy_id = meta.policy_id, .negate = meta.negate });
                }
            }
        }
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
        self.scratch_pool.deinit();
        self.db.deinit();
        // Free pattern metadata (including policy_id strings we duped)
        for (self.patterns) |meta| {
            self.allocator.free(meta.policy_id);
        }
        self.allocator.free(self.patterns);
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

    /// Maps policy_id -> PolicyInfo
    policies: std.StringHashMapUnmanaged(PolicyInfo),

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

        var self = Self{
            .allocator = allocator,
            .databases = std.HashMap(MatcherKey, *MatcherDatabase, MatcherKeyContext, std.hash_map.default_max_load_percentage).init(allocator),
            .policies = .{},
            .matcher_keys = &.{},
            .key_storage = .{},
            .policy_id_storage = .{},
            .bus = bus,
        };
        errdefer self.deinit();

        // Temporary storage for collecting patterns per MatcherKey
        var patterns_by_key = std.HashMap(
            MatcherKey,
            std.ArrayListUnmanaged(PatternCollector),
            MatcherKeyContext,
            std.hash_map.default_max_load_percentage,
        ).init(allocator);
        defer {
            var it = patterns_by_key.valueIterator();
            while (it.next()) |list| {
                list.deinit(allocator);
            }
            patterns_by_key.deinit();
        }

        // First pass: collect patterns and build policy info
        for (policies_slice) |*policy| {
            bus.debug(ProcessingPolicy{ .id = policy.id, .name = policy.name, .enabled = policy.enabled });

            const filter_config = policy.log_filter orelse {
                bus.debug(SkippingPolicyNoFilter{ .id = policy.id });
                continue;
            };

            // Count regex matchers (exclude severity_number which uses range)
            var regex_matcher_count: u32 = 0;
            var negated_matchers = std.ArrayListUnmanaged(PolicyInfo.NegatedMatcherInfo){};

            bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = filter_config.matchers.items.len, .action = filter_config.action });

            for (filter_config.matchers.items, 0..) |matcher, matcher_idx| {
                const match = matcher.match orelse {
                    bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
                    continue;
                };
                const match_case: MatchCase = match;

                // Skip severity_number - it uses min/max range, not regex
                if (match_case == .log_severity_number) {
                    bus.debug(MatcherSeverityNumber{ .matcher_idx = matcher_idx });
                    continue;
                }

                const regex = getRegexFromMatch(match) orelse {
                    bus.debug(MatcherNoRegex{ .matcher_idx = matcher_idx });
                    continue;
                };
                if (regex.len == 0) {
                    bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
                    continue;
                }

                regex_matcher_count += 1;

                // Get or create key
                const raw_key = getKeyFromMatch(match) orelse "";
                const matcher_key = MatcherKey{ .match_case = match_case, .key = raw_key };

                bus.debug(MatcherDetail{ .matcher_idx = matcher_idx, .match_case = match_case, .key = raw_key, .regex = regex, .negate = matcher.negate });

                // Track negated matchers
                if (matcher.negate) {
                    // Dupe the key if needed
                    const key_copy = if (raw_key.len > 0) try allocator.dupe(u8, raw_key) else "";
                    if (key_copy.len > 0) {
                        try self.key_storage.append(allocator, key_copy);
                    }
                    try negated_matchers.append(allocator, .{
                        .matcher_key = .{ .match_case = match_case, .key = key_copy },
                        .matcher_index = @intCast(matcher_idx),
                    });
                }

                // Add to patterns collection
                const gop = try patterns_by_key.getOrPut(matcher_key);
                if (!gop.found_existing) {
                    // First time seeing this key - dupe it
                    if (raw_key.len > 0) {
                        const key_copy = try allocator.dupe(u8, raw_key);
                        try self.key_storage.append(allocator, key_copy);
                        gop.key_ptr.key = key_copy;
                    }
                    gop.value_ptr.* = .{};
                }

                try gop.value_ptr.append(allocator, .{
                    .policy_id = policy.id,
                    .matcher_index = @intCast(matcher_idx),
                    .negate = matcher.negate,
                    .regex = regex,
                });
            }

            // Store policy info
            const policy_id_copy = try allocator.dupe(u8, policy.id);
            try self.policy_id_storage.append(allocator, policy_id_copy);

            try self.policies.put(allocator, policy_id_copy, .{
                .id = policy_id_copy,
                .regex_matcher_count = regex_matcher_count,
                .action = filter_config.action,
                .priority = policy.priority,
                .enabled = policy.enabled,
                .negated_matchers = negated_matchers,
            });

            bus.debug(PolicyStored{ .id = policy.id, .regex_matcher_count = regex_matcher_count, .negated_matcher_count = negated_matchers.items.len });
        }

        // Second pass: compile databases for each MatcherKey
        var keys_list = std.ArrayListUnmanaged(MatcherKey){};
        defer keys_list.deinit(allocator);

        var key_it = patterns_by_key.iterator();
        while (key_it.next()) |entry| {
            const matcher_key = entry.key_ptr.*;
            const collectors = entry.value_ptr.items;

            if (collectors.len == 0) continue;

            bus.debug(CompilingDatabase{ .match_case = matcher_key.match_case, .key = matcher_key.key, .pattern_count = collectors.len });
            for (collectors, 0..) |collector, idx| {
                bus.debug(CompilingDatabasePattern{ .idx = idx, .policy_id = collector.policy_id, .regex = collector.regex, .negate = collector.negate });
            }

            const db = try compileDatabase(allocator, bus, collectors);
            try self.databases.put(matcher_key, db);
            try keys_list.append(allocator, matcher_key);
        }

        // Store matcher keys for iteration
        self.matcher_keys = try allocator.dupe(MatcherKey, keys_list.items);

        span.completed(MatcherIndexBuildCompleted{
            .database_count = self.databases.count(),
            .matcher_key_count = self.matcher_keys.len,
        });

        return self;
    }

    /// Get the database for a MatcherKey, or null if none exists.
    pub fn getDatabase(self: *const Self, key: MatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    /// Get policy info by ID, or null if not found.
    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        return self.policies.get(id);
    }

    /// Get all matcher keys for iteration during evaluation.
    pub fn getMatcherKeys(self: *const Self) []const MatcherKey {
        return self.matcher_keys;
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
        return self.policies.count();
    }

    pub fn deinit(self: *Self) void {
        // Free databases
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        // Free policy info (including negated_matchers lists)
        var policy_it = self.policies.valueIterator();
        while (policy_it.next()) |info| {
            info.negated_matchers.deinit(self.allocator);
        }
        self.policies.deinit(self.allocator);

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
// Helper types and functions
// =============================================================================

/// Temporary struct for collecting patterns before compilation
const PatternCollector = struct {
    policy_id: []const u8,
    matcher_index: u32,
    negate: bool,
    regex: []const u8,
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

/// Compile a list of patterns into a MatcherDatabase
fn compileDatabase(
    allocator: std.mem.Allocator,
    bus: *EventBus,
    collectors: []const PatternCollector,
) !*MatcherDatabase {
    // Build Hyperscan pattern array
    const hs_patterns = try allocator.alloc(hyperscan.Pattern, collectors.len);
    defer allocator.free(hs_patterns);

    const pattern_metas = try allocator.alloc(PatternMeta, collectors.len);
    errdefer allocator.free(pattern_metas);

    for (collectors, 0..) |collector, i| {
        hs_patterns[i] = .{
            .expression = collector.regex,
            .id = @intCast(i),
            .flags = .{},
        };

        // Dupe the policy_id for the pattern meta
        const policy_id_copy = try allocator.dupe(u8, collector.policy_id);
        errdefer allocator.free(policy_id_copy);

        pattern_metas[i] = .{
            .policy_id = policy_id_copy,
            .matcher_index = collector.matcher_index,
            .negate = collector.negate,
        };
    }

    // Compile with Hyperscan
    var db = try hyperscan.Database.compileMulti(allocator, hs_patterns, .{});
    errdefer db.deinit();

    // Initialize scratch pool
    var scratch_pool = try MatcherDatabase.ScratchPool.init(&db);
    errdefer scratch_pool.deinit();

    // Create the database struct
    const matcher_db = try allocator.create(MatcherDatabase);
    matcher_db.* = .{
        .db = db,
        .scratch_pool = scratch_pool,
        .patterns = pattern_metas,
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
    try testing.expect(!MatcherKey.isKeyed(.scope_name));
    try testing.expect(MatcherKey.isKeyed(.log_attribute));
    try testing.expect(MatcherKey.isKeyed(.resource_attribute));
    try testing.expect(MatcherKey.isKeyed(.scope_attribute));
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
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // Check policy info
    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u32, 1), policy_info.?.regex_matcher_count);
    try testing.expectEqual(@as(i32, 10), policy_info.?.priority);
    try testing.expect(policy_info.?.enabled);

    // Check database exists for log_body
    const db = index.getDatabase(.{ .match_case = .log_body, .key = "" });
    try testing.expect(db != null);
}

test "MatcherIndex: build with keyed matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "service"),
            .regex = try allocator.dupe(u8, "payment"),
        } },
    });
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_attribute = .{
            .key = try allocator.dupe(u8, "env"),
            .regex = try allocator.dupe(u8, "prod"),
        } },
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
        .priority = 10,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy1.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    defer policy1.deinit(allocator);

    var policy2 = Policy{
        .id = try allocator.dupe(u8, "policy-2"),
        .name = try allocator.dupe(u8, "policy-2"),
        .enabled = true,
        .priority = 20,
        .log_filter = .{
            .action = .FILTER_ACTION_KEEP,
        },
    };
    try policy2.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "warning") } },
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
    try testing.expectEqual(@as(usize, 2), db.?.patterns.len);
}

test "MatcherIndex: negated matcher tracking" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
        .negate = true,
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(usize, 1), policy_info.?.negated_matchers.items.len);
    try testing.expectEqual(MatchCase.log_body, policy_info.?.negated_matchers.items[0].matcher_key.match_case);
}

test "MatcherIndex: scan database" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "warning") } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    var db = index.getDatabase(.{ .match_case = .log_body, .key = "" }).?;

    // Scan matching value
    var result_buf: [16]u32 = undefined;
    var result = db.scan("an error occurred", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Scan non-matching value
    result = db.scan("all good", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    // Scan value matching both patterns
    result = db.scan("error and warning", &result_buf);
    try testing.expectEqual(@as(usize, 2), result.count);
}

test "MatcherIndex: severity_number excluded from regex matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .log_filter = .{
            .action = .FILTER_ACTION_DROP,
        },
    };
    // Add a regex matcher
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_body = .{ .regex = try allocator.dupe(u8, "error") } },
    });
    // Add a severity_number matcher (should be excluded from count)
    try policy.log_filter.?.matchers.append(allocator, .{
        .match = .{ .log_severity_number = .{ .min = 17, .max = 21 } },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // Only 1 database (for log_body, not severity_number)
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    // regex_matcher_count should be 1 (excludes severity_number)
    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u32, 1), policy_info.?.regex_matcher_count);
}
