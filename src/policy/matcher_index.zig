//! Matcher Index - Inverted index for efficient policy matching
//!
//! This module compiles policies into Hyperscan databases indexed by MatcherKey.
//! At evaluation time, we scan each field value against its corresponding database
//! and aggregate matches to determine which policies fully match.
//!
//! ## Architecture
//!
//! 1. **LogMatcherIndex / MetricMatcherIndex**: Type-specific indices for each telemetry type
//! 2. **MatcherDatabase**: Compiled Hyperscan DBs for one MatcherKey (positive + negated)
//! 3. **IndexBuilder(T)**: Generic builder for constructing type-specific indices
//!
//! ## Performance Optimizations
//!
//! - **Compile-time dispatch**: No runtime telemetry type filtering
//! - **Numeric policy indices**: O(1) array lookups instead of string hash lookups
//! - **Separate positive/negated databases**: Clean separation, no per-pattern negate flag
//! - **Dense policy array**: Cache-friendly iteration over matched policies

const std = @import("std");
const proto = @import("proto");
const hyperscan = @import("../hyperscan/hyperscan.zig");
const policy_types = @import("./types.zig");
const sampler_mod = @import("./sampler.zig");
const rate_limiter_mod = @import("./rate_limiter.zig");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const Sampler = sampler_mod.Sampler;
const RateLimiter = rate_limiter_mod.RateLimiter;

const FieldRef = policy_types.FieldRef;
const MetricFieldRef = policy_types.MetricFieldRef;
pub const TelemetryType = policy_types.TelemetryType;

const Policy = proto.policy.Policy;
const LogMatcher = proto.policy.LogMatcher;
const LogTarget = proto.policy.LogTarget;
const LogField = proto.policy.LogField;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricTarget = proto.policy.MetricTarget;
const MetricField = proto.policy.MetricField;

// =============================================================================
// Observability Events
// =============================================================================

const MatcherIndexBuildStarted = struct { policy_count: usize, telemetry_type: TelemetryType };
const MatcherIndexBuildCompleted = struct { database_count: usize, matcher_key_count: usize, policy_count: usize };
const ScanMatched = struct { pattern_count: usize, value_len: usize, value_preview: []const u8, is_negated: bool };
const ScanMatchDetail = struct { pattern_id: u32, policy_index: PolicyIndex };
const ScanError = struct { err: []const u8 };
const ProcessingPolicy = struct { id: []const u8, name: []const u8, enabled: bool, index: PolicyIndex, telemetry_type: TelemetryType };
const SkippingPolicyWrongType = struct { id: []const u8 };
const PolicyMatcherCount = struct { id: []const u8, matcher_count: usize };
const MatcherNullField = struct { matcher_idx: usize };
const MatcherNullMatch = struct { matcher_idx: usize };
const MatcherEmptyRegex = struct { matcher_idx: usize };
const MatcherDetail = struct { matcher_idx: usize, regex: []const u8, negate: bool };
const PolicyStored = struct { id: []const u8, index: PolicyIndex, required_matches: u16, negated_count: u16 };

// =============================================================================
// Policy Index - Numeric identifier for O(1) lookups
// =============================================================================

/// Numeric policy index for efficient array-based lookups at runtime.
pub const PolicyIndex = u16;

/// Maximum number of policies supported
pub const MAX_POLICIES: usize = 4096;

// =============================================================================
// MatcherKey Types - Separate types for log and metric
// =============================================================================

/// Key for indexing Hyperscan databases for log policies.
pub const LogMatcherKey = struct {
    field: FieldRef,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        return hashFieldRef(FieldRef, self.field);
    }

    pub fn eql(a: Self, b: Self) bool {
        return eqlFieldRef(FieldRef, a.field, b.field);
    }
};

/// Key for indexing Hyperscan databases for metric policies.
pub const MetricMatcherKey = struct {
    field: MetricFieldRef,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        return hashFieldRef(MetricFieldRef, self.field);
    }

    pub fn eql(a: Self, b: Self) bool {
        return eqlFieldRef(MetricFieldRef, a.field, b.field);
    }
};

/// Generic hash implementation for field refs
fn hashFieldRef(comptime FieldRefT: type, field: FieldRefT) u64 {
    var h = std.hash.Wyhash.init(0);
    switch (field) {
        inline else => |val, tag| {
            h.update(std.mem.asBytes(&tag));
            const T = @TypeOf(val);
            if (T == []const u8) {
                h.update(val);
            } else {
                h.update(std.mem.asBytes(&val));
            }
        },
    }
    return h.final();
}

/// Generic equality implementation for field refs
fn eqlFieldRef(comptime FieldRefT: type, a: FieldRefT, b: FieldRefT) bool {
    const tag_a = std.meta.activeTag(a);
    const tag_b = std.meta.activeTag(b);
    if (tag_a != tag_b) return false;

    switch (a) {
        inline else => |val_a, tag| {
            const val_b = @field(b, @tagName(tag));
            const T = @TypeOf(val_a);
            if (T == []const u8) {
                return std.mem.eql(u8, val_a, val_b);
            } else {
                return val_a == val_b;
            }
        },
    }
}

/// Hash context for LogMatcherKey in hash maps
pub const LogMatcherKeyContext = struct {
    pub fn hash(_: LogMatcherKeyContext, key: LogMatcherKey) u64 {
        return key.hash();
    }
    pub fn eql(_: LogMatcherKeyContext, a: LogMatcherKey, b: LogMatcherKey) bool {
        return a.eql(b);
    }
};

/// Hash context for MetricMatcherKey in hash maps
pub const MetricMatcherKeyContext = struct {
    pub fn hash(_: MetricMatcherKeyContext, key: MetricMatcherKey) u64 {
        return key.hash();
    }
    pub fn eql(_: MetricMatcherKeyContext, a: MetricMatcherKey, b: MetricMatcherKey) bool {
        return a.eql(b);
    }
};

// =============================================================================
// KeepValue - Parsed keep configuration
// =============================================================================

/// Parsed keep value from policy.
/// Priority order (most restrictive first): none > rate_limit > percentage > all
pub const KeepValue = union(enum) {
    all,
    none,
    percentage: u8,
    per_second: u32,
    per_minute: u32,

    pub fn parse(s: []const u8) KeepValue {
        if (s.len == 0 or std.mem.eql(u8, s, "all")) return .all;
        if (std.mem.eql(u8, s, "none")) return .none;

        if (s.len >= 2 and s[s.len - 1] == '%') {
            const pct = std.fmt.parseInt(u8, s[0 .. s.len - 1], 10) catch return .all;
            if (pct > 100) return .all;
            return .{ .percentage = pct };
        }

        if (s.len >= 3 and s[s.len - 2] == '/') {
            const rate = std.fmt.parseInt(u32, s[0 .. s.len - 2], 10) catch return .all;
            return switch (s[s.len - 1]) {
                's' => .{ .per_second = rate },
                'm' => .{ .per_minute = rate },
                else => .all,
            };
        }
        return .all;
    }

    pub fn isMoreRestrictiveThan(self: KeepValue, other: KeepValue) bool {
        const self_rank = self.restrictiveness();
        const other_rank = other.restrictiveness();
        if (self_rank != other_rank) return self_rank < other_rank;
        return switch (self) {
            .percentage => |p| switch (other) {
                .percentage => |op| p < op,
                else => false,
            },
            else => false,
        };
    }

    fn restrictiveness(self: KeepValue) u8 {
        // Lower rank = more restrictive
        // none: drop everything (most restrictive)
        // rate limit: keep up to N per time unit
        // percentage: keep N% of data
        // all: keep everything (least restrictive)
        return switch (self) {
            .none => 0,
            .per_second, .per_minute => 1,
            .percentage => 2,
            .all => 3,
        };
    }
};

// =============================================================================
// PolicyInfo - Policy metadata for match aggregation
// =============================================================================

/// Policy information needed for match aggregation and action determination.
/// No telemetry_type field - that's implicit in the index type.
pub const PolicyInfo = struct {
    id: []const u8,
    index: PolicyIndex,
    required_match_count: u16,
    negated_count: u16,
    keep: KeepValue,
    enabled: bool,
    /// Rate limiter for per_second/per_minute policies. Null for other keep types.
    /// Pointer because RateLimiter contains atomics that need stable addresses.
    rate_limiter: ?*RateLimiter,
};

// =============================================================================
// PatternMeta - Metadata for each pattern in a database
// =============================================================================

const PatternMeta = struct {
    policy_index: PolicyIndex,
};

const PatternCollector = struct {
    policy_index: PolicyIndex,
    regex: []const u8,
};

// =============================================================================
// ScanResult - Result of scanning a value
// =============================================================================

pub const ScanResult = struct {
    count: usize,
    buf: []u32,

    pub fn matches(self: ScanResult) []const u32 {
        return self.buf[0..self.count];
    }
};

// =============================================================================
// MatcherDatabase - Compiled Hyperscan DBs for one MatcherKey
// =============================================================================

pub const MatcherDatabase = struct {
    positive_db: ?hyperscan.Database,
    negated_db: ?hyperscan.Database,
    scratch: ?hyperscan.Scratch,
    mutex: std.Thread.Mutex,
    positive_patterns: []const PatternMeta,
    negated_patterns: []const PatternMeta,
    allocator: std.mem.Allocator,
    bus: *EventBus,

    const Self = @This();

    pub fn scanPositive(self: *Self, value: []const u8, result_buf: []u32) ScanResult {
        return self.scanDb(self.positive_db, self.positive_patterns, value, result_buf, false);
    }

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
                    self.bus.debug(ScanMatchDetail{ .pattern_id = pattern_id, .policy_index = patterns[pattern_id].policy_index });
                }
            }
        }
        return result;
    }

    fn scanCallback(ctx: *ScanResult, match: hyperscan.Match) bool {
        if (ctx.count < ctx.buf.len) {
            // Deduplicate: only store each pattern ID once
            // (Hyperscan calls back multiple times for different match positions)
            for (ctx.buf[0..ctx.count]) |existing_id| {
                if (existing_id == match.id) {
                    return true; // Already recorded, skip
                }
            }
            ctx.buf[ctx.count] = match.id;
            ctx.count += 1;
            return true;
        }
        return false;
    }

    pub fn deinit(self: *Self) void {
        if (self.scratch) |*s| s.deinit();
        if (self.positive_db) |*db| db.deinit();
        if (self.negated_db) |*db| db.deinit();
        self.allocator.free(self.positive_patterns);
        self.allocator.free(self.negated_patterns);
    }
};

// =============================================================================
// Comptime Type Helpers
// =============================================================================

/// Returns the MatcherKey type for a given telemetry type
pub fn MatcherKeyType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherKey,
        .metric => MetricMatcherKey,
    };
}

/// Returns the FieldRef type for a given telemetry type
pub fn FieldRefType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => FieldRef,
        .metric => MetricFieldRef,
    };
}

/// Returns the Matcher type for a given telemetry type
fn MatcherType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcher,
        .metric => MetricMatcher,
    };
}

/// Returns the Target type for a given telemetry type
fn TargetType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogTarget,
        .metric => MetricTarget,
    };
}

/// Returns the HashContext type for a given telemetry type
fn HashContextType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherKeyContext,
        .metric => MetricMatcherKeyContext,
    };
}

/// Returns the MatcherIndex type for a given telemetry type
pub fn MatcherIndexType(comptime T: TelemetryType) type {
    return switch (T) {
        .log => LogMatcherIndex,
        .metric => MetricMatcherIndex,
    };
}

// =============================================================================
// PatternsPerKey - Collected patterns before compilation
// =============================================================================

const PatternsPerKey = struct {
    positive: std.ArrayListUnmanaged(PatternCollector),
    negated: std.ArrayListUnmanaged(PatternCollector),
};

// =============================================================================
// IndexBuilder - Generic builder for type-specific indices
// =============================================================================

fn IndexBuilder(comptime T: TelemetryType) type {
    const MatcherKeyT = MatcherKeyType(T);
    const FieldRefT = FieldRefType(T);
    const MatcherT = MatcherType(T);
    const TargetT = TargetType(T);
    const HashContextT = HashContextType(T);
    const IndexT = MatcherIndexType(T);

    return struct {
        allocator: std.mem.Allocator,
        temp_allocator: std.mem.Allocator,
        bus: *EventBus,
        patterns_by_key: std.HashMap(MatcherKeyT, PatternsPerKey, HashContextT, std.hash_map.default_max_load_percentage),
        policy_info_list: std.ArrayListUnmanaged(PolicyInfo),
        key_storage: std.ArrayListUnmanaged([]const u8),
        policy_id_storage: std.ArrayListUnmanaged([]const u8),
        policy_index: PolicyIndex,
        current_positive_count: u16,
        current_negated_count: u16,

        const Self = @This();

        fn init(allocator: std.mem.Allocator, temp_allocator: std.mem.Allocator, bus: *EventBus) Self {
            return .{
                .allocator = allocator,
                .temp_allocator = temp_allocator,
                .bus = bus,
                .patterns_by_key = std.HashMap(MatcherKeyT, PatternsPerKey, HashContextT, std.hash_map.default_max_load_percentage).init(temp_allocator),
                .policy_info_list = .{},
                .key_storage = .{},
                .policy_id_storage = .{},
                .policy_index = 0,
                .current_positive_count = 0,
                .current_negated_count = 0,
            };
        }

        fn processPolicy(self: *Self, policy: *const Policy) !void {
            const target = getTarget(policy) orelse {
                self.bus.debug(SkippingPolicyWrongType{ .id = policy.id });
                return;
            };

            self.bus.debug(ProcessingPolicy{
                .id = policy.id,
                .name = policy.name,
                .enabled = policy.enabled,
                .index = self.policy_index,
                .telemetry_type = T,
            });

            self.current_positive_count = 0;
            self.current_negated_count = 0;

            self.bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = target.match.items.len });

            for (target.match.items, 0..) |matcher, matcher_idx| {
                try self.processMatcher(&matcher, matcher_idx);
            }

            const keep_value = parseKeepValue(target);
            try self.storePolicyInfo(policy, keep_value);
        }

        fn getTarget(policy: *const Policy) ?*const TargetT {
            const target_ptr = &(policy.target orelse return null);
            return switch (T) {
                .log => switch (target_ptr.*) {
                    .log => |*log| log,
                    .metric => null,
                },
                .metric => switch (target_ptr.*) {
                    .metric => |*metric| metric,
                    .log => null,
                },
            };
        }

        fn parseKeepValue(target: *const TargetT) KeepValue {
            return switch (T) {
                .log => KeepValue.parse(target.keep),
                .metric => if (target.keep) .all else .none,
            };
        }

        fn processMatcher(self: *Self, matcher: *const MatcherT, matcher_idx: usize) !void {
            const field_ref = getFieldRef(matcher) orelse {
                self.bus.debug(MatcherNullField{ .matcher_idx = matcher_idx });
                return;
            };

            const regex = self.extractRegex(matcher.match, matcher_idx) orelse return;

            self.bus.debug(MatcherDetail{
                .matcher_idx = matcher_idx,
                .regex = regex,
                .negate = matcher.negate,
            });

            const matcher_key = MatcherKeyT{ .field = field_ref };
            try self.addPattern(matcher_key, regex, matcher.negate, field_ref);
        }

        fn getFieldRef(matcher: *const MatcherT) ?FieldRefT {
            return switch (T) {
                .log => FieldRef.fromMatcherField(matcher.field),
                .metric => MetricFieldRef.fromMatcherField(matcher.field),
            };
        }

        /// Pattern that matches any non-empty string (used for exists matching)
        const EXISTS_PATTERN = "^.+$";

        fn extractRegex(self: *Self, match_union: anytype, matcher_idx: usize) ?[]const u8 {
            const m = match_union orelse {
                self.bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
                return null;
            };
            const regex: []const u8 = switch (m) {
                .regex => |r| r,
                .exact => |e| e,
                .exists => |exists| if (exists) EXISTS_PATTERN else return null,
            };
            if (regex.len == 0) {
                self.bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
                return null;
            }
            return regex;
        }

        fn addPattern(self: *Self, key: MatcherKeyT, regex: []const u8, negate: bool, field_ref: FieldRefT) !void {
            if (negate) {
                self.current_negated_count += 1;
            } else {
                self.current_positive_count += 1;
            }

            const gop = try self.patterns_by_key.getOrPut(key);
            if (!gop.found_existing) {
                try self.dupeKeyIfNeeded(gop.key_ptr, field_ref);
                gop.value_ptr.* = .{ .positive = .{}, .negated = .{} };
            }

            const collector = PatternCollector{ .policy_index = self.policy_index, .regex = regex };
            if (negate) {
                try gop.value_ptr.negated.append(self.temp_allocator, collector);
            } else {
                try gop.value_ptr.positive.append(self.temp_allocator, collector);
            }
        }

        fn dupeKeyIfNeeded(self: *Self, key_ptr: *MatcherKeyT, field_ref: FieldRefT) !void {
            const attr_key = field_ref.getKey();
            if (attr_key.len == 0) return;

            const key_copy = try self.allocator.dupe(u8, attr_key);
            try self.key_storage.append(self.allocator, key_copy);

            // Update the key's field to point to the duped key
            key_ptr.field = dupeFieldRef(FieldRefT, field_ref, key_copy);
        }

        fn dupeFieldRef(comptime FieldRefTT: type, field_ref: FieldRefTT, key_copy: []const u8) FieldRefTT {
            switch (T) {
                .log => return switch (field_ref) {
                    .log_attribute => .{ .log_attribute = key_copy },
                    .resource_attribute => .{ .resource_attribute = key_copy },
                    .scope_attribute => .{ .scope_attribute = key_copy },
                    .log_field => field_ref,
                },
                .metric => return switch (field_ref) {
                    .datapoint_attribute => .{ .datapoint_attribute = key_copy },
                    .resource_attribute => .{ .resource_attribute = key_copy },
                    .scope_attribute => .{ .scope_attribute = key_copy },
                    .metric_field, .metric_type, .aggregation_temporality => field_ref,
                },
            }
        }

        fn storePolicyInfo(self: *Self, policy: *const Policy, keep: KeepValue) !void {
            const policy_id_copy = try self.allocator.dupe(u8, policy.id);
            try self.policy_id_storage.append(self.allocator, policy_id_copy);

            // Create rate limiter for rate limit policies
            const rate_limiter: ?*RateLimiter = switch (keep) {
                .per_second => |limit| blk: {
                    const rl = try self.allocator.create(RateLimiter);
                    rl.* = RateLimiter.initPerSecond(limit);
                    break :blk rl;
                },
                .per_minute => |limit| blk: {
                    const rl = try self.allocator.create(RateLimiter);
                    rl.* = RateLimiter.initPerMinute(limit);
                    break :blk rl;
                },
                else => null,
            };

            try self.policy_info_list.append(self.temp_allocator, .{
                .id = policy_id_copy,
                .index = self.policy_index,
                .required_match_count = self.current_positive_count + self.current_negated_count,
                .negated_count = self.current_negated_count,
                .keep = keep,
                .enabled = policy.enabled,
                .rate_limiter = rate_limiter,
            });

            self.bus.debug(PolicyStored{
                .id = policy.id,
                .index = self.policy_index,
                .required_matches = self.current_positive_count,
                .negated_count = self.current_negated_count,
            });

            self.policy_index += 1;
        }

        fn finish(self: *Self) !IndexT {
            const policies = try self.allocator.dupe(PolicyInfo, self.policy_info_list.items);

            var negation_indices = std.ArrayListUnmanaged(PolicyIndex){};
            for (policies) |p| {
                if (p.negated_count > 0) {
                    try negation_indices.append(self.temp_allocator, p.index);
                }
            }
            const policies_with_negation = try self.allocator.dupe(PolicyIndex, negation_indices.items);

            var databases = std.HashMap(MatcherKeyT, *MatcherDatabase, HashContextT, std.hash_map.default_max_load_percentage).init(self.allocator);
            var keys_list = std.ArrayListUnmanaged(MatcherKeyT){};

            var key_it = self.patterns_by_key.iterator();
            while (key_it.next()) |entry| {
                const matcher_key = entry.key_ptr.*;
                const patterns = entry.value_ptr.*;

                if (patterns.positive.items.len == 0 and patterns.negated.items.len == 0) continue;

                const db = try compileDatabase(self.allocator, self.bus, patterns.positive.items, patterns.negated.items);
                try databases.put(matcher_key, db);
                try keys_list.append(self.temp_allocator, matcher_key);
            }

            const matcher_keys = try self.allocator.dupe(MatcherKeyT, keys_list.items);

            return IndexT{
                .allocator = self.allocator,
                .databases = databases,
                .policies = policies,
                .policies_with_negation = policies_with_negation,
                .matcher_keys = matcher_keys,
                .key_storage = self.key_storage,
                .policy_id_storage = self.policy_id_storage,
                .bus = self.bus,
            };
        }
    };
}

// =============================================================================
// LogMatcherIndex - Index for log policies only
// =============================================================================

pub const LogMatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(LogMatcherKey, *MatcherDatabase, LogMatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []LogMatcherKey,
    key_storage: std.ArrayListUnmanaged([]const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len, .telemetry_type = .log });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = IndexBuilder(.log).init(allocator, arena.allocator(), bus);

        for (policies_slice) |*policy| {
            try builder.processPolicy(policy);
        }

        var index = try builder.finish();

        span.completed(MatcherIndexBuildCompleted{
            .database_count = index.databases.count(),
            .matcher_key_count = index.matcher_keys.len,
            .policy_count = index.policies.len,
        });

        return index;
    }

    pub fn getDatabase(self: *const Self, key: LogMatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    pub fn getMatcherKeys(self: *const Self) []const LogMatcherKey {
        return self.matcher_keys;
    }

    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    pub fn getPoliciesWithNegation(self: *const Self) []const PolicyIndex {
        return self.policies_with_negation;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.databases.count() == 0;
    }

    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        // Free rate limiters
        for (self.policies) |policy_info| {
            if (policy_info.rate_limiter) |rl| {
                self.allocator.destroy(rl);
            }
        }
        self.allocator.free(self.policies);
        self.allocator.free(self.policies_with_negation);
        self.allocator.free(self.matcher_keys);

        for (self.key_storage.items) |key| {
            self.allocator.free(key);
        }
        self.key_storage.deinit(self.allocator);

        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// MetricMatcherIndex - Index for metric policies only
// =============================================================================

pub const MetricMatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(MetricMatcherKey, *MatcherDatabase, MetricMatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []MetricMatcherKey,
    key_storage: std.ArrayListUnmanaged([]const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len, .telemetry_type = .metric });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = IndexBuilder(.metric).init(allocator, arena.allocator(), bus);

        for (policies_slice) |*policy| {
            try builder.processPolicy(policy);
        }

        var index = try builder.finish();

        span.completed(MatcherIndexBuildCompleted{
            .database_count = index.databases.count(),
            .matcher_key_count = index.matcher_keys.len,
            .policy_count = index.policies.len,
        });

        return index;
    }

    pub fn getDatabase(self: *const Self, key: MetricMatcherKey) ?*MatcherDatabase {
        return self.databases.get(key);
    }

    pub fn getPolicyByIndex(self: *const Self, index: PolicyIndex) ?PolicyInfo {
        if (index >= self.policies.len) return null;
        return self.policies[index];
    }

    pub fn getPolicy(self: *const Self, id: []const u8) ?PolicyInfo {
        for (self.policies) |info| {
            if (std.mem.eql(u8, info.id, id)) return info;
        }
        return null;
    }

    pub fn getMatcherKeys(self: *const Self) []const MetricMatcherKey {
        return self.matcher_keys;
    }

    pub fn getPolicies(self: *const Self) []const PolicyInfo {
        return self.policies;
    }

    pub fn getPoliciesWithNegation(self: *const Self) []const PolicyIndex {
        return self.policies_with_negation;
    }

    pub fn isEmpty(self: *const Self) bool {
        return self.databases.count() == 0;
    }

    pub fn getDatabaseCount(self: *const Self) usize {
        return self.databases.count();
    }

    pub fn getPolicyCount(self: *const Self) usize {
        return self.policies.len;
    }

    pub fn deinit(self: *Self) void {
        var db_it = self.databases.valueIterator();
        while (db_it.next()) |db| {
            db.*.deinit();
            self.allocator.destroy(db.*);
        }
        self.databases.deinit();

        // Free rate limiters
        for (self.policies) |policy_info| {
            if (policy_info.rate_limiter) |rl| {
                self.allocator.destroy(rl);
            }
        }
        self.allocator.free(self.policies);
        self.allocator.free(self.policies_with_negation);
        self.allocator.free(self.matcher_keys);

        for (self.key_storage.items) |key| {
            self.allocator.free(key);
        }
        self.key_storage.deinit(self.allocator);

        for (self.policy_id_storage.items) |id| {
            self.allocator.free(id);
        }
        self.policy_id_storage.deinit(self.allocator);
    }
};

// =============================================================================
// Database Compilation
// =============================================================================

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

    var positive_patterns: []PatternMeta = &.{};
    if (positive_collectors.len > 0) {
        const result = try compilePatterns(allocator, positive_collectors);
        positive_db = result.db;
        positive_patterns = result.meta;
    }

    var negated_patterns: []PatternMeta = &.{};
    if (negated_collectors.len > 0) {
        const result = try compilePatterns(allocator, negated_collectors);
        negated_db = result.db;
        negated_patterns = result.meta;
    }

    if (positive_db) |*db| {
        scratch = try hyperscan.Scratch.init(db);
        if (negated_db) |*ndb| {
            _ = try hyperscan.Scratch.init(ndb);
        }
    } else if (negated_db) |*db| {
        scratch = try hyperscan.Scratch.init(db);
    }

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

fn compilePatterns(allocator: std.mem.Allocator, collectors: []const PatternCollector) !struct { db: hyperscan.Database, meta: []PatternMeta } {
    const hs_patterns = try allocator.alloc(hyperscan.Pattern, collectors.len);
    defer allocator.free(hs_patterns);

    const meta = try allocator.alloc(PatternMeta, collectors.len);
    errdefer allocator.free(meta);

    for (collectors, 0..) |collector, i| {
        hs_patterns[i] = .{ .expression = collector.regex, .id = @intCast(i), .flags = .{} };
        meta[i] = .{ .policy_index = collector.policy_index };
    }

    const db = try hyperscan.Database.compileMulti(allocator, hs_patterns, .{});
    return .{ .db = db, .meta = meta };
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "LogMatcherKey: hash and equality" {
    const key1 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const key2 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const key3 = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT } };
    const key4 = LogMatcherKey{ .field = .{ .log_attribute = "service" } };
    const key5 = LogMatcherKey{ .field = .{ .log_attribute = "service" } };
    const key6 = LogMatcherKey{ .field = .{ .log_attribute = "env" } };

    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());
}

test "MetricMatcherKey: hash and equality" {
    const key1 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_NAME } };
    const key2 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_NAME } };
    const key3 = MetricMatcherKey{ .field = .{ .metric_field = .METRIC_FIELD_UNIT } };
    const key4 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "status" } };
    const key5 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "status" } };
    const key6 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "env" } };

    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());
}

test "FieldRef: isKeyed" {
    const log_field = FieldRef{ .log_field = .LOG_FIELD_BODY };
    const log_attr = FieldRef{ .log_attribute = "service" };
    const resource_attr = FieldRef{ .resource_attribute = "env" };

    try testing.expect(!log_field.isKeyed());
    try testing.expect(log_attr.isKeyed());
    try testing.expect(resource_attr.isKeyed());
}

test "KeepValue: parse" {
    try testing.expectEqual(KeepValue.all, KeepValue.parse(""));
    try testing.expectEqual(KeepValue.all, KeepValue.parse("all"));
    try testing.expectEqual(KeepValue.none, KeepValue.parse("none"));
    try testing.expectEqual(KeepValue{ .percentage = 50 }, KeepValue.parse("50%"));
    try testing.expectEqual(KeepValue{ .per_second = 100 }, KeepValue.parse("100/s"));
    try testing.expectEqual(KeepValue{ .per_minute = 1000 }, KeepValue.parse("1000/m"));
}

test "KeepValue: restrictiveness comparison" {
    const all: KeepValue = .all;
    const none: KeepValue = .none;
    const pct50: KeepValue = .{ .percentage = 50 };
    const pct25: KeepValue = .{ .percentage = 25 };
    const rate: KeepValue = .{ .per_second = 100 };

    try testing.expect(none.isMoreRestrictiveThan(all));
    try testing.expect(none.isMoreRestrictiveThan(pct50));
    try testing.expect(pct50.isMoreRestrictiveThan(all));
    try testing.expect(pct25.isMoreRestrictiveThan(pct50));
    try testing.expect(!all.isMoreRestrictiveThan(rate));
}

test "LogMatcherIndex: build empty" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getPolicyCount());
}

test "MetricMatcherIndex: build empty" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{});
    defer index.deinit();

    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 0), index.getPolicyCount());
}

test "LogMatcherIndex: build with single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    const policy_info_by_id = index.getPolicy("policy-1");
    try testing.expect(policy_info_by_id != null);
    try testing.expectEqualStrings("policy-1", policy_info_by_id.?.id);
}

test "MetricMatcherIndex: build with single policy" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric-policy"),
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

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
}

test "LogMatcherIndex: build with keyed matchers" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment-api") },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const expected_key = LogMatcherKey{ .field = .{ .log_attribute = "service" } };
    const db = index.getDatabase(expected_key);
    try testing.expect(db != null);
}

test "LogMatcherIndex: negated matcher creates negated database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const expected_key = LogMatcherKey{ .field = .{ .log_field = .LOG_FIELD_BODY } };
    const db = index.getDatabase(expected_key);
    try testing.expect(db != null);
    try testing.expect(db.?.negated_db != null);
    try testing.expect(db.?.positive_db == null);
}

test "LogMatcherIndex: scan database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
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

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    const db = index.getDatabase(.{ .field = .{ .log_field = .LOG_FIELD_BODY } });
    try testing.expect(db != null);

    var result_buf: [256]u32 = undefined;

    const match_result = db.?.scanPositive("an error occurred", &result_buf);
    try testing.expectEqual(@as(usize, 1), match_result.count);
    try testing.expectEqual(@as(u32, 0), match_result.matches()[0]);

    const no_match_result = db.?.scanPositive("everything is fine", &result_buf);
    try testing.expectEqual(@as(usize, 0), no_match_result.count);
}

test "LogMatcherIndex: exists=true matcher uses ^.+$ pattern" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "trace_id") },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists=true should create a database with ^.+$ pattern
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // The database should match any non-empty string
    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);

    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;
    var result = db.scanPositive("some-trace-id-value", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Empty string should not match
    result = db.scanPositive("", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "LogMatcherIndex: exists=false matcher is excluded" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "trace_id") },
        .match = .{ .exists = false },
    });
    defer policy.deinit(allocator);

    var index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists=false should not create any database entries
    try testing.expect(index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());
}

test "MetricMatcherIndex: exists=true matcher uses ^.+$ pattern" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .resource_attribute = try allocator.dupe(u8, "service.name") },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // exists=true should create a database with ^.+$ pattern
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // The database should match any non-empty string
    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);

    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;
    var result = db.scanPositive("my-service", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Empty string should not match
    result = db.scanPositive("", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "MetricMatcherIndex: metric_type field creates Hyperscan database" {
    // metric_type is matched as a string via Hyperscan. The field accessor returns
    // the type as a string (e.g., "gauge", "sum", "histogram") which is then matched
    // against the regex pattern.
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    const MetricType = proto.policy.MetricType;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-gauge-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match on metric_type with exists=true (uses ^.+$ pattern)
    // The proto field uses the enum value, but we only care that it's metric_type
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = MetricType.METRIC_TYPE_GAUGE },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    // metric_type field should create a database with ^.+$ pattern
    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    // The policy should have 1 required match
    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    // The database should match metric type strings
    const keys = index.getMatcherKeys();
    try testing.expectEqual(@as(usize, 1), keys.len);

    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;

    // Should match any non-empty metric type string
    var result = db.scanPositive("gauge", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("histogram", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Empty string should not match
    result = db.scanPositive("", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "MetricMatcherIndex: metric_type with regex pattern" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    const MetricType = proto.policy.MetricType;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-gauge-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match on metric_type with regex pattern for "gauge"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = MetricType.METRIC_TYPE_GAUGE },
        .match = .{ .exact = try allocator.dupe(u8, "gauge") },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());

    const keys = index.getMatcherKeys();
    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;

    // Should match "gauge"
    var result = db.scanPositive("gauge", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should NOT match other types
    result = db.scanPositive("histogram", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("sum", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "MetricMatcherIndex: aggregation_temporality field creates Hyperscan database" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    const AggregationTemporality = proto.policy.AggregationTemporality;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "match-delta-metrics"),
        .enabled = true,
        .target = .{ .metric = .{
            .keep = false,
        } },
    };
    // Match on aggregation_temporality with regex for "delta"
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .aggregation_temporality = AggregationTemporality.AGGREGATION_TEMPORALITY_DELTA },
        .match = .{ .exact = try allocator.dupe(u8, "delta") },
    });
    defer policy.deinit(allocator);

    var index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicy("policy-1");
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);

    const keys = index.getMatcherKeys();
    const db = index.getDatabase(keys[0]).?;
    var result_buf: [MAX_POLICIES]u32 = undefined;

    // Should match "delta"
    var result = db.scanPositive("delta", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    // Should NOT match "cumulative"
    result = db.scanPositive("cumulative", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);
}

test "Mixed log and metric policies: each index only gets its type" {
    const allocator = testing.allocator;
    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();

    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy-1"),
        .name = try allocator.dupe(u8, "test-log"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
        } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric"),
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

    const policies = &[_]Policy{ log_policy, metric_policy };

    // Log index should only have log policy
    var log_index = try LogMatcherIndex.build(allocator, noop_bus.eventBus(), policies);
    defer log_index.deinit();
    try testing.expectEqual(@as(usize, 1), log_index.getPolicyCount());
    try testing.expectEqual(@as(usize, 1), log_index.getDatabaseCount());

    const log_info = log_index.getPolicy("log-policy-1");
    try testing.expect(log_info != null);

    const metric_in_log = log_index.getPolicy("metric-policy-1");
    try testing.expect(metric_in_log == null);

    // Metric index should only have metric policy
    var metric_index = try MetricMatcherIndex.build(allocator, noop_bus.eventBus(), policies);
    defer metric_index.deinit();
    try testing.expectEqual(@as(usize, 1), metric_index.getPolicyCount());
    try testing.expectEqual(@as(usize, 1), metric_index.getDatabaseCount());

    const metric_info = metric_index.getPolicy("metric-policy-1");
    try testing.expect(metric_info != null);

    const log_in_metric = metric_index.getPolicy("log-policy-1");
    try testing.expect(log_in_metric == null);
}
