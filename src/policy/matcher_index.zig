//! Matcher Index - Inverted index for efficient policy matching
//!
//! This module compiles policies into Hyperscan databases indexed by MatcherKey.
//! At evaluation time, we scan each field value against its corresponding database
//! and aggregate matches to determine which policies fully match.
//!
//! ## Architecture
//!
//! 1. **MatcherKey**: Tagged union of LogMatcherKey/MetricMatcherKey for hash map indexing
//! 2. **MatcherDatabase**: Compiled Hyperscan DBs for one MatcherKey (positive + negated)
//! 3. **MatcherIndex**: Collection of all databases + policy metadata for match aggregation
//! 4. **Builder**: Internal helper for constructing MatcherIndex from policies
//!
//! ## Performance Optimizations
//!
//! - **Numeric policy indices**: O(1) array lookups instead of string hash lookups
//! - **Separate positive/negated databases**: Clean separation, no per-pattern negate flag
//! - **Dense policy array**: Cache-friendly iteration over matched policies

const std = @import("std");
const proto = @import("proto");
const hyperscan = @import("../hyperscan/hyperscan.zig");
const policy_types = @import("./types.zig");
const policy_engine = @import("./policy_engine.zig");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const FieldRef = policy_types.FieldRef;
const MetricFieldRef = policy_types.MetricFieldRef;
const TelemetryType = policy_types.TelemetryType;

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

const MatcherIndexBuildStarted = struct { policy_count: usize };
const MatcherIndexBuildCompleted = struct { database_count: usize, matcher_key_count: usize, policy_count: usize };
const ScanMatched = struct { pattern_count: usize, value_len: usize, value_preview: []const u8, is_negated: bool };
const ScanMatchDetail = struct { pattern_id: u32, policy_index: PolicyIndex };
const ScanError = struct { err: []const u8 };
const ProcessingPolicy = struct { id: []const u8, name: []const u8, enabled: bool, index: PolicyIndex, telemetry_type: TelemetryType };
const SkippingPolicyNoTarget = struct { id: []const u8 };
const PolicyMatcherCount = struct { id: []const u8, matcher_count: usize };
const MatcherNullField = struct { matcher_idx: usize };
const MatcherNullMatch = struct { matcher_idx: usize };
const MatcherEmptyRegex = struct { matcher_idx: usize };
const LogMatcherDetail = struct { matcher_idx: usize, field: FieldRef, regex: []const u8, negate: bool };
const MetricMatcherDetail = struct { matcher_idx: usize, field: MetricFieldRef, regex: []const u8, negate: bool };
const PolicyStored = struct { id: []const u8, index: PolicyIndex, required_matches: u16, negated_count: u16 };
const CompilingDatabase = struct { key: MatcherKey, positive_count: usize, negated_count: usize };

// =============================================================================
// Policy Index - Numeric identifier for O(1) lookups
// =============================================================================

/// Numeric policy index for efficient array-based lookups at runtime.
pub const PolicyIndex = u16;

/// Maximum number of policies supported
pub const MAX_POLICIES: usize = 4096;

// =============================================================================
// MatcherKey Types
// =============================================================================

/// Key for indexing Hyperscan databases for log policies.
pub const LogMatcherKey = struct {
    field: FieldRef,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        var h = std.hash.Wyhash.init(0);
        switch (self.field) {
            .log_field => |lf| h.update(std.mem.asBytes(&lf)),
            .log_attribute => |k| {
                h.update(&.{0});
                h.update(k);
            },
            .resource_attribute => |k| {
                h.update(&.{1});
                h.update(k);
            },
            .scope_attribute => |k| {
                h.update(&.{2});
                h.update(k);
            },
        }
        return h.final();
    }

    pub fn eql(a: Self, b: Self) bool {
        return switch (a.field) {
            .log_field => |lf_a| switch (b.field) {
                .log_field => |lf_b| lf_a == lf_b,
                else => false,
            },
            .log_attribute => |k_a| switch (b.field) {
                .log_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
            .resource_attribute => |k_a| switch (b.field) {
                .resource_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
            .scope_attribute => |k_a| switch (b.field) {
                .scope_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
        };
    }
};

/// Key for indexing Hyperscan databases for metric policies.
pub const MetricMatcherKey = struct {
    field: MetricFieldRef,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        var h = std.hash.Wyhash.init(0);
        switch (self.field) {
            .metric_field => |mf| h.update(std.mem.asBytes(&mf)),
            .datapoint_attribute => |k| {
                h.update(&.{0});
                h.update(k);
            },
            .resource_attribute => |k| {
                h.update(&.{1});
                h.update(k);
            },
            .scope_attribute => |k| {
                h.update(&.{2});
                h.update(k);
            },
        }
        return h.final();
    }

    pub fn eql(a: Self, b: Self) bool {
        return switch (a.field) {
            .metric_field => |mf_a| switch (b.field) {
                .metric_field => |mf_b| mf_a == mf_b,
                else => false,
            },
            .datapoint_attribute => |k_a| switch (b.field) {
                .datapoint_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
            .resource_attribute => |k_a| switch (b.field) {
                .resource_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
            .scope_attribute => |k_a| switch (b.field) {
                .scope_attribute => |k_b| std.mem.eql(u8, k_a, k_b),
                else => false,
            },
        };
    }
};

/// Unified key for indexing Hyperscan databases.
pub const MatcherKey = union(enum) {
    log: LogMatcherKey,
    metric: MetricMatcherKey,

    const Self = @This();

    pub fn hash(self: Self) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(std.mem.asBytes(&@intFromEnum(self)));
        return switch (self) {
            .log => |k| h.final() ^ k.hash(),
            .metric => |k| h.final() ^ k.hash(),
        };
    }

    pub fn eql(a: Self, b: Self) bool {
        return switch (a) {
            .log => |ka| switch (b) {
                .log => |kb| ka.eql(kb),
                .metric => false,
            },
            .metric => |ka| switch (b) {
                .metric => |kb| ka.eql(kb),
                .log => false,
            },
        };
    }

    pub fn telemetryType(self: Self) TelemetryType {
        return switch (self) {
            .log => .log,
            .metric => .metric,
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
// KeepValue - Parsed keep configuration
// =============================================================================

/// Parsed keep value from policy.
/// Priority order (most restrictive first): none > percentage > all > rate_limit
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
        return switch (self) {
            .none => 0,
            .percentage => 1,
            .all => 2,
            .per_second, .per_minute => 3,
        };
    }
};

// =============================================================================
// PolicyInfo - Policy metadata for match aggregation
// =============================================================================

/// Policy information needed for match aggregation and action determination.
pub const PolicyInfo = struct {
    id: []const u8,
    index: PolicyIndex,
    required_match_count: u16,
    negated_count: u16,
    keep: KeepValue,
    enabled: bool,
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
// Builder - Internal helper for constructing MatcherIndex
// =============================================================================

const PatternsPerKey = struct {
    positive: std.ArrayListUnmanaged(PatternCollector),
    negated: std.ArrayListUnmanaged(PatternCollector),
};

const Builder = struct {
    // Permanent allocator (for final output)
    allocator: std.mem.Allocator,
    // Temporary allocator (arena, freed after build)
    temp_allocator: std.mem.Allocator,
    // Event bus
    bus: *EventBus,
    // Pattern collection per key
    patterns_by_key: std.HashMap(MatcherKey, PatternsPerKey, MatcherKeyContext, std.hash_map.default_max_load_percentage),
    // Policy info list
    policy_info_list: std.ArrayListUnmanaged(PolicyInfo),
    // Storage for duped attribute keys
    key_storage: std.ArrayListUnmanaged([]const u8),
    // Storage for duped policy IDs
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    // Current policy index
    policy_index: PolicyIndex,
    // Track positive/negated counts for current policy
    current_positive_count: u16,
    current_negated_count: u16,

    const Self = @This();

    fn init(allocator: std.mem.Allocator, temp_allocator: std.mem.Allocator, bus: *EventBus) Self {
        return .{
            .allocator = allocator,
            .temp_allocator = temp_allocator,
            .bus = bus,
            .patterns_by_key = std.HashMap(MatcherKey, PatternsPerKey, MatcherKeyContext, std.hash_map.default_max_load_percentage).init(temp_allocator),
            .policy_info_list = .{},
            .key_storage = .{},
            .policy_id_storage = .{},
            .policy_index = 0,
            .current_positive_count = 0,
            .current_negated_count = 0,
        };
    }

    fn processPolicy(self: *Self, policy: *const Policy) !void {
        if (policy_engine.getLogTarget(policy)) |log_target| {
            try self.processLogTarget(policy, log_target);
        } else if (policy_engine.getMetricTarget(policy)) |metric_target| {
            try self.processMetricTarget(policy, metric_target);
        } else {
            self.bus.debug(SkippingPolicyNoTarget{ .id = policy.id });
        }
    }

    fn processLogTarget(self: *Self, policy: *const Policy, log_target: *const LogTarget) !void {
        self.bus.debug(ProcessingPolicy{
            .id = policy.id,
            .name = policy.name,
            .enabled = policy.enabled,
            .index = self.policy_index,
            .telemetry_type = .log,
        });

        self.current_positive_count = 0;
        self.current_negated_count = 0;

        self.bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = log_target.match.items.len });

        for (log_target.match.items, 0..) |matcher, matcher_idx| {
            try self.processLogMatcher(&matcher, matcher_idx);
        }

        try self.storePolicyInfo(policy, KeepValue.parse(log_target.keep));
    }

    fn processLogMatcher(self: *Self, matcher: *const LogMatcher, matcher_idx: usize) !void {
        const field_ref = FieldRef.fromMatcherField(matcher.field) orelse {
            self.bus.debug(MatcherNullField{ .matcher_idx = matcher_idx });
            return;
        };

        const regex = self.extractRegex(matcher.match, matcher_idx) orelse return;

        self.bus.debug(LogMatcherDetail{
            .matcher_idx = matcher_idx,
            .field = field_ref,
            .regex = regex,
            .negate = matcher.negate,
        });

        const matcher_key = MatcherKey{ .log = .{ .field = field_ref } };
        try self.addPattern(matcher_key, regex, matcher.negate, .{ .log_field_ref = field_ref });
    }

    fn processMetricTarget(self: *Self, policy: *const Policy, metric_target: *const MetricTarget) !void {
        self.bus.debug(ProcessingPolicy{
            .id = policy.id,
            .name = policy.name,
            .enabled = policy.enabled,
            .index = self.policy_index,
            .telemetry_type = .metric,
        });

        self.current_positive_count = 0;
        self.current_negated_count = 0;

        self.bus.debug(PolicyMatcherCount{ .id = policy.id, .matcher_count = metric_target.match.items.len });

        for (metric_target.match.items, 0..) |matcher, matcher_idx| {
            try self.processMetricMatcher(&matcher, matcher_idx);
        }

        const keep_value: KeepValue = if (metric_target.keep) .all else .none;
        try self.storePolicyInfo(policy, keep_value);
    }

    fn processMetricMatcher(self: *Self, matcher: *const MetricMatcher, matcher_idx: usize) !void {
        // MetricFieldRef.fromMatcherField returns null for enum matchers (metric_type, aggregation_temporality)
        const field_ref = MetricFieldRef.fromMatcherField(matcher.field) orelse return;

        const regex = self.extractMetricRegex(matcher.match, matcher_idx) orelse return;

        self.bus.debug(MetricMatcherDetail{
            .matcher_idx = matcher_idx,
            .field = field_ref,
            .regex = regex,
            .negate = matcher.negate,
        });

        const matcher_key = MatcherKey{ .metric = .{ .field = field_ref } };
        try self.addPattern(matcher_key, regex, matcher.negate, .{ .metric_field_ref = field_ref });
    }

    const FieldRefContext = union(enum) {
        log_field_ref: FieldRef,
        metric_field_ref: MetricFieldRef,
    };

    fn addPattern(self: *Self, key: MatcherKey, regex: []const u8, negate: bool, field_ctx: FieldRefContext) !void {
        if (negate) {
            self.current_negated_count += 1;
        } else {
            self.current_positive_count += 1;
        }

        const gop = try self.patterns_by_key.getOrPut(key);
        if (!gop.found_existing) {
            // First time seeing this key - dupe attribute key if needed
            try self.dupeKeyIfNeeded(gop.key_ptr, field_ctx);
            gop.value_ptr.* = .{ .positive = .{}, .negated = .{} };
        }

        const collector = PatternCollector{ .policy_index = self.policy_index, .regex = regex };
        if (negate) {
            try gop.value_ptr.negated.append(self.temp_allocator, collector);
        } else {
            try gop.value_ptr.positive.append(self.temp_allocator, collector);
        }
    }

    fn dupeKeyIfNeeded(self: *Self, key_ptr: *MatcherKey, field_ctx: FieldRefContext) !void {
        switch (field_ctx) {
            .log_field_ref => |field_ref| {
                const attr_key = field_ref.getKey();
                if (attr_key.len > 0) {
                    const key_copy = try self.allocator.dupe(u8, attr_key);
                    try self.key_storage.append(self.allocator, key_copy);
                    key_ptr.log.field = switch (field_ref) {
                        .log_attribute => .{ .log_attribute = key_copy },
                        .resource_attribute => .{ .resource_attribute = key_copy },
                        .scope_attribute => .{ .scope_attribute = key_copy },
                        .log_field => field_ref,
                    };
                }
            },
            .metric_field_ref => |field_ref| {
                const attr_key = field_ref.getKey();
                if (attr_key.len > 0) {
                    const key_copy = try self.allocator.dupe(u8, attr_key);
                    try self.key_storage.append(self.allocator, key_copy);
                    key_ptr.metric.field = switch (field_ref) {
                        .datapoint_attribute => .{ .datapoint_attribute = key_copy },
                        .resource_attribute => .{ .resource_attribute = key_copy },
                        .scope_attribute => .{ .scope_attribute = key_copy },
                        .metric_field => field_ref,
                    };
                }
            },
        }
    }

    fn extractRegex(self: *Self, match_union: ?LogMatcher.match_union, matcher_idx: usize) ?[]const u8 {
        const m = match_union orelse {
            self.bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
            return null;
        };
        const regex: []const u8 = switch (m) {
            .regex => |r| r,
            .exact => |e| e,
            .exists => return null,
        };
        if (regex.len == 0) {
            self.bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
            return null;
        }
        return regex;
    }

    fn extractMetricRegex(self: *Self, match_union: ?MetricMatcher.match_union, matcher_idx: usize) ?[]const u8 {
        const m = match_union orelse {
            self.bus.debug(MatcherNullMatch{ .matcher_idx = matcher_idx });
            return null;
        };
        const regex: []const u8 = switch (m) {
            .regex => |r| r,
            .exact => |e| e,
            .exists => return null,
        };
        if (regex.len == 0) {
            self.bus.debug(MatcherEmptyRegex{ .matcher_idx = matcher_idx });
            return null;
        }
        return regex;
    }

    fn storePolicyInfo(self: *Self, policy: *const Policy, keep: KeepValue) !void {
        const policy_id_copy = try self.allocator.dupe(u8, policy.id);
        try self.policy_id_storage.append(self.allocator, policy_id_copy);

        try self.policy_info_list.append(self.temp_allocator, .{
            .id = policy_id_copy,
            .index = self.policy_index,
            .required_match_count = self.current_positive_count + self.current_negated_count,
            .negated_count = self.current_negated_count,
            .keep = keep,
            .enabled = policy.enabled,
        });

        self.bus.debug(PolicyStored{
            .id = policy.id,
            .index = self.policy_index,
            .required_matches = self.current_positive_count,
            .negated_count = self.current_negated_count,
        });

        self.policy_index += 1;
    }

    fn finish(self: *Self) !MatcherIndex {
        // Copy policy info to owned slice
        const policies = try self.allocator.dupe(PolicyInfo, self.policy_info_list.items);

        // Build list of policy indices with negated patterns
        var negation_indices = std.ArrayListUnmanaged(PolicyIndex){};
        for (policies) |p| {
            if (p.negated_count > 0) {
                try negation_indices.append(self.temp_allocator, p.index);
            }
        }
        const policies_with_negation = try self.allocator.dupe(PolicyIndex, negation_indices.items);

        // Compile databases
        var databases = std.HashMap(MatcherKey, *MatcherDatabase, MatcherKeyContext, std.hash_map.default_max_load_percentage).init(self.allocator);
        var keys_list = std.ArrayListUnmanaged(MatcherKey){};

        var key_it = self.patterns_by_key.iterator();
        while (key_it.next()) |entry| {
            const matcher_key = entry.key_ptr.*;
            const patterns = entry.value_ptr.*;

            if (patterns.positive.items.len == 0 and patterns.negated.items.len == 0) continue;

            self.bus.debug(CompilingDatabase{
                .key = matcher_key,
                .positive_count = patterns.positive.items.len,
                .negated_count = patterns.negated.items.len,
            });

            const db = try compileDatabase(self.allocator, self.bus, patterns.positive.items, patterns.negated.items);
            try databases.put(matcher_key, db);
            try keys_list.append(self.temp_allocator, matcher_key);
        }

        const matcher_keys = try self.allocator.dupe(MatcherKey, keys_list.items);

        return MatcherIndex{
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

// =============================================================================
// MatcherIndex - The complete compiled index
// =============================================================================

/// The compiled matcher index containing all databases and policy metadata.
pub const MatcherIndex = struct {
    allocator: std.mem.Allocator,
    databases: std.HashMap(MatcherKey, *MatcherDatabase, MatcherKeyContext, std.hash_map.default_max_load_percentage),
    policies: []PolicyInfo,
    policies_with_negation: []PolicyIndex,
    matcher_keys: []MatcherKey,
    key_storage: std.ArrayListUnmanaged([]const u8),
    policy_id_storage: std.ArrayListUnmanaged([]const u8),
    bus: *EventBus,

    const Self = @This();

    /// Build a MatcherIndex from a slice of policies.
    pub fn build(allocator: std.mem.Allocator, bus: *EventBus, policies_slice: []const Policy) !Self {
        var span = bus.started(.info, MatcherIndexBuildStarted{ .policy_count = policies_slice.len });

        if (policies_slice.len > MAX_POLICIES) {
            return error.TooManyPolicies;
        }

        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var builder = Builder.init(allocator, arena.allocator(), bus);

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

    pub fn getDatabase(self: *const Self, key: MatcherKey) ?*MatcherDatabase {
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

    pub fn getMatcherKeys(self: *const Self) []const MatcherKey {
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
    const key4 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "host" } };
    const key5 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "host" } };
    const key6 = MetricMatcherKey{ .field = .{ .datapoint_attribute = "env" } };

    try testing.expect(key1.eql(key2));
    try testing.expect(key4.eql(key5));
    try testing.expect(!key1.eql(key3));
    try testing.expect(!key4.eql(key6));
    try testing.expectEqual(key1.hash(), key2.hash());
    try testing.expectEqual(key4.hash(), key5.hash());
}

test "MatcherKey: tagged union hash and equality" {
    const log_key1 = MatcherKey{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } };
    const log_key2 = MatcherKey{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } };
    const metric_key1 = MatcherKey{ .metric = .{ .field = .{ .metric_field = .METRIC_FIELD_NAME } } };
    const metric_key2 = MatcherKey{ .metric = .{ .field = .{ .metric_field = .METRIC_FIELD_NAME } } };

    try testing.expect(log_key1.eql(log_key2));
    try testing.expect(metric_key1.eql(metric_key2));
    try testing.expect(!log_key1.eql(metric_key1));
    try testing.expectEqual(log_key1.hash(), log_key2.hash());
    try testing.expectEqual(metric_key1.hash(), metric_key2.hash());
    try testing.expect(log_key1.hash() != metric_key1.hash());
    try testing.expectEqual(TelemetryType.log, log_key1.telemetryType());
    try testing.expectEqual(TelemetryType.metric, metric_key1.telemetryType());
}

test "FieldRef: isKeyed" {
    const log_body: FieldRef = .{ .log_field = .LOG_FIELD_BODY };
    const log_attr: FieldRef = .{ .log_attribute = "service" };
    const res_attr: FieldRef = .{ .resource_attribute = "host" };
    const scope_attr: FieldRef = .{ .scope_attribute = "name" };

    try testing.expect(!log_body.isKeyed());
    try testing.expect(log_attr.isKeyed());
    try testing.expect(res_attr.isKeyed());
    try testing.expect(scope_attr.isKeyed());
}

test "KeepValue: parse" {
    try testing.expectEqual(KeepValue.all, KeepValue.parse("all"));
    try testing.expectEqual(KeepValue.all, KeepValue.parse(""));
    try testing.expectEqual(KeepValue.none, KeepValue.parse("none"));
    try testing.expectEqual(KeepValue{ .percentage = 50 }, KeepValue.parse("50%"));
    try testing.expectEqual(KeepValue{ .percentage = 0 }, KeepValue.parse("0%"));
    try testing.expectEqual(KeepValue{ .percentage = 100 }, KeepValue.parse("100%"));
    try testing.expectEqual(KeepValue{ .per_second = 100 }, KeepValue.parse("100/s"));
    try testing.expectEqual(KeepValue{ .per_minute = 1000 }, KeepValue.parse("1000/m"));
    try testing.expectEqual(KeepValue.all, KeepValue.parse("invalid"));
    try testing.expectEqual(KeepValue.all, KeepValue.parse("101%"));
}

test "KeepValue: restrictiveness comparison" {
    const none: KeepValue = .none;
    const all: KeepValue = .all;
    const pct50: KeepValue = .{ .percentage = 50 };
    const pct10: KeepValue = .{ .percentage = 10 };
    const rate100: KeepValue = .{ .per_second = 100 };

    try testing.expect(none.isMoreRestrictiveThan(all));
    try testing.expect(none.isMoreRestrictiveThan(pct50));
    try testing.expect(pct50.isMoreRestrictiveThan(all));
    try testing.expect(pct10.isMoreRestrictiveThan(pct50));
    try testing.expect(all.isMoreRestrictiveThan(rate100));
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
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
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

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
    try testing.expectEqual(@as(u16, 0), policy_info.?.negated_count);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
    try testing.expect(policy_info.?.enabled);

    const policy_info_by_id = index.getPolicy("policy-1");
    try testing.expect(policy_info_by_id != null);
    try testing.expectEqualStrings("policy-1", policy_info_by_id.?.id);

    const db = index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } });
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
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "service") },
        .match = .{ .regex = try allocator.dupe(u8, "payment") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "env") },
        .match = .{ .regex = try allocator.dupe(u8, "prod") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());
    try testing.expect(index.getDatabase(.{ .log = .{ .field = .{ .log_attribute = "service" } } }) != null);
    try testing.expect(index.getDatabase(.{ .log = .{ .field = .{ .log_attribute = "env" } } }) != null);
    try testing.expect(index.getDatabase(.{ .log = .{ .field = .{ .log_attribute = "other" } } }) == null);
}

test "MatcherIndex: multiple policies same matcher key" {
    const allocator = testing.allocator;

    var policy1 = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "policy-1"),
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
        .name = try allocator.dupe(u8, "policy-2"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all") } },
    };
    try policy2.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy2.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{ policy1, policy2 });
    defer index.deinit();

    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 2), index.getPolicyCount());

    const db = index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } });
    try testing.expect(db != null);
    try testing.expectEqual(@as(usize, 2), db.?.positive_patterns.len);
}

test "MatcherIndex: negated matcher creates negated database" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
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
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
    try testing.expectEqual(@as(u16, 1), policy_info.?.negated_count);

    const db = index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } });
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
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
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
    try testing.expectEqual(@as(u16, 2), policy_info.?.required_match_count);
    try testing.expectEqual(@as(u16, 1), policy_info.?.negated_count);

    const db = index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } });
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
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "warning") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    var db = index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } }).?;

    var result_buf: [16]u32 = undefined;
    var result = db.scanPositive("an error occurred", &result_buf);
    try testing.expectEqual(@as(usize, 1), result.count);

    result = db.scanPositive("all good", &result_buf);
    try testing.expectEqual(@as(usize, 0), result.count);

    result = db.scanPositive("error and warning", &result_buf);
    try testing.expectEqual(@as(usize, 2), result.count);
}

test "MatcherIndex: exists matcher excluded from regex matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "policy-1"),
        .name = try allocator.dupe(u8, "test-policy"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    try policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = try allocator.dupe(u8, "trace_id") },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
}

// =============================================================================
// Metric Policy Tests
// =============================================================================

test "MatcherIndex: build with single metric policy" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric-policy"),
        .enabled = true,
        .target = .{ .metric = .{ .keep = false } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_requests_total") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expect(!index.isEmpty());
    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 1), index.getPolicyCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
    try testing.expectEqual(@as(u16, 0), policy_info.?.negated_count);
    try testing.expectEqual(KeepValue.none, policy_info.?.keep);
    try testing.expect(policy_info.?.enabled);

    const db = index.getDatabase(.{ .metric = .{ .field = .{ .metric_field = .METRIC_FIELD_NAME } } });
    try testing.expect(db != null);
    try testing.expect(db.?.positive_db != null);
    try testing.expect(db.?.negated_db == null);
}

test "MatcherIndex: metric policy with datapoint attribute" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "test-metric-policy"),
        .enabled = true,
        .target = .{ .metric = .{ .keep = true } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_requests") },
    });
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .datapoint_attribute = try allocator.dupe(u8, "method") },
        .match = .{ .regex = try allocator.dupe(u8, "GET|POST") },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());
    try testing.expect(index.getDatabase(.{ .metric = .{ .field = .{ .metric_field = .METRIC_FIELD_NAME } } }) != null);
    try testing.expect(index.getDatabase(.{ .metric = .{ .field = .{ .datapoint_attribute = "method" } } }) != null);

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 2), policy_info.?.required_match_count);
    try testing.expectEqual(KeepValue.all, policy_info.?.keep);
}

test "MatcherIndex: mixed log and metric policies" {
    const allocator = testing.allocator;

    var log_policy = Policy{
        .id = try allocator.dupe(u8, "log-policy-1"),
        .name = try allocator.dupe(u8, "drop-errors"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try log_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "error") },
    });
    defer log_policy.deinit(allocator);

    var metric_policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "drop-http-metrics"),
        .enabled = true,
        .target = .{ .metric = .{ .keep = false } },
    };
    try metric_policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "http_") },
    });
    defer metric_policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{ log_policy, metric_policy });
    defer index.deinit();

    try testing.expectEqual(@as(usize, 2), index.getDatabaseCount());
    try testing.expectEqual(@as(usize, 2), index.getPolicyCount());

    try testing.expect(index.getDatabase(.{ .log = .{ .field = .{ .log_field = .LOG_FIELD_BODY } } }) != null);
    try testing.expect(index.getDatabase(.{ .metric = .{ .field = .{ .metric_field = .METRIC_FIELD_NAME } } }) != null);

    const log_info = index.getPolicy("log-policy-1");
    try testing.expect(log_info != null);
    try testing.expectEqual(KeepValue.none, log_info.?.keep);

    const metric_info = index.getPolicy("metric-policy-1");
    try testing.expect(metric_info != null);
    try testing.expectEqual(KeepValue.none, metric_info.?.keep);
}

test "MatcherIndex: metric policy skips enum matchers" {
    const allocator = testing.allocator;

    var policy = Policy{
        .id = try allocator.dupe(u8, "metric-policy-1"),
        .name = try allocator.dupe(u8, "gauge-only"),
        .enabled = true,
        .target = .{ .metric = .{ .keep = true } },
    };
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "cpu_") },
    });
    try policy.target.?.metric.match.append(allocator, .{
        .field = .{ .metric_type = .METRIC_TYPE_GAUGE },
        .match = .{ .exists = true },
    });
    defer policy.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var index = try MatcherIndex.build(allocator, noop_bus.eventBus(), &.{policy});
    defer index.deinit();

    try testing.expectEqual(@as(usize, 1), index.getDatabaseCount());

    const policy_info = index.getPolicyByIndex(0);
    try testing.expect(policy_info != null);
    try testing.expectEqual(@as(u16, 1), policy_info.?.required_match_count);
}
