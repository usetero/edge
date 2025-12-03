# Hyperscan Filtering Redesign - Implementation Plan

## Problem Statement

The current implementation is "inverted" - it iterates through policies one by one and checks each matcher against the input. This is inefficient because:
1. Each policy is evaluated sequentially
2. For each matcher, we have to look up the appropriate Hyperscan database
3. The same field value may be scanned multiple times against different databases

## New Architecture: Inverted Index Approach

The new approach flips the logic:
1. **Compile phase**: When policies are received, compile ONE Hyperscan database per `(MatcherType, Key)` tuple. Each pattern in the DB maps to a policy ID.
2. **Scan phase**: For each field in the incoming telemetry, scan against the corresponding database. Collect all matching policy IDs.
3. **Aggregation phase**: Count matches per policy. A policy matches IFF it has matches equal to its matcher count (accounting for negation).
4. **Action phase**: Apply the highest priority matching policy's action.

## Key Design Decisions

### 1. MatcherKey Type
```zig
pub const MatcherKey = struct {
    match_case: MatchCase,
    key: []const u8,  // Empty for non-keyed types
};
```

### 2. Pattern Metadata
Each pattern in a Hyperscan database needs to map back to:
- `policy_id: []const u8` - The policy this pattern belongs to
- `matcher_index: u32` - Which matcher in the policy
- `negate: bool` - Whether this is a negated matcher

### 3. Policy Tracking Structure
```zig
pub const PolicyInfo = struct {
    id: []const u8,
    matcher_count: u32,      // Total matchers in policy
    action: FilterAction,
    priority: i32,
    enabled: bool,
};
```

### 4. Match Counting
For each policy, track:
- `positive_matches: u32` - Non-negated matchers that matched
- `negative_matches: u32` - Negated matchers where pattern was NOT found

A policy fully matches when: `positive_matches + negative_matches == matcher_count`

## New File Structure

```
src/core/
├── filter.zig              # Keep existing (for backwards compat during migration)
├── filter_engine.zig       # NEW: Main filter engine using inverted index
├── matcher_index.zig       # NEW: Compiles policies into matcher-keyed databases
├── policy_registry.zig     # Keep existing
└── regex_index.zig         # Keep existing (will be deprecated after migration)
```

## Implementation Details

### File 1: `src/core/matcher_index.zig`

**Purpose**: Compile policies into Hyperscan databases indexed by `(MatchCase, Key)`.

**Types**:
```zig
/// Key for indexing databases - combines match type and attribute key
pub const MatcherKey = struct {
    match_case: MatchCase,
    key: []const u8,  // Empty string for non-keyed types

    pub fn hash(self: MatcherKey) u64 { ... }
    pub fn eql(a: MatcherKey, b: MatcherKey) bool { ... }
};

/// Metadata for a pattern in the database
pub const PatternMeta = struct {
    policy_id: []const u8,
    matcher_index: u32,
    negate: bool,
};

/// A compiled database for a specific matcher key
pub const MatcherDatabase = struct {
    db: hyperscan.Database,
    scratch: hyperscan.Scratch,
    mutex: std.Thread.Mutex,
    patterns: []const PatternMeta,
    allocator: std.mem.Allocator,
    
    pub fn scan(self: *MatcherDatabase, value: []const u8) []const u32 { ... }
    pub fn deinit(self: *MatcherDatabase) void { ... }
};

/// Policy info for quick lookup during evaluation
pub const PolicyInfo = struct {
    id: []const u8,
    matcher_count: u32,
    action: FilterAction,
    priority: i32,
    enabled: bool,
};

/// The compiled matcher index
pub const MatcherIndex = struct {
    allocator: std.mem.Allocator,
    
    /// Maps MatcherKey -> MatcherDatabase
    databases: std.HashMap(MatcherKey, *MatcherDatabase, ...),
    
    /// Maps policy_id -> PolicyInfo
    policies: std.StringHashMap(PolicyInfo),
    
    /// List of all matcher keys (for iteration during scan)
    matcher_keys: []const MatcherKey,
    
    pub fn build(allocator: Allocator, policies: []const Policy) !MatcherIndex { ... }
    pub fn getDatabase(self: *const MatcherIndex, key: MatcherKey) ?*MatcherDatabase { ... }
    pub fn getPolicy(self: *const MatcherIndex, id: []const u8) ?PolicyInfo { ... }
    pub fn iterateMatcherKeys(self: *const MatcherIndex) []const MatcherKey { ... }
    pub fn deinit(self: *MatcherIndex) void { ... }
};
```

### File 2: `src/core/filter_engine.zig`

**Purpose**: Evaluate telemetry against the compiled matcher index.

**Types**:
```zig
/// Field accessor - same interface as before
pub const FieldAccessor = *const fn (
    ctx: *const anyopaque,
    match_case: MatchCase,
    key: []const u8
) ?[]const u8;

/// Match state for a single policy during evaluation
const PolicyMatchState = struct {
    positive_matches: u32 = 0,
    negative_nonmatches: u32 = 0,  // Negated patterns that did NOT match
};

/// Result of filtering
pub const FilterResult = enum { keep, drop };

/// The filter engine
pub const FilterEngine = struct {
    registry: *const PolicyRegistry,
    
    pub fn init(registry: *const PolicyRegistry) FilterEngine { ... }
    
    /// Evaluate a single telemetry item
    pub fn evaluate(
        self: *const FilterEngine,
        ctx: *const anyopaque,
        field_accessor: FieldAccessor,
    ) FilterResult {
        // 1. Get snapshot
        const snapshot = self.registry.getSnapshot() orelse return .keep;
        const index = &snapshot.matcher_index;
        
        // 2. Track match counts per policy
        var match_states = std.StringHashMap(PolicyMatchState).init(...);
        defer match_states.deinit();
        
        // 3. For each matcher key in the index
        for (index.iterateMatcherKeys()) |matcher_key| {
            // 3a. Get field value using accessor
            const value = field_accessor(ctx, matcher_key.match_case, matcher_key.key);
            
            // 3b. Get database for this matcher key
            const db = index.getDatabase(matcher_key) orelse continue;
            
            // 3c. Scan value against database
            if (value) |v| {
                const matches = db.scan(v);
                // Update match states for each matching pattern
                for (matches) |pattern_id| {
                    const meta = db.patterns[pattern_id];
                    const state = match_states.getOrPut(meta.policy_id);
                    if (!meta.negate) {
                        state.positive_matches += 1;
                    }
                    // For negated: we track NON-matches below
                }
            }
            
            // 3d. For negated patterns, if value is null or didn't match, that's success
            // ... handle negation logic
        }
        
        // 4. Find fully-matched policies
        var best_policy: ?PolicyInfo = null;
        var it = match_states.iterator();
        while (it.next()) |entry| {
            const policy = index.getPolicy(entry.key_ptr.*) orelse continue;
            if (!policy.enabled) continue;
            
            const total_matches = entry.value_ptr.positive_matches + 
                                  entry.value_ptr.negative_nonmatches;
            if (total_matches == policy.matcher_count) {
                // Policy fully matches
                if (best_policy == null or policy.priority > best_policy.?.priority) {
                    best_policy = policy;
                }
            }
        }
        
        // 5. Return action of highest priority matching policy
        if (best_policy) |p| {
            return switch (p.action) {
                .FILTER_ACTION_DROP => .drop,
                else => .keep,
            };
        }
        
        return .keep;  // Default: keep
    }
};
```

### File 3: Update `src/core/policy_registry.zig`

Add `matcher_index` to `PolicySnapshot`:
```zig
pub const PolicySnapshot = struct {
    policies: []const Policy,
    log_filter_indices: []const u32,
    compiled_regex_index: CompiledRegexIndex,  // Keep for now
    matcher_index: MatcherIndex,  // NEW
    version: u64,
    allocator: std.mem.Allocator,
    
    // ... rest unchanged
};
```

Update `createSnapshot()` to build both indexes (for gradual migration).

## Handling Negation

Negation requires special handling:

1. **Negated matcher with value present**: Pattern must NOT match
2. **Negated matcher with value absent**: Counts as a match (pattern can't be in non-existent field)

For each negated matcher, we need to:
- Track which policies have negated matchers for each key
- After scanning, mark as "matched" any negated matchers whose patterns were NOT found
- If the field value is null, all negated matchers for that key automatically "match"

## Handling log_severity_number

This matcher type uses `min`/`max` range comparison, not regex. It should be:
1. Excluded from Hyperscan compilation
2. Evaluated separately as a simple numeric comparison
3. Tracked in a separate list of "range matchers" per policy

## Migration Strategy

1. Add new files alongside existing ones
2. Update `PolicySnapshot` to build both indexes
3. Add `FilterEngine` as alternative to `FilterEvaluator`  
4. Update `logs_v2.zig` to use `FilterEngine`
5. Test thoroughly
6. Remove old `CompiledRegexIndex` and `FilterEvaluator`

## Performance Characteristics

**Compile time**: O(P * M) where P = policies, M = avg matchers per policy
- One pass to collect patterns per MatcherKey
- One Hyperscan compilation per MatcherKey

**Scan time**: O(K * N + P) where K = unique MatcherKeys, N = input size, P = policies
- One Hyperscan scan per MatcherKey (O(N) each, independent of pattern count)
- One pass through match results to aggregate per policy

**Memory**: 
- One Hyperscan database per unique (MatchCase, Key) tuple
- Policy metadata map
- Per-scan temporary match state (small)

## Files to Create

1. `src/core/matcher_index.zig` - MatcherKey, MatcherDatabase, MatcherIndex
2. `src/core/filter_engine.zig` - FilterEngine with new evaluation logic

## Files to Modify

1. `src/core/policy_registry.zig` - Add matcher_index to PolicySnapshot
2. `src/modules/datadog/logs_v2.zig` - Use FilterEngine instead of FilterEvaluator

## Files to Eventually Delete

1. `src/core/regex_index.zig` - After migration complete
2. `src/core/filter.zig` - After migration complete (or keep as alias)
