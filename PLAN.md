# Implementation Plan: Policy Specification v1.2.0

## Overview

Update the edge proxy (Zig) to support policy specification v1.2.0. This
includes three new features:

1. Nested attribute accessors (dot-notation paths)
2. Optimized literal matchers with case-insensitivity
3. Sampling key support for consistent log sampling

## Current State Analysis

### Protobuf Schema (Already Updated)

The proto files in `proto/tero/policy/v1/` already contain the v1.2.0 schema:

- `AttributePath` with `repeated string path` for nested access
- `LogMatcher` with `starts_with`, `ends_with`, `contains`, and
  `case_insensitive` fields
- `LogSampleKey` message in `LogTarget`

The generated Zig code in `src/proto/tero/policy/v1.pb.zig` already reflects
these changes.

### Key Files to Modify

| File                              | Purpose                                                    |
| --------------------------------- | ---------------------------------------------------------- |
| `src/policy/parser.zig`           | JSON parser - needs AttributePath format support           |
| `src/policy/types.zig`            | Field reference types - needs path array support           |
| `src/policy/matcher_index.zig`    | Index builder - literal matchers, case-insensitivity flags |
| `src/policy/policy_engine.zig`    | Engine - needs sample_key integration                      |
| `src/modules/otlp_logs.zig`       | OTLP accessor - needs nested path traversal                |
| `src/modules/datadog_logs_v2.zig` | Datadog accessor - needs nested path traversal             |

---

## Task 1: Nested Attribute Accessors

### 1.1 Update FieldRef Types (`src/policy/types.zig`)

**Current**: Attribute fields store a single `[]const u8` key.

```zig
pub const FieldRef = union(enum) {
    log_field: LogField,
    log_attribute: []const u8,      // Single key
    resource_attribute: []const u8,
    scope_attribute: []const u8,
};
```

**Change**: Store the full path as `[]const []const u8`.

```zig
pub const FieldRef = union(enum) {
    log_field: LogField,
    log_attribute: []const []const u8,      // Path segments
    resource_attribute: []const []const u8,
    scope_attribute: []const []const u8,
};
```

**Impact**: Update all `fromMatcherField`, `fromRemoveField`, etc. methods to
extract `path.items` from `AttributePath`.

### 1.2 Update IndexBuilder Pattern Key Generation (`src/policy/matcher_index.zig`)

The `MatcherKey` currently uses the attribute key directly. With paths, we need
to:

- Store the full path for the field reference
- Use a consistent hash of the path for the key lookup

**Change `LogMatcherKey`**:

```zig
pub const LogMatcherKey = struct {
    field: FieldRef,

    pub fn hash(self: Self) u64 {
        var h = std.hash.Wyhash.init(0);
        switch (self.field) {
            .log_attribute, .resource_attribute, .scope_attribute => |path| {
                h.update(std.mem.asBytes(&std.meta.activeTag(self.field)));
                for (path) |segment| {
                    h.update(segment);
                    h.update(&[_]u8{0}); // separator
                }
            },
            .log_field => |lf| {
                h.update(std.mem.asBytes(&std.meta.activeTag(self.field)));
                h.update(std.mem.asBytes(&lf));
            },
        }
        return h.final();
    }
};
```

### 1.3 Update Field Accessors (`src/modules/otlp_logs.zig`, `src/modules/datadog_logs_v2.zig`)

**Current `findAttribute`**: Flat lookup by single key.

**New `findNestedAttribute`**: Traverse nested maps.

```zig
/// Traverse nested attributes using path segments
fn findNestedAttribute(attributes: []const KeyValue, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;

    // Find first segment
    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, path[0])) {
            if (path.len == 1) {
                // Final segment - return string value
                return getAnyValueString(kv.value);
            } else {
                // More segments - must be a map, recurse
                const v = kv.value orelse return null;
                const val_union = v.value orelse return null;
                switch (val_union) {
                    .kvlist_value => |kvlist| {
                        return findNestedAttribute(kvlist.values.items, path[1..]);
                    },
                    else => return null, // Not a nested structure
                }
            }
        }
    }
    return null;
}
```

**Update accessor**:

```zig
fn otlpFieldAccessor(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const log_ctx: *const OtlpLogContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .log_field => |lf| // ... unchanged
        .log_attribute => |path| findNestedAttribute(log_ctx.log_record.attributes.items, path),
        .resource_attribute => |path| // ... similar
        .scope_attribute => |path| // ... similar
    };
}
```

### 1.4 Test Cases

- Single-segment path: `["service"]` should work as before
- Multi-segment path: `["http", "method"]` should traverse nested maps
- Missing intermediate: `["http", "missing", "field"]` returns null
- Null value in path: `["http", null_field, "x"]` returns null
- Empty path: `[]` returns null

---

## Task 2: Optimized Literal Matchers

### 2.1 Update IndexBuilder Pattern Extraction (`src/policy/matcher_index.zig`)

**Current `extractRegex`**: Only handles `regex`, `exact`, `exists`.

**Add literal matchers**:

```zig
const ExtractResult = struct {
    pattern: []const u8,
    match_type: MatchType,
    flip_negate: bool,
};

const MatchType = enum {
    regex,
    exact,
    starts_with,
    ends_with,
    contains,
};

fn extractPattern(self: *Self, match_union: anytype, matcher_idx: usize) ?ExtractResult {
    const m = match_union orelse return null;
    return switch (m) {
        .regex => |r| .{ .pattern = r, .match_type = .regex, .flip_negate = false },
        .exact => |e| .{ .pattern = e, .match_type = .exact, .flip_negate = false },
        .starts_with => |s| .{ .pattern = s, .match_type = .starts_with, .flip_negate = false },
        .ends_with => |s| .{ .pattern = s, .match_type = .ends_with, .flip_negate = false },
        .contains => |s| .{ .pattern = s, .match_type = .contains, .flip_negate = false },
        .exists => |exists| .{ .pattern = EXISTS_PATTERN, .match_type = .regex, .flip_negate = !exists },
    };
}
```

### 2.2 Separate Literal and Regex Databases

**Option A (Recommended)**: Convert literal matchers to regex for Hyperscan

- `starts_with: "foo"` → regex `^foo`
- `ends_with: "bar"` → regex `bar$`
- `contains: "baz"` → regex `baz`
- `exact: "qux"` → regex `^qux$`

This keeps the current Hyperscan infrastructure and is simpler to implement.

**Option B**: Maintain separate literal matcher lists evaluated without
Hyperscan

- More complex but potentially faster for simple literals
- Would require changes to `MatcherDatabase` and scan logic

**Recommendation**: Start with Option A. Hyperscan is highly optimized and the
regex conversions are trivial. Profile later if needed.

### 2.3 Case-Insensitivity Support via Hyperscan Flags

Hyperscan natively supports case-insensitive matching via the `HS_FLAG_CASELESS`
flag. The existing wrapper in `src/hyperscan/hyperscan.zig` exposes this as
`Flags{ .caseless = true }`.

**Update `PatternCollector`** to include flags:

```zig
const PatternCollector = struct {
    policy_index: PolicyIndex,
    regex: []const u8,
    flags: hyperscan.Flags,  // NEW: per-pattern flags
};
```

**Update `compilePatterns`** to use per-pattern flags:

```zig
for (collectors, 0..) |collector, i| {
    hs_patterns[i] = .{
        .expression = collector.regex,
        .id = @intCast(i),
        .flags = collector.flags,  // Pass per-pattern flags
    };
    // ...
}
```

**In pattern extraction**, set caseless flag when `case_insensitive = true`:

```zig
const flags: hyperscan.Flags = if (matcher.case_insensitive) .{ .caseless = true } else .{};
```

### 2.4 Regex Escaping Helper

Need a helper to escape regex metacharacters for literal patterns converted to
regex:

```zig
/// Escape regex metacharacters in a literal string
fn escapeRegex(allocator: Allocator, literal: []const u8) ![]const u8 {
    // Metacharacters that need escaping: . ^ $ * + ? { } [ ] \ | ( )
    var escaped = std.ArrayList(u8).init(allocator);
    for (literal) |c| {
        if (std.mem.indexOfScalar(u8, ".^$*+?{}[]\\|()", c) != null) {
            try escaped.append('\\');
        }
        try escaped.append(c);
    }
    return escaped.toOwnedSlice();
}
```

### 2.5 Build Regex from Literal Match Types

Convert literal matchers to anchored regex patterns:

```zig
fn buildPattern(allocator: Allocator, pattern: []const u8, match_type: MatchType) ![]const u8 {
    return switch (match_type) {
        .regex => pattern,  // Use as-is
        .contains => try escapeRegex(allocator, pattern),  // No anchors needed
        .starts_with => try std.fmt.allocPrint(allocator, "^{s}", .{try escapeRegex(allocator, pattern)}),
        .ends_with => try std.fmt.allocPrint(allocator, "{s}$", .{try escapeRegex(allocator, pattern)}),
        .exact => try std.fmt.allocPrint(allocator, "^{s}$", .{try escapeRegex(allocator, pattern)}),
    };
}
```

### 2.6 Test Cases

- `starts_with: "ERROR"` matches "ERROR: something" but not "some ERROR"
- `ends_with: ".json"` matches "config.json" but not "json_file"
- `contains: "warn"` matches "warning" and "a warn message"
- `exact: "DEBUG"` matches only "DEBUG", not "DEBUG:" or "a DEBUG"
- `case_insensitive: true` with `exact: "error"` matches "ERROR", "Error",
  "error"
- Combined: `starts_with: "http"` + `case_insensitive: true` matches "HTTP/1.1"
- Literal with special chars: `contains: "foo.bar"` matches "foo.bar" but not
  "fooXbar"

---

## Task 3: Sampling Key Support for Logs

### 3.1 Parse sample_key in PolicyInfo (`src/policy/matcher_index.zig`)

**Add to PolicyInfo**:

```zig
pub const PolicyInfo = struct {
    id: []const u8,
    index: PolicyIndex,
    required_match_count: u16,
    negated_count: u16,
    keep: KeepValue,
    enabled: bool,
    rate_limiter: ?*RateLimiter,
    sample_key: ?SampleKeyRef,  // NEW
};

/// Reference for extracting sample key value
pub const SampleKeyRef = union(enum) {
    log_field: LogField,
    log_attribute: []const []const u8,
    resource_attribute: []const []const u8,
    scope_attribute: []const []const u8,
};
```

**Update `storePolicyInfo`** to extract `sample_key` from `LogTarget`.

### 3.2 Integrate sample_key in Sampling Decision (`src/policy/policy_engine.zig`)

**Current `applyKeepValue`**: Uses `hash_input` (context pointer or trace_id).

**With sample_key**:

```zig
fn applyKeepValue(
    policy_info: PolicyInfo,
    default_hash_input: u64,
    ctx: *anyopaque,
    field_accessor: LogFieldAccessor,
) FilterDecision {
    const hash_input = if (policy_info.sample_key) |sample_key| blk: {
        // Extract value from sample_key field
        const field_ref = sampleKeyToFieldRef(sample_key);
        if (field_accessor(ctx, field_ref)) |value| {
            break :blk hashString(value);
        }
        // Field not present - use default
        break :blk default_hash_input;
    } else default_hash_input;

    return switch (policy_info.keep) {
        .none => .drop,
        .all => .keep,
        .percentage => |pct| {
            const sampler = Sampler{ .percentage = pct };
            return if (sampler.shouldKeep(hash_input)) .keep else .drop;
        },
        // ... rate limiters don't use sample_key
    };
}

fn hashString(s: []const u8) u64 {
    return std.hash.Wyhash.hash(0, s);
}
```

### 3.3 Update findMatchingPolicies

Pass the field accessor to `applyKeepValue` so it can extract sample_key values:

```zig
inline fn findMatchingPolicies(
    self: *const Self,
    comptime T: TelemetryType,
    index: *const matcher_index.MatcherIndexType(T),
    scan_state: *const ScanState,
    policy_id_buf: [][]const u8,
    default_hash_input: u64,
    ctx: *anyopaque,                    // NEW
    field_accessor: FieldAccessorType(T), // NEW
) MatchState {
    // ... in the loop:
    const decision = applyKeepValue(policy_info, default_hash_input, ctx, field_accessor);
}
```

### 3.4 Test Cases

- Without sample_key: Uses context pointer hash (existing behavior)
- With sample_key on existing field: All logs with same value get same decision
- With sample_key on missing field: Falls back to default hash
- Verify consistency: Same `request_id` value always produces same keep/drop
  decision
- Verify distribution: 10% sampling with sample_key still samples ~10% of unique
  keys

---

## Task 4: Policy Parser Updates for AttributePath

The policy JSON/YAML parser (`src/policy/parser.zig`) needs to support the three
ways of specifying AttributePath as defined in the proto spec:

### 4.1 Three Input Formats for AttributePath

Per the proto documentation, implementations MUST accept:

1. **Canonical (proto-native)**:

   ```json
   { "log_attribute": { "path": ["http", "method"] } }
   ```

2. **Shorthand array**:

   ```json
   { "log_attribute": ["http", "method"] }
   ```

3. **Shorthand string (single-segment only)**:
   ```json
   { "log_attribute": "user_id" }
   ```

### 4.2 Update JSON Schema Types

**Current `LogMatcherJson`**:

```zig
const LogMatcherJson = struct {
    log_attribute: ?[]const u8 = null,  // Single string
    // ...
};
```

**New approach**: Use a custom JSON parse function to handle all three formats.

```zig
/// AttributePath that can be parsed from string, array, or canonical form
const AttributePathJson = union(enum) {
    string: []const u8,
    array: [][]const u8,
    canonical: struct { path: [][]const u8 },

    /// Convert to path array for internal use
    pub fn toPath(self: AttributePathJson) []const []const u8 {
        return switch (self) {
            .string => |s| &[_][]const u8{s},
            .array => |a| a,
            .canonical => |c| c.path,
        };
    }
};
```

### 4.3 Custom JSON Parsing

Implement custom `jsonParse` for the attribute path fields:

```zig
fn parseAttributePath(allocator: Allocator, source: anytype) ![]const []const u8 {
    const token = try source.peekNextTokenType();
    return switch (token) {
        .string => blk: {
            // Shorthand string: "user_id" -> ["user_id"]
            const s = try source.next();
            const path = try allocator.alloc([]const u8, 1);
            path[0] = try allocator.dupe(u8, s.string);
            break :blk path;
        },
        .array_begin => blk: {
            // Shorthand array: ["http", "method"]
            _ = try source.next(); // consume array_begin
            var segments = std.ArrayList([]const u8).init(allocator);
            while (true) {
                const t = try source.next();
                switch (t) {
                    .string => |s| try segments.append(try allocator.dupe(u8, s)),
                    .array_end => break,
                    else => return error.UnexpectedToken,
                }
            }
            break :blk try segments.toOwnedSlice();
        },
        .object_begin => blk: {
            // Canonical form: { "path": ["http", "method"] }
            const obj = try std.json.innerParse(
                struct { path: [][]const u8 },
                allocator,
                source,
                .{},
            );
            break :blk obj.path;
        },
        else => return error.UnexpectedToken,
    };
}
```

### 4.4 Update LogMatcherJson and Related Types

```zig
const LogMatcherJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?std.json.Value = null,      // Accept any JSON value
    resource_attribute: ?std.json.Value = null,
    scope_attribute: ?std.json.Value = null,
    // ... match types and flags
    starts_with: ?[]const u8 = null,
    ends_with: ?[]const u8 = null,
    contains: ?[]const u8 = null,
    case_insensitive: bool = false,
};
```

Then in `parseLogMatcher`:

```zig
fn parseLogMatcher(allocator: Allocator, jm: LogMatcherJson) !LogMatcher {
    const field: LogMatcher.field_union = blk: {
        if (jm.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jm.log_attribute) |attr_json| {
            const path = try parseAttributePathFromValue(allocator, attr_json);
            break :blk .{ .log_attribute = path };
        }
        // ... etc
    };
    // ...
}
```

### 4.5 Update sample_key Parsing

Similarly, update `LogSampleKey` parsing to handle the three formats.

### 4.6 Test Cases

```json
// All three should produce path: ["http", "method"]
{ "log_attribute": "http.method" }                    // ERROR - dot notation not supported!
{ "log_attribute": ["http", "method"] }               // Shorthand array
{ "log_attribute": { "path": ["http", "method"] } }   // Canonical

// Single segment
{ "log_attribute": "service" }                        // Shorthand string
{ "log_attribute": ["service"] }                      // Shorthand array (single element)
{ "log_attribute": { "path": ["service"] } }          // Canonical (single element)
```

**Note**: Dot notation (`"http.method"`) is NOT supported - path segments must
be explicit.

---

## Implementation Order

1. **Task 1: Nested Attribute Accessors** (most foundational)
   - Update `FieldRef` types to use path arrays
   - Update `fromMatcherField` and related methods
   - Implement `findNestedAttribute` in OTLP/Datadog modules
   - Update hash/equality for `MatcherKey`
   - Add tests

2. **Task 4: Policy Parser Updates** (needed before Task 1 can be tested
   end-to-end)
   - Implement custom JSON parsing for AttributePath
   - Update LogMatcherJson and related types
   - Update sample_key parsing
   - Add tests for all three input formats

3. **Task 2: Optimized Literal Matchers**
   - Add regex escape helper
   - Update `extractPattern` to handle new match types
   - Add per-pattern Hyperscan flags for case-insensitivity
   - Build regex patterns from literals
   - Add tests

4. **Task 3: Sampling Key Support**
   - Add `SampleKeyRef` type and `sample_key` to `PolicyInfo`
   - Extract sample_key during index building
   - Integrate into `applyKeepValue`
   - Add tests

---

## Testing Strategy

### Unit Tests

- Add tests in each modified file's test section
- Cover edge cases: empty paths, null values, missing fields

### Integration Tests

- Create test policies using all new features
- Process sample OTLP/Datadog payloads
- Verify correct filtering and sampling behavior

### Benchmark Tests

- Compare literal matcher performance (Hyperscan regex vs native string ops)
- Measure impact of nested attribute traversal
- Profile sampling key extraction overhead

---

## Risks and Mitigations

| Risk                                   | Impact         | Mitigation                                                       |
| -------------------------------------- | -------------- | ---------------------------------------------------------------- |
| Path array allocation overhead         | Performance    | Use arena allocator; paths are typically short                   |
| Regex escaping edge cases              | Correctness    | Comprehensive test coverage for special chars                    |
| Hyperscan pattern compilation failures | Runtime errors | Validate patterns during policy loading                          |
| Breaking change for existing configs   | Compatibility  | Single-element paths should work identically to current behavior |

---

## Verification Checklist

- [ ] `task test` passes
- [ ] `task build:safe` succeeds
- [ ] Existing policy configurations continue to work (backward compatibility)
- [ ] Nested attribute paths work: `["http", "method"]`
- [ ] All three AttributePath JSON formats parse correctly
- [ ] Literal matchers work: `starts_with`, `ends_with`, `contains`
- [ ] Case-insensitive matching works via Hyperscan flags
- [ ] Sampling key produces consistent decisions for same key values
- [ ] Performance benchmarks show no regression
