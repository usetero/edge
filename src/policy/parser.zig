const std = @import("std");
const proto = @import("proto");

const Policy = proto.policy.Policy;
const LogTarget = proto.policy.LogTarget;
const LogMatcher = proto.policy.LogMatcher;
const LogField = proto.policy.LogField;
const LogTransform = proto.policy.LogTransform;
const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;
const MetricTarget = proto.policy.MetricTarget;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricField = proto.policy.MetricField;
const TraceTarget = proto.policy.TraceTarget;
const TraceMatcher = proto.policy.TraceMatcher;
const TraceField = proto.policy.TraceField;
const TraceSamplingConfig = proto.policy.TraceSamplingConfig;
const SamplingMode = proto.policy.SamplingMode;
const SpanKind = proto.policy.SpanKind;
const SpanStatusCode = proto.policy.SpanStatusCode;
const AttributePath = proto.policy.AttributePath;

/// Create an AttributePath from a simple key string.
/// For backward compatibility, a single key becomes a single-element path.
/// TODO (Step 2): Support full AttributePath formats (array, dot notation)
fn makeAttributePath(allocator: std.mem.Allocator, key: []const u8) !AttributePath {
    var attr_path = AttributePath{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, key));
    return attr_path;
}

// =============================================================================
// New JSON Schema - matches YAML format closely
// =============================================================================

/// JSON schema for a log matcher
/// Example: { "log_field": "body", "regex": "GET /health" }
/// Example: { "log_attribute": "service", "regex": "payment.*" }
const LogMatcherJson = struct {
    // Field selectors (one of these should be set)
    log_field: ?[]const u8 = null, // "body", "severity_text", etc.
    log_attribute: ?[]const u8 = null, // attribute key
    resource_attribute: ?[]const u8 = null, // resource attribute key
    scope_attribute: ?[]const u8 = null, // scope attribute key

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,

    // Optional negation
    negate: bool = false,
};

/// JSON schema for a metric matcher
/// Example: { "metric_field": "name", "regex": "^debug\\." }
/// Example: { "datapoint_attribute": "env", "exact": "dev" }
const MetricMatcherJson = struct {
    // Field selectors (one of these should be set)
    metric_field: ?[]const u8 = null, // "name", "unit", etc.
    datapoint_attribute: ?[]const u8 = null, // datapoint attribute key
    resource_attribute: ?[]const u8 = null, // resource attribute key
    scope_attribute: ?[]const u8 = null, // scope attribute key

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,

    // Optional negation
    negate: bool = false,
};

/// JSON schema for a remove transform
const RemoveJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?[]const u8 = null,
    resource_attribute: ?[]const u8 = null,
    scope_attribute: ?[]const u8 = null,
};

/// JSON schema for a redact transform
const RedactJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?[]const u8 = null,
    resource_attribute: ?[]const u8 = null,
    scope_attribute: ?[]const u8 = null,
    replacement: []const u8 = "[REDACTED]",
};

/// JSON schema for a rename transform
const RenameJson = struct {
    from_log_field: ?[]const u8 = null,
    from_log_attribute: ?[]const u8 = null,
    from_resource_attribute: ?[]const u8 = null,
    from_scope_attribute: ?[]const u8 = null,
    to: []const u8,
    upsert: bool = true,
};

/// JSON schema for an add transform
const AddJson = struct {
    log_field: ?[]const u8 = null,
    log_attribute: ?[]const u8 = null,
    resource_attribute: ?[]const u8 = null,
    scope_attribute: ?[]const u8 = null,
    value: []const u8,
    upsert: bool = true,
};

/// JSON schema for transforms
const TransformJson = struct {
    remove: ?[]RemoveJson = null,
    redact: ?[]RedactJson = null,
    rename: ?[]RenameJson = null,
    add: ?[]AddJson = null,
};

/// JSON schema for log target
/// Example:
/// "log": {
///   "match": [{ "log_field": "body", "regex": "GET /health" }],
///   "keep": "none",
///   "transform": { ... }
/// }
const LogTargetJson = struct {
    match: ?[]LogMatcherJson = null,
    keep: []const u8 = "all",
    transform: ?TransformJson = null,
};

/// JSON schema for metric target
/// Example:
/// "metric": {
///   "match": [{ "metric_field": "name", "regex": "^debug\\." }],
///   "keep": false
/// }
const MetricTargetJson = struct {
    match: ?[]MetricMatcherJson = null,
    keep: bool = true,
};

/// JSON schema for a trace matcher
/// Example: { "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }
/// Example: { "span_attribute": "peer.service", "exists": true }
/// Example: { "span_kind": "SPAN_KIND_INTERNAL", "exists": true }
const TraceMatcherJson = struct {
    // Field selectors (one of these should be set)
    trace_field: ?[]const u8 = null, // "TRACE_FIELD_NAME", "TRACE_FIELD_TRACE_ID", etc.
    span_attribute: ?[]const u8 = null, // span attribute key
    resource_attribute: ?[]const u8 = null, // resource attribute key
    scope_attribute: ?[]const u8 = null, // scope attribute key
    span_kind: ?[]const u8 = null, // "SPAN_KIND_INTERNAL", "SPAN_KIND_SERVER", etc.
    span_status: ?[]const u8 = null, // "SPAN_STATUS_CODE_OK", "SPAN_STATUS_CODE_ERROR"
    event_name: ?[]const u8 = null, // event name to match
    event_attribute: ?[]const u8 = null, // event attribute key
    link_trace_id: ?[]const u8 = null, // link trace_id matcher

    // Match type (one of these should be set)
    regex: ?[]const u8 = null,
    exact: ?[]const u8 = null,
    exists: ?bool = null,

    // Optional negation
    negate: bool = false,
};

/// JSON schema for trace sampling config
const TraceSamplingConfigJson = struct {
    percentage: f32 = 100.0,
    mode: ?[]const u8 = null, // "SAMPLING_MODE_HASH_SEED", "SAMPLING_MODE_PROPORTIONAL", etc.
    sampling_precision: ?u32 = null,
    hash_seed: ?u32 = null,
    fail_closed: ?bool = null,
};

/// JSON schema for trace target
/// Example:
/// "trace": {
///   "match": [{ "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }],
///   "keep": { "percentage": 50.0, "mode": "SAMPLING_MODE_HASH_SEED" }
/// }
const TraceTargetJson = struct {
    match: ?[]TraceMatcherJson = null,
    keep: ?TraceSamplingConfigJson = null,
};

/// JSON schema for a policy
/// Example:
/// {
///   "id": "drop-debug-metrics",
///   "name": "Drop debug metrics",
///   "metric": { ... }
/// }
/// or:
/// {
///   "id": "drop-health-checks",
///   "name": "Drop health check logs",
///   "log": { ... }
/// }
const PolicyJson = struct {
    id: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
    enabled: bool = true,

    // Target type (one of these should be set)
    log: ?LogTargetJson = null,
    metric: ?MetricTargetJson = null,
    trace: ?TraceTargetJson = null,
};

/// JSON schema for a policies file
const PoliciesFileJson = struct {
    policies: []PolicyJson,
};

// =============================================================================
// Public API
// =============================================================================

/// Parse policies-only JSON file
pub fn parsePoliciesFile(allocator: std.mem.Allocator, path: []const u8) ![]Policy {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(contents);

    return parsePoliciesBytes(allocator, contents);
}

/// Parse policies from JSON bytes
pub fn parsePoliciesBytes(allocator: std.mem.Allocator, json_bytes: []const u8) ![]Policy {
    const parsed = try std.json.parseFromSlice(
        PoliciesFileJson,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always },
    );
    defer parsed.deinit();

    const json_policies = parsed.value;
    return parsePolicies(allocator, json_policies.policies);
}

/// Parse policies from JSON array
pub fn parsePolicies(allocator: std.mem.Allocator, json_policies: []PolicyJson) ![]Policy {
    var policies = try allocator.alloc(Policy, json_policies.len);

    for (json_policies, 0..) |json_policy, i| {
        policies[i] = try parsePolicy(allocator, json_policy);
    }

    return policies;
}

/// Parse a single policy
fn parsePolicy(allocator: std.mem.Allocator, json_policy: PolicyJson) !Policy {
    const id = try allocator.dupe(u8, json_policy.id);
    const name = try allocator.dupe(u8, json_policy.name);
    const description = if (json_policy.description) |desc| try allocator.dupe(u8, desc) else &.{};

    // Determine target type
    var target: ?Policy.target_union = null;

    if (json_policy.log) |log_json| {
        target = .{ .log = try parseLogTarget(allocator, log_json) };
    } else if (json_policy.metric) |metric_json| {
        target = .{ .metric = try parseMetricTarget(allocator, metric_json) };
    } else if (json_policy.trace) |trace_json| {
        target = .{ .trace = try parseTraceTarget(allocator, trace_json) };
    }

    return Policy{
        .id = id,
        .name = name,
        .description = description,
        .enabled = json_policy.enabled,
        .target = target,
    };
}

// =============================================================================
// Log Target Parsing
// =============================================================================

fn parseLogTarget(allocator: std.mem.Allocator, json: LogTargetJson) !LogTarget {
    var matchers = std.ArrayListUnmanaged(LogMatcher){};

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseLogMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    var transform: ?LogTransform = null;
    if (json.transform) |jt| {
        transform = try parseLogTransform(allocator, jt);
    }

    return LogTarget{
        .match = matchers,
        .keep = try allocator.dupe(u8, json.keep),
        .transform = transform,
    };
}

fn parseLogMatcher(allocator: std.mem.Allocator, jm: LogMatcherJson) !LogMatcher {
    // Parse field
    const field: LogMatcher.field_union = blk: {
        if (jm.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jm.log_attribute) |key| {
            break :blk .{ .log_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    // Parse match
    const match: LogMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else {
            return error.MissingMatch;
        }
    };

    return LogMatcher{
        .negate = jm.negate,
        .field = field,
        .match = match,
    };
}

fn parseLogFieldName(name: []const u8) !LogField {
    if (std.mem.eql(u8, name, "body")) return .LOG_FIELD_BODY;
    if (std.mem.eql(u8, name, "severity_text")) return .LOG_FIELD_SEVERITY_TEXT;
    if (std.mem.eql(u8, name, "trace_id")) return .LOG_FIELD_TRACE_ID;
    if (std.mem.eql(u8, name, "span_id")) return .LOG_FIELD_SPAN_ID;
    if (std.mem.eql(u8, name, "event_name")) return .LOG_FIELD_EVENT_NAME;
    if (std.mem.eql(u8, name, "resource_schema_url")) return .LOG_FIELD_RESOURCE_SCHEMA_URL;
    if (std.mem.eql(u8, name, "scope_schema_url")) return .LOG_FIELD_SCOPE_SCHEMA_URL;
    return error.InvalidLogField;
}

fn parseLogTransform(allocator: std.mem.Allocator, jt: TransformJson) !LogTransform {
    var transform = LogTransform{};

    if (jt.remove) |removes| {
        try transform.remove.ensureTotalCapacity(allocator, removes.len);
        for (removes) |jr| {
            const remove = try parseLogRemove(allocator, jr);
            transform.remove.appendAssumeCapacity(remove);
        }
    }

    if (jt.redact) |redacts| {
        try transform.redact.ensureTotalCapacity(allocator, redacts.len);
        for (redacts) |jr| {
            const redact = try parseLogRedact(allocator, jr);
            transform.redact.appendAssumeCapacity(redact);
        }
    }

    if (jt.rename) |renames| {
        try transform.rename.ensureTotalCapacity(allocator, renames.len);
        for (renames) |jr| {
            const rename = try parseLogRename(allocator, jr);
            transform.rename.appendAssumeCapacity(rename);
        }
    }

    if (jt.add) |adds| {
        try transform.add.ensureTotalCapacity(allocator, adds.len);
        for (adds) |ja| {
            const add = try parseLogAdd(allocator, ja);
            transform.add.appendAssumeCapacity(add);
        }
    }

    return transform;
}

fn parseLogRemove(allocator: std.mem.Allocator, jr: RemoveJson) !LogRemove {
    const field: LogRemove.field_union = blk: {
        if (jr.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jr.log_attribute) |key| {
            break :blk .{ .log_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    return LogRemove{ .field = field };
}

fn parseLogRedact(allocator: std.mem.Allocator, jr: RedactJson) !LogRedact {
    const field: LogRedact.field_union = blk: {
        if (jr.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (jr.log_attribute) |key| {
            break :blk .{ .log_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    return LogRedact{
        .field = field,
        .replacement = try allocator.dupe(u8, jr.replacement),
    };
}

fn parseLogRename(allocator: std.mem.Allocator, jr: RenameJson) !LogRename {
    const from: LogRename.from_union = blk: {
        if (jr.from_log_field) |field_name| {
            break :blk .{ .from_log_field = try parseLogFieldName(field_name) };
        } else if (jr.from_log_attribute) |key| {
            break :blk .{ .from_log_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.from_resource_attribute) |key| {
            break :blk .{ .from_resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jr.from_scope_attribute) |key| {
            break :blk .{ .from_scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    return LogRename{
        .from = from,
        .to = try allocator.dupe(u8, jr.to),
        .upsert = jr.upsert,
    };
}

fn parseLogAdd(allocator: std.mem.Allocator, ja: AddJson) !LogAdd {
    const field: LogAdd.field_union = blk: {
        if (ja.log_field) |field_name| {
            break :blk .{ .log_field = try parseLogFieldName(field_name) };
        } else if (ja.log_attribute) |key| {
            break :blk .{ .log_attribute = try makeAttributePath(allocator, key) };
        } else if (ja.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (ja.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    return LogAdd{
        .field = field,
        .value = try allocator.dupe(u8, ja.value),
        .upsert = ja.upsert,
    };
}

// =============================================================================
// Metric Target Parsing
// =============================================================================

fn parseMetricTarget(allocator: std.mem.Allocator, json: MetricTargetJson) !MetricTarget {
    var matchers = std.ArrayListUnmanaged(MetricMatcher){};

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseMetricMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    return MetricTarget{
        .match = matchers,
        .keep = json.keep,
    };
}

fn parseMetricMatcher(allocator: std.mem.Allocator, jm: MetricMatcherJson) !MetricMatcher {
    // Parse field
    const field: MetricMatcher.field_union = blk: {
        if (jm.metric_field) |field_name| {
            break :blk .{ .metric_field = try parseMetricFieldName(field_name) };
        } else if (jm.datapoint_attribute) |key| {
            break :blk .{ .datapoint_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else {
            return error.MissingField;
        }
    };

    // Parse match
    const match: MetricMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else {
            return error.MissingMatch;
        }
    };

    return MetricMatcher{
        .negate = jm.negate,
        .field = field,
        .match = match,
    };
}

fn parseMetricFieldName(name: []const u8) !MetricField {
    if (std.mem.eql(u8, name, "name")) return .METRIC_FIELD_NAME;
    if (std.mem.eql(u8, name, "description")) return .METRIC_FIELD_DESCRIPTION;
    if (std.mem.eql(u8, name, "unit")) return .METRIC_FIELD_UNIT;
    if (std.mem.eql(u8, name, "resource_schema_url")) return .METRIC_FIELD_RESOURCE_SCHEMA_URL;
    if (std.mem.eql(u8, name, "scope_schema_url")) return .METRIC_FIELD_SCOPE_SCHEMA_URL;
    if (std.mem.eql(u8, name, "scope_name")) return .METRIC_FIELD_SCOPE_NAME;
    if (std.mem.eql(u8, name, "scope_version")) return .METRIC_FIELD_SCOPE_VERSION;
    return error.InvalidMetricField;
}

// =============================================================================
// Trace Target Parsing
// =============================================================================

fn parseTraceTarget(allocator: std.mem.Allocator, json: TraceTargetJson) !TraceTarget {
    var matchers = std.ArrayListUnmanaged(TraceMatcher){};

    if (json.match) |json_matchers| {
        try matchers.ensureTotalCapacity(allocator, json_matchers.len);
        for (json_matchers) |jm| {
            const matcher = try parseTraceMatcher(allocator, jm);
            matchers.appendAssumeCapacity(matcher);
        }
    }

    var sampling_config: ?TraceSamplingConfig = null;
    if (json.keep) |jk| {
        sampling_config = try parseTraceSamplingConfig(jk);
    }

    return TraceTarget{
        .match = matchers,
        .keep = sampling_config,
    };
}

fn parseTraceMatcher(allocator: std.mem.Allocator, jm: TraceMatcherJson) !TraceMatcher {
    // Parse field
    const field: TraceMatcher.field_union = blk: {
        if (jm.trace_field) |field_name| {
            break :blk .{ .trace_field = try parseTraceFieldName(field_name) };
        } else if (jm.span_attribute) |key| {
            break :blk .{ .span_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.resource_attribute) |key| {
            break :blk .{ .resource_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.scope_attribute) |key| {
            break :blk .{ .scope_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.span_kind) |kind_name| {
            break :blk .{ .span_kind = try parseSpanKind(kind_name) };
        } else if (jm.span_status) |status_name| {
            break :blk .{ .span_status = try parseSpanStatusCode(status_name) };
        } else if (jm.event_name) |name| {
            break :blk .{ .event_name = try allocator.dupe(u8, name) };
        } else if (jm.event_attribute) |key| {
            break :blk .{ .event_attribute = try makeAttributePath(allocator, key) };
        } else if (jm.link_trace_id) |id| {
            break :blk .{ .link_trace_id = try allocator.dupe(u8, id) };
        } else {
            return error.MissingField;
        }
    };

    // Parse match
    const match: TraceMatcher.match_union = blk: {
        if (jm.regex) |pattern| {
            break :blk .{ .regex = try allocator.dupe(u8, pattern) };
        } else if (jm.exact) |pattern| {
            break :blk .{ .exact = try allocator.dupe(u8, pattern) };
        } else if (jm.exists) |exists| {
            break :blk .{ .exists = exists };
        } else {
            return error.MissingMatch;
        }
    };

    return TraceMatcher{
        .negate = jm.negate,
        .field = field,
        .match = match,
    };
}

fn parseTraceFieldName(name: []const u8) !TraceField {
    if (std.mem.eql(u8, name, "TRACE_FIELD_NAME")) return .TRACE_FIELD_NAME;
    if (std.mem.eql(u8, name, "TRACE_FIELD_TRACE_ID")) return .TRACE_FIELD_TRACE_ID;
    if (std.mem.eql(u8, name, "TRACE_FIELD_SPAN_ID")) return .TRACE_FIELD_SPAN_ID;
    if (std.mem.eql(u8, name, "TRACE_FIELD_PARENT_SPAN_ID")) return .TRACE_FIELD_PARENT_SPAN_ID;
    if (std.mem.eql(u8, name, "TRACE_FIELD_TRACE_STATE")) return .TRACE_FIELD_TRACE_STATE;
    if (std.mem.eql(u8, name, "TRACE_FIELD_RESOURCE_SCHEMA_URL")) return .TRACE_FIELD_RESOURCE_SCHEMA_URL;
    if (std.mem.eql(u8, name, "TRACE_FIELD_SCOPE_SCHEMA_URL")) return .TRACE_FIELD_SCOPE_SCHEMA_URL;
    if (std.mem.eql(u8, name, "TRACE_FIELD_SCOPE_NAME")) return .TRACE_FIELD_SCOPE_NAME;
    if (std.mem.eql(u8, name, "TRACE_FIELD_SCOPE_VERSION")) return .TRACE_FIELD_SCOPE_VERSION;
    return error.InvalidTraceField;
}

fn parseSpanKind(name: []const u8) !SpanKind {
    if (std.mem.eql(u8, name, "SPAN_KIND_UNSPECIFIED")) return .SPAN_KIND_UNSPECIFIED;
    if (std.mem.eql(u8, name, "SPAN_KIND_INTERNAL")) return .SPAN_KIND_INTERNAL;
    if (std.mem.eql(u8, name, "SPAN_KIND_SERVER")) return .SPAN_KIND_SERVER;
    if (std.mem.eql(u8, name, "SPAN_KIND_CLIENT")) return .SPAN_KIND_CLIENT;
    if (std.mem.eql(u8, name, "SPAN_KIND_PRODUCER")) return .SPAN_KIND_PRODUCER;
    if (std.mem.eql(u8, name, "SPAN_KIND_CONSUMER")) return .SPAN_KIND_CONSUMER;
    return error.InvalidSpanKind;
}

fn parseSpanStatusCode(name: []const u8) !SpanStatusCode {
    if (std.mem.eql(u8, name, "SPAN_STATUS_CODE_UNSPECIFIED")) return .SPAN_STATUS_CODE_UNSPECIFIED;
    if (std.mem.eql(u8, name, "SPAN_STATUS_CODE_OK")) return .SPAN_STATUS_CODE_OK;
    if (std.mem.eql(u8, name, "SPAN_STATUS_CODE_ERROR")) return .SPAN_STATUS_CODE_ERROR;
    return error.InvalidSpanStatusCode;
}

fn parseSamplingMode(name: []const u8) !SamplingMode {
    if (std.mem.eql(u8, name, "SAMPLING_MODE_UNSPECIFIED")) return .SAMPLING_MODE_UNSPECIFIED;
    if (std.mem.eql(u8, name, "SAMPLING_MODE_HASH_SEED")) return .SAMPLING_MODE_HASH_SEED;
    if (std.mem.eql(u8, name, "SAMPLING_MODE_PROPORTIONAL")) return .SAMPLING_MODE_PROPORTIONAL;
    if (std.mem.eql(u8, name, "SAMPLING_MODE_EQUALIZING")) return .SAMPLING_MODE_EQUALIZING;
    return error.InvalidSamplingMode;
}

fn parseTraceSamplingConfig(jk: TraceSamplingConfigJson) !TraceSamplingConfig {
    var config = TraceSamplingConfig{
        .percentage = jk.percentage,
    };

    if (jk.mode) |mode_name| {
        config.mode = try parseSamplingMode(mode_name);
    }

    config.sampling_precision = jk.sampling_precision;
    config.hash_seed = jk.hash_seed;
    config.fail_closed = jk.fail_closed;

    return config;
}

// =============================================================================
// Keep Value Parsing
// =============================================================================

/// Parse keep value - validates format
/// Valid formats: "all", "none", "N%", "N/s", "N/m"
pub fn parseKeepValue(s: []const u8) !void {
    if (s.len == 0 or std.mem.eql(u8, s, "all") or std.mem.eql(u8, s, "none")) {
        return;
    }
    // Check for percentage: "N%"
    if (s.len >= 2 and s[s.len - 1] == '%') {
        const num_str = s[0 .. s.len - 1];
        const pct = std.fmt.parseInt(u8, num_str, 10) catch return error.InvalidKeepValue;
        if (pct > 100) return error.InvalidKeepValue;
        return;
    }
    // Check for rate limit: "N/s" or "N/m"
    if (s.len >= 3 and s[s.len - 2] == '/') {
        const num_str = s[0 .. s.len - 2];
        _ = std.fmt.parseInt(u32, num_str, 10) catch return error.InvalidKeepValue;
        if (s[s.len - 1] != 's' and s[s.len - 1] != 'm') {
            return error.InvalidKeepValue;
        }
        return;
    }
    return error.InvalidKeepValue;
}

// =============================================================================
// Tests
// =============================================================================

test "parseKeepValue" {
    try parseKeepValue("all");
    try parseKeepValue("none");
    try parseKeepValue("");
    try parseKeepValue("50%");
    try parseKeepValue("0%");
    try parseKeepValue("100%");
    try parseKeepValue("100/s");
    try parseKeepValue("1000/m");

    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("101%"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("invalid"));
    try std.testing.expectError(error.InvalidKeepValue, parseKeepValue("100/x"));
}

test "parsePoliciesBytes: log policy with new format" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-health-checks",
        \\      "name": "Drop health check logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "GET /health" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("drop-health-checks", policies[0].id);
    try std.testing.expectEqualStrings("Drop health check logs", policies[0].name);
    try std.testing.expect(policies[0].enabled);

    // Verify it's a log target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .log);

    const log_target = policies[0].target.?.log;
    try std.testing.expectEqualStrings("none", log_target.keep);
    try std.testing.expectEqual(@as(usize, 1), log_target.match.items.len);

    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_BODY, matcher.field.?.log_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("GET /health", matcher.match.?.regex);
}

test "parsePoliciesBytes: metric policy with new format" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-debug-metrics",
        \\      "name": "Drop debug metrics",
        \\      "metric": {
        \\        "match": [
        \\          { "metric_field": "name", "regex": "^debug\\." }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("drop-debug-metrics", policies[0].id);
    try std.testing.expectEqualStrings("Drop debug metrics", policies[0].name);
    try std.testing.expect(policies[0].enabled);

    // Verify it's a metric target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .metric);

    const metric_target = policies[0].target.?.metric;
    try std.testing.expectEqual(false, metric_target.keep);
    try std.testing.expectEqual(@as(usize, 1), metric_target.match.items.len);

    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .metric_field);
    try std.testing.expectEqual(MetricField.METRIC_FIELD_NAME, matcher.field.?.metric_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("^debug\\.", matcher.match.?.regex);
}

test "parsePoliciesBytes: log policy with attribute matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-dev-logs",
        \\      "name": "Drop development logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_attribute": "environment", "exact": "development" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expectEqualStrings("environment", matcher.field.?.log_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exact);
    try std.testing.expectEqualStrings("development", matcher.match.?.exact);
}

test "parsePoliciesBytes: metric policy with datapoint attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "drop-dev-metrics",
        \\      "name": "Drop development metrics",
        \\      "metric": {
        \\        "match": [
        \\          { "datapoint_attribute": "env", "regex": "dev" }
        \\        ],
        \\        "keep": false
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const metric_target = policies[0].target.?.metric;
    const matcher = metric_target.match.items[0];
    try std.testing.expect(matcher.field.? == .datapoint_attribute);
    try std.testing.expectEqualStrings("env", matcher.field.?.datapoint_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("dev", matcher.match.?.regex);
}

test "parsePoliciesBytes: log policy with transform" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "redact-sensitive",
        \\      "name": "Redact sensitive data",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "password" }
        \\        ],
        \\        "keep": "all",
        \\        "transform": {
        \\          "redact": [
        \\            { "log_attribute": "password", "replacement": "***" }
        \\          ],
        \\          "remove": [
        \\            { "log_attribute": "secret_key" }
        \\          ]
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    try std.testing.expectEqualStrings("all", log_target.keep);
    try std.testing.expect(log_target.transform != null);

    const transform = log_target.transform.?;
    try std.testing.expectEqual(@as(usize, 1), transform.redact.items.len);
    try std.testing.expectEqual(@as(usize, 1), transform.remove.items.len);

    // Check redact
    const redact = transform.redact.items[0];
    try std.testing.expect(redact.field.? == .log_attribute);
    try std.testing.expectEqualStrings("password", redact.field.?.log_attribute.path.items[0]);
    try std.testing.expectEqualStrings("***", redact.replacement);

    // Check remove
    const remove = transform.remove.items[0];
    try std.testing.expect(remove.field.? == .log_attribute);
    try std.testing.expectEqualStrings("secret_key", remove.field.?.log_attribute.path.items[0]);
}

test "parsePoliciesBytes: mixed log and metric policies" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "log-policy",
        \\      "name": "Log Policy",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "error" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    },
        \\    {
        \\      "id": "metric-policy",
        \\      "name": "Metric Policy",
        \\      "metric": {
        \\        "match": [
        \\          { "metric_field": "name", "regex": "test_.*" }
        \\        ],
        \\        "keep": true
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 2), policies.len);

    // First policy should be log
    try std.testing.expectEqualStrings("log-policy", policies[0].id);
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .log);

    // Second policy should be metric
    try std.testing.expectEqualStrings("metric-policy", policies[1].id);
    try std.testing.expect(policies[1].target != null);
    try std.testing.expect(policies[1].target.? == .metric);
}

test "parsePoliciesBytes: negated matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-non-debug",
        \\      "name": "Keep non-debug logs",
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "severity_text", "regex": "DEBUG", "negate": true }
        \\        ],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.negate);
    try std.testing.expect(matcher.field.? == .log_field);
    try std.testing.expectEqual(LogField.LOG_FIELD_SEVERITY_TEXT, matcher.field.?.log_field);
}

test "parsePoliciesBytes: exists matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "require-trace",
        \\      "name": "Require trace ID",
        \\      "log": {
        \\        "match": [
        \\          { "log_attribute": "trace_id", "exists": true }
        \\        ],
        \\        "keep": "all"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const log_target = policies[0].target.?.log;
    const matcher = log_target.match.items[0];
    try std.testing.expect(matcher.field.? == .log_attribute);
    try std.testing.expectEqualStrings("trace_id", matcher.field.?.log_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);
}

test "parsePoliciesBytes: disabled policy" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "disabled-policy",
        \\      "name": "Disabled Policy",
        \\      "enabled": false,
        \\      "log": {
        \\        "match": [
        \\          { "log_field": "body", "regex": "test" }
        \\        ],
        \\        "keep": "none"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expect(!policies[0].enabled);
}

test "parsePoliciesBytes: trace policy with span name matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-ping-spans",
        \\      "name": "Sample ping spans at 50%",
        \\      "trace": {
        \\        "match": [
        \\          { "trace_field": "TRACE_FIELD_NAME", "regex": "^ping$" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 50.0,
        \\          "mode": "SAMPLING_MODE_HASH_SEED",
        \\          "sampling_precision": 4
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);
    try std.testing.expectEqualStrings("sample-ping-spans", policies[0].id);

    // Verify it's a trace target
    try std.testing.expect(policies[0].target != null);
    try std.testing.expect(policies[0].target.? == .trace);

    const trace_target = policies[0].target.?.trace;
    try std.testing.expectEqual(@as(usize, 1), trace_target.match.items.len);

    // Check matcher
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field != null);
    try std.testing.expect(matcher.field.? == .trace_field);
    try std.testing.expectEqual(TraceField.TRACE_FIELD_NAME, matcher.field.?.trace_field);
    try std.testing.expect(matcher.match != null);
    try std.testing.expect(matcher.match.? == .regex);
    try std.testing.expectEqualStrings("^ping$", matcher.match.?.regex);

    // Check sampling config
    try std.testing.expect(trace_target.keep != null);
    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 50.0), sampling.percentage);
    try std.testing.expect(sampling.mode != null);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_HASH_SEED, sampling.mode.?);
    try std.testing.expect(sampling.sampling_precision != null);
    try std.testing.expectEqual(@as(u32, 4), sampling.sampling_precision.?);
}

test "parsePoliciesBytes: trace policy with span kind matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-internal-spans",
        \\      "name": "Sample internal spans",
        \\      "trace": {
        \\        "match": [
        \\          { "span_kind": "SPAN_KIND_INTERNAL", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 75.0,
        \\          "mode": "SAMPLING_MODE_EQUALIZING"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_kind);
    try std.testing.expectEqual(SpanKind.SPAN_KIND_INTERNAL, matcher.field.?.span_kind);
    try std.testing.expect(matcher.match.? == .exists);
    try std.testing.expectEqual(true, matcher.match.?.exists);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 75.0), sampling.percentage);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_EQUALIZING, sampling.mode.?);
}

test "parsePoliciesBytes: trace policy with span attribute" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-peer-service",
        \\      "name": "Sample spans with peer.service",
        \\      "trace": {
        \\        "match": [
        \\          { "span_attribute": "peer.service", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 10.0,
        \\          "hash_seed": 12345
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_attribute);
    try std.testing.expectEqualStrings("peer.service", matcher.field.?.span_attribute.path.items[0]);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 10.0), sampling.percentage);
    try std.testing.expect(sampling.hash_seed != null);
    try std.testing.expectEqual(@as(u32, 12345), sampling.hash_seed.?);
}

test "parsePoliciesBytes: trace policy with resource attribute and exact match" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "sample-test-service",
        \\      "name": "Sample test-service spans",
        \\      "trace": {
        \\        "match": [
        \\          { "resource_attribute": "service.name", "exact": "test-service" }
        \\        ],
        \\        "keep": {
        \\          "percentage": 25.0,
        \\          "mode": "SAMPLING_MODE_PROPORTIONAL",
        \\          "sampling_precision": 6
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .resource_attribute);
    try std.testing.expectEqualStrings("service.name", matcher.field.?.resource_attribute.path.items[0]);
    try std.testing.expect(matcher.match.? == .exact);
    try std.testing.expectEqualStrings("test-service", matcher.match.?.exact);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 25.0), sampling.percentage);
    try std.testing.expectEqual(SamplingMode.SAMPLING_MODE_PROPORTIONAL, sampling.mode.?);
    try std.testing.expectEqual(@as(u32, 6), sampling.sampling_precision.?);
}

test "parsePoliciesBytes: trace policy with span status matcher" {
    const allocator = std.testing.allocator;

    const json =
        \\{
        \\  "policies": [
        \\    {
        \\      "id": "keep-error-spans",
        \\      "name": "Keep all error spans",
        \\      "trace": {
        \\        "match": [
        \\          { "span_status": "SPAN_STATUS_CODE_ERROR", "exists": true }
        \\        ],
        \\        "keep": {
        \\          "percentage": 100.0
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const policies = try parsePoliciesBytes(allocator, json);
    defer {
        for (policies) |*p| {
            p.deinit(allocator);
        }
        allocator.free(policies);
    }

    try std.testing.expectEqual(@as(usize, 1), policies.len);

    const trace_target = policies[0].target.?.trace;
    const matcher = trace_target.match.items[0];
    try std.testing.expect(matcher.field.? == .span_status);
    try std.testing.expectEqual(SpanStatusCode.SPAN_STATUS_CODE_ERROR, matcher.field.?.span_status);

    const sampling = trace_target.keep.?;
    try std.testing.expectEqual(@as(f32, 100.0), sampling.percentage);
}
