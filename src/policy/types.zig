const std = @import("std");
const proto = @import("proto");
const provider_http = @import("./provider_http.zig");

pub const Header = provider_http.Header;

// =============================================================================
// TelemetryType - Distinguishes between log and metric telemetry
// =============================================================================

/// Type of telemetry being evaluated
pub const TelemetryType = enum {
    /// Log telemetry (OTLP logs, Datadog logs, etc.)
    log,
    /// Metric telemetry (Prometheus, OTLP metrics, etc.)
    metric,
    /// Trace telemetry (OTLP traces only - Datadog traces not supported)
    trace,
};

// =============================================================================
// Service and Provider Configuration
// =============================================================================

/// Service metadata for identifying this edge instance
pub const ServiceMetadata = struct {
    /// Service name (e.g., "tero-edge")
    name: []const u8 = "tero-edge",
    /// Service namespace (e.g., "tero")
    namespace: []const u8 = "tero",
    /// Service version (e.g., "0.1.0", defaults to "latest")
    version: []const u8 = "latest",
    /// Service instance ID - generated at startup, not configurable
    /// This field is set by the runtime, not from config
    instance_id: []const u8 = "",
};

/// Provider type enumeration
pub const ProviderType = enum {
    file,
    http,
};

/// Configuration for a policy provider
pub const ProviderConfig = struct {
    /// Unique identifier for this provider (used to track which policies came from where)
    id: []const u8,
    type: ProviderType,
    // For file provider
    path: ?[]const u8 = null,
    // For http provider
    url: ?[]const u8 = null,
    poll_interval: ?u64 = null, // seconds
    headers: []const Header = &.{}, // custom headers for http provider
};

// =============================================================================
// Field Reference Types
// =============================================================================

const LogRemove = proto.policy.LogRemove;
const LogRedact = proto.policy.LogRedact;
const LogRename = proto.policy.LogRename;
const LogAdd = proto.policy.LogAdd;
const LogMatcher = proto.policy.LogMatcher;
const LogField = proto.policy.LogField;
const MetricMatcher = proto.policy.MetricMatcher;
const MetricField = proto.policy.MetricField;

/// Reference to a field for accessor/mutator operations
pub const FieldRef = union(enum) {
    log_field: LogField,
    log_attribute: []const u8,
    resource_attribute: []const u8,
    scope_attribute: []const u8,

    pub fn fromRemoveField(field: ?LogRemove.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromRedactField(field: ?LogRedact.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromRenameFrom(from: ?LogRename.from_union) ?FieldRef {
        const f = from orelse return null;
        return switch (f) {
            .from_log_field => |v| .{ .log_field = v },
            .from_log_attribute => |v| .{ .log_attribute = v },
            .from_resource_attribute => |v| .{ .resource_attribute = v },
            .from_scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromAddField(field: ?LogAdd.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    pub fn fromMatcherField(field: ?LogMatcher.field_union) ?FieldRef {
        const f = field orelse return null;
        return switch (f) {
            .log_field => |v| .{ .log_field = v },
            .log_attribute => |v| .{ .log_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
        };
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: FieldRef) bool {
        return switch (self) {
            .log_attribute, .resource_attribute, .scope_attribute => true,
            .log_field => false,
        };
    }

    /// Get the key for attribute-based fields, empty string for log_field
    pub fn getKey(self: FieldRef) []const u8 {
        return switch (self) {
            .log_attribute => |k| k,
            .resource_attribute => |k| k,
            .scope_attribute => |k| k,
            .log_field => "",
        };
    }
};

// =============================================================================
// Metric Field Reference Types
// =============================================================================

const MetricType = proto.policy.MetricType;
const AggregationTemporality = proto.policy.AggregationTemporality;

/// Reference to a metric field for accessor/mutator operations.
/// Enum fields (metric_type, aggregation_temporality) are matched as strings via Hyperscan.
pub const MetricFieldRef = union(enum) {
    metric_field: MetricField,
    datapoint_attribute: []const u8,
    resource_attribute: []const u8,
    scope_attribute: []const u8,
    /// Match on metric type (gauge, sum, histogram, etc.)
    /// The field accessor returns the type as a string, matched via regex.
    metric_type: void,
    /// Match on aggregation temporality (delta, cumulative)
    /// The field accessor returns the temporality as a string, matched via regex.
    aggregation_temporality: void,

    pub fn fromMatcherField(field: ?MetricMatcher.field_union) ?MetricFieldRef {
        const f = field orelse return null;
        return switch (f) {
            .metric_field => |v| .{ .metric_field = v },
            .datapoint_attribute => |v| .{ .datapoint_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
            .metric_type => .{ .metric_type = {} },
            .aggregation_temporality => .{ .aggregation_temporality = {} },
        };
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: MetricFieldRef) bool {
        return switch (self) {
            .datapoint_attribute, .resource_attribute, .scope_attribute => true,
            .metric_field, .metric_type, .aggregation_temporality => false,
        };
    }

    /// Get the key for attribute-based fields, empty string for simple fields
    pub fn getKey(self: MetricFieldRef) []const u8 {
        return switch (self) {
            .datapoint_attribute => |k| k,
            .resource_attribute => |k| k,
            .scope_attribute => |k| k,
            .metric_field, .metric_type, .aggregation_temporality => "",
        };
    }
};

// =============================================================================
// Log Field Accessor/Mutator Types
// =============================================================================

/// Log field accessor function type - returns the value for a given log field
/// Returns null if the field doesn't exist
pub const LogFieldAccessor = *const fn (ctx: *const anyopaque, field: FieldRef) ?[]const u8;

/// Log field mutator function type - sets, removes, or renames a log field
/// Returns true if the operation succeeded
pub const LogFieldMutator = *const fn (ctx: *anyopaque, op: MutateOp) bool;

// =============================================================================
// Metric Field Accessor/Mutator Types
// =============================================================================

/// Metric field accessor function type - returns the value for a given metric field
/// Returns null if the field doesn't exist
pub const MetricFieldAccessor = *const fn (ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8;

/// Metric field mutator function type - sets, removes, or renames a metric field
/// Returns true if the operation succeeded
pub const MetricFieldMutator = *const fn (ctx: *anyopaque, op: MetricMutateOp) bool;

/// Mutation operation for log field mutator
pub const MutateOp = union(enum) {
    /// Remove a field entirely
    remove: FieldRef,
    /// Set a field to a value (upsert controls insert vs update behavior)
    set: struct {
        field: FieldRef,
        value: []const u8,
        upsert: bool,
    },
    /// Rename a field (move value from one field to another)
    rename: struct {
        from: FieldRef,
        to: []const u8,
        upsert: bool,
    },
};

/// Mutation operation for metric field mutator
pub const MetricMutateOp = union(enum) {
    /// Remove a field entirely
    remove: MetricFieldRef,
    /// Set a field to a value (upsert controls insert vs update behavior)
    set: struct {
        field: MetricFieldRef,
        value: []const u8,
        upsert: bool,
    },
    /// Rename a field (move value from one field to another)
    rename: struct {
        from: MetricFieldRef,
        to: []const u8,
        upsert: bool,
    },
};

// =============================================================================
// Trace Field Reference Types
// =============================================================================

const TraceMatcher = proto.policy.TraceMatcher;
const TraceField = proto.policy.TraceField;
const SpanKind = proto.policy.SpanKind;
const SpanStatusCode = proto.policy.SpanStatusCode;

/// Reference to a trace/span field for accessor/mutator operations.
/// Supports all field types from TraceMatcher for comprehensive span matching.
pub const TraceFieldRef = union(enum) {
    /// Simple trace fields (name, trace_id, span_id, etc.)
    trace_field: TraceField,
    /// Span attribute by key
    span_attribute: []const u8,
    /// Resource attribute by key
    resource_attribute: []const u8,
    /// Scope attribute by key
    scope_attribute: []const u8,
    /// Match on span kind (enum value)
    span_kind: SpanKind,
    /// Match on span status code (enum value)
    span_status: SpanStatusCode,
    /// Event name matcher (matches if span contains an event with this name)
    event_name: []const u8,
    /// Event attribute matcher (matches if span contains an event with this attribute)
    event_attribute: []const u8,
    /// Link trace ID matcher (matches if span has a link to this trace)
    link_trace_id: []const u8,

    pub fn fromMatcherField(field: ?TraceMatcher.field_union) ?TraceFieldRef {
        const f = field orelse return null;
        return switch (f) {
            .trace_field => |v| .{ .trace_field = v },
            .span_attribute => |v| .{ .span_attribute = v },
            .resource_attribute => |v| .{ .resource_attribute = v },
            .scope_attribute => |v| .{ .scope_attribute = v },
            .span_kind => |v| .{ .span_kind = v },
            .span_status => |v| .{ .span_status = v },
            .event_name => |v| .{ .event_name = v },
            .event_attribute => |v| .{ .event_attribute = v },
            .link_trace_id => |v| .{ .link_trace_id = v },
        };
    }

    /// Check if this field ref requires a key (attribute-based fields)
    pub fn isKeyed(self: TraceFieldRef) bool {
        return switch (self) {
            .span_attribute, .resource_attribute, .scope_attribute, .event_name, .event_attribute, .link_trace_id => true,
            .trace_field, .span_kind, .span_status => false,
        };
    }

    /// Get the key for attribute-based fields, empty string for simple fields
    pub fn getKey(self: TraceFieldRef) []const u8 {
        return switch (self) {
            .span_attribute => |k| k,
            .resource_attribute => |k| k,
            .scope_attribute => |k| k,
            .event_name => |k| k,
            .event_attribute => |k| k,
            .link_trace_id => |k| k,
            .trace_field, .span_kind, .span_status => "",
        };
    }
};

// =============================================================================
// Trace Field Accessor/Mutator Types
// =============================================================================

/// Trace field accessor function type - returns the value for a given trace/span field
/// Returns null if the field doesn't exist
pub const TraceFieldAccessor = *const fn (ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8;

/// Trace field mutator function type - sets, removes, or renames a trace/span field
/// Returns true if the operation succeeded
pub const TraceFieldMutator = *const fn (ctx: *anyopaque, op: TraceMutateOp) bool;

/// Mutation operation for trace field mutator
pub const TraceMutateOp = union(enum) {
    /// Remove a field entirely
    remove: TraceFieldRef,
    /// Set a field to a value (upsert controls insert vs update behavior)
    set: struct {
        field: TraceFieldRef,
        value: []const u8,
        upsert: bool,
    },
    /// Rename a field (move value from one field to another)
    rename: struct {
        from: TraceFieldRef,
        to: []const u8,
        upsert: bool,
    },
};

// =============================================================================
// Transform Result
// =============================================================================

/// Result of applying transforms to a log record.
/// Tracks both attempted and applied counts for each transform stage.
/// Used for reporting transform hit/miss statistics.
pub const TransformResult = struct {
    /// Number of remove operations attempted
    removes_attempted: usize = 0,
    /// Number of remove operations applied (hits)
    removes_applied: usize = 0,
    /// Number of redact operations attempted
    redacts_attempted: usize = 0,
    /// Number of redact operations applied (hits)
    redacts_applied: usize = 0,
    /// Number of rename operations attempted
    renames_attempted: usize = 0,
    /// Number of rename operations applied (hits)
    renames_applied: usize = 0,
    /// Number of add operations attempted
    adds_attempted: usize = 0,
    /// Number of add operations applied (hits)
    adds_applied: usize = 0,

    pub fn totalApplied(self: TransformResult) usize {
        return self.removes_applied + self.redacts_applied + self.renames_applied + self.adds_applied;
    }

    pub fn totalAttempted(self: TransformResult) usize {
        return self.removes_attempted + self.redacts_attempted + self.renames_attempted + self.adds_attempted;
    }
};
