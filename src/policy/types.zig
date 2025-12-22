const std = @import("std");
const proto = @import("proto");
const provider_http = @import("./provider_http.zig");

pub const Header = provider_http.Header;

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

/// Field accessor function type - returns the value for a given field
/// Returns null if the field doesn't exist
pub const FieldAccessor = *const fn (ctx: *const anyopaque, field: FieldRef) ?[]const u8;

/// Field mutator function type - sets, removes, or renames a field
/// Returns true if the operation succeeded
pub const FieldMutator = *const fn (ctx: *anyopaque, op: MutateOp) bool;

/// Mutation operation for field mutator
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
