//! Zonfig - Comptime-generated configuration with environment overrides
//!
//! A configuration system that uses comptime reflection to automatically generate:
//! - JSON parsing
//! - Environment variable overrides (with configurable prefix)
//! - Default values
//! - Validation
//!
//! ## Usage
//!
//! Define your config struct with defaults:
//!
//! ```zig
//! const MyConfig = struct {
//!     port: u16 = 8080,
//!     host: []const u8 = "localhost",
//!     debug: bool = false,
//!     nested: struct {
//!         timeout_ms: u32 = 5000,
//!     } = .{},
//! };
//!
//! // Load from JSON file with env overrides
//! const config = try zonfig.load(MyConfig, allocator, .{
//!     .json_path = "config.json",
//!     .env_prefix = "MYAPP",
//! });
//! defer zonfig.deinit(MyConfig, allocator, config);
//! ```
//!
//! Environment variables are named by converting field paths to SCREAMING_SNAKE_CASE:
//! - `port` -> `MYAPP_PORT`
//! - `nested.timeout_ms` -> `MYAPP_NESTED_TIMEOUT_MS`
//!
//! Environment variables override JSON values, which override defaults.

const std = @import("std");
pub const env_subst = @import("env_subst.zig");

// =============================================================================
// Public Types
// =============================================================================

pub const LoadOptions = struct {
    /// Path to JSON config file (optional - if null, uses defaults + env only)
    json_path: ?[]const u8 = null,
    /// Prefix for environment variables (e.g., "TERO" -> TERO_PORT)
    env_prefix: []const u8 = "",
    /// Whether to allow env-only mode (no JSON file required)
    allow_env_only: bool = true,
};

pub const LoadError = error{
    OutOfMemory,
    FileNotFound,
    JsonParseError,
    InvalidValue,
    UnclosedVariable,
    EmptyVariableName,
    InvalidVariableName,
    InvalidIpv4,
    Overflow,
};

// =============================================================================
// Core Functions
// =============================================================================

/// Load configuration from JSON file with environment variable overrides.
/// Priority: env vars > JSON values > struct defaults
pub fn load(comptime T: type, allocator: std.mem.Allocator, options: LoadOptions) LoadError!*T {
    const config = try allocator.create(T);
    errdefer allocator.destroy(config);

    // Start with defaults
    config.* = defaultValue(T);

    // Load JSON if path provided
    if (options.json_path) |path| {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => {
                if (!options.allow_env_only) return LoadError.FileNotFound;
                // Continue with defaults + env
                try applyEnvOverrides(T, allocator, config, options.env_prefix);
                return config;
            },
            else => return LoadError.FileNotFound,
        };
        defer file.close();

        const contents = file.readToEndAlloc(allocator, 10 * 1024 * 1024) catch return LoadError.OutOfMemory;
        defer allocator.free(contents);

        try parseJsonInto(T, allocator, config, contents);
    }

    // Apply environment overrides (highest priority)
    try applyEnvOverrides(T, allocator, config, options.env_prefix);

    // Apply environment variable substitution to all string fields
    try applyEnvSubstitution(T, allocator, config);

    return config;
}

/// Load configuration from JSON bytes with environment variable overrides.
/// Internal helper - use `load` with `json_path` for file-based loading.
fn loadFromBytes(comptime T: type, allocator: std.mem.Allocator, json_bytes: []const u8, env_prefix: []const u8) LoadError!*T {
    const config = try allocator.create(T);
    errdefer allocator.destroy(config);

    // Start with defaults
    config.* = defaultValue(T);

    // Parse JSON
    try parseJsonInto(T, allocator, config, json_bytes);

    // Apply environment overrides
    try applyEnvOverrides(T, allocator, config, env_prefix);

    return config;
}

/// Load configuration from environment variables only (no JSON).
/// Internal helper - use `load` with `json_path = null` for env-only loading.
fn loadFromEnv(comptime T: type, allocator: std.mem.Allocator, env_prefix: []const u8) LoadError!*T {
    const config = try allocator.create(T);
    errdefer allocator.destroy(config);

    // Start with defaults
    config.* = defaultValue(T);

    // Apply environment overrides
    try applyEnvOverrides(T, allocator, config, env_prefix);

    return config;
}

/// Free all allocated memory in a config struct.
pub fn deinit(comptime T: type, allocator: std.mem.Allocator, config: *T) void {
    freeAllocatedFields(T, allocator, config);
    allocator.destroy(config);
}

// =============================================================================
// Comptime Default Value Generation
// =============================================================================

/// Generate default value for a type using field defaults or zero values.
fn defaultValue(comptime T: type) T {
    const info = @typeInfo(T);

    return switch (info) {
        .@"struct" => |s| blk: {
            var result: T = undefined;
            inline for (s.fields) |field| {
                if (field.default_value_ptr) |default_ptr| {
                    const typed_ptr: *const field.type = @ptrCast(@alignCast(default_ptr));
                    @field(result, field.name) = typed_ptr.*;
                } else {
                    // Recurse for nested structs, or use zero value
                    @field(result, field.name) = defaultValue(field.type);
                }
            }
            break :blk result;
        },
        .optional => null,
        .pointer => |p| switch (p.size) {
            .slice => &.{},
            else => @compileError("Unsupported pointer type in config"),
        },
        .int, .float => 0,
        .bool => false,
        .@"enum" => |e| if (e.fields.len > 0) @enumFromInt(0) else @compileError("Empty enum"),
        .array => |a| [_]a.child{defaultValue(a.child)} ** a.len,
        else => @compileError("Unsupported type in config: " ++ @typeName(T)),
    };
}

// =============================================================================
// JSON Parsing
// =============================================================================

/// Parse JSON into an existing config struct, preserving defaults for missing fields.
fn parseJsonInto(comptime T: type, allocator: std.mem.Allocator, config: *T, json_bytes: []const u8) LoadError!void {
    const JsonT = jsonType(T);

    const parsed = std.json.parseFromSlice(
        JsonT,
        allocator,
        json_bytes,
        .{ .allocate = .alloc_always, .ignore_unknown_fields = true },
    ) catch return LoadError.JsonParseError;
    defer parsed.deinit();

    try applyJsonValues(T, allocator, config, parsed.value);
}

/// Generate the JSON-compatible type for parsing (makes all fields optional).
/// Special cases:
/// - [4]u8 arrays (IP addresses) are parsed as optional strings
/// - Enums are parsed as optional strings
/// - Nested structs are recursively converted
/// - Slices of structs are converted to optional slices of JSON-compatible structs
/// - All other fields become optional
fn jsonType(comptime T: type) type {
    const info = @typeInfo(T);

    return switch (info) {
        .@"struct" => |s| blk: {
            var fields: [s.fields.len]std.builtin.Type.StructField = undefined;
            inline for (s.fields, 0..) |field, i| {
                const FieldType = field.type;
                const JsonFieldType = if (@typeInfo(FieldType) == .@"struct")
                    ?jsonType(FieldType)
                else if (@typeInfo(FieldType) == .optional)
                    FieldType
                else if (@typeInfo(FieldType) == .array and @typeInfo(FieldType).array.child == u8)
                    // [N]u8 arrays (like IP addresses) are parsed as strings
                    ?[]const u8
                else if (@typeInfo(FieldType) == .@"enum")
                    // Enums are parsed as strings in JSON
                    ?[]const u8
                else if (@typeInfo(FieldType) == .pointer and @typeInfo(FieldType).pointer.size == .slice) blk2: {
                    const ChildType = @typeInfo(FieldType).pointer.child;
                    // Slice of structs - convert to optional slice of JSON-compatible structs
                    if (@typeInfo(ChildType) == .@"struct") {
                        break :blk2 ?[]const jsonType(ChildType);
                    } else {
                        // Other slices (strings, etc.) - just make optional
                        break :blk2 ?FieldType;
                    }
                } else ?FieldType;

                fields[i] = .{
                    .name = field.name,
                    .type = JsonFieldType,
                    .default_value_ptr = &@as(JsonFieldType, null),
                    .is_comptime = false,
                    .alignment = @alignOf(JsonFieldType),
                };
            }
            break :blk @Type(.{ .@"struct" = .{
                .layout = .auto,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            } });
        },
        else => T,
    };
}

/// Apply parsed JSON values to config.
fn applyJsonValues(comptime T: type, allocator: std.mem.Allocator, config: *T, json: anytype) LoadError!void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => |s| {
            inline for (s.fields) |field| {
                const json_value = @field(json, field.name);
                if (json_value != null) {
                    const value = json_value.?;
                    const field_ptr = &@field(config, field.name);

                    if (@typeInfo(field.type) == .@"struct") {
                        // Recurse into nested struct
                        try applyJsonValues(field.type, allocator, field_ptr, value);
                    } else if (@typeInfo(field.type) == .pointer and @typeInfo(field.type).pointer.size == .slice) {
                        const ChildType = @typeInfo(field.type).pointer.child;
                        if (ChildType == u8) {
                            // String field - copy value
                            field_ptr.* = allocator.dupe(u8, value) catch return LoadError.OutOfMemory;
                        } else if (@typeInfo(ChildType) == .@"struct") {
                            // Slice of structs - allocate and copy each element
                            const result = allocator.alloc(ChildType, value.len) catch return LoadError.OutOfMemory;
                            for (value, 0..) |json_elem, i| {
                                result[i] = defaultValue(ChildType);
                                try applyJsonValues(ChildType, allocator, &result[i], json_elem);
                            }
                            field_ptr.* = result;
                        } else {
                            // Other slices - copy as-is
                            field_ptr.* = allocator.dupe(ChildType, value) catch return LoadError.OutOfMemory;
                        }
                    } else if (@typeInfo(field.type) == .optional) {
                        // Optional field
                        const ChildType = @typeInfo(field.type).optional.child;
                        if (@typeInfo(ChildType) == .pointer and @typeInfo(ChildType).pointer.size == .slice) {
                            if (@typeInfo(ChildType).pointer.child == u8) {
                                // Optional string - copy value
                                field_ptr.* = allocator.dupe(u8, value) catch return LoadError.OutOfMemory;
                            }
                        } else {
                            field_ptr.* = value;
                        }
                    } else if (@typeInfo(field.type) == .array) {
                        // Fixed-size array (e.g., [4]u8 for IP address)
                        const ArrayInfo = @typeInfo(field.type).array;
                        if (ArrayInfo.child == u8) {
                            // Parse IP address string (value is []const u8 from jsonType)
                            field_ptr.* = parseIpv4(value) catch return LoadError.InvalidIpv4;
                        } else {
                            field_ptr.* = value;
                        }
                    } else if (@typeInfo(field.type) == .@"enum") {
                        // Parse enum from string
                        if (@TypeOf(value) == []const u8) {
                            field_ptr.* = std.meta.stringToEnum(field.type, value) orelse return LoadError.InvalidValue;
                        } else {
                            field_ptr.* = value;
                        }
                    } else {
                        // Scalar types
                        field_ptr.* = value;
                    }
                }
            }
        },
        else => {},
    }
}

// =============================================================================
// Environment Variable Overrides
// =============================================================================

/// Apply environment variable overrides to config.
fn applyEnvOverrides(comptime T: type, allocator: std.mem.Allocator, config: *T, prefix: []const u8) LoadError!void {
    // Build env var names at runtime using the prefix
    var env_name_buf: [256]u8 = undefined;
    try applyEnvOverridesRecursive(T, allocator, config, prefix, "", &env_name_buf);
}

fn applyEnvOverridesRecursive(
    comptime T: type,
    allocator: std.mem.Allocator,
    config: *T,
    prefix: []const u8,
    comptime path: []const u8,
    env_name_buf: *[256]u8,
) LoadError!void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => |s| {
            inline for (s.fields) |field| {
                const field_path = comptime if (path.len == 0)
                    field.name
                else
                    path ++ "_" ++ field.name;

                const field_ptr = &@field(config, field.name);

                if (@typeInfo(field.type) == .@"struct") {
                    // Recurse into nested struct
                    try applyEnvOverridesRecursive(field.type, allocator, field_ptr, prefix, field_path, env_name_buf);
                } else {
                    // Build env var name at runtime: PREFIX_FIELD_PATH
                    // field_path is comptime known, so we pass it directly
                    const env_name = buildEnvName(prefix, field_path, env_name_buf);
                    if (std.posix.getenv(env_name)) |env_value| {
                        try applyEnvValue(field.type, allocator, field_ptr, env_value);
                    }
                }
            }
        },
        else => {},
    }
}

/// Build environment variable name at runtime from prefix and field path.
/// Converts the result to SCREAMING_SNAKE_CASE.
fn buildEnvName(prefix: []const u8, field_path: []const u8, buf: *[256]u8) [:0]const u8 {
    var len: usize = 0;

    // Copy prefix and convert to uppercase
    for (prefix) |c| {
        if (len >= buf.len - 1) break;
        buf[len] = toUpper(c);
        len += 1;
    }

    // Add separator if prefix is non-empty
    if (prefix.len > 0 and field_path.len > 0) {
        if (len < buf.len - 1) {
            buf[len] = '_';
            len += 1;
        }
    }

    // Copy field path, converting to SCREAMING_SNAKE_CASE
    for (field_path) |c| {
        if (len >= buf.len - 1) break;
        buf[len] = toUpper(c);
        len += 1;
    }

    // Null terminate
    buf[len] = 0;
    return buf[0..len :0];
}

fn toUpper(c: u8) u8 {
    return if (c >= 'a' and c <= 'z') c - 'a' + 'A' else c;
}

/// Convert a field path to SCREAMING_SNAKE_CASE at comptime.
fn toScreamingSnake(comptime input: []const u8) [:0]const u8 {
    comptime {
        var result: [input.len * 2]u8 = undefined; // Max expansion for camelCase
        var len: usize = 0;

        for (input, 0..) |c, i| {
            if (c == '.') {
                result[len] = '_';
                len += 1;
            } else if (c >= 'a' and c <= 'z') {
                result[len] = c - 'a' + 'A';
                len += 1;
            } else if (c >= 'A' and c <= 'Z') {
                // Insert underscore before uppercase if not at start and prev wasn't underscore
                if (i > 0 and result[len - 1] != '_') {
                    result[len] = '_';
                    len += 1;
                }
                result[len] = c;
                len += 1;
            } else {
                result[len] = c;
                len += 1;
            }
        }

        result[len] = 0;
        return result[0..len :0];
    }
}

/// Apply a single environment variable value to a field.
fn applyEnvValue(comptime T: type, allocator: std.mem.Allocator, ptr: *T, env_value: []const u8) LoadError!void {
    const info = @typeInfo(T);

    switch (info) {
        .int => {
            ptr.* = std.fmt.parseInt(T, env_value, 10) catch return LoadError.InvalidValue;
        },
        .float => {
            ptr.* = std.fmt.parseFloat(T, env_value) catch return LoadError.InvalidValue;
        },
        .bool => {
            if (std.mem.eql(u8, env_value, "true") or std.mem.eql(u8, env_value, "1")) {
                ptr.* = true;
            } else if (std.mem.eql(u8, env_value, "false") or std.mem.eql(u8, env_value, "0")) {
                ptr.* = false;
            } else {
                return LoadError.InvalidValue;
            }
        },
        .@"enum" => {
            ptr.* = std.meta.stringToEnum(T, env_value) orelse return LoadError.InvalidValue;
        },
        .pointer => |p| {
            if (p.size == .slice and p.child == u8) {
                // String - free old value if it was allocated, then dupe new value
                // Note: we can't easily tell if the old value was allocated, so we
                // just allocate a new one. The deinit function will free it.
                ptr.* = allocator.dupe(u8, env_value) catch return LoadError.OutOfMemory;
            }
        },
        .optional => |o| {
            // For optional types, if env var is set to empty string, set to null
            if (env_value.len == 0) {
                ptr.* = null;
            } else {
                var inner_value: o.child = undefined;
                try applyEnvValue(o.child, allocator, &inner_value, env_value);
                ptr.* = inner_value;
            }
        },
        .array => |a| {
            if (a.child == u8) {
                // Parse as IP address string
                ptr.* = parseIpv4(env_value) catch return LoadError.InvalidIpv4;
            }
        },
        else => {},
    }
}

// =============================================================================
// Environment Variable Substitution
// =============================================================================

/// Apply environment variable substitution (${VAR}) to all string fields.
/// This is run as a final pass after JSON parsing and env overrides.
fn applyEnvSubstitution(comptime T: type, allocator: std.mem.Allocator, config: *T) LoadError!void {
    applyEnvSubstitutionWithDefaults(T, allocator, config, defaultValue(T)) catch |err| switch (err) {
        error.OutOfMemory => return LoadError.OutOfMemory,
        error.UnclosedVariable => return LoadError.UnclosedVariable,
        error.EmptyVariableName => return LoadError.EmptyVariableName,
        error.InvalidVariableName => return LoadError.InvalidVariableName,
    };
}

fn applyEnvSubstitutionWithDefaults(
    comptime T: type,
    allocator: std.mem.Allocator,
    config: *T,
    defaults: T,
) env_subst.SubstError!void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => |s| {
            inline for (s.fields) |field| {
                const field_ptr = &@field(config, field.name);
                const default_field = @field(defaults, field.name);

                if (@typeInfo(field.type) == .@"struct") {
                    // Recurse into nested struct
                    try applyEnvSubstitutionWithDefaults(field.type, allocator, field_ptr, default_field);
                } else if (@typeInfo(field.type) == .pointer) {
                    const p = @typeInfo(field.type).pointer;
                    if (p.size == .slice and p.child == u8) {
                        // String field - apply substitution
                        const current = field_ptr.*;
                        const result = try env_subst.substitute(allocator, current);
                        if (result.was_substituted) {
                            // Free old value if it was allocated (not a default)
                            if (current.ptr != default_field.ptr and current.len > 0) {
                                allocator.free(current);
                            }
                            field_ptr.* = result.value;
                        }
                    } else if (p.size == .slice and @typeInfo(p.child) == .@"struct") {
                        // Slice of structs - apply substitution to each element
                        const ChildType = p.child;
                        const child_default = defaultValue(ChildType);
                        for (field_ptr.*) |*elem| {
                            try applyEnvSubstitutionWithDefaults(ChildType, allocator, @constCast(elem), child_default);
                        }
                    }
                } else if (@typeInfo(field.type) == .optional) {
                    const ChildType = @typeInfo(field.type).optional.child;
                    if (@typeInfo(ChildType) == .pointer) {
                        const p = @typeInfo(ChildType).pointer;
                        if (p.size == .slice and p.child == u8) {
                            // Optional string field
                            if (field_ptr.*) |current| {
                                const result = try env_subst.substitute(allocator, current);
                                if (result.was_substituted) {
                                    // Free old value (optional strings are always allocated if non-null)
                                    if (current.len > 0) {
                                        allocator.free(current);
                                    }
                                    field_ptr.* = result.value;
                                }
                            }
                        }
                    }
                }
            }
        },
        else => {},
    }
}

// =============================================================================
// Memory Management
// =============================================================================

/// Free all allocated string fields in a config struct.
/// Only frees strings that differ from the default value (i.e., were allocated).
fn freeAllocatedFields(comptime T: type, allocator: std.mem.Allocator, config: *T) void {
    freeAllocatedFieldsWithDefaults(T, allocator, config, defaultValue(T));
}

fn freeAllocatedFieldsWithDefaults(comptime T: type, allocator: std.mem.Allocator, config: *T, defaults: T) void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => |s| {
            inline for (s.fields) |field| {
                const field_ptr = &@field(config, field.name);
                const default_field = @field(defaults, field.name);

                if (@typeInfo(field.type) == .@"struct") {
                    freeAllocatedFieldsWithDefaults(field.type, allocator, field_ptr, default_field);
                } else if (@typeInfo(field.type) == .pointer) {
                    const p = @typeInfo(field.type).pointer;
                    if (p.size == .slice) {
                        const slice = field_ptr.*;
                        // Only free if the pointer differs from the default (was allocated)
                        if (slice.ptr != default_field.ptr) {
                            if (p.child == u8) {
                                // String slice
                                if (slice.len > 0) {
                                    allocator.free(slice);
                                }
                            } else if (@typeInfo(p.child) == .@"struct") {
                                // Slice of structs - free each element's allocated fields, then free the slice
                                const ChildType = p.child;
                                const child_default = defaultValue(ChildType);
                                for (slice) |*elem| {
                                    freeAllocatedFieldsWithDefaults(ChildType, allocator, @constCast(elem), child_default);
                                }
                                if (slice.len > 0) {
                                    allocator.free(slice);
                                }
                            } else {
                                // Other slices
                                if (slice.len > 0) {
                                    allocator.free(slice);
                                }
                            }
                        }
                    }
                } else if (@typeInfo(field.type) == .optional) {
                    const ChildType = @typeInfo(field.type).optional.child;
                    if (@typeInfo(ChildType) == .pointer) {
                        const p = @typeInfo(ChildType).pointer;
                        if (p.size == .slice and p.child == u8) {
                            if (field_ptr.*) |slice| {
                                // For optionals, default is null, so any non-null value was allocated
                                if (slice.len > 0) {
                                    allocator.free(slice);
                                }
                            }
                        }
                    }
                }
            }
        },
        else => {},
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;

    while (iter.next()) |octet| : (i += 1) {
        if (i >= 4) return error.InvalidIpv4;
        result[i] = std.fmt.parseInt(u8, octet, 10) catch return error.Overflow;
    }

    if (i != 4) return error.InvalidIpv4;
    return result;
}

// =============================================================================
// Comptime Utilities (Internal)
// =============================================================================

/// Get the environment variable name suffix for a field path (comptime).
fn envNameSuffix(comptime field_path: []const u8) [:0]const u8 {
    return toScreamingSnake(field_path);
}

/// Check if a type can be configured via environment variable.
fn isEnvConfigurable(comptime T: type) bool {
    const info = @typeInfo(T);
    return switch (info) {
        .int, .float, .bool, .@"enum" => true,
        .pointer => |p| p.size == .slice and p.child == u8,
        .optional => |o| isEnvConfigurable(o.child),
        .array => |a| a.child == u8, // IP address
        else => false,
    };
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

/// Test helper to create a temporary JSON config file.
fn createTempConfigFile(dir: std.fs.Dir, content: []const u8) !void {
    const file = try dir.createFile("config.json", .{});
    defer file.close();
    try file.writeAll(content);
}

// -----------------------------------------------------------------------------
// load: defaults only (no JSON, no env)
// -----------------------------------------------------------------------------

test "load: defaults only - all types use defaults when no JSON or env" {
    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
        debug: bool = false,
        timeout_ms: u32 = 5000,
        rate: f32 = 1.5,
    };

    const config = try load(Config, testing.allocator, .{});
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.port);
    try testing.expectEqualStrings("localhost", config.host);
    try testing.expectEqual(false, config.debug);
    try testing.expectEqual(@as(u32, 5000), config.timeout_ms);
    try testing.expectEqual(@as(f32, 1.5), config.rate);
}

test "load: defaults only - nested structs use nested defaults" {
    const Config = struct {
        server: struct {
            port: u16 = 3000,
            host: []const u8 = "0.0.0.0",
        } = .{},
        client: struct {
            timeout: u32 = 10000,
            retries: u8 = 3,
        } = .{},
    };

    const config = try load(Config, testing.allocator, .{});
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 3000), config.server.port);
    try testing.expectEqualStrings("0.0.0.0", config.server.host);
    try testing.expectEqual(@as(u32, 10000), config.client.timeout);
    try testing.expectEqual(@as(u8, 3), config.client.retries);
}

test "load: defaults only - optional fields default to null" {
    const Config = struct {
        required: u16 = 8080,
        optional_port: ?u16 = null,
        optional_host: ?[]const u8 = null,
    };

    const config = try load(Config, testing.allocator, .{});
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.required);
    try testing.expectEqual(@as(?u16, null), config.optional_port);
    try testing.expectEqual(@as(?[]const u8, null), config.optional_host);
}

test "load: defaults only - array fields use defaults" {
    const Config = struct {
        ip_address: [4]u8 = .{ 127, 0, 0, 1 },
    };

    const config = try load(Config, testing.allocator, .{});
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &config.ip_address);
}

test "load: defaults only - enum fields use first value as default" {
    const LogLevel = enum { debug, info, warn, err };
    const Config = struct {
        level: LogLevel = .info,
    };

    const config = try load(Config, testing.allocator, .{});
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(LogLevel.info, config.level);
}

// -----------------------------------------------------------------------------
// load: JSON file parsing
// -----------------------------------------------------------------------------

test "load: JSON file - complete config overrides all defaults" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"port": 9000, "host": "example.com", "debug": true}
    );

    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
        debug: bool = false,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 9000), config.port);
    try testing.expectEqualStrings("example.com", config.host);
    try testing.expectEqual(true, config.debug);
}

test "load: JSON file - partial config preserves defaults for missing fields" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"port": 9000}
    );

    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
        debug: bool = false,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 9000), config.port);
    try testing.expectEqualStrings("localhost", config.host);
    try testing.expectEqual(false, config.debug);
}

test "load: JSON file - nested struct partial override" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"server": {"port": 9000}}
    );

    const Config = struct {
        server: struct {
            port: u16 = 8080,
            host: []const u8 = "localhost",
        } = .{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 9000), config.server.port);
    try testing.expectEqualStrings("localhost", config.server.host);
}

test "load: JSON file - deeply nested structs" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"a": {"b": {"c": {"value": 42}}}}
    );

    const Config = struct {
        a: struct {
            b: struct {
                c: struct {
                    value: u32 = 0,
                } = .{},
            } = .{},
        } = .{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u32, 42), config.a.b.c.value);
}

test "load: JSON file - ignores unknown fields" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"port": 9000, "unknown_field": "ignored", "another": 123}
    );

    const Config = struct {
        port: u16 = 8080,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 9000), config.port);
}

test "load: JSON file - empty object uses all defaults" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir, "{}");

    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.port);
    try testing.expectEqualStrings("localhost", config.host);
}

// -----------------------------------------------------------------------------
// load: file not found behavior
// -----------------------------------------------------------------------------

test "load: missing file - uses defaults when allow_env_only is true (default)" {
    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
    };

    const config = try load(Config, testing.allocator, .{
        .json_path = "/nonexistent/path/config.json",
    });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.port);
    try testing.expectEqualStrings("localhost", config.host);
}

test "load: missing file - returns error when allow_env_only is false" {
    const Config = struct {
        port: u16 = 8080,
    };

    const result = load(Config, testing.allocator, .{
        .json_path = "/nonexistent/path/config.json",
        .allow_env_only = false,
    });

    try testing.expectError(LoadError.FileNotFound, result);
}

// -----------------------------------------------------------------------------
// load: JSON parse errors
// -----------------------------------------------------------------------------

test "load: invalid JSON - returns JsonParseError" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir, "not valid json {{{");

    const Config = struct {
        port: u16 = 8080,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const result = load(Config, testing.allocator, .{ .json_path = path });
    try testing.expectError(LoadError.JsonParseError, result);
}

test "load: JSON type mismatch - returns JsonParseError" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"port": "not a number"}
    );

    const Config = struct {
        port: u16 = 8080,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const result = load(Config, testing.allocator, .{ .json_path = path });
    try testing.expectError(LoadError.JsonParseError, result);
}

// -----------------------------------------------------------------------------
// load: optional fields
// -----------------------------------------------------------------------------

test "load: JSON with optional fields - null values stay null" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"required": 9000}
    );

    const Config = struct {
        required: u16 = 8080,
        optional_port: ?u16 = null,
        optional_host: ?[]const u8 = null,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 9000), config.required);
    try testing.expectEqual(@as(?u16, null), config.optional_port);
    try testing.expectEqual(@as(?[]const u8, null), config.optional_host);
}

test "load: JSON with optional fields - provided values override null" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"optional_port": 9000, "optional_host": "example.com"}
    );

    const Config = struct {
        optional_port: ?u16 = null,
        optional_host: ?[]const u8 = null,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(?u16, 9000), config.optional_port);
    try testing.expectEqualStrings("example.com", config.optional_host.?);
}

// -----------------------------------------------------------------------------
// load: env_prefix behavior
// -----------------------------------------------------------------------------

test "load: empty env_prefix - no prefix used" {
    const Config = struct {
        port: u16 = 8080,
    };

    // With empty prefix, would look for just "PORT" env var (not set in test)
    const config = try load(Config, testing.allocator, .{ .env_prefix = "" });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.port);
}

test "load: env_prefix - is converted to uppercase" {
    const Config = struct {
        port: u16 = 8080,
    };

    // lowercase prefix should work (converted to MYAPP_PORT internally)
    const config = try load(Config, testing.allocator, .{ .env_prefix = "myapp" });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u16, 8080), config.port);
}

// -----------------------------------------------------------------------------
// load: memory management
// -----------------------------------------------------------------------------

test "load: memory - no leaks with defaults only" {
    const Config = struct {
        port: u16 = 8080,
        host: []const u8 = "localhost",
    };

    const config = try load(Config, testing.allocator, .{});
    deinit(Config, testing.allocator, config);
    // testing.allocator will detect leaks
}

test "load: memory - no leaks with JSON strings" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"host": "example.com", "url": "/api/v1"}
    );

    const Config = struct {
        host: []const u8 = "localhost",
        url: []const u8 = "/",
    };

    const file_path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(file_path);

    const config = try load(Config, testing.allocator, .{ .json_path = file_path });
    deinit(Config, testing.allocator, config);
    // testing.allocator will detect leaks
}

test "load: memory - no leaks with nested structs containing strings" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"server": {"host": "example.com"}, "client": {"name": "test-client"}}
    );

    const Config = struct {
        server: struct {
            host: []const u8 = "localhost",
        } = .{},
        client: struct {
            name: []const u8 = "default",
        } = .{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    deinit(Config, testing.allocator, config);
    // testing.allocator will detect leaks
}

test "load: memory - no leaks with optional strings" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"optional_host": "example.com"}
    );

    const Config = struct {
        optional_host: ?[]const u8 = null,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    deinit(Config, testing.allocator, config);
    // testing.allocator will detect leaks
}

// -----------------------------------------------------------------------------
// load: various scalar types
// -----------------------------------------------------------------------------

test "load: JSON with various integer types" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"u8_val": 255, "i32_val": -1000, "u64_val": 9999999999}
    );

    const Config = struct {
        u8_val: u8 = 0,
        i32_val: i32 = 0,
        u64_val: u64 = 0,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(u8, 255), config.u8_val);
    try testing.expectEqual(@as(i32, -1000), config.i32_val);
    try testing.expectEqual(@as(u64, 9999999999), config.u64_val);
}

test "load: JSON with float types" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"f32_val": 3.14, "f64_val": 2.718281828}
    );

    const Config = struct {
        f32_val: f32 = 0.0,
        f64_val: f64 = 0.0,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectApproxEqAbs(@as(f32, 3.14), config.f32_val, 0.001);
    try testing.expectApproxEqAbs(@as(f64, 2.718281828), config.f64_val, 0.0000001);
}

test "load: JSON with boolean values" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"enabled": true, "disabled": false}
    );

    const Config = struct {
        enabled: bool = false,
        disabled: bool = true,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(true, config.enabled);
    try testing.expectEqual(false, config.disabled);
}

// -----------------------------------------------------------------------------
// Internal helper tests (kept for regression)
// -----------------------------------------------------------------------------

test "internal: parseIpv4" {
    const addr = try parseIpv4("127.0.0.1");
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &addr);

    const addr2 = try parseIpv4("192.168.1.100");
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &addr2);

    const addr3 = try parseIpv4("0.0.0.0");
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, &addr3);

    const addr4 = try parseIpv4("255.255.255.255");
    try testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 255 }, &addr4);
}

test "internal: parseIpv4 - invalid inputs" {
    try testing.expectError(error.InvalidIpv4, parseIpv4("127.0.0"));
    try testing.expectError(error.InvalidIpv4, parseIpv4("127.0.0.1.2"));
    try testing.expectError(error.Overflow, parseIpv4("256.0.0.1"));
    try testing.expectError(error.Overflow, parseIpv4("127.0.0.-1"));
}

test "internal: buildEnvName" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings("TERO_PORT", buildEnvName("TERO", "port", &buf));
    try testing.expectEqualStrings("TERO_LISTEN_PORT", buildEnvName("TERO", "listen_port", &buf));
    try testing.expectEqualStrings("PORT", buildEnvName("", "port", &buf));
    try testing.expectEqualStrings("MYAPP_PORT", buildEnvName("myapp", "port", &buf));
    try testing.expectEqualStrings("APP_SERVER_HOST", buildEnvName("APP", "server_host", &buf));
}

// -----------------------------------------------------------------------------
// load: slice of structs
// -----------------------------------------------------------------------------

test "load: JSON with slice of structs - empty array" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"items": []}
    );

    const Item = struct {
        name: []const u8 = "default",
        value: u32 = 0,
    };
    const Config = struct {
        items: []Item = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 0), config.items.len);
}

test "load: JSON with slice of structs - single item" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"items": [{"name": "first", "value": 42}]}
    );

    const Item = struct {
        name: []const u8 = "default",
        value: u32 = 0,
    };
    const Config = struct {
        items: []Item = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 1), config.items.len);
    try testing.expectEqualStrings("first", config.items[0].name);
    try testing.expectEqual(@as(u32, 42), config.items[0].value);
}

test "load: JSON with slice of structs - multiple items" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"items": [{"name": "first", "value": 1}, {"name": "second", "value": 2}, {"name": "third", "value": 3}]}
    );

    const Item = struct {
        name: []const u8 = "default",
        value: u32 = 0,
    };
    const Config = struct {
        items: []Item = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 3), config.items.len);
    try testing.expectEqualStrings("first", config.items[0].name);
    try testing.expectEqual(@as(u32, 1), config.items[0].value);
    try testing.expectEqualStrings("second", config.items[1].name);
    try testing.expectEqual(@as(u32, 2), config.items[1].value);
    try testing.expectEqualStrings("third", config.items[2].name);
    try testing.expectEqual(@as(u32, 3), config.items[2].value);
}

test "load: JSON with slice of structs - partial item uses defaults" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"items": [{"name": "only_name"}, {"value": 99}]}
    );

    const Item = struct {
        name: []const u8 = "default",
        value: u32 = 0,
    };
    const Config = struct {
        items: []Item = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 2), config.items.len);
    // First item: name set, value default
    try testing.expectEqualStrings("only_name", config.items[0].name);
    try testing.expectEqual(@as(u32, 0), config.items[0].value);
    // Second item: name default, value set
    try testing.expectEqualStrings("default", config.items[1].name);
    try testing.expectEqual(@as(u32, 99), config.items[1].value);
}

test "load: JSON with nested slice of structs containing slices" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"providers": [{"id": "file", "path": "/etc/config"}, {"id": "http", "url": "https://example.com"}]}
    );

    const Provider = struct {
        id: []const u8 = "",
        path: ?[]const u8 = null,
        url: ?[]const u8 = null,
    };
    const Config = struct {
        providers: []Provider = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 2), config.providers.len);
    try testing.expectEqualStrings("file", config.providers[0].id);
    try testing.expectEqualStrings("/etc/config", config.providers[0].path.?);
    try testing.expectEqual(@as(?[]const u8, null), config.providers[0].url);
    try testing.expectEqualStrings("http", config.providers[1].id);
    try testing.expectEqual(@as(?[]const u8, null), config.providers[1].path);
    try testing.expectEqualStrings("https://example.com", config.providers[1].url.?);
}

test "load: memory - no leaks with slice of structs" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"items": [{"name": "allocated1", "value": 1}, {"name": "allocated2", "value": 2}]}
    );

    const Item = struct {
        name: []const u8 = "default",
        value: u32 = 0,
    };
    const Config = struct {
        items: []Item = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    deinit(Config, testing.allocator, config);
    // testing.allocator will detect leaks
}

// -----------------------------------------------------------------------------
// load: enum fields from JSON strings
// -----------------------------------------------------------------------------

test "load: JSON with enum field from string" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"level": "warn"}
    );

    const LogLevel = enum { debug, info, warn, err };
    const Config = struct {
        level: LogLevel = .info,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(LogLevel.warn, config.level);
}

test "load: JSON with slice of structs containing enums" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"providers": [{"id": "local", "type": "file"}, {"id": "remote", "type": "http"}]}
    );

    const ProviderType = enum { file, http };
    const Provider = struct {
        id: []const u8 = "",
        type: ProviderType = .file,
    };
    const Config = struct {
        providers: []Provider = &.{},
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const config = try load(Config, testing.allocator, .{ .json_path = path });
    defer deinit(Config, testing.allocator, config);

    try testing.expectEqual(@as(usize, 2), config.providers.len);
    try testing.expectEqualStrings("local", config.providers[0].id);
    try testing.expectEqual(ProviderType.file, config.providers[0].type);
    try testing.expectEqualStrings("remote", config.providers[1].id);
    try testing.expectEqual(ProviderType.http, config.providers[1].type);
}

test "load: JSON with invalid enum value returns error" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try createTempConfigFile(tmp_dir.dir,
        \\{"level": "invalid_level"}
    );

    const LogLevel = enum { debug, info, warn, err };
    const Config = struct {
        level: LogLevel = .info,
    };

    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "config.json");
    defer testing.allocator.free(path);

    const result = load(Config, testing.allocator, .{ .json_path = path });
    try testing.expectError(LoadError.InvalidValue, result);
}
