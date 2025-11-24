const std = @import("std");
const policy_pb = @import("proto");
const TelemetryType = policy_pb.TelemetryType;

/// Source type for policies with priority ordering
/// Higher numeric value = higher priority (HTTP overlays file)
pub const SourceType = enum(u8) {
    file = 0,
    http = 1,

    pub fn priority(self: SourceType) u8 {
        return @intFromEnum(self);
    }
};

/// Composite key for policy deduplication
/// Policies are uniquely identified by (name, telemetry_type) tuple
pub const PolicyKey = struct {
    name: []const u8,
    telemetry_type: TelemetryType,

    /// Create a string key for HashMap storage
    /// Format: "name:telemetry_type_value"
    pub fn toString(self: PolicyKey, allocator: std.mem.Allocator) ![]u8 {
        const type_value = @intFromEnum(self.telemetry_type);
        return std.fmt.allocPrint(allocator, "{s}:{d}", .{ self.name, type_value });
    }

    /// Parse a string key back to PolicyKey
    pub fn fromString(allocator: std.mem.Allocator, key: []const u8) !PolicyKey {
        const colon_idx = std.mem.indexOf(u8, key, ":") orelse return error.InvalidKeyFormat;

        const name = try allocator.dupe(u8, key[0..colon_idx]);
        const type_value = try std.fmt.parseInt(i32, key[colon_idx + 1 ..], 10);

        return .{
            .name = name,
            .telemetry_type = @enumFromInt(type_value),
        };
    }

    pub fn eql(a: PolicyKey, b: PolicyKey) bool {
        return std.mem.eql(u8, a.name, b.name) and
            a.telemetry_type == b.telemetry_type;
    }
};

/// Metadata about a policy's source and history
/// Cold data: only accessed during updates, not during evaluation
pub const PolicyMetadata = struct {
    source: SourceType,
    last_updated: i128, // Unix timestamp in nanoseconds

    pub fn init(source: SourceType) PolicyMetadata {
        return .{
            .source = source,
            .last_updated = std.time.nanoTimestamp(),
        };
    }

    /// Check if this policy should be replaced by a new one from the given source
    pub fn shouldReplace(self: PolicyMetadata, new_source: SourceType) bool {
        return new_source.priority() >= self.source.priority();
    }
};

test "PolicyKey.toString and fromString" {
    const allocator = std.testing.allocator;

    const key = PolicyKey{
        .name = "test-policy",
        .telemetry_type = .TELEMETRY_TYPE_LOG,
    };

    const key_string = try key.toString(allocator);
    defer allocator.free(key_string);

    const parsed = try PolicyKey.fromString(allocator, key_string);
    defer allocator.free(parsed.name);

    try std.testing.expect(key.eql(parsed));
}

test "PolicyMetadata.shouldReplace prioritizes HTTP over file" {
    const file_meta = PolicyMetadata.init(.file);
    const http_meta = PolicyMetadata.init(.http);

    // HTTP should replace file
    try std.testing.expect(file_meta.shouldReplace(.http));

    // File should not replace HTTP
    try std.testing.expect(!http_meta.shouldReplace(.file));

    // Same source should replace (update)
    try std.testing.expect(file_meta.shouldReplace(.file));
    try std.testing.expect(http_meta.shouldReplace(.http));
}
