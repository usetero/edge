const std = @import("std");
const proto = @import("proto");
const TelemetryType = proto.policy.TelemetryType;

/// Source type for policies with priority ordering
/// Higher numeric value = higher priority (HTTP overlays file)
pub const SourceType = enum(u8) {
    file = 0,
    http = 1,

    pub fn priority(self: SourceType) u8 {
        return @intFromEnum(self);
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
