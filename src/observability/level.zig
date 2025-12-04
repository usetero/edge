const std = @import("std");

/// Event severity levels, matching std.log.Level for compatibility
pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn asText(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }

    pub fn asTextLower(self: Level) []const u8 {
        return switch (self) {
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
        };
    }

    /// Convert from std.log.Level
    pub fn fromStd(level: std.log.Level) Level {
        return switch (level) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
    }

    /// Convert to std.log.Level
    pub fn toStd(self: Level) std.log.Level {
        return switch (self) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
    }
};

test "Level.asText" {
    const testing = std.testing;
    try testing.expectEqualStrings("DEBUG", Level.debug.asText());
    try testing.expectEqualStrings("INFO", Level.info.asText());
    try testing.expectEqualStrings("WARN", Level.warn.asText());
    try testing.expectEqualStrings("ERROR", Level.err.asText());
}
