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

    /// Parse log level from a string (case-insensitive).
    /// Returns null if the string is not a valid level.
    pub fn parse(value: []const u8) ?Level {
        if (std.ascii.eqlIgnoreCase(value, "debug")) return .debug;
        if (std.ascii.eqlIgnoreCase(value, "info")) return .info;
        if (std.ascii.eqlIgnoreCase(value, "warn")) return .warn;
        if (std.ascii.eqlIgnoreCase(value, "warning")) return .warn;
        if (std.ascii.eqlIgnoreCase(value, "error")) return .err;
        if (std.ascii.eqlIgnoreCase(value, "err")) return .err;
        return null;
    }

    /// Parse log level from an environment variable.
    /// Returns the default level if the env var is not set or invalid.
    pub fn parseFromEnv(env_var: []const u8, default: Level) Level {
        const env_value = std.posix.getenv(env_var) orelse return default;
        return parse(env_value) orelse default;
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

test "Level.parse" {
    const testing = std.testing;

    // Valid values (case-insensitive)
    try testing.expectEqual(Level.debug, Level.parse("debug").?);
    try testing.expectEqual(Level.debug, Level.parse("DEBUG").?);
    try testing.expectEqual(Level.debug, Level.parse("Debug").?);
    try testing.expectEqual(Level.info, Level.parse("info").?);
    try testing.expectEqual(Level.warn, Level.parse("warn").?);
    try testing.expectEqual(Level.warn, Level.parse("warning").?);
    try testing.expectEqual(Level.err, Level.parse("error").?);
    try testing.expectEqual(Level.err, Level.parse("err").?);

    // Invalid values
    try testing.expect(Level.parse("invalid") == null);
    try testing.expect(Level.parse("") == null);
    try testing.expect(Level.parse("trace") == null);
}
