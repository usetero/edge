const std = @import("std");
const policy_mod = @import("../core/policy.zig");

pub const Policy = policy_mod.Policy;
pub const PolicyType = policy_mod.PolicyType;
pub const TelemetryType = policy_mod.TelemetryType;
pub const Action = policy_mod.Action;
pub const ActionType = policy_mod.ActionType;

pub const LogLevel = enum(u8) {
    debug,
    info,
    warn,
    err,

    pub fn parse(s: []const u8) !LogLevel {
        if (std.mem.eql(u8, s, "debug")) return .debug;
        if (std.mem.eql(u8, s, "info")) return .info;
        if (std.mem.eql(u8, s, "warn")) return .warn;
        if (std.mem.eql(u8, s, "err")) return .err;
        return error.InvalidLogLevel;
    }
};

pub const ProxyConfig = struct {
    // Network config
    listen_address: [4]u8,
    listen_port: u16,
    upstream_url: []const u8, // Now supports full URLs like "http://example.com:8080"

    // Inspection config
    log_level: LogLevel,
    pretty_print_json: bool,
    max_body_size: u32,

    // Policies for filtering/transforming telemetry
    policies: []Policy,

    pub fn default() ProxyConfig {
        return .{
            .listen_address = .{ 127, 0, 0, 1 },
            .listen_port = 8080,
            .upstream_url = "http://127.0.0.1:80",
            .log_level = .info,
            .pretty_print_json = true,
            .max_body_size = 1024 * 1024, // 1MB
            .policies = &.{}, // Empty slice by default
        };
    }
};

test "LogLevel.parse" {
    try std.testing.expectEqual(LogLevel.debug, try LogLevel.parse("debug"));
    try std.testing.expectEqual(LogLevel.info, try LogLevel.parse("info"));
    try std.testing.expectEqual(LogLevel.warn, try LogLevel.parse("warn"));
    try std.testing.expectEqual(LogLevel.err, try LogLevel.parse("err"));
    try std.testing.expectError(error.InvalidLogLevel, LogLevel.parse("invalid"));
}
