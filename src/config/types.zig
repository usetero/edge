const std = @import("std");
const proto = @import("proto");

pub const Policy = proto.policy.Policy;
pub const PolicyType = proto.policy.PolicyType;
pub const FilterAction = proto.policy.FilterAction;
pub const LogFilterConfig = proto.policy.LogFilterConfig;
pub const LogMatcher = proto.policy.LogMatcher;

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

pub const ProviderType = enum {
    file,
    http,
};

pub const ProviderConfig = struct {
    type: ProviderType,
    // For file provider
    path: ?[]const u8 = null,
    // For http provider
    url: ?[]const u8 = null,
    poll_interval: ?u64 = null, // seconds
};

pub const ProxyConfig = struct {
    // Network config
    listen_address: [4]u8,
    listen_port: u16,
    upstream_url: []const u8, // Now supports full URLs like "http://example.com:8080"

    // Edge metadata
    workspace_id: []const u8,

    // Inspection config
    log_level: LogLevel,
    pretty_print_json: bool,
    max_body_size: u32,

    // Policy providers
    policy_providers: []ProviderConfig,

    pub fn default() ProxyConfig {
        return .{
            .listen_address = .{ 127, 0, 0, 1 },
            .listen_port = 8080,
            .upstream_url = "http://127.0.0.1:80",
            .workspace_id = "90A6EFC2-27B8-41BC-9343-43BFB1DF0732",
            .log_level = .info,
            .pretty_print_json = true,
            .max_body_size = 1024 * 1024, // 1MB
            .policy_providers = &.{},
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
