const std = @import("std");
const policy = @import("../policy/root.zig");

const ProviderConfig = policy.ProviderConfig;
const ServiceMetadata = policy.ServiceMetadata;

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

/// Prometheus module configuration
pub const PrometheusModuleConfig = struct {
    /// Maximum input bytes to process per scrape (limits data read from upstream)
    /// This bounds memory usage for buffering input data.
    /// Default: 10MB
    max_input_bytes_per_scrape: usize = 10 * 1024 * 1024,

    /// Maximum output bytes to forward per scrape (limits response size to client)
    /// Set higher than input limit if filtering reduces data significantly.
    /// Default: 10MB
    max_output_bytes_per_scrape: usize = 10 * 1024 * 1024,
};

pub const ProxyConfig = struct {
    // Network config
    listen_address: [4]u8,
    listen_port: u16,
    upstream_url: []const u8, // Default upstream URL for passthrough traffic

    // Datadog-specific upstream URLs (optional, fall back to upstream_url if not set)
    logs_url: ?[]const u8 = null, // e.g., "https://http-intake.logs.datadoghq.com"
    metrics_url: ?[]const u8 = null, // e.g., "https://api.datadoghq.com"

    // Service identity metadata
    service: ServiceMetadata,

    // Inspection config
    log_level: LogLevel,

    max_body_size: u32,

    // Retry config
    max_upstream_retries: u8,

    // Policy providers
    policy_providers: []ProviderConfig,

    // Module-specific configuration
    prometheus: PrometheusModuleConfig = .{},

    pub fn default() ProxyConfig {
        return .{
            .listen_address = .{ 127, 0, 0, 1 },
            .listen_port = 8080,
            .upstream_url = "http://127.0.0.1:80",
            .service = .{},
            .log_level = .info,
            .max_body_size = 1024 * 1024, // 1MB
            .max_upstream_retries = 10,
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
