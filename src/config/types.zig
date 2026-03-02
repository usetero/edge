const std = @import("std");
const zonfig = @import("../zonfig/root.zig");
const router = @import("../control/router.zig");

pub const AppConfig = struct {
    listen_address: []const u8 = "127.0.0.1",
    listen_port: u16 = 8080,
    max_body_size: usize = 1_048_576,
    upstream_url: []const u8 = "http://127.0.0.1:9000",
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,
    policy_providers: []const PolicyProviderConfig = &.{},

    pub fn fromArgs(allocator: std.mem.Allocator) !AppConfig {
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);

        const json_path: ?[]const u8 = if (args.len >= 2) args[1] else null;
        const loaded = try zonfig.load(AppConfig, allocator, .{
            .json_path = json_path,
            .env_prefix = "TERO",
            .allow_env_only = true,
        });
        // Intentionally not deinitializing here: returned slices may reference
        // memory allocated during zonfig processing and must remain valid for
        // process lifetime.
        return loaded.*;
    }

    pub fn upstreamFor(self: AppConfig, route: router.RouteKind) []const u8 {
        return switch (route) {
            .otlp_logs, .datadog_logs => self.logs_url orelse self.upstream_url,
            .otlp_metrics, .prometheus_metrics => self.metrics_url orelse self.upstream_url,
            else => self.upstream_url,
        };
    }
};

pub const PolicyProviderConfig = struct {
    id: []const u8 = "",
    type: []const u8 = "",
    path: ?[]const u8 = null,
    url: ?[]const u8 = null,
};

test "upstream selection prefers specialized URLs" {
    const c = AppConfig{
        .upstream_url = "http://default",
        .logs_url = "http://logs",
        .metrics_url = "http://metrics",
    };
    try std.testing.expectEqualStrings("http://logs", c.upstreamFor(.otlp_logs));
    try std.testing.expectEqualStrings("http://metrics", c.upstreamFor(.otlp_metrics));
    try std.testing.expectEqualStrings("http://metrics", c.upstreamFor(.prometheus_metrics));
    try std.testing.expectEqualStrings("http://default", c.upstreamFor(.passthrough));
}

test "upstream selection falls back to upstream_url" {
    const c = AppConfig{
        .upstream_url = "http://default",
        .logs_url = null,
        .metrics_url = null,
    };
    try std.testing.expectEqualStrings("http://default", c.upstreamFor(.datadog_logs));
    try std.testing.expectEqualStrings("http://default", c.upstreamFor(.prometheus_metrics));
}
