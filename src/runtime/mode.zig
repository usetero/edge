const std = @import("std");

pub const Distribution = enum {
    edge,
    datadog,
    otlp,
    prometheus,

    pub fn defaultConfigPath(self: Distribution) []const u8 {
        return switch (self) {
            .otlp => "config-otlp.json",
            .prometheus => "config-prometheus.json",
            else => "config.json",
        };
    }
};

test "prometheus distro defaults to config-prometheus.json" {
    try std.testing.expectEqualStrings(
        "config-prometheus.json",
        Distribution.prometheus.defaultConfigPath(),
    );
}
