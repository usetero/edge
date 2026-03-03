pub const Distribution = enum {
    edge,
    datadog,
    otlp,
    prometheus,

    pub fn defaultConfigPath(self: Distribution) []const u8 {
        return switch (self) {
            .otlp => "config-otlp.json",
            else => "config.json",
        };
    }
};
