pub const Distribution = enum {
    edge,
    datadog,
    otlp,
    prometheus,
    lambda,

    pub fn name(self: Distribution) []const u8 {
        return switch (self) {
            .edge => "edge",
            .datadog => "datadog",
            .otlp => "otlp",
            .prometheus => "prometheus",
            .lambda => "lambda",
        };
    }
};
