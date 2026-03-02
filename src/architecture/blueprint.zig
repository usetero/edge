pub const Stage = enum {
    scaffold,
    transport,
    streaming_pipeline,
    protocol_adapters,
    conformance,
    performance,
};

pub const Pipeline = struct {
    ingress: []const u8,
    policy: []const u8,
    transform: []const u8,
    egress: []const u8,
};

pub const target_pipeline = Pipeline{
    .ingress = "http ingress reads request stream",
    .policy = "policy engine evaluates and emits actions",
    .transform = "filters/transforms are applied incrementally",
    .egress = "upstream request stream is written while processing input",
};
