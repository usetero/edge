const std = @import("std");
const policy = @import("policy_zig");

const log = std.log.scoped(.config);

pub const ProviderConfig = policy.ProviderConfig;
pub const ServiceMetadata = policy.ServiceMetadata;
pub const StringPair = policy.StringPair;

pub const LogLevel = enum(u8) {
    debug,
    info,
    warn,
    err,
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

/// A single S3-compatible destination the s3-dump extension can write to.
/// Fields (except `name`) mirror the z3 target config the extension expects;
/// `name` is what policies reference via `ExtensionTargetRef`.
pub const S3TargetConfig = struct {
    name: []const u8,
    /// S3-compatible endpoint URL. Null uses the AWS default for `region`.
    endpoint: ?[]const u8 = null,
    region: []const u8 = "us-east-1",
    bucket: []const u8,
    prefix: []const u8 = "",
    /// Path-style (MinIO/R2) vs virtual-host-style URLs.
    force_path_style: bool = true,
};

/// `com.usetero/s3-dump` extension configuration. Off unless `enabled` and at
/// least one target is set. Credentials are NOT here — they come from the
/// AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables.
pub const S3DumpConfig = struct {
    enabled: bool = false,
    /// Interval between background flush cycles (single flush task).
    flush_interval_ms: u64 = 30_000,
    // Batching knobs — map 1:1 onto the extension's S3Dump.Options.
    max_batch_bytes: usize = 4 << 20,
    max_batch_records: u32 = 10_000,
    max_batch_age_ms: u64 = 30_000,
    max_sealed_bytes: usize = 32 << 20,
    max_attempts: usize = 1,
    targets: []const S3TargetConfig = &.{},

    /// Env-only escape hatch for `targets`: a JSON array of `S3TargetConfig`,
    /// e.g. `TERO_S3_DUMP_TARGETS_JSON='[{"name":"main","bucket":"b",...}]'`.
    /// zonfig can't express a slice-of-struct through an env var (only scalars
    /// and string slices), so the Lambda distro — which loads config env-only,
    /// no JSON file — parses this into `targets` after load. Mirrors the
    /// `TERO_POLICY_STATIC` pattern. Unused by the server distro (it reads
    /// `targets` straight from its JSON config file). Parsed in lambda_main.
    targets_json: ?[]const u8 = null,

    /// Batch/backlog caps that must be nonzero no matter how flush is driven —
    /// a zero cap makes the handler treat every record as oversized and drop it.
    /// Used by every distribution (the Lambda flush is event-driven, so it only
    /// needs this, not the flush-interval check below).
    pub fn validateBatching(self: S3DumpConfig) !void {
        if (!self.enabled) return;
        if (self.max_batch_bytes == 0 or self.max_sealed_bytes == 0 or self.max_batch_records == 0) {
            log.warn("s3_dump batch caps (max_batch_bytes/max_sealed_bytes/max_batch_records) must be > 0", .{});
            return error.InvalidS3DumpConfig;
        }
    }

    /// Full validation for distributions that run the wall-clock flush task
    /// (the server distro): the batch caps plus a nonzero flush interval, since
    /// a zero interval spins the flush loop tight. Lambda calls
    /// `validateBatching` directly instead — `flush_interval_ms` is unused there.
    pub fn validate(self: S3DumpConfig) !void {
        try self.validateBatching();
        if (self.enabled and self.flush_interval_ms == 0) {
            log.warn("s3_dump.flush_interval_ms must be > 0", .{});
            return error.InvalidS3DumpConfig;
        }
    }
};

/// Main proxy configuration - loadable via zonfig
pub const ProxyConfig = struct {
    // Network config
    listen_address: [4]u8 = .{ 127, 0, 0, 1 },
    listen_port: u16 = 8080,
    upstream_url: []const u8 = "http://127.0.0.1:80",

    // Datadog-specific upstream URLs (optional, fall back to upstream_url if not set)
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,

    // Service identity metadata
    service: ServiceMetadata = .{},

    // Inspection config
    log_level: LogLevel = .info,

    max_body_size: u32 = 1024 * 1024, // 1MB

    /// Post-decompression body ceiling; defaults to `max_body_size` when unset.
    /// Raise it to admit payloads that decompress larger than the raw cap.
    max_decoded_bytes: ?u32 = null,

    /// Max concurrent connections; the dominant memory/throughput knob (see
    /// limits.zig). Also honors the `TERO_MAX_CONNECTIONS` env override.
    max_connections: u32 = 256,

    /// httpz event-loop worker count (null = httpz default of 1).
    worker_count: ?u16 = null,

    /// httpz request-handler thread-pool count (null = httpz default of 32).
    /// Multiplies the per-thread pipeline-scratch memory floor.
    thread_pool_count: ?u16 = null,

    /// Enables the `/_edge/tap/{pre,post}` debug endpoints, which stream raw
    /// in-flight telemetry records (before/after policy evaluation). Off by
    /// default — this exposes customer payloads, so only enable on a trusted
    /// listener.
    tap_enabled: bool = false,

    // Policy providers - array of provider configurations
    policy_providers: []ProviderConfig = &.{},

    // Module-specific configuration
    prometheus: PrometheusModuleConfig = .{},

    /// com.usetero/s3-dump extension (Datadog logs → S3). Disabled by default.
    s3_dump: S3DumpConfig = .{},

    /// Post-load validation hook (called by zonfig).
    pub fn validate(self: *ProxyConfig) !void {
        try self.s3_dump.validate();
    }
};

test "ProxyConfig.validate rejects zero s3_dump knobs when enabled" {
    // Disabled: knobs are ignored even if degenerate.
    var disabled: ProxyConfig = .{ .s3_dump = .{ .enabled = false, .flush_interval_ms = 0 } };
    try disabled.validate();

    // Enabled with a zero flush interval → tight-spin guard.
    var zero_interval: ProxyConfig = .{ .s3_dump = .{ .enabled = true, .flush_interval_ms = 0 } };
    try std.testing.expectError(error.InvalidS3DumpConfig, zero_interval.validate());

    // Enabled with a zero batch cap → every record would drop.
    var zero_bytes: ProxyConfig = .{ .s3_dump = .{ .enabled = true, .max_batch_bytes = 0 } };
    try std.testing.expectError(error.InvalidS3DumpConfig, zero_bytes.validate());

    // Enabled with sane defaults → accepted.
    var ok: ProxyConfig = .{ .s3_dump = .{ .enabled = true } };
    try ok.validate();
}

test "s3_dump targets_json parses into S3TargetConfig (Lambda env-only path)" {
    // The exact parse lambda_main runs on TERO_S3_DUMP_TARGETS_JSON. Only
    // `name` and `bucket` are required; the rest fall back to field defaults.
    const json =
        \\[{"name":"main","bucket":"logs","endpoint":"http://minio:9000","force_path_style":true},
        \\ {"name":"backup","bucket":"logs-eu","region":"eu-west-1"}]
    ;
    const parsed = try std.json.parseFromSlice(
        []const S3TargetConfig,
        std.testing.allocator,
        json,
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 2), parsed.value.len);
    try std.testing.expectEqualStrings("main", parsed.value[0].name);
    try std.testing.expectEqualStrings("http://minio:9000", parsed.value[0].endpoint.?);
    try std.testing.expectEqualStrings("us-east-1", parsed.value[0].region); // default
    // Second target defaults endpoint to null and overrides region.
    try std.testing.expect(parsed.value[1].endpoint == null);
    try std.testing.expectEqualStrings("eu-west-1", parsed.value[1].region);
    try std.testing.expect(parsed.value[1].force_path_style); // default true
}

test "S3DumpConfig.validateBatching (Lambda path) ignores flush_interval_ms" {
    // Lambda flush is event-driven, so a zero interval is fine there...
    const zero_interval: S3DumpConfig = .{ .enabled = true, .flush_interval_ms = 0 };
    try zero_interval.validateBatching();
    // ...but the full validate (server distro) still rejects it.
    try std.testing.expectError(error.InvalidS3DumpConfig, zero_interval.validate());

    // Zero batch caps are rejected on both paths.
    const zero_cap: S3DumpConfig = .{ .enabled = true, .max_batch_bytes = 0 };
    try std.testing.expectError(error.InvalidS3DumpConfig, zero_cap.validateBatching());
}
