const policy = @import("policy_zig");

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

    // Policy providers - array of provider configurations
    policy_providers: []ProviderConfig = &.{},

    // Module-specific configuration
    prometheus: PrometheusModuleConfig = .{},
};
