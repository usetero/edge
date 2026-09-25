//! Lambda extension distribution: Datadog ingestion with policy filtering.
//! The main thread runs the Lambda Extensions API event loop. The engine runs in the background.
//! Config comes from TERO_* env vars.

const std = @import("std");
const build_options = @import("build_options");

const edge = @import("root.zig");
const runtime_metrics_mod = @import("runtime/runtime_metrics.zig");
const app = @import("runtime/app.zig");
const crash = @import("runtime/crash.zig");
const ext_rt = @import("runtime/extensions.zig");
const config_types = @import("config/types.zig");
const policy = edge.policy;
const zonfig = edge.zonfig;

const lambda = @import("lambda/root.zig");
const ExtensionClient = lambda.ExtensionClient;

const o11y = @import("o11y");
const StdLogAdapter = o11y.StdLogAdapter;
const Level = o11y.Level;

const RuntimeMetrics = runtime_metrics_mod.RuntimeMetrics;

// =============================================================================
// Lambda Configuration
// =============================================================================

/// Lambda extension configuration loaded via zonfig.
/// All fields can be overridden via environment variables with TERO_ prefix.
pub const LambdaConfig = struct {
    // Network
    listen_address: [4]u8 = .{ 127, 0, 0, 1 },
    listen_port: u16 = 8080,

    // Upstream URLs
    upstream_url: []const u8 = "http://localhost",
    logs_url: ?[]const u8 = null,
    metrics_url: ?[]const u8 = null,

    // Limits
    max_body_size: u32 = 5 * 1024 * 1024, // 5MB

    /// Post-decompression body ceiling; null uses the runtime default, which is
    /// never below `max_body_size`. Honors `TERO_MAX_DECODED_BYTES`.
    max_decoded_bytes: ?u32 = null,

    /// Max concurrent connections; the dominant memory/throughput knob (see
    /// limits.zig). Also honors the `TERO_MAX_CONNECTIONS` env override.
    max_connections: u32 = 256,

    /// httpz event-loop worker count (null = httpz default of 1).
    worker_count: ?u16 = null,

    /// httpz request-handler thread-pool count (null = httpz default of 32).
    thread_pool_count: ?u16 = null,

    // Service metadata
    service: struct {
        name: []const u8 = "tero-edge-lambda",
        namespace: []const u8 = "tero",
        version: []const u8 = "latest",
    } = .{},

    // Policy configuration
    policy: struct {
        /// JSON array of policies to load at startup
        /// Example: TERO_POLICY_STATIC='{"policies":[{"id":"drop-health",
        ///   "name":"Drop health","log":{"match":[{"log_field":"body",
        ///   "regex":"health"}],"keep":"none"}}]}'
        static: ?[]const u8 = null,
        /// HTTP policy provider URL for dynamic updates
        url: ?[]const u8 = null,
        poll_interval: u64 = 60,
        api_key: ?[]const u8 = null,
    } = .{},

    /// com.usetero/s3-dump extension (Datadog logs → S3). Disabled by default.
    /// In Lambda the flush is event-driven (per-invoke + shutdown), so
    /// `flush_interval_ms` is unused here — see the event loop in `main`.
    s3_dump: config_types.S3DumpConfig = .{},

    /// zonfig validation hook, run after env/JSON overrides. Clamps env knobs
    /// into ranges the runtime requires so a bad override degrades instead of
    /// aborting (or silently wedging) the extension at startup.
    pub fn validate(self: *LambdaConfig) !void {
        // The limit subsystem asserts 0 < max_connections < 65535
        // (core/limits.zig, core/arena_pool.zig).
        const clamped = std.math.clamp(self.max_connections, 1, 65534);
        if (clamped != self.max_connections) {
            std.log.warn(
                "TERO_MAX_CONNECTIONS={d} out of range [1,65534]; clamping to {d}",
                .{ self.max_connections, clamped },
            );
            self.max_connections = clamped;
        }

        // A zero worker or pool count binds the port but never serves a request. Treat 0 as null (the httpz default).
        if (self.worker_count) |w| if (w == 0) {
            std.log.warn("TERO_WORKER_COUNT=0 starts no accept threads; using httpz default", .{});
            self.worker_count = null;
        };
        if (self.thread_pool_count) |t| if (t == 0) {
            std.log.warn("TERO_THREAD_POOL_COUNT=0 starts no handler threads; using httpz default", .{});
            self.thread_pool_count = null;
        };

        // Lambda flush is event-driven (per-invoke + shutdown), so
        // `flush_interval_ms` is unused here — validate only the batch caps.
        try self.s3_dump.validateBatching();
    }
};

pub const std_options = app.std_options;
pub const debug = crash.debug;

// =============================================================================
// Observability Events
// =============================================================================

const LambdaExtensionStarting = struct {};
const LambdaExtensionReady = struct { port: u16 };
const LambdaExtensionShutdown = struct { reason: []const u8 };
const LambdaExtensionError = struct { err: []const u8 };
const LambdaInvokeReceived = struct { request_id: []const u8 };
const ProxyServerStarted = struct { port: u16 };
const ProxyServerStopped = struct {};
const ConfigurationLoaded = struct {
    logs_url: []const u8,
    metrics_url: []const u8,
};
const StaticPoliciesLoading = struct {};
const StaticPoliciesLoaded = struct { count: usize };
const StaticPoliciesError = struct { err: []const u8 };

// =============================================================================
// Main Entry Point
// =============================================================================

pub fn main(init: std.process.Init) !void {
    crash.setDistribution("lambda");
    const allocator = init.gpa;
    const io = init.io;

    // Initialize observability
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init(io);
    const bus = stdio_bus.eventBus();

    // Parse log level from environment
    bus.setLevel(Level.parseFromEnv(init.environ_map, "TERO_LOG_LEVEL", .info));

    // Initialize std.log adapter
    StdLogAdapter.init(bus);
    defer StdLogAdapter.deinit();

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(LambdaExtensionStarting{});

    // Load configuration via zonfig (env vars with TERO_ prefix, no JSON file)
    const config = zonfig.load(
        LambdaConfig,
        allocator,
        io,
        .{ .env_prefix = "TERO", .environ = init.environ_map },
    ) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.err(LambdaExtensionError{ .err = @errorName(err) });
        return err;
    };
    defer zonfig.deinit(LambdaConfig, allocator, config);

    // zonfig cannot read a slice of structs from an env var, so Lambda reads s3-dump targets as JSON
    // from TERO_S3_DUMP_TARGETS_JSON. Keep the parsed targets in their own arena: zonfig.deinit would
    // free them in config.s3_dump.targets. Parse only when enabled, so a bad value cannot stop startup.
    var s3_targets: []const config_types.S3TargetConfig = config.s3_dump.targets;
    var targets_parsed: ?std.json.Parsed([]const config_types.S3TargetConfig) = null;
    defer if (targets_parsed) |p| p.deinit();
    if (config.s3_dump.enabled) {
        if (config.s3_dump.targets_json) |targets_json| {
            targets_parsed = std.json.parseFromSlice(
                []const config_types.S3TargetConfig,
                allocator,
                targets_json,
                .{},
            ) catch |err| {
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                bus.err(LambdaExtensionError{ .err = @errorName(err) });
                return err;
            };
            s3_targets = targets_parsed.?.value;
        }
    }

    // Determine effective URLs
    const logs_url = config.logs_url orelse config.upstream_url;
    const metrics_url = config.metrics_url orelse config.upstream_url;

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ConfigurationLoaded{
        .logs_url = logs_url,
        .metrics_url = metrics_url,
    });

    // Generate instance ID
    var instance_id_buf: [64]u8 = undefined;
    const instance_id = try std.fmt.bufPrint(&instance_id_buf, "lambda-{d}-{d}", .{
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
        std.Thread.getCurrentId(),
    });

    // Build service metadata
    const service_metadata: policy.ServiceMetadata = .{
        .name = config.service.name,
        .namespace = config.service.namespace,
        .version = config.service.version,
        .instance_id = instance_id,
        .supported_stages = edge.distro.supportedStagesFor(.datadog),
    };

    var registry = policy.Registry.init(allocator, bus);
    defer registry.deinit();

    // s3-dump extension: wired before policies compile so extension bindings
    // resolve at snapshot build. Inert unless enabled with targets.
    var exts = ext_rt.Extensions.init(allocator, .{ .log = ext_rt.datadogLogEncode });
    defer exts.deinit();
    const s3_dump_active = config.s3_dump.enabled and s3_targets.len > 0;
    var extension_sink: ?policy.ExtensionSink = null;
    if (s3_dump_active) {
        var s3_cfg = config.s3_dump;
        s3_cfg.targets = s3_targets; // env-JSON targets (see targets_json above)
        try ext_rt.configure(&exts, allocator, io, s3_cfg, init.environ_map);
        exts.register(&registry);
        extension_sink = exts.sink();
    }

    var runtime_metrics = try RuntimeMetrics.init(allocator, io, .lambda);
    defer runtime_metrics.deinit();
    runtime_metrics.setBuildInfo(build_options.version, build_options.commit);

    // Load static policies from environment variable (TERO_POLICY_STATIC)
    if (config.policy.static) |static_json| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.info(StaticPoliciesLoading{});

        const policies = policy.parser.parsePoliciesBytes(allocator, static_json) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            bus.err(StaticPoliciesError{ .err = @errorName(err) });
            return err;
        };
        defer {
            for (policies) |*p| {
                p.deinit(allocator);
            }
            allocator.free(policies);
        }

        try registry.updatePolicies(policies, "static", .file);
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.info(StaticPoliciesLoaded{ .count = policies.len });
    }

    // Create HTTP policy loader if configured
    var loader: ?*policy.Loader = null;
    defer if (loader) |l| l.deinit();

    if (config.policy.url) |policy_url| {
        // Build headers if API key is set
        var headers_buf: [1]policy.Header = undefined;
        var headers_count: usize = 0;

        var auth_value_buf: [256]u8 = undefined;
        if (config.policy.api_key) |api_key| {
            const auth_value = try std.fmt.bufPrint(&auth_value_buf, "Bearer {s}", .{api_key});
            headers_buf[0] = .{
                .name = "Authorization",
                .value = auth_value,
            };
            headers_count = 1;
        }

        const provider_config: policy.ProviderConfig = .{
            .id = "lambda-http",
            .type = .http,
            .url = policy_url,
            .poll_interval = config.policy.poll_interval,
            .headers = headers_buf[0..headers_count],
        };

        const providers = [_]policy.ProviderConfig{provider_config};
        loader = try policy.Loader.init(
            allocator,
            io,
            bus,
            &registry,
            &providers,
            service_metadata,
        );
        try loader.?.startAsync(io);
    }

    const kinds = edge.distro.servicesFor(.datadog);
    const engine = try app.Engine.create(allocator, io, bus, &registry, &runtime_metrics, kinds, .{
        .listen_address = config.listen_address,
        .listen_port = config.listen_port,
        .max_body_size = config.max_body_size,
        .max_decoded_bytes = config.max_decoded_bytes,
        .max_connections = config.max_connections,
        .worker_count = config.worker_count,
        .thread_pool_count = config.thread_pool_count,
        .upstream_url = config.upstream_url,
        .logs_url = config.logs_url,
        .metrics_url = config.metrics_url,
        .extension_sink = extension_sink,
    });
    defer engine.destroy();

    // Register before the engine starts. If registration fails (for example, outside Lambda),
    // no accept loop exists to tear down.
    var extension = try ExtensionClient.init(allocator, io, bus, init.environ_map, "tero-edge");
    defer extension.deinit();
    try extension.register();

    try engine.start();
    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ProxyServerStarted{ .port = config.listen_port });

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(LambdaExtensionReady{ .port = config.listen_port });

    // Event loop - poll for Lambda events
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    while (true) {
        // Reset arena for each event
        _ = arena.reset(.retain_capacity);

        const event = extension.nextEvent(arena.allocator()) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            bus.err(LambdaExtensionError{ .err = @errorName(err) });
            continue;
        };

        switch (event) {
            .invoke => |invoke_event| {
                bus.debug(LambdaInvokeReceived{
                    .request_id = invoke_event.request_id,
                });
                // Lambda freezes the process between invocations, so a timer flush is not reliable. INVOKE means
                // the prior invocation is complete, so flush here. SHUTDOWN flushes the last invocation.
                if (s3_dump_active) runtime_metrics.recordS3DumpFlush(exts.flush(io, .{}));
            },
            .shutdown => |shutdown_event| {
                bus.info(LambdaExtensionShutdown{
                    .reason = @tagName(shutdown_event.reason),
                });

                // The two-phase S3 drain runs after the loop (see below).
                engine.requestShutdown();
                break;
            },
        }
    }

    // Flush s3-dump twice, with io live. engine.stop() can block for about 5 s, and Lambda can kill the
    // process at its deadline.
    //   1. Before stop(): persist the records batched when SHUTDOWN arrived.
    //   2. After stop(): persist the records that in-flight handlers appended during the join.
    if (s3_dump_active) runtime_metrics.recordS3DumpFlush(exts.flush(io, .{ .force = true }));

    // Send final policy stats before engine.stop(). The freeze makes the poll sync unreliable, so this
    // sync carries the real stats. stop() can block past the deadline. A failure must not stop shutdown.
    if (loader) |l| l.close() catch |err|
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.err(LambdaExtensionError{ .err = @errorName(err) });

    // Cancel the accept loop and every connection task, then wait.
    engine.stop();

    if (s3_dump_active) runtime_metrics.recordS3DumpFlush(exts.flush(io, .{ .force = true }));

    // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
    bus.info(ProxyServerStopped{});
}
