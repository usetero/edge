const std = @import("std");
const m = @import("metrics_zig");
const ext = @import("extensions");
const build_options = @import("build_options");

const log = std.log.scoped(.runtime_metrics);

/// Connection-level series need a hook at accept and at slot release. The
/// stdio frontend owns both; httpz owns neither (it exports its own
/// `httpz_connections` and `httpz_invalid_request` through endpoints.zig
/// instead). Registering them on an httpz build would publish a flat zero,
/// which reads as "no connections" rather than "not measured".
const conn_metrics_enabled = build_options.frontend == .stdio;

pub const DistributionLabel = enum {
    edge,
    datadog,
    otlp,
    prometheus,
    lambda,
    tail,
};

pub const MethodLabel = enum {
    get,
    post,
    put,
    delete,
    patch,
    head,
    options,
    other,
};

pub const RouteKindLabel = enum {
    datadog_logs,
    datadog_metrics,
    otlp_logs,
    otlp_metrics,
    otlp_traces,
    prometheus_metrics,
    health,
    passthrough,
};

pub const KnownPathLabel = enum {
    api_v2_logs,
    api_v2_series,
    v1_logs,
    v1_metrics,
    v1_traces,
    metrics,
    health,
    edge_metrics,
    other,
};

pub const PrefilterDecisionLabel = enum {
    policy_path,
    fast_path,
    none,
};

pub const StatusClassLabel = enum {
    s2xx,
    s3xx,
    s4xx,
    s5xx,
    other,
};

pub const ErrorClassLabel = enum {
    uncaught,
    module,
};

/// Why a connection was refused before it ever carried a request.
pub const ShedReasonLabel = enum {
    /// No free connection slab slot: the process is at `max_connections`.
    slab_full,
    /// The Io implementation refused another concurrent task.
    concurrency,
};

const ShedLabels = struct {
    reason: ShedReasonLabel,
};

/// Which inbound deadline expired. `idle` is a keep-alive wait with no
/// request in flight; `request` means a partial request stalled and was
/// answered with 408.
pub const InboundPhaseLabel = enum {
    idle,
    request,
};

const InboundTimeoutLabels = struct {
    phase: InboundPhaseLabel,
};

pub const PolicyTelemetryLabel = enum {
    datadog_logs,
    datadog_metrics,
    otlp_logs,
    otlp_metrics,
    otlp_traces,
    prometheus_metrics,
};

const RequestLabels = struct {
    method: MethodLabel,
    known_path: KnownPathLabel,
};

const DurationLabels = struct { known_path: KnownPathLabel };

const ResponseLabels = struct { known_path: KnownPathLabel, status_class: StatusClassLabel };

const PrefilterLabels = struct {
    route_kind: RouteKindLabel,
    decision: PrefilterDecisionLabel,
};

const ErrorLabels = struct {
    known_path: KnownPathLabel,
    class: ErrorClassLabel,
};

const PolicyLabels = struct {
    telemetry: PolicyTelemetryLabel,
};

pub const SignalLabel = enum { log, metric, trace };

const PolicySignalLabels = struct {
    signal: SignalLabel,
};

const BuildInfoLabels = struct {
    version: []const u8,
    commit: []const u8,
    distribution: DistributionLabel,
};

const InternalMetrics = struct {
    edge_upstream_attempts_total: m.Counter(u64) = .init(
        "edge_upstream_attempts_total",
        .{ .help = "Upstream attempts, including retries." },
        .{},
    ),
    edge_upstream_retries_total: m.Counter(u64) = .init(
        "edge_upstream_retries_total",
        .{ .help = "Fresh-connection transport retries." },
        .{},
    ),
    edge_upstream_timeouts_total: m.Counter(u64) = .init(
        "edge_upstream_timeouts_total",
        .{ .help = "Upstream attempts the watchdog cut off at its deadline." },
        .{},
    ),
    /// Connections accepted, and the count currently holding a slab slot.
    /// stdio only: see `conn_metrics_enabled`.
    edge_connections_total: m.Counter(u64) = if (conn_metrics_enabled) .init(
        "edge_connections_total",
        .{ .help = "Inbound connections accepted." },
        .{},
    ) else .{ .noop = {} },
    edge_connections_active: m.Gauge(i64) = if (conn_metrics_enabled) .init(
        "edge_connections_active",
        .{ .help = "Inbound connections currently holding a connection slot." },
        .{},
    ) else .{ .noop = {} },
    /// Connections refused before a request: the exhaustion signal. Read it
    /// against `edge_connections_max`.
    edge_connections_shed_total: ConnectionsShedTotal,
    /// Inbound reads cut off by their deadline. The `request` phase counts
    /// dropped requests; the `idle` phase counts reclaimed keep-alive slots.
    edge_inbound_timeouts_total: InboundTimeoutsTotal,
    /// Heads that failed to parse, answered with 400 and a close. stdio only.
    edge_requests_invalid_total: m.Counter(u64) = if (conn_metrics_enabled) .init(
        "edge_requests_invalid_total",
        .{ .help = "Requests rejected before routing because the head failed to parse." },
        .{},
    ) else .{ .noop = {} },
    /// The configured connection ceiling. Both frontends report it, so an
    /// alert can compare use against capacity without knowing the frontend.
    edge_connections_max: m.Gauge(i64) = .init(
        "edge_connections_max",
        .{ .help = "Configured maximum concurrent inbound connections." },
        .{},
    ),
    /// Handler threads currently holding a request. Against the configured
    /// thread pool count this is the saturation signal: at the ceiling, a new
    /// request (a health probe included) waits for a thread to come free.
    edge_requests_in_flight: m.Gauge(i64) = .init(
        "edge_requests_in_flight",
        .{ .help = "Requests currently held by a handler thread." },
        .{},
    ),
    edge_requests_total: RequestsTotal,
    edge_request_duration_seconds: RequestDurationSeconds,
    edge_responses_total: ResponsesTotal,
    edge_prefilter_decisions_total: PrefilterDecisionsTotal,
    edge_request_errors_total: RequestErrorsTotal,
    edge_policy_records_evaluated_total: PolicyRecordsEvaluatedTotal,
    edge_policy_records_kept_total: PolicyRecordsKeptTotal,
    edge_policy_records_dropped_total: PolicyRecordsDroppedTotal,
    edge_policies_loaded: PoliciesLoaded,
    /// Policies present in the snapshot whose pattern the matcher refused.
    /// They evaluate nothing, so a non-zero value means a rule an operator
    /// believes is live is doing nothing at all.
    edge_policies_rejected: m.Gauge(i64) = .init(
        "edge_policies_rejected",
        .{ .help = "Loaded policies the matcher could not compile." },
        .{},
    ),
    edge_build_info: BuildInfo,

    // s3-dump extension flush stats (aggregate across targets; the FlushResult
    // the handler returns is already summed, so these carry no labels).
    edge_s3_dump_flushes_total: S3DumpFlushes,
    edge_s3_dump_objects_uploaded_total: S3DumpCounter,
    edge_s3_dump_objects_failed_total: S3DumpCounter,
    edge_s3_dump_records_uploaded_total: S3DumpCounter,
    edge_s3_dump_records_dropped_total: S3DumpCounter,
    edge_s3_dump_bytes_uploaded_total: S3DumpCounter,
    edge_s3_dump_backlog_bytes: S3DumpBacklog,

    const RequestsTotal = m.CounterVec(u64, RequestLabels);
    const RequestDurationSeconds = m.HistogramVec(
        f64,
        DurationLabels,
        &.{ 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60 },
    );
    const ResponsesTotal = m.CounterVec(u64, ResponseLabels);
    const PrefilterDecisionsTotal = m.CounterVec(u64, PrefilterLabels);
    const RequestErrorsTotal = m.CounterVec(u64, ErrorLabels);
    const ConnectionsShedTotal = m.CounterVec(u64, ShedLabels);
    const InboundTimeoutsTotal = m.CounterVec(u64, InboundTimeoutLabels);
    const PolicyRecordsEvaluatedTotal = m.CounterVec(u64, PolicyLabels);
    const PolicyRecordsKeptTotal = m.CounterVec(u64, PolicyLabels);
    const PolicyRecordsDroppedTotal = m.CounterVec(u64, PolicyLabels);
    const PoliciesLoaded = m.GaugeVec(u64, PolicySignalLabels);
    const BuildInfo = m.GaugeVec(u64, BuildInfoLabels);

    // Label-less: one series each, so plain Counter/Gauge (no allocation).
    const S3DumpFlushes = m.Counter(u64);
    const S3DumpCounter = m.Counter(u64);
    const S3DumpBacklog = m.Gauge(u64);
};

pub const RuntimeMetrics = struct {
    allocator: std.mem.Allocator,
    distribution: DistributionLabel,
    internal: InternalMetrics = m.initializeNoop(InternalMetrics),

    pub fn init(allocator: std.mem.Allocator, io: std.Io, distribution: DistributionLabel) !RuntimeMetrics {
        var metrics: RuntimeMetrics = .{
            .allocator = allocator,
            .distribution = distribution,
            .internal = .{
                .edge_requests_total = try InternalMetrics.RequestsTotal.init(
                    allocator,
                    io,
                    "edge_requests_total",
                    .{ .help = "Total number of HTTP requests handled by edge." },
                    .{},
                ),
                .edge_request_duration_seconds = try InternalMetrics.RequestDurationSeconds.init(
                    allocator,
                    io,
                    "edge_request_duration_seconds",
                    .{ .help = "HTTP request latency in seconds." },
                    .{},
                ),
                .edge_responses_total = try InternalMetrics.ResponsesTotal.init(
                    allocator,
                    io,
                    "edge_responses_total",
                    .{ .help = "Total number of HTTP responses produced by edge." },
                    .{},
                ),
                .edge_prefilter_decisions_total = try InternalMetrics.PrefilterDecisionsTotal.init(
                    allocator,
                    io,
                    "edge_prefilter_decisions_total",
                    .{ .help = "Total number of prefilter routing decisions." },
                    .{},
                ),
                .edge_request_errors_total = try InternalMetrics.RequestErrorsTotal.init(
                    allocator,
                    io,
                    "edge_request_errors_total",
                    .{ .help = "Total number of request-level errors." },
                    .{},
                ),
                .edge_connections_shed_total = try InternalMetrics.ConnectionsShedTotal.init(
                    allocator,
                    io,
                    "edge_connections_shed_total",
                    .{ .help = "Connections refused before carrying a request." },
                    .{},
                ),
                .edge_inbound_timeouts_total = try InternalMetrics.InboundTimeoutsTotal.init(
                    allocator,
                    io,
                    "edge_inbound_timeouts_total",
                    .{ .help = "Inbound reads cut off by the idle or request deadline." },
                    .{},
                ),
                .edge_policy_records_evaluated_total = try InternalMetrics.PolicyRecordsEvaluatedTotal.init(
                    allocator,
                    io,
                    "edge_policy_records_evaluated_total",
                    .{ .help = "Total number of telemetry records evaluated by the policy engine." },
                    .{},
                ),
                .edge_policy_records_kept_total = try InternalMetrics.PolicyRecordsKeptTotal.init(
                    allocator,
                    io,
                    "edge_policy_records_kept_total",
                    .{ .help = "Total number of telemetry records kept after policy evaluation." },
                    .{},
                ),
                .edge_policy_records_dropped_total = try InternalMetrics.PolicyRecordsDroppedTotal.init(
                    allocator,
                    io,
                    "edge_policy_records_dropped_total",
                    .{ .help = "Total number of telemetry records dropped after policy evaluation." },
                    .{},
                ),
                .edge_policies_loaded = try InternalMetrics.PoliciesLoaded.init(
                    allocator,
                    io,
                    "edge_policies_loaded",
                    .{ .help = "Number of loaded policies targeting each signal in the active snapshot." },
                    .{},
                ),
                .edge_build_info = try InternalMetrics.BuildInfo.init(
                    allocator,
                    io,
                    "edge_build_info",
                    .{ .help = "Build metadata for this edge process." },
                    .{},
                ),
                .edge_s3_dump_flushes_total = InternalMetrics.S3DumpFlushes.init(
                    "edge_s3_dump_flushes_total",
                    .{ .help = "Total number of s3-dump flush cycles executed." },
                    .{},
                ),
                .edge_s3_dump_objects_uploaded_total = InternalMetrics.S3DumpCounter.init(
                    "edge_s3_dump_objects_uploaded_total",
                    .{ .help = "Total s3-dump objects successfully uploaded." },
                    .{},
                ),
                .edge_s3_dump_objects_failed_total = InternalMetrics.S3DumpCounter.init(
                    "edge_s3_dump_objects_failed_total",
                    .{ .help = "Total s3-dump object uploads that failed." },
                    .{},
                ),
                .edge_s3_dump_records_uploaded_total = InternalMetrics.S3DumpCounter.init(
                    "edge_s3_dump_records_uploaded_total",
                    .{ .help = "Total telemetry records uploaded via s3-dump." },
                    .{},
                ),
                .edge_s3_dump_records_dropped_total = InternalMetrics.S3DumpCounter.init(
                    "edge_s3_dump_records_dropped_total",
                    .{ .help = "Total records dropped by s3-dump (backlog full, encode failure, or no credentials)." },
                    .{},
                ),
                .edge_s3_dump_bytes_uploaded_total = InternalMetrics.S3DumpCounter.init(
                    "edge_s3_dump_bytes_uploaded_total",
                    .{ .help = "Total object body bytes uploaded via s3-dump." },
                    .{},
                ),
                .edge_s3_dump_backlog_bytes = InternalMetrics.S3DumpBacklog.init(
                    "edge_s3_dump_backlog_bytes",
                    .{ .help = "Sealed-but-not-yet-uploaded s3-dump bytes after the last flush." },
                    .{},
                ),
            },
        };
        try metrics.initializeStaticSeries();
        return metrics;
    }

    fn initializeStaticSeries(self: *RuntimeMetrics) !void {
        inline for (std.meta.tags(MethodLabel)) |method| {
            inline for (std.meta.tags(KnownPathLabel)) |known_path| {
                try self.internal.edge_requests_total.incrBy(.{
                    .method = method,
                    .known_path = known_path,
                }, 0);
            }
        }

        inline for (std.meta.tags(KnownPathLabel)) |known_path| {
            inline for (std.meta.tags(StatusClassLabel)) |status_class| {
                try self.internal.edge_responses_total.incrBy(.{
                    .known_path = known_path,
                    .status_class = status_class,
                }, 0);
            }
            inline for (std.meta.tags(ErrorClassLabel)) |class| {
                try self.internal.edge_request_errors_total.incrBy(.{
                    .known_path = known_path,
                    .class = class,
                }, 0);
            }
        }

        inline for (std.meta.tags(RouteKindLabel)) |route_kind| {
            inline for (std.meta.tags(PrefilterDecisionLabel)) |decision| {
                try self.internal.edge_prefilter_decisions_total.incrBy(.{
                    .route_kind = route_kind,
                    .decision = decision,
                }, 0);
            }
        }

        inline for (std.meta.tags(PolicyTelemetryLabel)) |telemetry| {
            try self.internal.edge_policy_records_evaluated_total.incrBy(.{ .telemetry = telemetry }, 0);
            try self.internal.edge_policy_records_kept_total.incrBy(.{ .telemetry = telemetry }, 0);
            try self.internal.edge_policy_records_dropped_total.incrBy(.{ .telemetry = telemetry }, 0);
        }

        inline for (std.meta.tags(SignalLabel)) |signal| {
            try self.internal.edge_policies_loaded.set(.{ .signal = signal }, 0);
        }
    }

    pub fn deinit(self: *RuntimeMetrics) void {
        // Free each metric vector's per-series allocations. Safe at shutdown:
        // callers deinit RuntimeMetrics only after the server has stopped
        // (listen thread joined), so no worker threads touch the metrics here.
        inline for (std.meta.fields(InternalMetrics)) |field| {
            // Vec metrics allocate per-series and expose deinit; the label-less
            // plain Counter/Gauge don't allocate and have none.
            if (@hasDecl(field.type, "deinit")) @field(self.internal, field.name).deinit();
        }
        self.* = undefined;
    }

    pub fn writePrometheus(self: *RuntimeMetrics, writer: *std.Io.Writer) !void {
        try m.write(&self.internal, writer);
    }

    /// Fold one s3-dump flush result into the extension metrics. Called after
    /// every flush (the background loop and the shutdown drain).
    pub fn recordS3DumpFlush(self: *RuntimeMetrics, result: ext.S3Dump.FlushResult) void {
        self.internal.edge_s3_dump_flushes_total.incr();
        self.internal.edge_s3_dump_objects_uploaded_total.incrBy(result.objects_uploaded);
        self.internal.edge_s3_dump_objects_failed_total.incrBy(result.objects_failed);
        self.internal.edge_s3_dump_records_uploaded_total.incrBy(result.records_uploaded);
        self.internal.edge_s3_dump_records_dropped_total.incrBy(result.records_dropped);
        self.internal.edge_s3_dump_bytes_uploaded_total.incrBy(result.bytes_uploaded);
        self.internal.edge_s3_dump_backlog_bytes.set(@intCast(result.backlog_bytes));
    }

    pub fn recordRequest(
        self: *RuntimeMetrics,
        method: MethodLabel,
        known_path: KnownPathLabel,
    ) void {
        self.internal.edge_requests_total.incr(.{
            .method = method,
            .known_path = known_path,
        }) catch |err| log.debug("failed to record request metric: {}", .{err});
    }

    pub fn recordRequestDuration(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        duration_seconds: f64,
    ) void {
        self.internal.edge_request_duration_seconds.observe(.{
            .known_path = known_path,
        }, duration_seconds) catch |err| log.debug("failed to record request duration metric: {}", .{err});
    }

    pub fn recordUpstreamAttempt(self: *RuntimeMetrics, retry: bool) void {
        self.internal.edge_upstream_attempts_total.incr();
        if (retry) self.internal.edge_upstream_retries_total.incr();
    }

    pub fn recordUpstreamTimeout(self: *RuntimeMetrics) void {
        self.internal.edge_upstream_timeouts_total.incr();
    }

    /// `delta` is +1 when a handler takes a request and -1 when it returns it.
    pub fn recordInFlight(self: *RuntimeMetrics, delta: i64) void {
        self.internal.edge_requests_in_flight.incrBy(delta);
    }

    pub fn recordConnectionAccepted(self: *RuntimeMetrics) void {
        self.internal.edge_connections_total.incr();
    }

    /// `delta` is +1 when a connection claims a slot and -1 when it frees it.
    pub fn recordConnectionsActive(self: *RuntimeMetrics, delta: i64) void {
        self.internal.edge_connections_active.incrBy(delta);
    }

    pub fn recordConnectionShed(self: *RuntimeMetrics, reason: ShedReasonLabel) void {
        self.internal.edge_connections_shed_total.incr(.{
            .reason = reason,
        }) catch |err| log.debug("failed to record shed metric: {}", .{err});
    }

    pub fn recordInboundTimeout(self: *RuntimeMetrics, phase: InboundPhaseLabel) void {
        self.internal.edge_inbound_timeouts_total.incr(.{
            .phase = phase,
        }) catch |err| log.debug("failed to record inbound timeout metric: {}", .{err});
    }

    pub fn recordInvalidRequest(self: *RuntimeMetrics) void {
        self.internal.edge_requests_invalid_total.incr();
    }

    pub fn setMaxConnections(self: *RuntimeMetrics, max_connections: usize) void {
        self.internal.edge_connections_max.set(@intCast(max_connections));
    }

    pub fn recordResponse(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        status_class: StatusClassLabel,
    ) void {
        self.internal.edge_responses_total.incr(.{
            .known_path = known_path,
            .status_class = status_class,
        }) catch |err| log.debug("failed to record response metric: {}", .{err});
    }

    pub fn recordPrefilterDecision(
        self: *RuntimeMetrics,
        route_kind: RouteKindLabel,
        decision: PrefilterDecisionLabel,
    ) void {
        self.internal.edge_prefilter_decisions_total.incr(.{
            .route_kind = route_kind,
            .decision = decision,
        }) catch |err| log.debug("failed to record prefilter decision metric: {}", .{err});
    }

    pub fn recordRequestError(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        class: ErrorClassLabel,
    ) void {
        self.internal.edge_request_errors_total.incr(.{
            .known_path = known_path,
            .class = class,
        }) catch |err| log.debug("failed to record request error metric: {}", .{err});
    }

    pub fn recordPolicyBatch(
        self: *RuntimeMetrics,
        telemetry: PolicyTelemetryLabel,
        evaluated_count: usize,
        dropped_count: usize,
    ) void {
        const kept_count = evaluated_count -| dropped_count;
        self.internal.edge_policy_records_evaluated_total.incrBy(.{
            .telemetry = telemetry,
        }, evaluated_count) catch |err| log.debug("failed to record policy evaluated metric: {}", .{err});
        self.internal.edge_policy_records_kept_total.incrBy(.{
            .telemetry = telemetry,
        }, kept_count) catch |err| log.debug("failed to record policy kept metric: {}", .{err});
        self.internal.edge_policy_records_dropped_total.incrBy(.{
            .telemetry = telemetry,
        }, dropped_count) catch |err| log.debug("failed to record policy dropped metric: {}", .{err});
    }

    pub fn setPoliciesLoaded(self: *RuntimeMetrics, signal: SignalLabel, count: u64) void {
        self.internal.edge_policies_loaded.set(.{ .signal = signal }, count) catch |err|
            log.warn("failed to set policies loaded metric: {}", .{err});
    }

    pub fn setPoliciesRejected(self: *RuntimeMetrics, count: usize) void {
        self.internal.edge_policies_rejected.set(@intCast(count));
    }

    pub fn setBuildInfo(self: *RuntimeMetrics, version: []const u8, commit: []const u8) void {
        self.internal.edge_build_info.set(.{
            .version = version,
            .commit = commit,
            .distribution = self.distribution,
        }, 1) catch |err| log.warn("failed to set build info metric: {}", .{err});
    }
};

pub fn statusClass(status: u16) StatusClassLabel {
    if (status >= 200 and status < 300) return .s2xx;
    if (status >= 300 and status < 400) return .s3xx;
    if (status >= 400 and status < 500) return .s4xx;
    if (status >= 500 and status < 600) return .s5xx;
    return .other;
}

// ============================== Tests ==============================

const testing = std.testing;

test "connection and saturation series reach the scrape" {
    var metrics: RuntimeMetrics = try .init(testing.allocator, testing.io, .datadog);
    defer metrics.deinit();

    metrics.setMaxConnections(256);
    metrics.recordConnectionAccepted();
    metrics.recordConnectionsActive(1);
    metrics.recordConnectionsActive(1);
    metrics.recordConnectionsActive(-1);
    metrics.recordConnectionShed(.slab_full);
    metrics.recordConnectionShed(.concurrency);
    metrics.recordInvalidRequest();
    metrics.recordInFlight(3);
    metrics.recordInFlight(-1);
    metrics.recordUpstreamTimeout();
    metrics.recordInboundTimeout(.idle);
    metrics.recordInboundTimeout(.request);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try metrics.writePrometheus(&out.writer);
    const text = out.written();

    // Frontend-neutral series: present on every build.
    try testing.expect(std.mem.indexOf(u8, text, "edge_connections_max 256") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_requests_in_flight 2") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_upstream_timeouts_total 1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_connections_shed_total{reason=\"slab_full\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_connections_shed_total{reason=\"concurrency\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_inbound_timeouts_total{phase=\"idle\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "edge_inbound_timeouts_total{phase=\"request\"} 1") != null);

    // Accept-time series exist only where a frontend can feed them.
    const has_conn_series = std.mem.indexOf(u8, text, "edge_connections_active 1") != null;
    try testing.expectEqual(conn_metrics_enabled, has_conn_series);
    const has_invalid = std.mem.indexOf(u8, text, "edge_requests_invalid_total 1") != null;
    try testing.expectEqual(conn_metrics_enabled, has_invalid);
}
