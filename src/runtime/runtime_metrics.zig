const std = @import("std");
const m = @import("metrics_zig");

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

const BuildInfoLabels = struct {
    version: []const u8,
    commit: []const u8,
    distribution: DistributionLabel,
};

const InternalMetrics = struct {
    edge_requests_total: RequestsTotal,
    edge_request_duration_seconds: RequestDurationSeconds,
    edge_responses_total: ResponsesTotal,
    edge_prefilter_decisions_total: PrefilterDecisionsTotal,
    edge_request_errors_total: RequestErrorsTotal,
    edge_policy_records_evaluated_total: PolicyRecordsEvaluatedTotal,
    edge_policy_records_kept_total: PolicyRecordsKeptTotal,
    edge_policy_records_dropped_total: PolicyRecordsDroppedTotal,
    edge_build_info: BuildInfo,

    const RequestsTotal = m.CounterVec(u64, RequestLabels);
    const RequestDurationSeconds = m.HistogramVec(
        f64,
        DurationLabels,
        &.{ 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5 },
    );
    const ResponsesTotal = m.CounterVec(u64, ResponseLabels);
    const PrefilterDecisionsTotal = m.CounterVec(u64, PrefilterLabels);
    const RequestErrorsTotal = m.CounterVec(u64, ErrorLabels);
    const PolicyRecordsEvaluatedTotal = m.CounterVec(u64, PolicyLabels);
    const PolicyRecordsKeptTotal = m.CounterVec(u64, PolicyLabels);
    const PolicyRecordsDroppedTotal = m.CounterVec(u64, PolicyLabels);
    const BuildInfo = m.GaugeVec(u64, BuildInfoLabels);
};

pub const RuntimeMetrics = struct {
    allocator: std.mem.Allocator,
    distribution: DistributionLabel,
    internal: InternalMetrics = m.initializeNoop(InternalMetrics),

    pub fn init(allocator: std.mem.Allocator, distribution: DistributionLabel) !RuntimeMetrics {
        var metrics = RuntimeMetrics{
            .allocator = allocator,
            .distribution = distribution,
            .internal = .{
                .edge_requests_total = try InternalMetrics.RequestsTotal.init(
                    allocator,
                    "edge_requests_total",
                    .{ .help = "Total number of HTTP requests handled by edge." },
                    .{},
                ),
                .edge_request_duration_seconds = try InternalMetrics.RequestDurationSeconds.init(
                    allocator,
                    "edge_request_duration_seconds",
                    .{ .help = "HTTP request latency in seconds." },
                    .{},
                ),
                .edge_responses_total = try InternalMetrics.ResponsesTotal.init(
                    allocator,
                    "edge_responses_total",
                    .{ .help = "Total number of HTTP responses produced by edge." },
                    .{},
                ),
                .edge_prefilter_decisions_total = try InternalMetrics.PrefilterDecisionsTotal.init(
                    allocator,
                    "edge_prefilter_decisions_total",
                    .{ .help = "Total number of prefilter routing decisions." },
                    .{},
                ),
                .edge_request_errors_total = try InternalMetrics.RequestErrorsTotal.init(
                    allocator,
                    "edge_request_errors_total",
                    .{ .help = "Total number of request-level errors." },
                    .{},
                ),
                .edge_policy_records_evaluated_total = try InternalMetrics.PolicyRecordsEvaluatedTotal.init(
                    allocator,
                    "edge_policy_records_evaluated_total",
                    .{ .help = "Total number of telemetry records evaluated by the policy engine." },
                    .{},
                ),
                .edge_policy_records_kept_total = try InternalMetrics.PolicyRecordsKeptTotal.init(
                    allocator,
                    "edge_policy_records_kept_total",
                    .{ .help = "Total number of telemetry records kept after policy evaluation." },
                    .{},
                ),
                .edge_policy_records_dropped_total = try InternalMetrics.PolicyRecordsDroppedTotal.init(
                    allocator,
                    "edge_policy_records_dropped_total",
                    .{ .help = "Total number of telemetry records dropped after policy evaluation." },
                    .{},
                ),
                .edge_build_info = try InternalMetrics.BuildInfo.init(
                    allocator,
                    "edge_build_info",
                    .{ .help = "Build metadata for this edge process." },
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
    }

    pub fn deinit(self: *RuntimeMetrics) void {
        _ = self;
        // Intentionally no-op at process shutdown.
        // These metric vectors may still be touched by worker threads during teardown,
        // and freeing them has caused shutdown-time memory corruption.
    }

    pub fn writePrometheus(self: *RuntimeMetrics, writer: *std.Io.Writer) !void {
        try m.write(&self.internal, writer);
    }

    pub fn recordRequest(
        self: *RuntimeMetrics,
        method: MethodLabel,
        known_path: KnownPathLabel,
    ) void {
        self.internal.edge_requests_total.incr(.{
            .method = method,
            .known_path = known_path,
        }) catch {};
    }

    pub fn recordRequestDuration(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        duration_seconds: f64,
    ) void {
        self.internal.edge_request_duration_seconds.observe(.{
            .known_path = known_path,
        }, duration_seconds) catch {};
    }

    pub fn recordResponse(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        status_class: StatusClassLabel,
    ) void {
        self.internal.edge_responses_total.incr(.{
            .known_path = known_path,
            .status_class = status_class,
        }) catch {};
    }

    pub fn recordPrefilterDecision(
        self: *RuntimeMetrics,
        route_kind: RouteKindLabel,
        decision: PrefilterDecisionLabel,
    ) void {
        self.internal.edge_prefilter_decisions_total.incr(.{
            .route_kind = route_kind,
            .decision = decision,
        }) catch {};
    }

    pub fn recordRequestError(
        self: *RuntimeMetrics,
        known_path: KnownPathLabel,
        class: ErrorClassLabel,
    ) void {
        self.internal.edge_request_errors_total.incr(.{
            .known_path = known_path,
            .class = class,
        }) catch {};
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
        }, evaluated_count) catch {};
        self.internal.edge_policy_records_kept_total.incrBy(.{
            .telemetry = telemetry,
        }, kept_count) catch {};
        self.internal.edge_policy_records_dropped_total.incrBy(.{
            .telemetry = telemetry,
        }, dropped_count) catch {};
    }

    pub fn setBuildInfo(self: *RuntimeMetrics, version: []const u8, commit: []const u8) void {
        self.internal.edge_build_info.set(.{
            .version = version,
            .commit = commit,
            .distribution = self.distribution,
        }, 1) catch {};
    }
};

pub fn statusClass(status: u16) StatusClassLabel {
    if (status >= 200 and status < 300) return .s2xx;
    if (status >= 300 and status < 400) return .s3xx;
    if (status >= 400 and status < 500) return .s4xx;
    if (status >= 500 and status < 600) return .s5xx;
    return .other;
}
