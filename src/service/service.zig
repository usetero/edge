//! Service layer: pure decision logic mapping a matched request to a
//! declarative Outcome that the connection driver executes (PLAN.md §8).
//!
//! Services never perform IO. `plan()` looks at method, path, and headers
//! and returns WHAT should happen — respond statically, copy raw, run the
//! record pipeline, run a buffered batch transform, or fetch-and-filter a
//! response. Dispatch is a tagged union with inline-else (no vtables);
//! per-service state is plain data.
const std = @import("std");
const framer_mod = @import("../pipeline/framer.zig");
const encoding = @import("../pipeline/encoding.zig");

pub const health = @import("health.zig");
pub const passthrough = @import("passthrough.zig");
pub const datadog = @import("datadog.zig");
pub const otlp = @import("otlp.zig");
pub const prometheus = @import("prometheus.zig");

pub const ServiceKind = enum {
    health,
    passthrough,
    datadog_logs,
    datadog_metrics,
    otlp,
    prometheus,
};

/// Index into a distro's service table; 16 bits keeps route entries compact.
pub const ServiceIndex = enum(u16) { _ };

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    OTHER,

    pub fn fromStd(method: std.http.Method) HttpMethod {
        return switch (method) {
            .GET => .GET,
            .POST => .POST,
            .PUT => .PUT,
            .DELETE => .DELETE,
            .PATCH => .PATCH,
            .HEAD => .HEAD,
            .OPTIONS => .OPTIONS,
            else => .OTHER,
        };
    }
};

pub const MethodBitmask = packed struct(u8) {
    get: bool = false,
    post: bool = false,
    put: bool = false,
    delete: bool = false,
    patch: bool = false,
    head: bool = false,
    options: bool = false,
    _unused: u1 = 0,

    pub const all: MethodBitmask = .{
        .get = true,
        .post = true,
        .put = true,
        .delete = true,
        .patch = true,
        .head = true,
        .options = true,
    };

    pub fn matches(self: MethodBitmask, method: HttpMethod) bool {
        return switch (method) {
            .GET => self.get,
            .POST => self.post,
            .PUT => self.put,
            .DELETE => self.delete,
            .PATCH => self.patch,
            .HEAD => self.head,
            .OPTIONS => self.options,
            .OTHER => false,
        };
    }
};

/// Route pattern, ported from modules/module_types.zig (same matching
/// semantics so router behavior is unchanged by the rewrite).
pub const RoutePattern = struct {
    pattern_type: PatternType,
    hash: u64,
    pattern: []const u8,
    methods: MethodBitmask,

    pub const PatternType = enum {
        exact,
        prefix,
        suffix,
        any,
    };

    pub fn exact(path: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .exact,
            .hash = std.hash.Wyhash.hash(0, path),
            .pattern = path,
            .methods = methods,
        };
    }

    pub fn prefix(path_prefix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .prefix,
            .hash = 0,
            .pattern = path_prefix,
            .methods = methods,
        };
    }

    pub fn suffix(path_suffix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .suffix,
            .hash = 0,
            .pattern = path_suffix,
            .methods = methods,
        };
    }

    pub fn any(methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .any,
            .hash = 0,
            .pattern = "/*",
            .methods = methods,
        };
    }
};

/// Telemetry signal a piped body carries; selects the policy index and the
/// record sink binding in the connection driver.
pub const Signal = enum { log, metric, trace };

/// Which configured upstream the outcome targets. Resolved to a concrete
/// upstream at startup by the distro wiring (logs_url / metrics_url fall
/// back to upstream_url, per app.zig:409-410 semantics).
pub const UpstreamChoice = enum { default, logs, metrics };

/// Whole-body batch transforms for shapes the streaming framers do not
/// cover yet: JSON OBJECT bodies ({"series":[...]}, OTLP/JSON). The driver
/// decodes fully (bounded by max_body_size), calls the signal batch fn,
/// re-encodes. Same semantics as the old modules.
pub const BufferedKind = enum {
    datadog_metrics_json,
    otlp_logs_json,
    otlp_metrics_json,
    otlp_traces_json,
};

pub const StaticResponse = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

pub const PipeStream = struct {
    format: framer_mod.WireFormat,
    signal: Signal,
    upstream: UpstreamChoice,
    /// Request body Content-Encoding; output is re-encoded the same way.
    codec: encoding.ContentEncoding,
};

pub const PipeBuffered = struct {
    kind: BufferedKind,
    signal: Signal,
    upstream: UpstreamChoice,
    codec: encoding.ContentEncoding,
};

pub const Forward = struct {
    upstream: UpstreamChoice,
};

pub const FetchFiltered = struct {
    upstream: UpstreamChoice,
    /// Prometheus scrape budgets (0 = unlimited), from config.prometheus.
    max_input_bytes: usize,
    max_output_bytes: usize,
};

/// What the connection driver should do for a matched request. Pure data —
/// produced without IO, executed by http/conn.zig.
pub const Outcome = union(enum) {
    respond: StaticResponse,
    forward_raw: Forward,
    pipe_stream: PipeStream,
    pipe_buffered: PipeBuffered,
    fetch_filtered: FetchFiltered,
};

/// Everything plan() may consult. Header values are pre-extracted by the
/// driver so services never touch connection state.
pub const PlanRequest = struct {
    method: HttpMethod,
    path: []const u8,
    content_type: []const u8 = "",
    content_encoding: []const u8 = "",
};

pub const Service = union(ServiceKind) {
    health: health.Health,
    passthrough: passthrough.Passthrough,
    datadog_logs: datadog.Logs,
    datadog_metrics: datadog.Metrics,
    otlp: otlp.Otlp,
    prometheus: prometheus.Prometheus,

    pub fn plan(self: *const Service, req: PlanRequest) Outcome {
        return switch (self.*) {
            inline else => |*svc| svc.plan(req),
        };
    }

    pub fn routes(self: *const Service) []const RoutePattern {
        return switch (self.*) {
            .health => &health.routes,
            .passthrough => &passthrough.routes,
            .datadog_logs => &datadog.logs_routes,
            .datadog_metrics => &datadog.metrics_routes,
            .otlp => &otlp.routes,
            .prometheus => &prometheus.routes,
        };
    }
};

/// Resolves a Content-Encoding header to a codec, or null when the encoding
/// is unsupported — the caller forwards the body opaque/unfiltered rather
/// than failing the request (PLAN §6.5 fail-open posture).
pub fn resolveCodec(content_encoding: []const u8) ?encoding.ContentEncoding {
    return encoding.ContentEncoding.fromHeader(content_encoding);
}

test {
    _ = health;
    _ = passthrough;
    _ = datadog;
    _ = otlp;
    _ = prometheus;
}

test "MethodBitmask.matches" {
    const post_only: MethodBitmask = .{ .post = true };
    try std.testing.expect(post_only.matches(.POST));
    try std.testing.expect(!post_only.matches(.GET));

    const get_post: MethodBitmask = .{ .get = true, .post = true };
    try std.testing.expect(get_post.matches(.GET));
    try std.testing.expect(get_post.matches(.POST));

    try std.testing.expect(MethodBitmask.all.matches(.DELETE));
}

test "RoutePattern.exact" {
    const route = RoutePattern.exact("/api/v2/logs", .{ .post = true });
    try std.testing.expectEqual(RoutePattern.PatternType.exact, route.pattern_type);
    try std.testing.expectEqual(std.hash.Wyhash.hash(0, "/api/v2/logs"), route.hash);
    try std.testing.expectEqualStrings("/api/v2/logs", route.pattern);
}

test "HttpMethod.fromStd" {
    // Parity with the old proxy/server.zig toHttpMethod test.
    try std.testing.expectEqual(HttpMethod.GET, HttpMethod.fromStd(.GET));
    try std.testing.expectEqual(HttpMethod.POST, HttpMethod.fromStd(.POST));
    try std.testing.expectEqual(HttpMethod.DELETE, HttpMethod.fromStd(.DELETE));
}
