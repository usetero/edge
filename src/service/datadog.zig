//! Datadog intake services. Logs bodies are top-level JSON arrays → the
//! streaming json_array framer. Series (metrics) bodies are JSON OBJECTS
//! ({"series":[...]}) the streaming framers don't cover yet → buffered
//! batch transform, same semantics as the old module path.
//!
//! Fail-open posture ported from modules/datadog_module.zig +
//! signals/datadog/logs.zig: non-JSON content types and unsupported
//! content encodings forward raw, unevaluated — never rejected.
const std = @import("std");
const service = @import("service.zig");
const framer_mod = @import("../pipeline/framer.zig");
const encoding = @import("../pipeline/encoding.zig");

pub const logs_routes = [_]service.RoutePattern{
    .exact("/api/v2/logs", .{ .post = true }),
};

pub const metrics_routes = [_]service.RoutePattern{
    .exact("/api/v2/series", .{ .post = true }),
};

pub const Logs = struct {
    pub fn plan(_: *const Logs, req: service.PlanRequest) service.Outcome {
        // Same gate as the old processLogsStream: only JSON is evaluated.
        if (std.mem.indexOf(u8, req.content_type, "application/json") == null) {
            return .{ .forward_raw = .{ .upstream = .logs } };
        }
        const codec = service.resolveCodec(req.content_encoding) orelse {
            return .{ .forward_raw = .{ .upstream = .logs } };
        };
        return .{ .pipe_stream = .{
            .format = .json_array,
            .signal = .log,
            .upstream = .logs,
            .codec = codec,
        } };
    }
};

pub const Metrics = struct {
    pub fn plan(_: *const Metrics, req: service.PlanRequest) service.Outcome {
        if (std.mem.indexOf(u8, req.content_type, "application/json") == null) {
            return .{ .forward_raw = .{ .upstream = .metrics } };
        }
        const codec = service.resolveCodec(req.content_encoding) orelse {
            return .{ .forward_raw = .{ .upstream = .metrics } };
        };
        return .{ .pipe_buffered = .{
            .kind = .datadog_metrics_json,
            .signal = .metric,
            .upstream = .metrics,
            .codec = codec,
        } };
    }
};

const testing = std.testing;

test "logs: json body pipes through the json_array framer to the logs upstream" {
    const svc: Logs = .{};
    const outcome = svc.plan(.{
        .method = .POST,
        .path = "/api/v2/logs",
        .content_type = "application/json",
        .content_encoding = "gzip",
    });
    try testing.expectEqual(service.Signal.log, outcome.pipe_stream.signal);
    try testing.expectEqual(service.UpstreamChoice.logs, outcome.pipe_stream.upstream);
    try testing.expectEqual(framer_mod.WireFormat.json_array, outcome.pipe_stream.format);
    try testing.expectEqual(encoding.ContentEncoding.gzip, outcome.pipe_stream.codec);
}

test "logs: non-json content type forwards raw (fail-open)" {
    const svc: Logs = .{};
    const outcome = svc.plan(.{
        .method = .POST,
        .path = "/api/v2/logs",
        .content_type = "text/plain",
    });
    try testing.expectEqual(service.UpstreamChoice.logs, outcome.forward_raw.upstream);
}

test "logs: unsupported content encoding forwards raw (fail-open)" {
    const svc: Logs = .{};
    const outcome = svc.plan(.{
        .method = .POST,
        .path = "/api/v2/logs",
        .content_type = "application/json",
        .content_encoding = "br",
    });
    try testing.expectEqual(service.UpstreamChoice.logs, outcome.forward_raw.upstream);
}

test "metrics: json series body uses the buffered batch path" {
    const svc: Metrics = .{};
    const outcome = svc.plan(.{
        .method = .POST,
        .path = "/api/v2/series",
        .content_type = "application/json",
        .content_encoding = "zstd",
    });
    try testing.expectEqual(service.BufferedKind.datadog_metrics_json, outcome.pipe_buffered.kind);
    try testing.expectEqual(service.Signal.metric, outcome.pipe_buffered.signal);
    try testing.expectEqual(service.UpstreamChoice.metrics, outcome.pipe_buffered.upstream);
}
