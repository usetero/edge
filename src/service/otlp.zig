//! OTLP ingest service: one service handles /v1/logs, /v1/metrics, and
//! /v1/traces. Protobuf bodies (the dominant encoding) stream through the
//! otlp_protobuf framer — each top-level ResourceLogs/Metrics/Spans
//! submessage is a record. JSON bodies are objects the streaming framers
//! don't cover yet → buffered batch transform, same semantics as the old
//! module path. Unknown content types forward raw (fail-open), matching
//! modules/otlp_module.zig.
const std = @import("std");
const service = @import("service.zig");
const framer_mod = @import("../pipeline/framer.zig");

pub const routes = [_]service.RoutePattern{
    .exact("/v1/logs", .{ .post = true }),
    .exact("/v1/metrics", .{ .post = true }),
    .exact("/v1/traces", .{ .post = true }),
};

pub const Otlp = struct {
    pub fn plan(_: *const Otlp, req: service.PlanRequest) service.Outcome {
        const signal = signalForPath(req.path) orelse {
            return .{ .forward_raw = .{ .upstream = .default } };
        };
        const codec = service.resolveCodec(req.content_encoding) orelse {
            return .{ .forward_raw = .{ .upstream = .default } };
        };
        if (std.mem.indexOf(u8, req.content_type, "application/x-protobuf") != null) {
            return .{ .pipe_stream = .{
                .format = .otlp_protobuf,
                .signal = signal,
                .upstream = .default,
                .codec = codec,
            } };
        }
        if (std.mem.indexOf(u8, req.content_type, "application/json") != null) {
            return .{ .pipe_buffered = .{
                .kind = switch (signal) {
                    .log => .otlp_logs_json,
                    .metric => .otlp_metrics_json,
                    .trace => .otlp_traces_json,
                },
                .signal = signal,
                .upstream = .default,
                .codec = codec,
            } };
        }
        return .{ .forward_raw = .{ .upstream = .default } };
    }

    fn signalForPath(path: []const u8) ?service.Signal {
        if (std.mem.endsWith(u8, path, "/v1/logs")) return .log;
        if (std.mem.endsWith(u8, path, "/v1/metrics")) return .metric;
        if (std.mem.endsWith(u8, path, "/v1/traces")) return .trace;
        return null;
    }
};

const testing = std.testing;

test "protobuf bodies stream per signal path" {
    const svc: Otlp = .{};
    const cases = [_]struct { path: []const u8, signal: service.Signal }{
        .{ .path = "/v1/logs", .signal = .log },
        .{ .path = "/v1/metrics", .signal = .metric },
        .{ .path = "/v1/traces", .signal = .trace },
    };
    for (cases) |case| {
        const outcome = svc.plan(.{
            .method = .POST,
            .path = case.path,
            .content_type = "application/x-protobuf",
        });
        try testing.expectEqual(case.signal, outcome.pipe_stream.signal);
        try testing.expectEqual(framer_mod.WireFormat.otlp_protobuf, outcome.pipe_stream.format);
    }
}

test "json bodies take the buffered path per signal" {
    const svc: Otlp = .{};
    const outcome = svc.plan(.{
        .method = .POST,
        .path = "/v1/metrics",
        .content_type = "application/json",
        .content_encoding = "gzip",
    });
    try testing.expectEqual(service.BufferedKind.otlp_metrics_json, outcome.pipe_buffered.kind);
}

test "unknown content type and unknown path forward raw" {
    const svc: Otlp = .{};
    const weird_type = svc.plan(.{
        .method = .POST,
        .path = "/v1/logs",
        .content_type = "text/csv",
    });
    try testing.expectEqual(service.UpstreamChoice.default, weird_type.forward_raw.upstream);

    const weird_path = svc.plan(.{ .method = .POST, .path = "/v1/profiles" });
    try testing.expectEqual(service.UpstreamChoice.default, weird_path.forward_raw.upstream);
}
