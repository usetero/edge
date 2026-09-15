//! Characterization fixtures for behavior the replacement runtime must preserve.
const std = @import("std");
const config = @import("../config/types.zig");
const distro = @import("../runtime/distro.zig");
const mode = @import("../runtime/mode.zig");
const service = @import("../service/service.zig");
const routing = @import("../service/router.zig");
const httpz_server = @import("../frontend/httpz/server.zig");
const checkpoint_wal = @import("../tail/checkpoint/wal.zig");
const checkpoint_snapshot = @import("../tail/checkpoint/snapshot.zig");
const checkpoint_types = @import("../tail/checkpoint/types.zig");

const testing = std.testing;
const DISTRIBUTIONS = [_]mode.Distribution{ .edge, .datadog, .otlp, .prometheus };

fn makeRouter(comptime distribution: mode.Distribution) !routing.Router {
    const kinds = comptime distro.servicesFor(distribution);
    var sets: [kinds.len]routing.RouteSet = undefined;
    for (kinds, 0..) |kind, i| {
        const svc = distro.buildService(kind, .{});
        sets[i] = .{ .service = @enumFromInt(i), .routes = svc.routes() };
    }
    return routing.Router.init(testing.allocator, &sets);
}

test "v2 compatibility preserves HTTP distribution routing and method boundaries" {
    const Case = struct {
        path: []const u8,
        method: service.HttpMethod,
        expected: [4]?service.ServiceKind,
    };
    const cases = [_]Case{
        .{ .path = "/_health", .method = .GET, .expected = @splat(.health) },
        .{ .path = "/_health", .method = .POST, .expected = @splat(.passthrough) },
        .{
            .path = "/api/v2/logs",
            .method = .POST,
            .expected = .{ .datadog_logs, .datadog_logs, .passthrough, .passthrough },
        },
        .{
            .path = "/api/v2/series",
            .method = .POST,
            .expected = .{ .datadog_metrics, .datadog_metrics, .passthrough, .passthrough },
        },
        .{ .path = "/v1/logs", .method = .POST, .expected = .{ .otlp, .passthrough, .otlp, .passthrough } },
        .{ .path = "/v1/metrics", .method = .POST, .expected = .{ .otlp, .passthrough, .otlp, .passthrough } },
        .{ .path = "/v1/traces", .method = .POST, .expected = .{ .otlp, .passthrough, .otlp, .passthrough } },
        .{ .path = "/metrics", .method = .GET, .expected = .{ .prometheus, .passthrough, .passthrough, .prometheus } },
        .{
            .path = "/metrics/instance",
            .method = .GET,
            .expected = .{ .prometheus, .passthrough, .passthrough, .prometheus },
        },
        .{ .path = "/metrics-extra", .method = .GET, .expected = @splat(.passthrough) },
        .{ .path = "/metrics", .method = .POST, .expected = @splat(.passthrough) },
        .{ .path = "/v1/logs", .method = .GET, .expected = @splat(.passthrough) },
        .{ .path = "/unknown", .method = .PATCH, .expected = @splat(.passthrough) },
        .{ .path = "/unknown", .method = .OTHER, .expected = @splat(null) },
    };
    inline for (DISTRIBUTIONS, 0..) |distribution, column| {
        var router = try makeRouter(distribution);
        defer router.deinit();
        const kinds = distro.servicesFor(distribution);
        for (cases) |case| {
            const matched = router.route(case.path, case.method);
            const actual = if (matched) |m| kinds[@intFromEnum(m.service)] else null;
            try testing.expectEqual(case.expected[column], actual);
        }
    }
}

test "v2 compatibility preserves raw intake destinations and duplicate tolerance" {
    const Case = struct {
        kind: service.ServiceKind,
        path: []const u8,
        upstream: service.UpstreamChoice,
        replayable: bool,
    };
    const cases = [_]Case{
        .{ .kind = .datadog_logs, .path = "/api/v2/logs", .upstream = .logs, .replayable = true },
        .{ .kind = .datadog_metrics, .path = "/api/v2/series", .upstream = .metrics, .replayable = false },
        .{ .kind = .otlp, .path = "/v1/logs", .upstream = .default, .replayable = true },
        .{ .kind = .otlp, .path = "/v1/metrics", .upstream = .default, .replayable = false },
        .{ .kind = .otlp, .path = "/v1/traces", .upstream = .default, .replayable = false },
        .{ .kind = .passthrough, .path = "/unknown", .upstream = .default, .replayable = false },
    };
    for (cases) |case| {
        const svc = distro.buildService(case.kind, .{});
        for ([_][]const u8{ "text/plain", "application/json" }) |content_type| {
            for ([_][]const u8{ "br", "gzip, deflate" }) |content_encoding| {
                const actual = svc.plan(.{
                    .method = .POST,
                    .path = case.path,
                    .content_type = content_type,
                    .content_encoding = content_encoding,
                });
                const expected: service.Outcome = .{
                    .forward_raw = .{ .upstream = case.upstream, .replayable = case.replayable },
                };
                try testing.expectEqualDeep(expected, actual);
            }
        }
    }
}

test "v2 compatibility preserves processed intake format signal and codec" {
    const logs = distro.buildService(.datadog_logs, .{});
    const logs_expected: service.Outcome = .{ .pipe_stream = .{
        .upstream = .logs,
        .signal = .log,
        .format = .json_array,
        .codec = .gzip,
    } };
    try testing.expectEqualDeep(logs_expected, logs.plan(.{
        .method = .POST,
        .path = "/api/v2/logs",
        .content_type = "application/json",
        .content_encoding = "gzip",
    }));
    const metrics = distro.buildService(.datadog_metrics, .{});
    const metrics_expected: service.Outcome = .{ .pipe_buffered = .{
        .upstream = .metrics,
        .signal = .metric,
        .kind = .datadog_metrics_json,
        .codec = .zstd,
    } };
    try testing.expectEqualDeep(metrics_expected, metrics.plan(.{
        .method = .POST,
        .path = "/api/v2/series",
        .content_type = "application/json",
        .content_encoding = "zstd",
    }));
    const otlp = distro.buildService(.otlp, .{});
    const cases = [_]struct { path: []const u8, signal: service.Signal, kind: service.BufferedKind }{
        .{ .path = "/v1/logs", .signal = .log, .kind = .otlp_logs_json },
        .{ .path = "/v1/metrics", .signal = .metric, .kind = .otlp_metrics_json },
        .{ .path = "/v1/traces", .signal = .trace, .kind = .otlp_traces_json },
    };
    for (cases) |case| {
        const pb_expected: service.Outcome = .{
            .pipe_stream = .{ .upstream = .default, .signal = case.signal, .format = .otlp_protobuf, .codec = .gzip },
        };
        try testing.expectEqualDeep(pb_expected, otlp.plan(.{
            .method = .POST,
            .path = case.path,
            .content_type = "application/x-protobuf",
            .content_encoding = "gzip",
        }));
        const json_expected: service.Outcome = .{
            .pipe_buffered = .{ .upstream = .default, .signal = case.signal, .kind = case.kind, .codec = .zstd },
        };
        try testing.expectEqualDeep(json_expected, otlp.plan(.{
            .method = .POST,
            .path = case.path,
            .content_type = "application/json",
            .content_encoding = "zstd",
        }));
    }
}

test "v2 compatibility preserves zero scrape limits through service composition" {
    const svc = distro.buildService(.prometheus, .{
        .prometheus_max_input_bytes = 0,
        .prometheus_max_output_bytes = 0,
    });
    const expected: service.Outcome = .{
        .fetch_filtered = .{ .upstream = .metrics, .max_input_bytes = 0, .max_output_bytes = 0 },
    };
    try testing.expectEqualDeep(expected, svc.plan(.{ .method = .GET, .path = "/metrics" }));
}

test "v2 compatibility preserves config defaults and explicit thread values" {
    var defaults: config.ProxyConfig = .{};
    try defaults.validate();
    try testing.expectEqual(@as(u32, 256), defaults.max_connections);
    try testing.expectEqual(@as(u32, 1572864), defaults.max_body_size);
    try testing.expectEqual(@as(?u32, null), defaults.max_decoded_bytes);
    try testing.expect(defaults.worker_count == null and defaults.thread_pool_count == null);
    try testing.expectEqualStrings("http://127.0.0.1:80", defaults.upstream_url);
    try testing.expect(defaults.logs_url == null and defaults.metrics_url == null);
    try testing.expect(!defaults.tap_enabled and !defaults.s3_dump.enabled);
    try testing.expectEqual(@as(usize, 10485760), defaults.prometheus.max_input_bytes_per_scrape);
    try testing.expectEqual(@as(usize, 10485760), defaults.prometheus.max_output_bytes_per_scrape);

    var explicit: config.ProxyConfig = .{ .worker_count = 65, .thread_pool_count = 128, .max_connections = 65535 };
    try explicit.validate();
    try testing.expectEqual(@as(?u16, 65), explicit.worker_count);
    try testing.expectEqual(@as(?u16, 128), explicit.thread_pool_count);
    explicit.max_connections = 65536;
    try testing.expectError(error.InvalidLimits, explicit.validate());
    explicit.max_connections = 1;
    explicit.thread_pool_count = 0;
    try testing.expectError(error.InvalidLimits, explicit.validate());
}

test "v2 compat: processed intake replays only the log signal" {
    // Raw routes carry an explicit `replayable` flag; processed routes decide at
    // the exchange call sites from the signal alone. Both paths still add a
    // second attempt for GET/HEAD inside the exchange itself.
    try std.testing.expect(httpz_server.processedReplayable(.log));
    try std.testing.expect(!httpz_server.processedReplayable(.metric));
    try std.testing.expect(!httpz_server.processedReplayable(.trace));
}

test "v2 compat: admin endpoints are GET-only and precede service routing" {
    const Admin = httpz_server.AdminRoute;
    const Case = struct { path: []const u8, get: ?Admin };
    const cases = [_]Case{
        .{ .path = "/_edge/metrics", .get = .metrics },
        .{ .path = "/_edge/policies", .get = .policies },
        .{ .path = "/_edge/tap/pre", .get = .tap_pre },
        .{ .path = "/_edge/tap/post", .get = .tap_post },
        .{ .path = "/_edge/tap/other", .get = .tap_unknown },
        .{ .path = "/_edge/tap", .get = null },
        .{ .path = "/_edge/unknown", .get = null },
        .{ .path = "/_health", .get = null },
    };
    for (cases) |case| {
        try testing.expectEqual(case.get, httpz_server.adminRoute(.GET, case.path));
        // Any other method falls through to the router, which serves passthrough.
        try testing.expectEqual(@as(?Admin, null), httpz_server.adminRoute(.POST, case.path));
        try testing.expectEqual(@as(?Admin, null), httpz_server.adminRoute(.HEAD, case.path));
    }
}

// One WAL record / one snapshot for {dev 1, inode 2, fingerprint 3, offset 99,
// last_seen_ns 456}, lsn 7: little-endian extern layout with CRC32 over the
// zero-checksum record. v2 tail must read and write exactly these bytes.
const GOLDEN_WAL_RECORD = "5757414c01000000070000000000000001000000000000000200000000000000" ++
    "03000000000000006300000000000000c801000000000000a813289600000000";
const GOLDEN_SNAPSHOT = "43504b5301000000010000000000000001000000000000000200000000000000" ++
    "03000000000000006300000000000000c8010000000000007787a1bb00000000";
const golden_value: checkpoint_types.Value = .{
    .identity = .{ .dev = 1, .inode = 2, .fingerprint = 3 },
    .offset = 99,
    .last_seen_ns = 456,
};

test "v2 compat: tail checkpoint WAL bytes are stable and replay to the same value" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(dir);
    var wal = try checkpoint_wal.Wal.init(testing.allocator, io, dir);
    defer wal.deinit();
    try wal.append(7, golden_value);
    try wal.sync();
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, GOLDEN_WAL_RECORD);
    const written = try tmp.dir.readFileAlloc(io, "checkpoint.wal", testing.allocator, .limited(1024));
    defer testing.allocator.free(written);
    try testing.expectEqualSlices(u8, &expected, written);
    var replayed = try wal.replay(testing.allocator);
    defer replayed.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), replayed.entries.items.len);
    try testing.expectEqual(@as(u64, 7), replayed.entries.items[0].lsn);
    try testing.expectEqual(golden_value, replayed.entries.items[0].value);
    try testing.expectEqual(@as(u64, 8), replayed.next_lsn);
}

test "v2 compat: tail checkpoint snapshot bytes are stable and load to the same value" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(dir);
    var snapshot = try checkpoint_snapshot.Snapshot.init(testing.allocator, io, dir);
    defer snapshot.deinit();
    var expected: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, GOLDEN_SNAPSHOT);
    // Today's writer produces the golden bytes...
    try snapshot.write(&.{golden_value});
    const written = try tmp.dir.readFileAlloc(io, "checkpoint.snap", testing.allocator, .limited(1024));
    defer testing.allocator.free(written);
    try testing.expectEqualSlices(u8, &expected, written);
    // ...and a file holding only the golden bytes loads back to the value.
    try tmp.dir.writeFile(io, .{ .sub_path = "checkpoint.snap", .data = &expected });
    var loaded = try snapshot.load(testing.allocator);
    defer loaded.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), loaded.items.len);
    try testing.expectEqual(golden_value, loaded.items[0]);
}
