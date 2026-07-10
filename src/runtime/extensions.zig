//! Wiring for the `com.usetero/s3-dump` policy extension.
//!
//! Today this dumps Datadog JSON logs to S3-compatible storage. The engine
//! classifies each record per policy binding (kept/dropped/unmatched) and
//! hands the selected records to the extension sink, which serializes them
//! into batches; a single background task flushes sealed batches to S3.
//!
//! Only the Datadog log path is wired: `Extensions` carries one encoder per
//! signal, and within a binary a signal maps to exactly one accessor context
//! type. Datadog logs use `dd_logs.FieldAccessorContext`, so that is the type
//! `datadogLogEncode` casts back to. Other signal sources leave the sink null
//! (fail-open, zero cost).

const std = @import("std");
const ext = @import("extensions");
const proto = @import("proto");
const dd_logs = @import("../signals/datadog/logs.zig");
const datadog_log = @import("../signals/datadog/log.zig");
const config = @import("../config/types.zig");
const runtime_metrics = @import("runtime_metrics.zig");

pub const Extensions = ext.Extensions;

// Routed into the EventBus via StdLogAdapter (see app.zig).
const log = std.log.scoped(.s3_dump);

/// Encoder for `.log` records on the Datadog path. The engine passes the
/// accessor context (`*FieldAccessorContext`) borrowed for the duration of
/// this call; we render its log as one JSON object (the handler appends the
/// newline that makes the batch ndjson).
pub fn datadogLogEncode(record: *const anyopaque, writer: *std.Io.Writer) anyerror!void {
    const field_ctx: *const dd_logs.FieldAccessorContext = @ptrCast(@alignCast(record));
    try std.json.Stringify.value(field_ctx.log.*, .{}, writer);
}

/// Read S3 credentials from the environment. Returns null when either half is
/// absent — the extension then counts-and-drops deliveries for its targets
/// (fail-open), so a missing credential never stalls telemetry.
pub fn credentialsFromEnv(env: *const std.process.Environ.Map) ?ext.S3Dump.Credentials {
    const access = env.get("AWS_ACCESS_KEY_ID") orelse return null;
    const secret = env.get("AWS_SECRET_ACCESS_KEY") orelse return null;
    if (access.len == 0 or secret.len == 0) return null;
    return .{ .access_key_id = access, .secret_access_key = secret };
}

/// Enable the s3-dump handler on `exts` from config, wiring credentials and
/// every configured target. Caller must have `init`ed `exts` with encoders and
/// must `register` it with the registry afterwards. Targets that fail to parse
/// are logged and skipped (fail-open); a target set that ends up empty leaves
/// the handler enabled but inert.
pub fn configure(
    exts: *Extensions,
    gpa: std.mem.Allocator,
    io: std.Io,
    cfg: config.S3DumpConfig,
    env: *const std.process.Environ.Map,
) !void {
    const creds = credentialsFromEnv(env);
    if (creds == null) log.warn("AWS credentials not set; deliveries will drop", .{});

    const handler = exts.enableS3Dump(gpa, .{
        .max_batch_bytes = cfg.max_batch_bytes,
        .max_batch_records = cfg.max_batch_records,
        .max_batch_age_ms = cfg.max_batch_age_ms,
        .max_sealed_bytes = cfg.max_sealed_bytes,
        .max_attempts = cfg.max_attempts,
    }, creds);

    for (cfg.targets) |target| {
        // z3 target config = the target fields minus the policy-facing `name`.
        var json: std.Io.Writer.Allocating = .init(gpa);
        defer json.deinit();
        try std.json.Stringify.value(.{
            .endpoint = target.endpoint,
            .region = target.region,
            .bucket = target.bucket,
            .prefix = target.prefix,
            .force_path_style = target.force_path_style,
        }, .{}, &json.writer);
        handler.addTarget(io, target.name, json.written()) catch |err| {
            log.warn("skipping target '{s}': {s}", .{ target.name, @errorName(err) });
        };
    }
}

/// Background flush task: seal-and-upload on an interval until the lifecycle
/// group cancels the sleep (shutdown). The final force-flush is done by the
/// caller on the main path, where `io` is still live.
pub fn flushLoop(
    exts: *Extensions,
    io: std.Io,
    interval_ms: u64,
    metrics: ?*runtime_metrics.RuntimeMetrics,
) void {
    const interval: std.Io.Duration = .fromMilliseconds(@intCast(interval_ms));
    while (true) {
        std.Io.sleep(io, interval, .awake) catch return; // canceled at shutdown
        const result = exts.flush(io, .{});
        if (metrics) |mx| mx.recordS3DumpFlush(result);
    }
}

test "datadogLogEncode renders the delivered log context as JSON" {
    const allocator = std.testing.allocator;
    var ddlog = try datadog_log.DatadogLog.parseRaw(allocator, "{\"status\":\"info\",\"message\":\"hi\"}");
    defer ddlog.deinit(allocator);

    // The engine hands the encoder the accessor context, borrowed for the call.
    var ctx: dd_logs.FieldAccessorContext = .{ .log = &ddlog, .allocator = allocator };

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try datadogLogEncode(&ctx, &out.writer);

    // Round-trips through the same serializer as the forwarding path.
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "\"message\":\"hi\"") != null);
}

// Real-storage smoke test: drives edge's encoder + the s3-dump handler + a
// real flush against a MinIO container, exactly the path a `mode: dropped`
// policy takes. Self-skips unless the S3 env vars are set, so it's inert in
// the normal suite; `task test:s3-e2e` starts MinIO, creates the bucket, sets
// the env, and runs `zig build test-s3-e2e` (which filters to this test).
//
// Verification is by the flush result: MinIO validates the payload SHA-256 z3
// sends, so `objects_uploaded == 1 && objects_failed == 0` means the bytes
// edge produced were accepted intact. Byte-exact readback is covered by the
// encoder test above and by policy-zig's own e2e.
test "e2e minio: edge datadog log dump uploads to a real S3 server" {
    const env = std.testing.environ;
    const access = env.getPosix("AWS_ACCESS_KEY_ID") orelse return error.SkipZigTest;
    const secret = env.getPosix("AWS_SECRET_ACCESS_KEY") orelse return error.SkipZigTest;
    const endpoint = env.getPosix("S3_ENDPOINT") orelse "http://127.0.0.1:9000";
    const bucket = env.getPosix("S3_BUCKET") orelse "edge-e2e";
    const gpa = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var exts = Extensions.init(gpa, .{ .log = datadogLogEncode });
    defer exts.deinit();
    const handler = exts.enableS3Dump(gpa, .{ .max_attempts = 1 }, .{
        .access_key_id = access,
        .secret_access_key = secret,
    });

    const target_json = try std.fmt.allocPrint(
        gpa,
        \\{{"endpoint":"{s}","region":"us-east-1","bucket":"{s}","prefix":"e2e/","force_path_style":true}}
    ,
        .{ endpoint, bucket },
    );
    defer gpa.free(target_json);
    try handler.addTarget(io, "minio", target_json);

    // Resolve a delivery slot the way the engine does at snapshot compile:
    // the extension config bytes are a serialized ExtensionTargetRef.
    var ref_w: std.Io.Writer.Allocating = .init(gpa);
    defer ref_w.deinit();
    const ref: proto.policy.ExtensionTargetRef = .{ .kind = "s3", .name = "minio" };
    try ref.encode(&ref_w.writer, gpa);
    const slot = handler.resolve(io, .log, "e2e-policy", ref_w.written()) orelse
        return error.TargetNotResolved;

    // A real Datadog log, delivered through edge's own encoder.
    var ddlog = try datadog_log.DatadogLog.parseRaw(gpa, "{\"status\":\"info\",\"message\":\"e2e\"}");
    defer ddlog.deinit(gpa);
    var ctx: dd_logs.FieldAccessorContext = .{ .log = &ddlog, .allocator = gpa };
    handler.deliver(io, slot, &ctx, datadogLogEncode);

    const result = exts.flush(io, .{ .force = true });
    try std.testing.expectEqual(@as(u32, 1), result.objects_uploaded);
    try std.testing.expectEqual(@as(u32, 0), result.objects_failed);
    try std.testing.expectEqual(@as(u64, 1), result.records_uploaded);

    // The flush stats must surface on the /_edge/metrics endpoint. Record the
    // result the way the flush loop does and scrape the rendered output.
    var metrics = try runtime_metrics.RuntimeMetrics.init(gpa, io, .edge);
    defer metrics.deinit();
    metrics.recordS3DumpFlush(result);

    var scrape: std.Io.Writer.Allocating = .init(gpa);
    defer scrape.deinit();
    try metrics.writePrometheus(&scrape.writer);
    const out = scrape.written();
    try std.testing.expect(std.mem.indexOf(u8, out, "edge_s3_dump_flushes_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "edge_s3_dump_objects_uploaded_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "edge_s3_dump_objects_failed_total 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "edge_s3_dump_records_uploaded_total 1") != null);
}
