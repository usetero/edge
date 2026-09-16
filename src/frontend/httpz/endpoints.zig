//! Internal observability endpoints under `/_edge/`: Prometheus scrape, the
//! loaded policy snapshot, and the config-gated record tap. Not the data
//! plane; nothing here touches an upstream. Frontend-neutral: responses go
//! through a `sink` (contract in exchange.zig); the frontend parses the query.
const std = @import("std");
const exec = @import("../exec.zig");

/// `write_frontend_metrics` appends the HTTP server's own counters (httpz has
/// them; std.http.Server does not).
pub fn metrics(
    ctx: *exec.SharedCtx,
    sink: anytype,
    write_frontend_metrics: ?*const fn (*std.Io.Writer) anyerror!void,
) !void {
    exec.refreshPolicyGauge(ctx);
    const out = try sink.begin(200, &.{.{ .name = "content-type", .value = "text/plain; version=0.0.4" }});
    if (ctx.metrics) |m| try m.writePrometheus(out);
    if (write_frontend_metrics) |f| try f(out);
    try sink.end();
}

pub fn policies(ctx: *exec.SharedCtx, sink: anytype, json: bool) !void {
    const ct = if (json) "application/json" else "text/plain; charset=utf-8";
    const out = try sink.begin(200, &.{.{ .name = "content-type", .value = ct }});
    try exec.writePolicies(ctx.registry, out, json);
    try sink.end();
}

pub fn recordTap(ctx: *exec.SharedCtx, sink: anytype, stage: exec.TapState.Stage, requested: u32) !void {
    const tap = ctx.tap orelse {
        const out = try sink.begin(404, &.{});
        try out.writeAll("tap disabled (set tap_enabled in config)\n");
        return sink.end();
    };

    const n = std.math.clamp(requested, 1, 1000);

    var buf: std.Io.Writer.Allocating = .init(ctx.gpa);
    defer buf.deinit();

    if (!tap.arm(stage, n, &buf.writer)) {
        const out = try sink.begin(409, &.{});
        try out.writeAll("a tap is already active\n");
        return sink.end();
    }
    errdefer tap.disarm();

    const deadline_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() + std.time.ns_per_s;
    while (!tap.finished()) {
        if (std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() >= deadline_ns) break;
        ctx.io.sleep(.fromNanoseconds(5 * std.time.ns_per_ms), .awake) catch break;
    }
    tap.disarm(); // stop producers before we read `buf`

    const out = try sink.begin(200, &.{.{ .name = "content-type", .value = "application/octet-stream" }});
    try out.writeAll(buf.written());
    try sink.end();
}
