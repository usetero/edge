//! Internal observability endpoints under `/_edge/`: Prometheus scrape, the
//! loaded policy snapshot, and the config-gated record tap. Not the data
//! plane; nothing here touches an upstream.
const std = @import("std");
const httpz = @import("httpz");
const exec = @import("../exec.zig");

pub fn metrics(ctx: *exec.SharedCtx, res: *httpz.Response) !void {
    res.header("content-type", "text/plain; version=0.0.4");
    exec.refreshPolicyGauge(ctx);
    if (ctx.metrics) |m| try m.writePrometheus(res.writer());
    // httpz's own counters. httpz_connections going flat while httpz_requests
    // keeps climbing is the signature of the connection cap being reached.
    try httpz.writeMetrics(res.writer());
}

pub fn policies(ctx: *exec.SharedCtx, req: *httpz.Request, res: *httpz.Response) !void {
    const json = std.mem.eql(u8, (try req.query()).get("format") orelse "", "json");
    res.header("content-type", if (json) "application/json" else "text/plain; charset=utf-8");
    try exec.writePolicies(ctx.registry, res.writer(), json);
}

pub fn recordTap(ctx: *exec.SharedCtx, req: *httpz.Request, res: *httpz.Response, stage: exec.TapState.Stage) !void {
    const tap = ctx.tap orelse {
        res.status = 404;
        res.body = "tap disabled (set tap_enabled in config)\n";
        return;
    };

    var n: u32 = 50;
    if ((try req.query()).get("n")) |raw| {
        n = std.fmt.parseInt(u32, raw, 10) catch 50;
    }
    n = std.math.clamp(n, 1, 1000);

    var buf: std.Io.Writer.Allocating = .init(ctx.gpa);
    defer buf.deinit();

    if (!tap.arm(stage, n, &buf.writer)) {
        res.status = 409;
        res.body = "a tap is already active\n";
        return;
    }
    errdefer tap.disarm();

    const deadline_ns = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() + std.time.ns_per_s;
    while (!tap.finished()) {
        if (std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds() >= deadline_ns) break;
        ctx.io.sleep(.fromNanoseconds(5 * std.time.ns_per_ms), .awake) catch break;
    }
    tap.disarm(); // stop producers before we read `buf`

    res.header("content-type", "application/octet-stream");
    try res.writer().writeAll(buf.written());
}
