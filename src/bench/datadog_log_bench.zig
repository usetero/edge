//! Benchmark for Datadog log search/filter performance.
//!
//! Exercises the policy matcher over the Datadog log accessor, including the
//! JSON-unwrapping fallback path (a log whose `message` field is itself a
//! stringified JSON document). Run with: `zig build datadog-log-bench`.
const std = @import("std");
const zbench = @import("zbench");
const edge = @import("edge");
const proto = @import("proto");
const o11y = @import("o11y");

const logs = edge.signals_datadog_logs;
const PolicyRegistry = edge.policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// A single real Datadog log whose `message` is a stringified JSON document
// (the wrapping a GCP/Cloud Run -> Datadog forwarder produces).
const wrapped_log = @embedFile("datadog_wrapped_log");

// A plain, high-volume-shaped log that does NOT match the policy: guards the
// hot path so the unwrap fallback can't regress the common case.
const plain_log =
    \\{"message":"GET /healthz 200 1ms","status":"info","service":"api","hostname":"web-01","ddsource":"nginx"}
;

const batch_count = 50;

// Globals: zbench's BenchFunc is `fn(Allocator) void` with no context pointer,
// so the prepared registry/bus and pre-built payloads live here.
var g_bus: *EventBus = undefined;
var g_registry: *PolicyRegistry = undefined;
var g_rewrite_registry: *PolicyRegistry = undefined;
var g_wrapped_batch: []const u8 = undefined;
var g_plain_batch: []const u8 = undefined;

fn runOnce(allocator: std.mem.Allocator, registry: *PolicyRegistry, payload: []const u8) void {
    var in_reader = std.Io.Reader.fixed(payload);
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    _ = logs.processLogsStream(
        allocator,
        registry,
        g_bus,
        &in_reader,
        &out.writer,
        "application/json",
    ) catch |err| {
        std.debug.panic("processLogsStream failed: {t}", .{err});
    };
}

fn benchWrappedSingle(allocator: std.mem.Allocator) void {
    runOnce(allocator, g_registry, wrapped_log);
}

fn benchWrappedBatch(allocator: std.mem.Allocator) void {
    runOnce(allocator, g_registry, g_wrapped_batch);
}

fn benchPlainBatch(allocator: std.mem.Allocator) void {
    runOnce(allocator, g_registry, g_plain_batch);
}

fn benchWrappedRewriteBatch(allocator: std.mem.Allocator) void {
    runOnce(allocator, g_rewrite_registry, g_wrapped_batch);
}

/// Build "[obj,obj,...]" from a single JSON object, `count` copies.
fn buildBatch(allocator: std.mem.Allocator, obj: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, obj, " \t\r\n");
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try out.writer.writeByte('[');
    for (0..batch_count) |i| {
        if (i != 0) try out.writer.writeByte(',');
        try out.writer.writeAll(trimmed);
    }
    try out.writer.writeByte(']');
    return out.toOwnedSlice();
}

/// The EvidenceSkipped policy from production: body == "evidence skipped" AND
/// data.jsonPayload.event_type == "EvidenceSkipped". Both are exact matches,
/// which only fire once the wrapped `message` is unwrapped.
fn buildPolicy(allocator: std.mem.Allocator) !proto.policy.Policy {
    var p: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "evidence-skipped"),
        .name = try allocator.dupe(u8, "worker-change-issue-resolve/issue_evidence_skipped"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try p.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try allocator.dupe(u8, "evidence skipped") },
    });
    var event_type_path: proto.policy.AttributePath = .{};
    try event_type_path.path.append(allocator, try allocator.dupe(u8, "data"));
    try event_type_path.path.append(allocator, try allocator.dupe(u8, "jsonPayload"));
    try event_type_path.path.append(allocator, try allocator.dupe(u8, "event_type"));
    try p.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = event_type_path },
        .match = .{ .exact = try allocator.dupe(u8, "EvidenceSkipped") },
    });
    return p;
}

/// keep=all policy that edits fields *inside* the wrapped message: remove
/// data.jsonPayload.event_type and redact data.jsonPayload.account_name.
/// Exercises the parse -> mutate -> re-serialize (re-wrap) path.
fn buildRewritePolicy(allocator: std.mem.Allocator) !proto.policy.Policy {
    var transform: proto.policy.LogTransform = .{};
    var remove_path: proto.policy.AttributePath = .{};
    try remove_path.path.append(allocator, try allocator.dupe(u8, "data"));
    try remove_path.path.append(allocator, try allocator.dupe(u8, "jsonPayload"));
    try remove_path.path.append(allocator, try allocator.dupe(u8, "event_type"));
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = remove_path } });

    var redact_path: proto.policy.AttributePath = .{};
    try redact_path.path.append(allocator, try allocator.dupe(u8, "data"));
    try redact_path.path.append(allocator, try allocator.dupe(u8, "jsonPayload"));
    try redact_path.path.append(allocator, try allocator.dupe(u8, "account_name"));
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = redact_path },
        .replacement = try allocator.dupe(u8, "REDACTED"),
    });

    var p: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "rewrite-wrapped"),
        .name = try allocator.dupe(u8, "rewrite-wrapped"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all"), .transform = transform } },
    };
    try p.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try allocator.dupe(u8, "evidence skipped") },
    });
    return p;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(init.io);
    g_bus = noop_bus.eventBus();

    var registry = PolicyRegistry.init(gpa, g_bus);
    defer registry.deinit();
    g_registry = &registry;

    var policy = try buildPolicy(gpa);
    defer policy.deinit(gpa);
    try registry.updatePolicies(&.{policy}, "bench", .file);

    var rewrite_registry = PolicyRegistry.init(gpa, g_bus);
    defer rewrite_registry.deinit();
    g_rewrite_registry = &rewrite_registry;
    var rewrite_policy = try buildRewritePolicy(gpa);
    defer rewrite_policy.deinit(gpa);
    try rewrite_registry.updatePolicies(&.{rewrite_policy}, "bench", .file);

    g_wrapped_batch = try buildBatch(gpa, wrapped_log);
    defer gpa.free(g_wrapped_batch);
    g_plain_batch = try buildBatch(gpa, plain_log);
    defer gpa.free(g_plain_batch);

    var bench = zbench.Benchmark.init(gpa, .{});
    defer bench.deinit();

    try bench.add("wrapped single", benchWrappedSingle, .{});
    try bench.add("wrapped batch x50", benchWrappedBatch, .{});
    try bench.add("wrapped rewrite x50", benchWrappedRewriteBatch, .{});
    try bench.add("plain batch x50 (no match)", benchPlainBatch, .{});

    const stdout: std.Io.File = .stdout();
    try bench.run(init.io, stdout);
}
