const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const datadog_log = @import("log.zig");

const PolicyEngine = policy.PolicyEngine;
pub const FieldRef = policy.FieldRef;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;
const DatadogLog = datadog_log.DatadogLog;

pub const Parser = datadog_log.Parser;

/// Verdict for one evaluated record. `replace` bytes are owned by the scratch
/// allocator passed to `evalLogRecord` and die on its next reset.
pub const RecordVerdict = union(enum) {
    keep,
    drop,
    replace: []const u8,
};

/// Evaluate ONE JSON log record (one intake-array element) in place.
///
/// The common case — no policy drops or mutates the record — returns `.keep`
/// without allocating or copying anything: the caller forwards the original
/// bytes. Output is serialized only when a transform actually changed the
/// record. Fail-open: input that doesn't parse as a JSON object is kept
/// verbatim, matching the batch path's returnUnchanged semantics.
pub fn evalLogRecord(
    scratch: std.mem.Allocator,
    parser: *Parser,
    parser_gpa: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    record: []const u8,
    sink: ?policy.ExtensionSink,
) !RecordVerdict {
    // Single-pass zero-copy parse; zimdjson never runs on the hot path.
    // Anything the walker doesn't like — non-object records, escaped keys,
    // structural surprises — re-parses through the fully validating
    // materializing path, so semantics never depend on the fast path. Only
    // when both fail does the record fail open to keep.
    // Hand the reused parser down so the lazy message unwrap does not build a
    // fresh structural index per record.
    var log_obj = DatadogLog.parseRaw(scratch, record) catch blk: {
        const document = parser.parseFromSlice(parser_gpa, record) catch return .keep;
        const value_type = document.asValue().getType() catch return .keep;
        if (value_type != .object) return .keep;
        // No `unwrap_parser` on this path. `parse` keeps unknown fields as
        // lazy AnyValues backed by `document`, which is backed by `parser`'s
        // structural index; a later body lookup re-parsing the inner wrapper
        // on that same parser would replace the index under them. The unwrap
        // falls back to its own local parser instead.
        break :blk DatadogLog.parse(scratch, document.asValue()) catch return .keep;
    };
    // Only reached when parseRaw succeeded, so the parser holds no document
    // this log still reads from. Sharing it saves a structural index per
    // record on the unwrap path.
    log_obj.unwrap_parser = parser;
    log_obj.unwrap_parser_gpa = parser_gpa;

    const engine = PolicyEngine.init(bus, @constCast(registry));
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;
    const result = filterLog(&engine, &log_obj, scratch, &policy_id_buf, sink);
    if (!result.keep) return .drop;
    if (!result.mutated) return .keep;

    var out: std.Io.Writer.Allocating = .init(scratch);
    try std.json.Stringify.value(log_obj, .{}, &out.writer);
    return .{ .replace = out.written() };
}

/// Context for field accessor and mutator - holds the DatadogLog struct.
pub const FieldAccessorContext = struct {
    log: *DatadogLog,
    allocator: std.mem.Allocator,
};

/// Look up an attribute across all Datadog log data sources.
/// Searches known fields, ddtags, and extra HashMap (with nested support).
/// Since Datadog has no resource/scope distinction, all attribute types
/// search the same flat namespace.
fn lookupLogAttribute(log: *DatadogLog, allocator: std.mem.Allocator, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;
    const key = path[0];

    // Check known fields (only for single-segment paths)
    if (path.len == 1) {
        if (std.mem.eql(u8, key, "service")) return log.service;
        if (std.mem.eql(u8, key, "hostname")) return log.hostname;
        if (std.mem.eql(u8, key, "ddsource")) return log.ddsource;
        if (std.mem.eql(u8, key, "ddtags")) return log.ddtags;
        if (std.mem.eql(u8, key, "environment")) return log.environment;
        if (std.mem.eql(u8, key, "custom_field")) return log.custom_field;
    }

    // Check extra fields (supports nested dotted-key paths)
    if (log.findExtraString(allocator, path)) |found| return found;

    // Fallback: the real payload may be a JSON document stringified inside the
    // `message`/`msg`/`log` field. Lazily unwrap it and walk the path within.
    return log.unwrappedAttribute(allocator, path);
}

/// Field accessor for Datadog JSON log format.
/// Datadog logs have fields at the root level: message, status/level, ddtags, service, etc.
/// All attribute types (log, resource, scope) search the same flat namespace since
/// Datadog has no OTLP-style resource/scope hierarchy.
/// Typed read primitive (required since v0.5.0). Known top-level fields are
/// strings, but single-segment attributes carry their native JSON type, so the
/// typed matchers fire on numeric/bool attributes; everything else (nested
/// attributes, known fields) falls back to the string primitive.
pub fn logTypedValue(ctx: *const anyopaque, field: FieldRef) ?policy.TypedValue {
    switch (field) {
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| {
            if (attr_path.path.items.len == 1) {
                const field_ctx: *const FieldAccessorContext = @ptrCast(@alignCast(ctx));
                if (field_ctx.log.findExtraTyped(field_ctx.allocator, attr_path.path.items[0])) |typed| {
                    return typed;
                }
            }
            return .{ .string = logValue(ctx, field) orelse return null };
        },
        else => return .{ .string = logValue(ctx, field) orelse return null },
    }
}

pub fn logValue(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const field_ctx: *const FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const log = field_ctx.log;

    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => log.bodyForMatch(field_ctx.allocator),
            .LOG_FIELD_SEVERITY_TEXT => log.status orelse log.level,
            // Datadog JSON format doesn't have direct equivalents for these OTLP fields
            else => null,
        },
        // All attribute types search the same Datadog flat namespace
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| lookupLogAttribute(
            log,
            field_ctx.allocator,
            attr_path.path.items,
        ),
    };
}

/// Top-level Datadog log fields that policies can mutate. Nested keys (in
/// `log.extra`) are read-only; rename targets resolve to these fields only.
const writable_log_fields = [_][]const u8{
    "service",
    "hostname",
    "ddsource",
    "ddtags",
    "environment",
    "custom_field",
};

/// Resolve a writable single-segment field name to its storage slot, or
/// null when the path is multi-segment or names an unknown field.
fn writableFieldRef(log: *DatadogLog, path: []const []const u8) ?*?[]const u8 {
    if (path.len != 1) return null;
    const key = path[0];
    inline for (writable_log_fields) |name| {
        if (std.mem.eql(u8, key, name)) return &@field(log, name);
    }
    return null;
}

/// Field setter for Datadog JSON log format. The engine handles upsert
/// semantics before calling set; for fields that don't exist in the Datadog
/// schema, the engine's snapshot-compile-time validation rejects the policy
/// (so set is never called).
pub fn logSet(ctx: *anyopaque, field: FieldRef, value: []const u8) void {
    const field_ctx: *FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const log = field_ctx.log;
    switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => {
                // Replacing the whole body discards any pending wrapper rewrite.
                log.message = value;
                log.clearWrappedRewrite(field_ctx.allocator);
            },
            .LOG_FIELD_SEVERITY_TEXT => log.status = value,
            else => {},
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| {
            if (writableFieldRef(log, attr_path.path.items)) |ref| {
                ref.* = value;
            } else {
                // Fall back to editing an existing field inside a JSON-wrapped
                // message (re-serialized on output).
                _ = log.setWrapped(field_ctx.allocator, attr_path.path.items, value);
            }
        },
    }
}

/// Field deleter for Datadog JSON log format. Returns true iff the field
/// existed.
pub fn logDelete(ctx: *anyopaque, field: FieldRef) bool {
    const field_ctx: *FieldAccessorContext = @ptrCast(@alignCast(ctx));
    const log = field_ctx.log;
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => blk: {
                if (log.message == null) break :blk false;
                log.message = null;
                log.clearWrappedRewrite(field_ctx.allocator);
                break :blk true;
            },
            .LOG_FIELD_SEVERITY_TEXT => blk: {
                var removed = false;
                if (log.status != null) {
                    log.status = null;
                    removed = true;
                }
                if (log.level != null) {
                    log.level = null;
                    removed = true;
                }
                break :blk removed;
            },
            else => false,
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            if (writableFieldRef(log, attr_path.path.items)) |ref| {
                if (ref.* == null) break :blk false;
                ref.* = null;
                break :blk true;
            }
            // Fall back to removing an existing field inside a JSON-wrapped message.
            break :blk log.deleteWrapped(field_ctx.allocator, attr_path.path.items);
        },
    };
}

/// LogAccessor template for unit tests in this module. Datadog logs don't
/// support rename, so `move` is left null (policies that require rename are
/// rejected at snapshot-compile time).
pub const log_accessor: policy.LogAccessor = .{
    .typed_value = logTypedValue,
    .set = logSet,
    .delete = logDelete,
};

/// Result of evaluating a single log
const FilterLogResult = struct {
    keep: bool,
    mutated: bool,
};

/// Evaluate a single log against policies, applying transforms if matched.
/// Returns whether to keep the log and whether it was mutated.
fn filterLog(
    engine: *const PolicyEngine,
    log: *DatadogLog,
    allocator: std.mem.Allocator,
    policy_id_buf: [][]const u8,
    sink: ?policy.ExtensionSink,
) FilterLogResult {
    var field_ctx: FieldAccessorContext = .{ .log = log, .allocator = allocator };
    const result = engine.evaluate(
        .log,
        &log_accessor,
        &field_ctx,
        policy_id_buf,
        .{
            .scratch = allocator,
            .io = engine.bus.io,
            .extension_sink = sink,
            // Null leaves the engine holding its own per-record state. A
            // reusable `ScanState` only pays off across a batch, and
            // `evalLogRecord` is the one caller: it handles one record, so the
            // 8 KiB `ScanState.init` clear would cost more than it saves.
            .scan_state = null,
        },
    );
    // The extension sink (s3-dump) fires INSIDE evaluate — after keep, before
    // transforms — so it snapshots the pre-transform record by design (policy
    // spec v1.6.0; the flagship `mode: dropped` dumps records discarded
    // downstream anyway). `finalizeWrapped` below rewrites a transform-mutated
    // wrapped `message` only for the forwarded output; the dump intentionally
    // keeps the original message. The dispatch point is owned by the engine,
    // not us, so pre-transform is the only possible (and correct) ordering.
    log.finalizeWrapped(allocator);
    return .{
        .keep = result.decision.shouldContinue(),
        .mutated = result.was_transformed,
    };
}

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

/// Test helper to create an AttributePath from a single key string.
/// Uses comptime to ensure the array literal has static storage.
fn testAttrPath(comptime key: []const u8) proto.policy.AttributePath {
    const items = @constCast(&[_][]const u8{key});
    return .{ .path = .{ .items = items, .capacity = items.len } };
}

/// Test helper: wrap `inner` JSON into a `{"message":"<escaped inner>"}` log,
/// mirroring GCP/Cloud Run forwarders. Lets fixtures keep the inner document
/// on short, readable lines — newlines (JSON whitespace between tokens) are
/// dropped and quotes escaped at comptime.
fn wrap(comptime inner: []const u8) []const u8 {
    comptime {
        var out: []const u8 = "{\"message\":\"";
        for (inner) |c| out = out ++ switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "",
            else => &[_]u8{c},
        };
        return out ++ "\"}";
    }
}

test "datadogFieldAccessor - extra field lookup" {
    // Unit test to verify the field accessor can retrieve extra fields
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "trace_id": "abc123-def456"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    // Verify the extra field was parsed
    try std.testing.expectEqual(@as(usize, 1), log.extra.count());
    try std.testing.expect(log.extra.contains("trace_id"));

    // Test the accessor directly
    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // Test known field
    const message_val = logValue(&field_ctx, .{ .log_field = .LOG_FIELD_BODY });
    try std.testing.expect(message_val != null);
    try std.testing.expectEqualStrings("test", message_val.?);

    // Test extra field - this is the critical test
    const trace_val = logValue(&field_ctx, .{ .log_attribute = testAttrPath("trace_id") });
    try std.testing.expect(trace_val != null);
    try std.testing.expectEqualStrings("abc123-def456", trace_val.?);
}

test "datadogFieldAccessor - typed attributes are numeric/bool, not string" {
    const allocator = std.testing.allocator;
    // No escapes in string values, so the string read borrows (no leak).
    const json =
        \\{"message":"x","duration":1234,"ratio":0.5,"ok":true,"name":"svc"}
    ;

    // Both parse paths must type identically: the materializing `parse` fills
    // the typed `extra` map; the fast `parseRaw` fills `extra_spans` (raw text).
    inline for (.{ "parse", "parseRaw" }) |which| {
        var parser: Parser = .init;
        defer parser.deinit(allocator);

        var log = if (comptime std.mem.eql(u8, which, "parse")) blk: {
            const doc = try parser.parseFromSlice(allocator, json);
            break :blk try DatadogLog.parse(allocator, doc.asValue());
        } else try DatadogLog.parseRaw(allocator, json);
        defer log.deinit(allocator);

        var ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

        const duration = logTypedValue(&ctx, .{ .log_attribute = testAttrPath("duration") });
        try std.testing.expectEqual(@as(i64, 1234), duration.?.int);

        const ratio = logTypedValue(&ctx, .{ .log_attribute = testAttrPath("ratio") });
        try std.testing.expectEqual(@as(f64, 0.5), ratio.?.double);

        const ok = logTypedValue(&ctx, .{ .log_attribute = testAttrPath("ok") });
        try std.testing.expectEqual(true, ok.?.bool);

        const name = logTypedValue(&ctx, .{ .log_attribute = testAttrPath("name") });
        try std.testing.expectEqualStrings("svc", name.?.string);

        // Known top-level fields stay string.
        const body = logTypedValue(&ctx, .{ .log_field = .LOG_FIELD_BODY });
        try std.testing.expect(body.? == .string);
    }
}

test "datadogFieldAccessor - unwraps JSON-stringified message for body and attributes" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // `message` is itself a stringified JSON document (GCP/Cloud Run shape):
    // body lives at data.jsonPayload.message, event_type at data.jsonPayload.event_type.
    // Includes a multi-element string array (`modules`) to exercise the
    // dotted-key collision path (arrays don't extend the path).
    const json = comptime wrap(
        \\{"data":{"jsonPayload":{
        \\"event_type":"EvidenceSkipped",
        \\"modules":["a","b"],
        \\"message":"evidence skipped"
        \\}}}
    );

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // Body DFS finds the nested "message" rather than the raw wrapped JSON.
    const body = logValue(&field_ctx, .{ .log_field = .LOG_FIELD_BODY });
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("evidence skipped", body.?);

    // Attribute fallback walks the path inside the unwrapped message.
    const event_type_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "data", "jsonPayload", "event_type" }), .capacity = 3 },
    };
    const event_type = logValue(&field_ctx, .{ .log_attribute = event_type_path });
    try std.testing.expect(event_type != null);
    try std.testing.expectEqualStrings("EvidenceSkipped", event_type.?);

    // A path absent from the unwrapped message still returns null.
    const missing_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "data", "jsonPayload", "nope" }), .capacity = 3 },
    };
    try std.testing.expect(logValue(&field_ctx, .{ .log_attribute = missing_path }) == null);
}

test "datadogFieldAccessor - plain-text message body is returned verbatim" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"just a plain log line"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };
    const body = logValue(&field_ctx, .{ .log_field = .LOG_FIELD_BODY });
    try std.testing.expect(body != null);
    try std.testing.expectEqualStrings("just a plain log line", body.?);
}

test "datadogFieldAccessor - resource_attribute searches log attributes" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "service": "my-svc", "trace_id": "abc123"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // resource_attribute should find known fields
    const svc_val = logValue(&field_ctx, .{ .resource_attribute = testAttrPath("service") });
    try std.testing.expect(svc_val != null);
    try std.testing.expectEqualStrings("my-svc", svc_val.?);

    // resource_attribute should find extra fields
    const trace_val = logValue(&field_ctx, .{ .resource_attribute = testAttrPath("trace_id") });
    try std.testing.expect(trace_val != null);
    try std.testing.expectEqualStrings("abc123", trace_val.?);
}

test "datadogFieldAccessor - scope_attribute searches log attributes" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "hostname": "web-01"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // scope_attribute should find known fields
    const host_val = logValue(&field_ctx, .{ .scope_attribute = testAttrPath("hostname") });
    try std.testing.expect(host_val != null);
    try std.testing.expectEqualStrings("web-01", host_val.?);
}

test "datadogFieldAccessor - nested extra field access via dotted key" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    // Datadog uses dotted keys for nested attributes
    const json =
        \\{"message": "test", "http.method": "GET", "http.status_code": "200"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // Two-segment path should be joined with '.' to match dotted key
    const method_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "http", "method" }), .capacity = 2 },
    };
    const method_val = logValue(&field_ctx, .{ .log_attribute = method_path });
    try std.testing.expect(method_val != null);
    try std.testing.expectEqualStrings("GET", method_val.?);
}

test "datadogFieldAccessor - nested dotted key not found returns null" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "http.method": "GET"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // Path to non-existent dotted key
    const missing_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "http", "nonexistent" }), .capacity = 2 },
    };
    const val = logValue(&field_ctx, .{ .log_attribute = missing_path });
    try std.testing.expect(val == null);
}

test "datadogFieldAccessor - nested object fallback via path segments" {
    // Arena-scratch like the production record arena: nested lookups may
    // copy decoded strings out of the transient std.json parse.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message":"test","http":{"status_code":"200","meta":{"region":"us-east-1"}}}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    const status_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "http", "status_code" }), .capacity = 2 },
    };
    const status_val = logValue(&field_ctx, .{ .log_attribute = status_path });
    try std.testing.expect(status_val != null);
    try std.testing.expectEqualStrings("200", status_val.?);

    const region_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "http", "meta", "region" }), .capacity = 3 },
    };
    const region_val = logValue(&field_ctx, .{ .log_attribute = region_path });
    try std.testing.expect(region_val != null);
    try std.testing.expectEqualStrings("us-east-1", region_val.?);
}

test "datadogFieldAccessor - multi-segment path with no matching dotted key returns null" {
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    const json =
        \\{"message": "test", "flat_field": "just-a-string"}
    ;

    const doc = try parser.parseFromSlice(allocator, json);
    var log = try DatadogLog.parse(allocator, doc.asValue());
    defer log.deinit(allocator);

    var field_ctx: FieldAccessorContext = .{ .log = &log, .allocator = allocator };

    // Multi-segment path that doesn't match any dotted key
    const bad_path: proto.policy.AttributePath = .{
        .path = .{ .items = @constCast(&[_][]const u8{ "flat_field", "nested" }), .capacity = 2 },
    };
    const val = logValue(&field_ctx, .{ .log_attribute = bad_path });
    try std.testing.expect(val == null);
}

test "evalLogRecord - no policies keeps record without output" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const verdict = try evalLogRecord(
        arena.allocator(),
        &parser,
        allocator,
        &registry,
        noop_bus.eventBus(),
        \\{"status": "info", "message": "test1"}
    ,
        null,
    );
    try std.testing.expectEqual(RecordVerdict.keep, verdict);
}

test "evalLogRecord - drop policy drops, non-matching keeps" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "debug") },
    });
    defer drop_policy.deinit(allocator);
    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const dropped = try evalLogRecord(
        arena.allocator(),
        &parser,
        allocator,
        &registry,
        noop_bus.eventBus(),
        \\{"status": "debug", "message": "debug msg"}
    ,
        null,
    );
    try std.testing.expectEqual(RecordVerdict.drop, dropped);

    _ = arena.reset(.retain_capacity);
    const kept = try evalLogRecord(
        arena.allocator(),
        &parser,
        allocator,
        &registry,
        noop_bus.eventBus(),
        \\{"status": "error", "message": "error msg"}
    ,
        null,
    );
    try std.testing.expectEqual(RecordVerdict.keep, kept);
}

test "evalLogRecord - transform yields replace with serialized record" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var transform: proto.policy.LogTransform = .{};
    var remove_attr_path: proto.policy.AttributePath = .{};
    try remove_attr_path.path.append(allocator, try allocator.dupe(u8, "service"));
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = remove_attr_path },
    });
    var test_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "remove-service"),
        .name = try allocator.dupe(u8, "remove-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    try test_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer test_policy.deinit(allocator);
    try registry.updatePolicies(&.{test_policy}, "test", .file);

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const verdict = try evalLogRecord(
        arena.allocator(),
        &parser,
        allocator,
        &registry,
        noop_bus.eventBus(),
        \\{"message": "test log message", "service": "my-service", "status": "info"}
    ,
        null,
    );
    try std.testing.expect(verdict == .replace);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "test log message") != null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "my-service") == null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "\"service\"") == null);
}

test "evalLogRecord - malformed unknown-field container fails open to keep under matching policy" {
    // Regression (Datadog logs / json_scan): FieldWalker.valueEnd used to
    // accept bracket-balanced-but-structurally-malformed container values in
    // unknown fields and store them verbatim, so a matching drop policy
    // returned `.drop` and a matching mutating policy returned `.replace` —
    // making verdicts depend on the fast path, contrary to the contract on
    // evalLogRecord. After the fix, parseRaw rejects these records, the
    // materializing `DatadogLog.parse` rejects them too, and both policy
    // shapes fail open to `.keep` (the record is forwarded verbatim).
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    const bus = noop_bus.eventBus();

    // Every input has a malformed container in an UNKNOWN field `x` whose
    // brackets balance but whose interior violates JSON grammar. The buggy
    // fast path accepted these and let the policy run; the corrected path
    // rejects them (parseRaw -> DatadogLog.parse) and fail-opens to `.keep`.
    // Each of these is verified to be rejected by the materializing fallback
    // (zimdjson ondemand is lazy; DatadogLog.parse's field iteration rejects
    // them), mirroring the bug report's corrected-path verdicts table.
    const malformed_values = [_][]const u8{
        "[1,]", // trailing comma in array
        "[,]", // leading comma in array
        "{,}", // leading comma in object
        "{\"k\":}", // missing object value
        "{1:2}", // non-string object key
        "[\"a\",,]", // missing value in array
    };

    // --- Drop policy (keep = "none"), matched on LOG_FIELD_BODY regex "matched".
    {
        var registry = PolicyRegistry.init(allocator, bus);
        defer registry.deinit();
        var drop_policy: proto.policy.Policy = .{
            .id = try allocator.dupe(u8, "drop-matched"),
            .name = try allocator.dupe(u8, "drop-matched"),
            .enabled = true,
            .target = .{ .log = .{ .keep = try allocator.dupe(u8, "none") } },
        };
        try drop_policy.target.?.log.match.append(allocator, .{
            .field = .{ .log_field = .LOG_FIELD_BODY },
            .match = .{ .regex = try allocator.dupe(u8, "matched") },
        });
        defer drop_policy.deinit(allocator);
        try registry.updatePolicies(&.{drop_policy}, "drop", .file);

        for (malformed_values) |val| {
            var buf: [128]u8 = undefined;
            const record = std.fmt.bufPrint(
                &buf,
                "{{\"message\":\"matched\",\"service\":\"s\",\"x\":{s}}}",
                .{val},
            ) catch unreachable;
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            try std.testing.expectEqual(
                RecordVerdict.keep,
                try evalLogRecord(arena.allocator(), &parser, allocator, &registry, bus, record, null),
            );
        }

        // Contrast: a well-formed matching record IS dropped (the fallback
        // accepts a valid object, so the policy runs). Guards against the
        // fix over-broadening into a keep-everything regression.
        const good = "{\"message\":\"matched\",\"service\":\"s\",\"x\":[1,2]}";
        var good_arena = std.heap.ArenaAllocator.init(allocator);
        defer good_arena.deinit();
        try std.testing.expectEqual(
            RecordVerdict.drop,
            try evalLogRecord(good_arena.allocator(), &parser, allocator, &registry, bus, good, null),
        );
    }

    // --- Mutating policy (keep = "all", removes `service`), matched on the body.
    {
        var registry = PolicyRegistry.init(allocator, bus);
        defer registry.deinit();
        var transform: proto.policy.LogTransform = .{};
        var remove_attr_path: proto.policy.AttributePath = .{};
        try remove_attr_path.path.append(allocator, try allocator.dupe(u8, "service"));
        try transform.remove.append(allocator, .{
            .field = .{ .log_attribute = remove_attr_path },
        });
        var mutate_policy: proto.policy.Policy = .{
            .id = try allocator.dupe(u8, "remove-service"),
            .name = try allocator.dupe(u8, "remove-service"),
            .enabled = true,
            .target = .{ .log = .{
                .keep = try allocator.dupe(u8, "all"),
                .transform = transform,
            } },
        };
        try mutate_policy.target.?.log.match.append(allocator, .{
            .field = .{ .log_field = .LOG_FIELD_BODY },
            .match = .{ .regex = try allocator.dupe(u8, "matched") },
        });
        defer mutate_policy.deinit(allocator);
        try registry.updatePolicies(&.{mutate_policy}, "mutate", .file);

        for (malformed_values) |val| {
            var buf: [128]u8 = undefined;
            const record = std.fmt.bufPrint(
                &buf,
                "{{\"message\":\"matched\",\"service\":\"s\",\"x\":{s}}}",
                .{val},
            ) catch unreachable;
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            try std.testing.expectEqual(
                RecordVerdict.keep,
                try evalLogRecord(arena.allocator(), &parser, allocator, &registry, bus, record, null),
            );
        }

        // Contrast: a well-formed matching record IS replaced (`service`
        // removed). The malformed path used to also `.replace` with the bad
        // span baked in; the fix sends malformed records to `.keep` instead.
        const good = "{\"message\":\"matched\",\"service\":\"s\",\"x\":[1,2]}";
        var good_arena = std.heap.ArenaAllocator.init(allocator);
        defer good_arena.deinit();
        const verdict = try evalLogRecord(good_arena.allocator(), &parser, allocator, &registry, bus, good, null);
        try std.testing.expect(verdict == .replace);
        try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "\"service\"") == null);
    }
}

test "evalLogRecord - two regex redacts on the same wrapped path compose" {
    // Regression (PR #203): the policy engine re-reads a field via the
    // accessor before each transform write. For a wrapped `message`, reads
    // go through `unwrappedAttribute`, which served a one-shot `message_flat`
    // snapshot built from the ORIGINAL `message`; `setWrapped` mutated the
    // live `message_tree` but never refreshed the flat, so rule N+1 read the
    // pre-transform value and overwrote rule N's edit. Two regex `redact`s on
    // the same nested path would then lose every earlier rule's substitution
    // and leak the scrubbed content back into the forwarded record.
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // keep=all + two regex redacts on data.jsonPayload.email, one per token
    // of the address: scrub the local-part, then scrub the domain. Each rule
    // needs its own replacement template, which a single alternation regex
    // cannot express -- exactly the routine configuration that triggered the
    // leak.
    var transform: proto.policy.LogTransform = .{};

    var email_path: proto.policy.AttributePath = .{};
    try email_path.path.append(allocator, try allocator.dupe(u8, "data"));
    try email_path.path.append(allocator, try allocator.dupe(u8, "jsonPayload"));
    try email_path.path.append(allocator, try allocator.dupe(u8, "email"));
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = email_path },
        .regex = try allocator.dupe(u8, "alice"),
        .replacement = try allocator.dupe(u8, "ALICE_R"),
    });

    var email_path2: proto.policy.AttributePath = .{};
    try email_path2.path.append(allocator, try allocator.dupe(u8, "data"));
    try email_path2.path.append(allocator, try allocator.dupe(u8, "jsonPayload"));
    try email_path2.path.append(allocator, try allocator.dupe(u8, "email"));
    try transform.redact.append(allocator, .{
        .field = .{ .log_attribute = email_path2 },
        .regex = try allocator.dupe(u8, "example"),
        .replacement = try allocator.dupe(u8, "EXAMPLE_R"),
    });

    var test_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "redact-email"),
        .name = try allocator.dupe(u8, "redact-email"),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, "all"), .transform = transform } },
    };
    try test_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .exact = try allocator.dupe(u8, "evidence skipped") },
    });
    defer test_policy.deinit(allocator);

    try registry.updatePolicies(&.{test_policy}, "test", .file);

    const record = comptime wrap(
        \\{"data":{"jsonPayload":{
        \\"email":"alice@example.com",
        \\"message":"evidence skipped"
        \\}}}
    );

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const verdict = try evalLogRecord(
        arena.allocator(),
        &parser,
        allocator,
        &registry,
        noop_bus.eventBus(),
        record,
        null,
    );
    try std.testing.expect(verdict == .replace);

    // Both redactions compose: the forwarded email carries BOTH replacement
    // tokens and neither original PII substring.
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "ALICE_R@EXAMPLE_R.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "alice") == null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "example") == null);
    // The body and wrapper shape survive the transform.
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "evidence skipped") != null);
    try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "jsonPayload") != null);
}

test "evalLogRecord - malformed and non-object records fail open to keep" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    var parser: Parser = .init;
    defer parser.deinit(allocator);
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const bus = noop_bus.eventBus();
    const malformed = try evalLogRecord(arena.allocator(), &parser, allocator, &registry, bus, "{ not json }", null);
    try std.testing.expectEqual(RecordVerdict.keep, malformed);

    const scalar = try evalLogRecord(arena.allocator(), &parser, allocator, &registry, bus, "42", null);
    try std.testing.expectEqual(RecordVerdict.keep, scalar);
}
