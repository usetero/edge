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
    // Try the single-pass parse first. When it fails, use the validating
    // parse. When both fail, keep the record.
    var log_obj = DatadogLog.parseRaw(scratch, record) catch blk: {
        const document = parser.parseFromSlice(parser_gpa, record) catch return .keep;
        const value_type = document.asValue().getType() catch return .keep;
        if (value_type != .object) return .keep;
        // Do not set `unwrap_parser` here. The extras of `parse` read from
        // `parser`, so a second parse on it would corrupt them.
        break :blk DatadogLog.parse(scratch, document.asValue()) catch return .keep;
    };
    // `parseRaw` did not use `parser`, so the unwrap can reuse it.
    log_obj.unwrap_parser = parser;
    log_obj.unwrap_parser_gpa = parser_gpa;

    const engine = PolicyEngine.init(bus, @constCast(registry));
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;
    var field_ctx: FieldAccessorContext = .{ .log = &log_obj, .allocator = scratch };
    const result = engine.evaluate(
        .log,
        &log_accessor,
        &field_ctx,
        &policy_id_buf,
        .{
            .scratch = scratch,
            .io = engine.bus.io,
            .extension_sink = sink,
            // Null: the engine keeps its own state. A shared `ScanState` pays
            // off only across a batch, and this call handles one record.
            .scan_state = null,
        },
    );
    // The extension sink runs inside `evaluate`, before transforms, so a dump
    // holds the record as it arrived. `finalizeWrapped` changes only the
    // forwarded output. See `datadogLogEncode` in runtime/extensions.zig.
    log_obj.finalizeWrapped(scratch);
    if (!result.decision.shouldContinue()) return .drop;
    if (!result.was_transformed) return .keep;

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

    // A known field answers even when it is null.
    if (writableFieldRef(log, path)) |ref| return ref.*;

    // Check extra fields (supports nested dotted-key paths)
    if (log.findExtraString(allocator, path)) |found| return found;

    // Fallback: the real payload may be a JSON document stringified inside the
    // `message`/`msg`/`log` field. Lazily unwrap it and walk the path within.
    return log.unwrappedAttribute(allocator, path);
}

/// Typed read for Datadog logs. Single-segment attributes keep their JSON
/// type; other fields use the string read. Datadog has no resource or scope
/// level, so all attribute kinds read one flat namespace.
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

/// Top-level fields that policies can change. Extras are read-only.
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

/// The log accessor that `evalLogRecord` gives to the engine.
///
/// Datadog logs do not support rename, so `move` is null. The engine rejects
/// a policy that needs rename when it compiles the snapshot.
pub const log_accessor: policy.LogAccessor = .{
    .typed_value = logTypedValue,
    .set = logSet,
    .delete = logDelete,
};

// =============================================================================
// Tests
// =============================================================================

const proto = @import("proto");

/// Test helper to create an AttributePath from its keys. The keys are
/// comptime, so the slice has static storage.
fn testAttrPath(comptime keys: []const []const u8) proto.policy.AttributePath {
    return .{ .path = .{ .items = @constCast(keys), .capacity = keys.len } };
}

/// Build a log policy with one regex matcher. The caller owns the policy.
fn logPolicy(
    allocator: std.mem.Allocator,
    id: []const u8,
    keep: []const u8,
    field: proto.policy.LogMatcher.field_union,
    regex: []const u8,
    transform: ?proto.policy.LogTransform,
) !proto.policy.Policy {
    var log_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .enabled = true,
        .target = .{ .log = .{ .keep = try allocator.dupe(u8, keep), .transform = transform } },
    };
    errdefer log_policy.deinit(allocator);
    try log_policy.target.?.log.match.append(allocator, .{
        .field = field,
        .match = .{ .regex = try allocator.dupe(u8, regex) },
    });
    return log_policy;
}

/// Build a transform that removes the single-key attribute `key`.
fn removeAttr(allocator: std.mem.Allocator, key: []const u8) !proto.policy.LogTransform {
    var path: proto.policy.AttributePath = .{};
    try path.path.append(allocator, try allocator.dupe(u8, key));
    var transform: proto.policy.LogTransform = .{};
    try transform.remove.append(allocator, .{ .field = .{ .log_attribute = path } });
    return transform;
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
    const trace_val = logValue(&field_ctx, .{ .log_attribute = testAttrPath(&.{"trace_id"}) });
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

        const duration = logTypedValue(&ctx, .{ .log_attribute = testAttrPath(&.{"duration"}) });
        try std.testing.expectEqual(@as(i64, 1234), duration.?.int);

        const ratio = logTypedValue(&ctx, .{ .log_attribute = testAttrPath(&.{"ratio"}) });
        try std.testing.expectEqual(@as(f64, 0.5), ratio.?.double);

        const ok = logTypedValue(&ctx, .{ .log_attribute = testAttrPath(&.{"ok"}) });
        try std.testing.expectEqual(true, ok.?.bool);

        const name = logTypedValue(&ctx, .{ .log_attribute = testAttrPath(&.{"name"}) });
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
    const event_type_path = testAttrPath(&.{ "data", "jsonPayload", "event_type" });
    const event_type = logValue(&field_ctx, .{ .log_attribute = event_type_path });
    try std.testing.expect(event_type != null);
    try std.testing.expectEqualStrings("EvidenceSkipped", event_type.?);

    // A path absent from the unwrapped message still returns null.
    const missing_path = testAttrPath(&.{ "data", "jsonPayload", "nope" });
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
    const svc_val = logValue(&field_ctx, .{ .resource_attribute = testAttrPath(&.{"service"}) });
    try std.testing.expect(svc_val != null);
    try std.testing.expectEqualStrings("my-svc", svc_val.?);

    // resource_attribute should find extra fields
    const trace_val = logValue(&field_ctx, .{ .resource_attribute = testAttrPath(&.{"trace_id"}) });
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
    const host_val = logValue(&field_ctx, .{ .scope_attribute = testAttrPath(&.{"hostname"}) });
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
    const method_path = testAttrPath(&.{ "http", "method" });
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
    const missing_path = testAttrPath(&.{ "http", "nonexistent" });
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

    const status_path = testAttrPath(&.{ "http", "status_code" });
    const status_val = logValue(&field_ctx, .{ .log_attribute = status_path });
    try std.testing.expect(status_val != null);
    try std.testing.expectEqualStrings("200", status_val.?);

    const region_path = testAttrPath(&.{ "http", "meta", "region" });
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
    const bad_path = testAttrPath(&.{ "flat_field", "nested" });
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

    var drop_policy = try logPolicy(
        allocator,
        "drop-debug",
        "none",
        .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        "debug",
        null,
    );
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

    var test_policy = try logPolicy(
        allocator,
        "remove-service",
        "all",
        .{ .log_field = .LOG_FIELD_BODY },
        "test",
        try removeAttr(allocator, "service"),
    );
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
    // A malformed container in an unknown field must fail open to `.keep` on
    // both parse paths.
    const allocator = std.testing.allocator;

    var parser: Parser = .init;
    defer parser.deinit(allocator);

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    const bus = noop_bus.eventBus();

    // Each input has a bracket-balanced but malformed container in the
    // unknown field `x`.
    const malformed_values = [_][]const u8{
        "[1,]", // trailing comma in array
        "[,]", // leading comma in array
        "{,}", // leading comma in object
        "{\"k\":}", // missing object value
        "{1:2}", // non-string object key
        "[\"a\",,]", // missing value in array
    };
    const expectAllKeep = struct {
        fn run(
            gpa: std.mem.Allocator,
            p: *Parser,
            registry: *const PolicyRegistry,
            b: *EventBus,
            values: []const []const u8,
        ) !void {
            for (values) |val| {
                var buf: [128]u8 = undefined;
                const record = std.fmt.bufPrint(
                    &buf,
                    "{{\"message\":\"matched\",\"service\":\"s\",\"x\":{s}}}",
                    .{val},
                ) catch unreachable;
                var arena = std.heap.ArenaAllocator.init(gpa);
                defer arena.deinit();
                try std.testing.expectEqual(
                    RecordVerdict.keep,
                    try evalLogRecord(arena.allocator(), p, gpa, registry, b, record, null),
                );
            }
        }
    }.run;

    // --- Drop policy (keep = "none"), matched on LOG_FIELD_BODY regex "matched".
    {
        var registry = PolicyRegistry.init(allocator, bus);
        defer registry.deinit();
        var drop_policy = try logPolicy(
            allocator,
            "drop-matched",
            "none",
            .{ .log_field = .LOG_FIELD_BODY },
            "matched",
            null,
        );
        defer drop_policy.deinit(allocator);
        try registry.updatePolicies(&.{drop_policy}, "drop", .file);

        try expectAllKeep(allocator, &parser, &registry, bus, &malformed_values);

        // A well-formed matching record is still dropped.
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
        var mutate_policy = try logPolicy(
            allocator,
            "remove-service",
            "all",
            .{ .log_field = .LOG_FIELD_BODY },
            "matched",
            try removeAttr(allocator, "service"),
        );
        defer mutate_policy.deinit(allocator);
        try registry.updatePolicies(&.{mutate_policy}, "mutate", .file);

        try expectAllKeep(allocator, &parser, &registry, bus, &malformed_values);

        // A well-formed matching record is still replaced.
        const good = "{\"message\":\"matched\",\"service\":\"s\",\"x\":[1,2]}";
        var good_arena = std.heap.ArenaAllocator.init(allocator);
        defer good_arena.deinit();
        const verdict = try evalLogRecord(good_arena.allocator(), &parser, allocator, &registry, bus, good, null);
        try std.testing.expect(verdict == .replace);
        try std.testing.expect(std.mem.indexOf(u8, verdict.replace, "\"service\"") == null);
    }
}

test "evalLogRecord - two regex redacts on the same wrapped path compose" {
    // The engine reads the field again before each transform, so the second
    // redact must apply on top of the first.
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // keep=all with two regex redacts on data.jsonPayload.email: the local
    // part, then the domain.
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

    // Both redactions compose: both replacement tokens, neither original.
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
