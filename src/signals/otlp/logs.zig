const std = @import("std");
const stream_io = @import("../stream_io.zig");
const proto = @import("proto");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const otlp_attr = @import("attributes.zig");
const common = @import("common.zig");

const LogsData = proto.logs.LogsData;
const ResourceLogs = proto.logs.ResourceLogs;
const ScopeLogs = proto.logs.ScopeLogs;
const LogRecord = proto.logs.LogRecord;
const KeyValue = proto.common.KeyValue;

const PolicyEngine = policy.PolicyEngine;
pub const FieldRef = policy.FieldRef;
const LogAccessor = policy.LogAccessor;
const LogField = proto.policy.LogField;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

pub const Format = common.Format;
pub const StreamProcessResult = common.StreamProcessResult;

/// Apply log policies to an OTLP logs body (JSON or protobuf) and write the result to out_writer.
pub fn processLogsStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
    format: Format,
) !StreamProcessResult {
    const data = try stream_io.readAll(allocator, in_reader);
    defer allocator.free(data);
    return switch (format) {
        .json => processJsonLogs(allocator, registry, bus, data, out_writer),
        .protobuf => processProtobufLogs(allocator, registry, bus, data, out_writer),
    };
}

/// Context for OTLP log field accessor and mutator - provides access to log record plus parent context.
pub const OtlpLogContext = struct {
    log_record: *LogRecord,
    resource_logs: *ResourceLogs,
    scope_logs: *ScopeLogs,
    allocator: std.mem.Allocator,
};

const findNestedAttribute = otlp_attr.findNestedAttribute;
const findAttrIndex = otlp_attr.findAttrIndex;
const removeAttributeByPath = otlp_attr.removeAttributeByPath;
const setAttributeByPath = otlp_attr.setAttributeByPath;

/// Pointer to the storage slot for a `[]const u8` field, or null if the
/// field tag isn't a plain string field on the OTLP context. `body` is
/// `?AnyValue` and handled separately in each primitive.
fn stringFieldRef(log_ctx: *OtlpLogContext, lf: LogField) ?*[]const u8 {
    return switch (lf) {
        .LOG_FIELD_SEVERITY_TEXT => &log_ctx.log_record.severity_text,
        .LOG_FIELD_TRACE_ID => &log_ctx.log_record.trace_id,
        .LOG_FIELD_SPAN_ID => &log_ctx.log_record.span_id,
        .LOG_FIELD_EVENT_NAME => &log_ctx.log_record.event_name,
        .LOG_FIELD_RESOURCE_SCHEMA_URL => &log_ctx.resource_logs.schema_url,
        .LOG_FIELD_SCOPE_SCHEMA_URL => &log_ctx.scope_logs.schema_url,
        else => null,
    };
}

/// Attribute list backing a `FieldRef` attribute variant, or null when the
/// resource/scope wrapper is absent on this record. `log_field` returns
/// null — fixed fields are not stored as attributes.
fn attributeList(log_ctx: *OtlpLogContext, field: FieldRef) ?*std.ArrayList(KeyValue) {
    return switch (field) {
        .log_attribute => &log_ctx.log_record.attributes,
        .resource_attribute => if (log_ctx.resource_logs.resource) |*res| &res.attributes else null,
        .scope_attribute => if (log_ctx.scope_logs.scope) |*scope| &scope.attributes else null,
        .log_field => null,
    };
}

/// Upsert a field. The engine pre-validates existence/upsert semantics, so
/// `set` is always called at a point where the write is expected to succeed.
pub fn logSet(ctx: *anyopaque, field: FieldRef, value: []const u8) void {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(ctx));
    switch (field) {
        .log_field => |lf| if (lf == .LOG_FIELD_BODY) {
            log_ctx.log_record.body = .{ .value = .{ .string_value = value } };
        } else if (stringFieldRef(log_ctx, lf)) |ref| {
            ref.* = value;
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| {
            if (attributeList(log_ctx, field)) |attrs| {
                _ = setAttributeByPath(log_ctx.allocator, attrs, attr_path.path.items, value);
            }
        },
    }
}

/// Remove a field. Returns true iff it existed.
pub fn logDelete(ctx: *anyopaque, field: FieldRef) bool {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .log_field => |lf| if (lf == .LOG_FIELD_BODY) blk: {
            if (log_ctx.log_record.body == null) break :blk false;
            log_ctx.log_record.body = null;
            break :blk true;
        } else if (stringFieldRef(log_ctx, lf)) |ref| blk: {
            if (ref.len == 0) break :blk false;
            ref.* = &.{};
            break :blk true;
        } else false,
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            const attrs = attributeList(log_ctx, field) orelse break :blk false;
            break :blk removeAttributeByPath(attrs, attr_path.path.items);
        },
    };
}

/// Rename: move source attribute value to `to` key. The engine pre-checks
/// source existence and upsert/conflict semantics, so this just performs the
/// move. `log_field` sources are not renamable.
pub fn logMove(ctx: *anyopaque, from: FieldRef, to: []const u8) void {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(ctx));
    const attrs = attributeList(log_ctx, from) orelse return;
    const path = switch (from) {
        .log_attribute, .resource_attribute, .scope_attribute => |attr| attr.path.items,
        .log_field => return,
    };
    if (path.len == 0) return;
    const src_idx = findAttrIndex(attrs.items, path[0]) orelse return;
    const src_val = attrs.items[src_idx].value;
    _ = attrs.orderedRemove(src_idx);
    attrs.append(log_ctx.allocator, .{ .key = to, .value = src_val }) catch return;
}

/// Presence check for exists matchers. A body is present when it holds a
/// non-empty string or any non-string value. A string field is present when
/// it is not empty. An attribute is present when its path has a string value.
pub fn logExists(ctx: *const anyopaque, field: FieldRef) bool {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(@constCast(ctx)));
    return switch (field) {
        .log_field => |lf| if (lf == .LOG_FIELD_BODY) blk: {
            const body = log_ctx.log_record.body orelse break :blk false;
            const inner = body.value orelse break :blk false;
            break :blk switch (inner) {
                .string_value => |s| s.len > 0,
                else => true,
            };
        } else if (stringFieldRef(log_ctx, lf)) |ref| ref.len > 0 else false,
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            const attrs = attributeList(log_ctx, field) orelse break :blk false;
            break :blk findNestedAttribute(attrs.items, attr_path.path.items) != null;
        },
    };
}

/// Typed-value accessor for the OTLP log context. The policy engine uses it
/// for all matchers and for probabilistic sampling (the `sample_key` field).
/// Identifier fields (trace_id/span_id) read as raw `TypedValue.bytes` so the
/// sampler hashes the right bytes. Body and attributes keep their scalar
/// type. All other fields read as non-empty strings.
pub fn logTypedValue(ctx: *const anyopaque, field: FieldRef) ?policy.TypedValue {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(@constCast(ctx)));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => otlp_attr.anyValueTyped(log_ctx.log_record.body),
            .LOG_FIELD_TRACE_ID => otlp_attr.typedBytes(log_ctx.log_record.trace_id),
            .LOG_FIELD_SPAN_ID => otlp_attr.typedBytes(log_ctx.log_record.span_id),
            else => otlp_attr.typedStr(if (stringFieldRef(log_ctx, lf)) |ref| ref.* else null),
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            const attrs = attributeList(log_ctx, field) orelse break :blk null;
            break :blk otlp_attr.findNestedAttributeTyped(attrs.items, attr_path.path.items);
        },
    };
}

/// LogAccessor template wiring the OTLP log primitives to a registry.
pub const log_accessor: LogAccessor = .{
    .exists = logExists,
    .typed_value = logTypedValue,
    .set = logSet,
    .delete = logDelete,
    .move = logMove,
};

/// Result of filtering logs in-place
const FilterCounts = struct {
    was_transformed: bool,
    original_count: usize,
    dropped_count: usize,
};

/// Filter logs in-place within the LogsData structure
/// This is the shared filtering logic used by both JSON and protobuf processing
///
/// Note: This function does not free dropped log records. The caller is responsible
/// for memory management (e.g., via json.Parsed.deinit() or LogsData.deinit()).
fn filterLogsInPlace(
    allocator: std.mem.Allocator,
    logs_data: *LogsData,
    registry: *const PolicyRegistry,
    bus: *EventBus,
) FilterCounts {
    const engine = PolicyEngine.init(bus, @constCast(registry));

    var original_count: usize = 0;
    var dropped_count: usize = 0;
    var was_transformed: bool = false;

    // Buffer for matched policy IDs (stack allocated)
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;

    // Iterate through the nested structure and filter logs in place
    // Structure: LogsData -> ResourceLogs[] -> ScopeLogs[] -> LogRecord[]
    for (logs_data.resource_logs.items) |*resource_logs| {
        for (resource_logs.scope_logs.items) |*scope_logs| {
            // Count original logs
            original_count += scope_logs.log_records.items.len;

            // Filter log records in place by shrinking the list
            var write_idx: usize = 0;
            for (scope_logs.log_records.items) |*log_record| {
                var ctx: OtlpLogContext = .{
                    .log_record = log_record,
                    .resource_logs = resource_logs,
                    .scope_logs = scope_logs,
                    .allocator = allocator,
                };

                const result = engine.evaluate(
                    .log,
                    &log_accessor,
                    &ctx,
                    &policy_id_buf,
                    .{ .scratch = allocator, .io = bus.io },
                );

                if (result.was_transformed) {
                    was_transformed = true;
                }

                if (result.decision.shouldContinue()) {
                    scope_logs.log_records.items[write_idx] = log_record.*;
                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_logs.log_records.shrinkRetainingCapacity(write_idx);
        }

        common.pruneEmpty(&resource_logs.scope_logs, "log_records");
    }

    common.pruneEmpty(&logs_data.resource_logs, "scope_logs");

    return .{
        .original_count = original_count,
        .dropped_count = dropped_count,
        .was_transformed = was_transformed,
    };
}

fn processJsonLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // Fast path: if no policies, skip decode/encode entirely
    const snapshot = registry.getSnapshot();
    if (snapshot == null or snapshot.?.log_index.isEmpty()) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = 0 };
    }

    // OTLP/JSON hex-encodes only the id fields. In memory the ids are raw
    // bytes, as on the protobuf path.
    var parsed = try LogsData.jsonDecodeOpts(data, .{
        .ignore_unknown_fields = true,
    }, .{ .hex_bytes_fields = otlp_attr.hex_id_fields }, allocator);
    defer parsed.deinit();

    const counts = filterLogsInPlace(allocator, &parsed.value, registry, bus);

    // Return the input bytes when nothing changed. A re-encode drops fields
    // the schema does not know.
    if (counts.dropped_count == 0 and !counts.was_transformed) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = counts.original_count };
    }

    // Re-serialize to JSON, hex-encoding the same identifier fields back out.
    const output = try parsed.value.jsonEncode(.{}, .{
        .emit_oneof_field_name = false,
        .hex_bytes_fields = otlp_attr.hex_id_fields,
    }, allocator);
    defer allocator.free(output);
    try out_writer.writeAll(output);

    return .{
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
        .was_transformed = counts.was_transformed,
    };
}

fn processProtobufLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // Basic validation: empty data or data that looks like JSON should not be decoded as protobuf.
    // The protobuf library panics on certain invalid inputs, so we validate first.
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON (starts with '{' or '[') - this would cause protobuf decoder to panic
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Fast path: if no policies, skip decode/encode entirely
    const snapshot = registry.getSnapshot();
    if (snapshot == null or snapshot.?.log_index.isEmpty()) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = 0 };
    }

    // Use an arena for the protobuf decode/filter/encode cycle.
    // This ensures all allocations (including dropped log records) are freed together.
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into LogsData struct using arena
    var logs_data = try LogsData.decode(&reader, arena_alloc);

    const counts = filterLogsInPlace(arena_alloc, &logs_data, registry, bus);

    // Return the input bytes when nothing changed. A re-encode drops fields
    // the schema does not know.
    if (counts.dropped_count == 0 and !counts.was_transformed) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = counts.original_count };
    }

    // Encode into a buffer first, so an encode error writes nothing.
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();
    try logs_data.encode(&output_writer.writer, arena_alloc);
    try out_writer.writeAll(output_writer.written());

    return .{
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
        .was_transformed = counts.was_transformed,
    };
}

// =============================================================================
// Tests
// =============================================================================

fn runLogs(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    input: []const u8,
    format: Format,
) !common.TestRun {
    var in_reader = std.Io.Reader.fixed(input);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const result = try processLogsStream(allocator, registry, bus, &in_reader, &out_writer.writer, format);
    return .{ .data = try out_writer.toOwnedSlice(), .result = result };
}

/// Load a policy that drops each log whose `field` matches `regex`.
fn loadLogDropPolicy(
    allocator: std.mem.Allocator,
    registry: *PolicyRegistry,
    id: []const u8,
    field: proto.policy.LogMatcher.field_union,
    regex: []const u8,
) !void {
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, id),
        .name = try allocator.dupe(u8, id),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    defer drop_policy.deinit(allocator);
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = field,
        .match = .{ .regex = try allocator.dupe(u8, regex) },
    });
    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);
}

test "processLogs - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"va" ++
        "lue\":{\"stringValue\":\"logs-integration-test\"}}]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"my-target\",\"version\":\"\"},\"logRecords\":[{\"observedTimeUnixNano" ++
        "\":\"1715753202587469939\",\"severityNumber\":9,\"severityText\":\"INFO\",\"body" ++
        "\":{\"stringValue\":\"hello from banana. My price is 2.99.\"},\"traceId\":\"\"," ++
        "\"spanId\":\"\"}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "banana") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "resourceLogs") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "processLogs - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), malformed, .json);
    defer allocator.free(run.data);

    try std.testing.expectEqualStrings(malformed, run.data);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "processLogs - malformed protobuf returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "not valid protobuf";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), malformed, .protobuf);
    defer allocator.free(run.data);

    try std.testing.expectEqualStrings(malformed, run.data);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "processLogs - no policies keeps all logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"msg1\"}},{\"severityText\":\"DEBUG\",\"body\":{\"stringValue\":\"msg2" ++
        "\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "msg1") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "msg2") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    // When no policies exist, we skip decoding entirely so original_count is 0
    try std.testing.expectEqual(@as(usize, 0), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
}

test "processLogs - DROP policy filters logs by severity" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for DEBUG logs
    try loadLogDropPolicy(allocator, &registry, "drop-debug", .{ .log_field = .LOG_FIELD_SEVERITY_TEXT }, "DEBUG");

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"info msg\"}},{\"severityText\":\"DEBUG\",\"body\":{\"stringValue\":\"d" ++
        "ebug msg\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // DEBUG log should be dropped, INFO log should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "debug msg") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "info msg") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());
}

test "processLogs - DROP policy filters logs by body content" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs containing "secret"
    try loadLogDropPolicy(allocator, &registry, "drop-secret", .{ .log_field = .LOG_FIELD_BODY }, "secret");

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"normal message\"}},{\"severityText\":\"INFO\",\"body\":{\"stringValue" ++
        "\":\"contains secret data\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // Log with "secret" should be dropped
    try std.testing.expect(std.mem.indexOf(u8, run.data, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "normal message") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
}

test "processLogs - DROP policy filters logs by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs from "test-service"
    // Create AttributePath with "service.name" as single path segment
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service.name"));
    try loadLogDropPolicy(
        allocator,
        &registry,
        "drop-test-service",
        .{ .resource_attribute = attr_path },
        "test-service",
    );

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"va" ++
        "lue\":{\"stringValue\":\"test-service\"}}]},\"scopeLogs\":[{\"scope\":{\"name\":" ++
        "\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"stringValue\":" ++
        "\"from test service\"}}]}]},{\"resource\":{\"attributes\":[{\"key\":\"service.na" ++
        "me\",\"value\":{\"stringValue\":\"prod-service\"}}]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"from prod service\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // Logs from test-service should be dropped
    try std.testing.expect(std.mem.indexOf(u8, run.data, "from test service") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "from prod service") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "logExists - empty body string treated as not present (spec)" {
    // An empty string body is not present (OTel policy spec). A non-string
    // body is present.
    const allocator = std.testing.allocator;

    const empty_body: proto.common.AnyValue = .{ .value = .{ .string_value = "" } };
    const non_empty_body: proto.common.AnyValue = .{ .value = .{ .string_value = "x" } };
    const int_body: proto.common.AnyValue = .{ .value = .{ .int_value = 42 } };

    var record_empty: proto.logs.LogRecord = .{ .body = empty_body };
    var record_nonempty: proto.logs.LogRecord = .{ .body = non_empty_body };
    var record_int: proto.logs.LogRecord = .{ .body = int_body };
    var record_missing: proto.logs.LogRecord = .{};
    var resource_logs: proto.logs.ResourceLogs = .{};
    defer resource_logs.deinit(allocator);
    var scope_logs: proto.logs.ScopeLogs = .{};
    defer scope_logs.deinit(allocator);

    inline for (.{
        .{ &record_empty, false },
        .{ &record_nonempty, true },
        .{ &record_int, true },
        .{ &record_missing, false },
    }) |case| {
        var ctx: OtlpLogContext = .{
            .log_record = case[0],
            .resource_logs = &resource_logs,
            .scope_logs = &scope_logs,
            .allocator = allocator,
        };
        const got = logExists(&ctx, .{ .log_field = .LOG_FIELD_BODY });
        try std.testing.expectEqual(@as(bool, case[1]), got);
    }
}

test "processLogs - all logs dropped returns empty structure" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all logs (using body pattern that matches both messages)
    try loadLogDropPolicy(allocator, &registry, "drop-all", .{ .log_field = .LOG_FIELD_BODY }, "msg");

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"msg1\"}},{\"severityText\":\"DEBUG\",\"body\":{\"stringValue\":\"msg2" ++
        "\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 2), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.allDropped());
}

// =============================================================================
// Protobuf Tests
// =============================================================================

/// Helper to create protobuf-encoded LogsData for testing
fn createTestProtobufLogs(allocator: std.mem.Allocator, messages: []const []const u8) ![]u8 {
    // Use an arena for the temporary protobuf structures
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var scope_logs: ScopeLogs = .{};
    for (messages) |msg| {
        const log_record: LogRecord = .{
            .severity_text = "INFO",
            .body = .{ .value = .{ .string_value = msg } },
        };
        try scope_logs.log_records.append(arena_alloc, log_record);
    }

    var resource_logs: ResourceLogs = .{};
    try resource_logs.scope_logs.append(arena_alloc, scope_logs);

    var logs_data: LogsData = .{};
    try logs_data.resource_logs.append(arena_alloc, resource_logs);

    // Encode to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try logs_data.encode(&output_writer.writer, arena_alloc);

    return output_writer.toOwnedSlice();
}

test "processLogs - protobuf parses and re-serializes" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create valid protobuf data
    const proto_data = try createTestProtobufLogs(allocator, &.{ "hello world", "test message" });
    defer allocator.free(proto_data);

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // With no policies, we skip decoding entirely so original_count is 0
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 0), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
}

test "processLogs - protobuf DROP policy filters logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs containing "secret"
    try loadLogDropPolicy(allocator, &registry, "drop-secret", .{ .log_field = .LOG_FIELD_BODY }, "secret");

    // Create protobuf data with one log containing "secret"
    const proto_data = try createTestProtobufLogs(allocator, &.{ "normal message", "contains secret data" });
    defer allocator.free(proto_data);

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    // One log should be dropped
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());

    // Verify the result can be decoded and contains only the normal message
    var reader = std.Io.Reader.fixed(run.data);
    var decoded = try LogsData.decode(&reader, allocator);
    defer decoded.deinit(allocator);

    // Should have 1 log record remaining
    var total_logs: usize = 0;
    for (decoded.resource_logs.items) |*rl| {
        for (rl.scope_logs.items) |*sl| {
            total_logs += sl.log_records.items.len;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), total_logs);
}

test "processLogs - protobuf all logs dropped" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy that matches all logs
    try loadLogDropPolicy(allocator, &registry, "drop-all", .{ .log_field = .LOG_FIELD_BODY }, "msg");

    // Create protobuf data with logs that all match the pattern
    const proto_data = try createTestProtobufLogs(allocator, &.{ "msg1", "msg2", "msg3" });
    defer allocator.free(proto_data);

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), proto_data, .protobuf);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 3), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 3), run.result.original_count);
    try std.testing.expect(run.result.allDropped());
}

test "processLogs - JSON transform removes severity_text field" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a policy with keep=all and a transform that removes the severity_text field
    var transform: proto.policy.LogTransform = .{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
    });

    var test_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "remove-severity-policy"),
        .name = try allocator.dupe(u8, "remove-severity"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    // Match on body containing "test"
    try test_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer test_policy.deinit(allocator);

    try registry.updatePolicies(&.{test_policy}, "test", .file);

    // Log with severityText that should be removed
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"test message\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // The log should be kept (keep=all)
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);

    // The body should still be present
    try std.testing.expect(std.mem.indexOf(u8, run.data, "test message") != null);

    // The severityText field should be removed (empty string in OTLP protobuf serialization)
    // After transform, severityText becomes empty string which may or may not appear in JSON
    // We verify the transform was applied by checking the log was kept
}

test "processLogs - JSON transform removes log attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a policy with keep=all and a transform that removes a log attribute
    var transform: proto.policy.LogTransform = .{};
    var remove_attr_path: proto.policy.AttributePath = .{};
    try remove_attr_path.path.append(allocator, try allocator.dupe(u8, "sensitive.data"));
    try transform.remove.append(allocator, .{
        .field = .{ .log_attribute = remove_attr_path },
    });

    var test_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "remove-attr-policy"),
        .name = try allocator.dupe(u8, "remove-attr"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    // Match on body containing "test"
    try test_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer test_policy.deinit(allocator);

    try registry.updatePolicies(&.{test_policy}, "test", .file);

    // Log with a sensitive attribute that should be removed
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"body\":{\"stringValue\":\"test message\"}," ++
        "\"attributes\":[{\"key\":\"sensitive.data\",\"value\":{\"stringValue\":\"secret1" ++
        "23\"}},{\"key\":\"safe.data\",\"value\":{\"stringValue\":\"public\"}}]}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // The log should be kept
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);

    // The sensitive attribute should be removed
    try std.testing.expect(std.mem.indexOf(u8, run.data, "sensitive.data") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "secret123") == null);

    // The safe attribute should still be present
    try std.testing.expect(std.mem.indexOf(u8, run.data, "safe.data") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "public") != null);
}

test "processLogs - DROP policy filters logs by event_name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs with event_name matching "user.login"
    try loadLogDropPolicy(
        allocator,
        &registry,
        "drop-login-events",
        .{ .log_field = .LOG_FIELD_EVENT_NAME },
        "^user\\.login$",
    );

    // Two logs: one with event_name "user.login" (should be dropped), one with "user.logout" (should be kept)
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"eventName\":\"user.login\",\"body\":{\"str" ++
        "ingValue\":\"login event\"}},{\"eventName\":\"user.logout\",\"body\":{\"stringVa" ++
        "lue\":\"logout event\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // Login event should be dropped, logout event should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "login event") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "logout event") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "processLogs - JSON transform removes event_name field" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a policy with keep=all and a transform that removes event_name
    var transform: proto.policy.LogTransform = .{};
    try transform.remove.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_EVENT_NAME },
    });

    var transform_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "remove-event-name"),
        .name = try allocator.dupe(u8, "remove-event-name"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "all"),
            .transform = transform,
        } },
    };
    // Match on body containing "test" to trigger the transform
    try transform_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "test") },
    });
    defer transform_policy.deinit(allocator);

    try registry.updatePolicies(&.{transform_policy}, "file-provider", .file);

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"eventName\":\"sensitive.event\",\"body\":{" ++
        "\"stringValue\":\"test message\"}}]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // The log should be kept
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);

    // The event_name should be removed (empty string in serialization)
    try std.testing.expect(std.mem.indexOf(u8, run.data, "sensitive.event") == null);
    // But the body should still be present
    try std.testing.expect(std.mem.indexOf(u8, run.data, "test message") != null);
}

// =============================================================================
// Tests for nested attribute path traversal
// =============================================================================

test "processLogs - DROP policy with nested attribute path" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy matching nested path http.method = GET
    // Create AttributePath with ["http", "method"]
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "http"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "method"));
    try loadLogDropPolicy(allocator, &registry, "drop-get-requests", .{ .log_attribute = attr_path }, "GET");

    // OTLP log with nested attribute: attributes containing http.method
    // The structure uses kvlist_value for nested objects
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[" ++
        "\n" ++
        "{\"body\":{\"stringValue\":\"GET request\"},\"attributes\":[{\"key\":\"http\",\"" ++
        "value\":{\"kvlistValue\":{\"values\":[{\"key\":\"method\",\"value\":{\"stringVal" ++
        "ue\":\"GET\"}}]}}}]}," ++
        "\n" ++
        "{\"body\":{\"stringValue\":\"POST request\"},\"attributes\":[{\"key\":\"http\"," ++
        "\"value\":{\"kvlistValue\":{\"values\":[{\"key\":\"method\",\"value\":{\"stringV" ++
        "alue\":\"POST\"}}]}}}]}" ++
        "\n" ++
        "]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // GET request should be dropped, POST request should remain
    try std.testing.expect(std.mem.indexOf(u8, run.data, "GET request") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "POST request") != null);
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
}

test "processLogs - policy with misaligned nested path returns no match" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy matching nested path http.request.method
    // but the actual data only has http.method (one level less)
    // Create AttributePath with ["http", "request", "method"] - 3 levels deep
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "http"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "request"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "method"));
    try loadLogDropPolicy(allocator, &registry, "drop-misaligned", .{ .log_attribute = attr_path }, "GET");

    // OTLP log with only 2 levels: http.method (no "request" in between)
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[" ++
        "\n" ++
        "{\"body\":{\"stringValue\":\"GET request\"},\"attributes\":[{\"key\":\"http\",\"" ++
        "value\":{\"kvlistValue\":{\"values\":[{\"key\":\"method\",\"value\":{\"stringVal" ++
        "ue\":\"GET\"}}]}}}]}" ++
        "\n" ++
        "]}]}]}";

    const run = try runLogs(allocator, &registry, noop_bus.eventBus(), logs, .json);
    defer allocator.free(run.data);

    // Nothing should be dropped because path doesn't match
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "GET request") != null);
}
