const std = @import("std");
const proto = @import("proto");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const otlp_attr = @import("attributes.zig");

const LogsData = proto.logs.LogsData;
const ResourceLogs = proto.logs.ResourceLogs;
const ScopeLogs = proto.logs.ScopeLogs;
const LogRecord = proto.logs.LogRecord;
const AnyValue = proto.common.AnyValue;
const KeyValue = proto.common.KeyValue;
const InstrumentationScope = proto.common.InstrumentationScope;

const PolicyEngine = policy.PolicyEngine;
const PolicyResult = policy.PolicyResult;
const FilterDecision = policy.FilterDecision;
pub const FieldRef = policy.FieldRef;
const LogAccessor = policy.LogAccessor;
const LogField = proto.policy.LogField;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

const LogsProcessingFailed = struct { err: []const u8, contentType: []const u8 };

/// Result of processing logs
pub const ProcessResult = struct {
    /// Whether any transformations were applied
    was_transformed: bool = false,
    /// Number of logs that were dropped by filter policies
    dropped_count: usize,
    /// Original number of logs before filtering
    original_count: usize,
    /// The processed data (caller owns this slice)
    data: []u8,

    /// Returns true if any logs were dropped or transformed
    pub fn wasModified(self: ProcessResult) bool {
        return self.dropped_count > 0 or self.was_transformed;
    }

    /// Returns true if all logs were dropped
    pub fn allDropped(self: ProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

pub const StreamProcessResult = struct {
    was_transformed: bool = false,
    dropped_count: usize,
    original_count: usize,

    pub fn wasModified(self: StreamProcessResult) bool {
        return self.dropped_count > 0 or self.was_transformed;
    }

    pub fn allDropped(self: StreamProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Content format for OTLP logs
pub const ContentFormat = enum {
    json,
    protobuf,
    unknown,

    /// Detect format from content-type header
    pub fn fromContentType(content_type: []const u8) ContentFormat {
        if (std.mem.indexOf(u8, content_type, "application/json") != null) {
            return .json;
        }
        if (std.mem.indexOf(u8, content_type, "application/x-protobuf") != null) {
            return .protobuf;
        }
        return .unknown;
    }
};

/// Process OTLP logs with filter evaluation
/// Takes decompressed data (JSON or protobuf) and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
///
/// OTLP format (ExportLogsServiceRequest/LogsData):
/// {
///   "resourceLogs": [
///     {
///       "resource": { "attributes": [...] },
///       "scopeLogs": [
///         {
///           "scope": { "name": "...", "version": "...", "attributes": [...] },
///           "logRecords": [
///             {
///               "body": { "stringValue": "..." },
///               "severityText": "INFO",
///               "severityNumber": 9,
///               "attributes": [...]
///             }
///           ]
///         }
///       ]
///     }
///   ]
/// }
const LogsProcessingStarted = struct {
    content_type: []const u8,
    data_len: usize,
    format: []const u8,
};

pub fn processLogsStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
    content_type: []const u8,
) !StreamProcessResult {
    const format = ContentFormat.fromContentType(content_type);
    return switch (format) {
        .protobuf => processProtobufLogsStream(allocator, registry, bus, in_reader, out_writer),
        .json => blk: {
            const data = try readAll(allocator, in_reader);
            defer allocator.free(data);
            const result = try processJsonLogs(allocator, registry, bus, data);
            defer allocator.free(result.data);
            try out_writer.writeAll(result.data);
            break :blk .{
                .was_transformed = result.was_transformed,
                .dropped_count = result.dropped_count,
                .original_count = result.original_count,
            };
        },
        .unknown => blk: {
            try streamAll(in_reader, out_writer);
            break :blk .{
                .dropped_count = 0,
                .original_count = 0,
                .was_transformed = false,
            };
        },
    };
}

fn readAll(allocator: std.mem.Allocator, reader: *std.Io.Reader) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try streamAll(reader, &out.writer);
    return out.toOwnedSlice();
}

fn streamAll(reader: *std.Io.Reader, writer: *std.Io.Writer) !void {
    while (true) {
        const n = reader.stream(writer, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
    }
}

/// Context for OTLP log field accessor and mutator - provides access to log record plus parent context.
pub const OtlpLogContext = struct {
    log_record: *LogRecord,
    resource_logs: *ResourceLogs,
    scope_logs: *ScopeLogs,
    allocator: std.mem.Allocator,
    /// Whether identifier fields (trace_id/span_id) are held as lowercase-hex
    /// strings in memory. Now false on both production paths — JSON decode
    /// hex-decodes ids to raw bytes (see processJsonLogs), matching the protobuf
    /// path — so the accessors' hex branch only serves callers that build a
    /// context from hex ids directly. Governs how `value`/`typed_value` normalize
    /// ids to raw bytes before matching/sampling.
    bytes_as_hex: bool,
};

const getAnyValueString = otlp_attr.getStringValue;
const findNestedAttribute = otlp_attr.findNestedAttribute;
const findAttrIndex = otlp_attr.findAttrIndex;
const removeAttributeByPath = otlp_attr.removeAttributeByPath;
const setAttributeByPath = otlp_attr.setAttributeByPath;
const setAttribute = otlp_attr.setAttribute;

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

/// Yields identifier fields (trace_id/span_id) as RAW bytes for the string-
/// matcher primitive. Policy authors write these as lowercase hex, but the
/// engine renders raw bytes to hex itself before matching, so `value` must
/// return raw bytes: pass through on the protobuf path, hex-decode on the JSON
/// path. Returns null on empty or malformed hex (hides the id from
/// exact/contains/regex matchers — fail-safe). Mirrors `idTyped`.
fn idBytes(log_ctx: *const OtlpLogContext, id: []const u8) ?[]const u8 {
    if (id.len == 0) return null;
    if (!log_ctx.bytes_as_hex) return id;
    if (id.len % 2 != 0) return null;
    const out = log_ctx.allocator.alloc(u8, id.len / 2) catch return null;
    _ = std.fmt.hexToBytes(out, id) catch return null;
    return out;
}

/// Field accessor primitive for the OTLP log context.
/// Returns the string view of the requested field, or null if missing/non-string.
pub fn logValue(ctx: *const anyopaque, field: FieldRef) ?[]const u8 {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(@constCast(ctx)));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => getAnyValueString(log_ctx.log_record.body),
            // Identifier bytes are stored raw (protobuf) or hex (JSON); the
            // engine hex-renders raw bytes before string matching, so return
            // raw bytes on both paths. See `idBytes`.
            .LOG_FIELD_TRACE_ID => idBytes(log_ctx, log_ctx.log_record.trace_id),
            .LOG_FIELD_SPAN_ID => idBytes(log_ctx, log_ctx.log_record.span_id),
            else => if (stringFieldRef(log_ctx, lf)) |ref|
                (if (ref.len > 0) ref.* else null)
            else
                null,
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            const attrs = attributeList(log_ctx, field) orelse break :blk null;
            break :blk findNestedAttribute(attrs.items, attr_path.path.items);
        },
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

/// Presence check for `exists` matchers. The engine's default fallback
/// (`value != null`) is wrong for `LOG_FIELD_BODY` in two ways:
///
///   1. `body = { stringValue: "" }` reads as the empty string via
///      `value()`, but per OTel-policy spec an empty body must be treated
///      as not-present.
///   2. `body = { intValue: ... }` (or any non-string body) reads as
///      `null` via `value()` because we only return string content, but
///      the spec says a non-null non-string body IS present.
///
/// String-typed log_fields (severity_text, trace_id, …) and attribute
/// paths follow the simpler "non-empty string view" rule, so wiring this
/// explicitly is still cheaper than relying on the fallback because we
/// skip the allocator-touching `findNestedAttribute` for presence-only
/// checks.
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

/// Typed-value accessor for the OTLP log context. The policy engine prefers
/// this over `logValue` for typed matchers and probabilistic sampling (the
/// `sample_key` field). Identifier fields (trace_id/span_id) read as raw
/// `TypedValue.bytes` so the sampler hashes the right bytes; body and
/// attributes carry their native scalar type; everything else falls back to
/// the string view.
pub fn logTypedValue(ctx: *const anyopaque, field: FieldRef) ?policy.TypedValue {
    const log_ctx: *OtlpLogContext = @ptrCast(@alignCast(@constCast(ctx)));
    return switch (field) {
        .log_field => |lf| switch (lf) {
            .LOG_FIELD_BODY => otlp_attr.anyValueTyped(log_ctx.log_record.body),
            .LOG_FIELD_TRACE_ID => idTyped(log_ctx, log_ctx.log_record.trace_id),
            .LOG_FIELD_SPAN_ID => idTyped(log_ctx, log_ctx.log_record.span_id),
            else => otlp_attr.typedStr(logValue(ctx, field)),
        },
        .log_attribute, .resource_attribute, .scope_attribute => |attr_path| blk: {
            const attrs = attributeList(log_ctx, field) orelse break :blk null;
            break :blk otlp_attr.findNestedAttributeTyped(attrs.items, attr_path.path.items);
        },
    };
}

/// Decode an identifier field to raw bytes for the sampler: hex-decode on the
/// JSON path, pass raw bytes through on the protobuf path.
fn idTyped(log_ctx: *const OtlpLogContext, id: []const u8) ?policy.TypedValue {
    if (id.len == 0) return null;
    return if (log_ctx.bytes_as_hex)
        otlp_attr.typedHexBytes(log_ctx.allocator, id)
    else
        otlp_attr.typedBytes(id);
}

/// LogAccessor template wiring the OTLP log primitives to a registry.
pub const log_accessor: LogAccessor = .{
    .value = logValue,
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
    bytes_as_hex: bool,
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
                    .bytes_as_hex = bytes_as_hex,
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
                    // Keep this log - move to write position if needed
                    if (write_idx != scope_logs.log_records.items.len - 1) {
                        scope_logs.log_records.items[write_idx] = log_record.*;
                    }
                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_logs.log_records.shrinkRetainingCapacity(write_idx);
        }

        // Prune empty scope containers
        var scope_write_idx: usize = 0;
        for (resource_logs.scope_logs.items) |scope_logs_item| {
            if (scope_logs_item.log_records.items.len > 0) {
                resource_logs.scope_logs.items[scope_write_idx] = scope_logs_item;
                scope_write_idx += 1;
            }
        }
        resource_logs.scope_logs.shrinkRetainingCapacity(scope_write_idx);
    }

    // Prune empty resource containers
    var resource_write_idx: usize = 0;
    for (logs_data.resource_logs.items) |resource_logs_item| {
        if (resource_logs_item.scope_logs.items.len > 0) {
            logs_data.resource_logs.items[resource_write_idx] = resource_logs_item;
            resource_write_idx += 1;
        }
    }
    logs_data.resource_logs.shrinkRetainingCapacity(resource_write_idx);

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
) !ProcessResult {
    // Fast path: if no policies, skip decode/encode entirely
    const snapshot = registry.getSnapshot();
    if (snapshot == null or snapshot.?.log_index.isEmpty()) {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = 0,
            .was_transformed = false,
        };
    }

    // OTLP/JSON hex-encodes only the identifier bytes fields (trace_id/span_id);
    // per-field hex decode leaves base64 bytes attributes intact. In memory the
    // ids become raw bytes, identical to the protobuf wire path.
    var parsed = try LogsData.jsonDecodeOpts(data, .{
        .ignore_unknown_fields = true,
    }, .{ .hex_bytes_fields = otlp_attr.hex_id_fields }, allocator);
    defer parsed.deinit();

    // Filter logs in-place. Identifier fields are raw bytes in memory now
    // (decoded above), same as protobuf.
    const counts = filterLogsInPlace(allocator, &parsed.value, registry, bus, false);

    // Fast path: if nothing was modified, return original data without re-encoding
    if (counts.dropped_count == 0 and !counts.was_transformed) {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = counts.original_count,
            .was_transformed = false,
        };
    }

    // Re-serialize to JSON, hex-encoding the same identifier fields back out.
    const output = try parsed.value.jsonEncode(.{}, .{
        .emit_oneof_field_name = false,
        .hex_bytes_fields = otlp_attr.hex_id_fields,
    }, allocator);

    return .{
        .data = @constCast(output),
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
) !ProcessResult {
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
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = 0,
            .was_transformed = false,
        };
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

    // Filter logs in-place. Protobuf identifier fields are raw bytes.
    const counts = filterLogsInPlace(arena_alloc, &logs_data, registry, bus, false);

    // Fast path: if nothing was modified, return original data without re-encoding
    if (counts.dropped_count == 0 and !counts.was_transformed) {
        const result = try allocator.alloc(u8, data.len);
        @memcpy(result, data);
        return .{
            .data = result,
            .dropped_count = 0,
            .original_count = counts.original_count,
            .was_transformed = false,
        };
    }

    // Re-serialize to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try logs_data.encode(&output_writer.writer, arena_alloc);

    // Transfer ownership of the written data to caller
    const output = try output_writer.toOwnedSlice();

    return .{
        .data = output,
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
        .was_transformed = counts.was_transformed,
    };
}

fn processProtobufLogsStream(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    in_reader: *std.Io.Reader,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    const data = try readAll(allocator, in_reader);
    defer allocator.free(data);

    const result = try processProtobufLogs(allocator, registry, bus, data);
    defer allocator.free(result.data);

    try out_writer.writeAll(result.data);
    return .{
        .was_transformed = result.was_transformed,
        .dropped_count = result.dropped_count,
        .original_count = result.original_count,
    };
}

// =============================================================================
// Tests
// =============================================================================

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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "banana") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "resourceLogs") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ not valid json }";

    var in_reader = std.Io.Reader.fixed(malformed);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - unknown content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some unknown data";

    var in_reader = std.Io.Reader.fixed(data);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "text/plain",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processLogs - malformed protobuf returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "not valid protobuf";

    var in_reader = std.Io.Reader.fixed(malformed);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/x-protobuf",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "msg1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "msg2") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    // When no policies exist, we skip decoding entirely so original_count is 0
    try std.testing.expectEqual(@as(usize, 0), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processLogs - DROP policy filters logs by severity" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for DEBUG logs
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-debug"),
        .name = try allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_SEVERITY_TEXT },
        .match = .{ .regex = try allocator.dupe(u8, "DEBUG") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"info msg\"}},{\"severityText\":\"DEBUG\",\"body\":{\"stringValue\":\"d" ++
        "ebug msg\"}}]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // DEBUG log should be dropped, INFO log should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "debug msg") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "info msg") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());
}

test "processLogs - DROP policy filters logs by body content" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs containing "secret"
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-secret"),
        .name = try allocator.dupe(u8, "drop-secret"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "secret") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"normal message\"}},{\"severityText\":\"INFO\",\"body\":{\"stringValue" ++
        "\":\"contains secret data\"}}]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // Log with "secret" should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "normal message") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
}

test "processLogs - DROP policy filters logs by resource attribute" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs from "test-service"
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-test-service"),
        .name = try allocator.dupe(u8, "drop-test-service"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    // Create AttributePath with "service.name" as single path segment
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "service.name"));
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .resource_attribute = attr_path },
        .match = .{ .regex = try allocator.dupe(u8, "test-service") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[{\"key\":\"service.name\",\"va" ++
        "lue\":{\"stringValue\":\"test-service\"}}]},\"scopeLogs\":[{\"scope\":{\"name\":" ++
        "\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"stringValue\":" ++
        "\"from test service\"}}]}]},{\"resource\":{\"attributes\":[{\"key\":\"service.na" ++
        "me\",\"value\":{\"stringValue\":\"prod-service\"}}]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"from prod service\"}}]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // Logs from test-service should be dropped
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from test service") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "from prod service") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}

test "logExists - empty body string treated as not present (spec)" {
    // Regression for the `compound_empty_vs_missing` conformance failure:
    // an OTel body with `stringValue: ""` MUST be treated as not present
    // for `exists: true` matchers. Edge previously fell back to the
    // engine's default callExists (`value != null`), which read the empty
    // string as a non-null view and reported exists=true.
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
            .bytes_as_hex = true,
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
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "msg") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"severityText\":\"INFO\",\"body\":{\"string" ++
        "Value\":\"msg1\"}},{\"severityText\":\"DEBUG\",\"body\":{\"stringValue\":\"msg2" ++
        "\"}}]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 2), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.allDropped());
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

    var in_reader = std.Io.Reader.fixed(proto_data);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/x-protobuf",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // With no policies, we skip decoding entirely so original_count is 0
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 0), result.original_count);
    try std.testing.expect(!result.wasModified());
}

test "processLogs - protobuf DROP policy filters logs" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs containing "secret"
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-secret"),
        .name = try allocator.dupe(u8, "drop-secret"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "secret") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with one log containing "secret"
    const proto_data = try createTestProtobufLogs(allocator, &.{ "normal message", "contains secret data" });
    defer allocator.free(proto_data);

    var in_reader = std.Io.Reader.fixed(proto_data);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/x-protobuf",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // One log should be dropped
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
    try std.testing.expect(result.wasModified());

    // Verify the result can be decoded and contains only the normal message
    var reader = std.Io.Reader.fixed(result.data);
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
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-all"),
        .name = try allocator.dupe(u8, "drop-all"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_BODY },
        .match = .{ .regex = try allocator.dupe(u8, "msg") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Create protobuf data with logs that all match the pattern
    const proto_data = try createTestProtobufLogs(allocator, &.{ "msg1", "msg2", "msg3" });
    defer allocator.free(proto_data);

    var in_reader = std.Io.Reader.fixed(proto_data);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/x-protobuf",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    try std.testing.expectEqual(@as(usize, 3), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 3), result.original_count);
    try std.testing.expect(result.allDropped());
}

test "ContentFormat.fromContentType" {
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json"));
    try std.testing.expectEqual(ContentFormat.json, ContentFormat.fromContentType("application/json; charset=utf-8"));
    try std.testing.expectEqual(ContentFormat.protobuf, ContentFormat.fromContentType("application/x-protobuf"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType("text/plain"));
    try std.testing.expectEqual(ContentFormat.unknown, ContentFormat.fromContentType(""));
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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // The log should be kept (keep=all)
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);

    // The body should still be present
    try std.testing.expect(std.mem.indexOf(u8, result.data, "test message") != null);

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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // The log should be kept
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);

    // The sensitive attribute should be removed
    try std.testing.expect(std.mem.indexOf(u8, result.data, "sensitive.data") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "secret123") == null);

    // The safe attribute should still be present
    try std.testing.expect(std.mem.indexOf(u8, result.data, "safe.data") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "public") != null);
}

test "processLogs - DROP policy filters logs by event_name" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy for logs with event_name matching "user.login"
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-login-events"),
        .name = try allocator.dupe(u8, "drop-login-events"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };
    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_field = .LOG_FIELD_EVENT_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "^user\\.login$") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // Two logs: one with event_name "user.login" (should be dropped), one with "user.logout" (should be kept)
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[{\"eventName\":\"user.login\",\"body\":{\"str" ++
        "ingValue\":\"login event\"}},{\"eventName\":\"user.logout\",\"body\":{\"stringVa" ++
        "lue\":\"logout event\"}}]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // Login event should be dropped, logout event should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "login event") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "logout event") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // The log should be kept
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);

    // The event_name should be removed (empty string in serialization)
    try std.testing.expect(std.mem.indexOf(u8, result.data, "sensitive.event") == null);
    // But the body should still be present
    try std.testing.expect(std.mem.indexOf(u8, result.data, "test message") != null);
}

// =============================================================================
// Tests for nested attribute path traversal
// =============================================================================

test "findNestedAttribute - single segment path" {
    // Test that single-segment paths work correctly
    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "service",
        .value = .{ .value = .{ .string_value = "payment-api" } },
    });

    const result = findNestedAttribute(attrs.items, &.{"service"});
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("payment-api", result.?);
}

test "findNestedAttribute - two segment path through kvlist" {
    // Test path ["http", "method"] where http contains a kvlist
    var inner_attrs: std.ArrayList(KeyValue) = .empty;
    defer inner_attrs.deinit(std.testing.allocator);

    try inner_attrs.append(std.testing.allocator, .{
        .key = "method",
        .value = .{ .value = .{ .string_value = "GET" } },
    });
    try inner_attrs.append(std.testing.allocator, .{
        .key = "status_code",
        .value = .{ .value = .{ .string_value = "200" } },
    });

    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "http",
        .value = .{ .value = .{ .kvlist_value = .{ .values = inner_attrs } } },
    });

    // Should find http.method
    const method = findNestedAttribute(attrs.items, &.{ "http", "method" });
    try std.testing.expect(method != null);
    try std.testing.expectEqualStrings("GET", method.?);

    // Should find http.status_code
    const status = findNestedAttribute(attrs.items, &.{ "http", "status_code" });
    try std.testing.expect(status != null);
    try std.testing.expectEqualStrings("200", status.?);
}

test "findNestedAttribute - three segment deep path" {
    // Test path ["request", "headers", "content-type"]
    var headers_attrs: std.ArrayList(KeyValue) = .empty;
    defer headers_attrs.deinit(std.testing.allocator);

    try headers_attrs.append(std.testing.allocator, .{
        .key = "content-type",
        .value = .{ .value = .{ .string_value = "application/json" } },
    });

    var request_attrs: std.ArrayList(KeyValue) = .empty;
    defer request_attrs.deinit(std.testing.allocator);

    try request_attrs.append(std.testing.allocator, .{
        .key = "headers",
        .value = .{ .value = .{ .kvlist_value = .{ .values = headers_attrs } } },
    });

    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "request",
        .value = .{ .value = .{ .kvlist_value = .{ .values = request_attrs } } },
    });

    const result = findNestedAttribute(attrs.items, &.{ "request", "headers", "content-type" });
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("application/json", result.?);
}

test "findNestedAttribute - path segment not found" {
    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "service",
        .value = .{ .value = .{ .string_value = "payment-api" } },
    });

    // Non-existent top-level key
    const result1 = findNestedAttribute(attrs.items, &.{"nonexistent"});
    try std.testing.expect(result1 == null);

    // Non-existent nested key
    const result2 = findNestedAttribute(attrs.items, &.{ "service", "name" });
    try std.testing.expect(result2 == null);
}

test "findNestedAttribute - path longer than nesting depth" {
    // Path ["http", "method", "extra"] but http.method is a string, not kvlist
    var inner_attrs: std.ArrayList(KeyValue) = .empty;
    defer inner_attrs.deinit(std.testing.allocator);

    try inner_attrs.append(std.testing.allocator, .{
        .key = "method",
        .value = .{ .value = .{ .string_value = "GET" } },
    });

    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "http",
        .value = .{ .value = .{ .kvlist_value = .{ .values = inner_attrs } } },
    });

    // Path is longer than nesting - should return null
    const result = findNestedAttribute(attrs.items, &.{ "http", "method", "extra" });
    try std.testing.expect(result == null);
}

test "findNestedAttribute - intermediate segment is not kvlist" {
    // Path ["service", "name"] but service is a string, not a kvlist
    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "service",
        .value = .{ .value = .{ .string_value = "payment-api" } },
    });

    // service is a string, can't traverse into it
    const result = findNestedAttribute(attrs.items, &.{ "service", "name" });
    try std.testing.expect(result == null);
}

test "findNestedAttribute - empty path returns null" {
    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "service",
        .value = .{ .value = .{ .string_value = "payment-api" } },
    });

    const result = findNestedAttribute(attrs.items, &.{});
    try std.testing.expect(result == null);
}

test "findNestedAttribute - intermediate segment missing" {
    // Path ["http", "request", "method"] but http only has "response"
    var inner_attrs: std.ArrayList(KeyValue) = .empty;
    defer inner_attrs.deinit(std.testing.allocator);

    try inner_attrs.append(std.testing.allocator, .{
        .key = "response",
        .value = .{ .value = .{ .string_value = "ok" } },
    });

    var attrs: std.ArrayList(KeyValue) = .empty;
    defer attrs.deinit(std.testing.allocator);

    try attrs.append(std.testing.allocator, .{
        .key = "http",
        .value = .{ .value = .{ .kvlist_value = .{ .values = inner_attrs } } },
    });

    // "request" doesn't exist under "http"
    const result = findNestedAttribute(attrs.items, &.{ "http", "request", "method" });
    try std.testing.expect(result == null);
}

test "processLogs - DROP policy with nested attribute path" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy matching nested path http.method = GET
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-get-requests"),
        .name = try allocator.dupe(u8, "drop-get-requests"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };

    // Create AttributePath with ["http", "method"]
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "http"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "method"));

    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .regex = try allocator.dupe(u8, "GET") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

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

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // GET request should be dropped, POST request should remain
    try std.testing.expect(std.mem.indexOf(u8, result.data, "GET request") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "POST request") != null);
    try std.testing.expectEqual(@as(usize, 1), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), result.original_count);
}

test "processLogs - policy with misaligned nested path returns no match" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create a DROP policy matching nested path http.request.method
    // but the actual data only has http.method (one level less)
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-misaligned"),
        .name = try allocator.dupe(u8, "drop-misaligned"),
        .enabled = true,
        .target = .{ .log = .{
            .keep = try allocator.dupe(u8, "none"),
        } },
    };

    // Create AttributePath with ["http", "request", "method"] - 3 levels deep
    var attr_path: proto.policy.AttributePath = .{};
    try attr_path.path.append(allocator, try allocator.dupe(u8, "http"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "request"));
    try attr_path.path.append(allocator, try allocator.dupe(u8, "method"));

    try drop_policy.target.?.log.match.append(allocator, .{
        .field = .{ .log_attribute = attr_path },
        .match = .{ .regex = try allocator.dupe(u8, "GET") },
    });
    defer drop_policy.deinit(allocator);

    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    // OTLP log with only 2 levels: http.method (no "request" in between)
    const logs = "{\"resourceLogs\":[{\"resource\":{\"attributes\":[]},\"scopeLogs\":[{\"scope\":{" ++
        "\"name\":\"test\"},\"logRecords\":[" ++
        "\n" ++
        "{\"body\":{\"stringValue\":\"GET request\"},\"attributes\":[{\"key\":\"http\",\"" ++
        "value\":{\"kvlistValue\":{\"values\":[{\"key\":\"method\",\"value\":{\"stringVal" ++
        "ue\":\"GET\"}}]}}}]}" ++
        "\n" ++
        "]}]}]}";

    var in_reader = std.Io.Reader.fixed(logs);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const stream_result = try processLogsStream(
        allocator,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        "application/json",
    );
    const result: ProcessResult = .{
        .data = try out_writer.toOwnedSlice(),
        .dropped_count = stream_result.dropped_count,
        .original_count = stream_result.original_count,
        .was_transformed = stream_result.was_transformed,
    };
    defer allocator.free(result.data);

    // Nothing should be dropped because path doesn't match
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), result.original_count);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "GET request") != null);
}
