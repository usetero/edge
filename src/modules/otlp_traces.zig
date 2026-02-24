//! OTLP Traces Processing Module
//!
//! Processes OpenTelemetry traces with policy-based filtering and sampling.
//! Supports both JSON and protobuf formats.
//!
//! Note: This module is OTLP-only. Datadog traces are NOT supported.
//!
//! OTLP Traces Structure:
//! TracesData
//! └─── ResourceSpans
//!   ├── Resource
//!   ├── SchemaURL
//!   └── ScopeSpans
//!      ├── Scope
//!      ├── SchemaURL
//!      └── Span
//!         ├── TraceID, SpanID, ParentSpanID
//!         ├── Name, Kind, Status
//!         ├── Attributes
//!         ├── Events
//!         └── Links

const std = @import("std");
const proto = @import("proto");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const otlp_attr = @import("otlp_attributes.zig");

const TracesData = proto.trace.TracesData;
const ResourceSpans = proto.trace.ResourceSpans;
const ScopeSpans = proto.trace.ScopeSpans;
const Span = proto.trace.Span;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;

const PolicyEngine = policy.PolicyEngine;
const TraceFieldRef = policy.TraceFieldRef;
const MAX_MATCHES_PER_SCAN = policy.MAX_MATCHES_PER_SCAN;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Observability Events
// =============================================================================

const TracesProcessingStarted = struct {
    content_type: []const u8,
    data_len: usize,
    format: []const u8,
};

const TracesProcessingFailed = struct { err: []const u8, contentType: []const u8 };

// =============================================================================
// Public API
// =============================================================================

/// Result of processing traces
pub const ProcessResult = struct {
    /// Whether any transformations were applied (e.g. tracestate sampling updates)
    was_transformed: bool = false,
    /// Number of spans that were dropped by filter policies
    dropped_count: usize,
    /// Original number of spans before filtering
    original_count: usize,
    /// The processed data (caller owns this slice)
    data: []u8,

    /// Returns true if any spans were dropped or transformed
    pub fn wasModified(self: ProcessResult) bool {
        return self.dropped_count > 0 or self.was_transformed;
    }

    /// Returns true if all spans were dropped
    pub fn allDropped(self: ProcessResult) bool {
        return self.original_count > 0 and self.dropped_count == self.original_count;
    }
};

/// Content format for OTLP traces
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

/// Process OTLP traces with filter evaluation
/// Takes decompressed data (JSON or protobuf) and applies filter policies
/// Returns ProcessResult with data and counts (caller owns the data slice)
pub fn processTraces(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    content_type: []const u8,
) !ProcessResult {
    const format = ContentFormat.fromContentType(content_type);

    bus.debug(TracesProcessingStarted{
        .content_type = content_type,
        .data_len = data.len,
        .format = @tagName(format),
    });

    return switch (format) {
        .json => processJsonTraces(allocator, registry, bus, data) catch |err| {
            bus.err(TracesProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .protobuf => processProtobufTraces(allocator, registry, bus, data) catch |err| {
            bus.err(TracesProcessingFailed{ .err = @errorName(err), .contentType = content_type });
            return copyUnchanged(allocator, data);
        },
        .unknown => copyUnchanged(allocator, data),
    };
}

// =============================================================================
// Internal Implementation
// =============================================================================

/// Copy data unchanged (fail-open behavior)
fn copyUnchanged(allocator: std.mem.Allocator, data: []const u8) !ProcessResult {
    const result = try allocator.alloc(u8, data.len);
    @memcpy(result, data);
    return .{
        .data = result,
        .dropped_count = 0,
        .original_count = 0,
    };
}

/// Context for OTLP span field accessor - provides access to span plus parent context
const OtlpSpanContext = struct {
    span: *Span,
    resource_spans: *ResourceSpans,
    scope_spans: *ScopeSpans,
    allocator: std.mem.Allocator,
};

const getAnyValueString = otlp_attr.getStringValue;
const findNestedAttribute = otlp_attr.findNestedAttribute;

/// Convert trace ID bytes to hex string (16 bytes -> 32 chars)
fn traceIdToHex(trace_id: []const u8, buf: *[32]u8) ?[]const u8 {
    if (trace_id.len != 16) return null;
    const hex_chars = "0123456789abcdef";
    for (trace_id, 0..) |byte, i| {
        buf[i * 2] = hex_chars[byte >> 4];
        buf[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return buf[0..32];
}

/// Field accessor for OTLP trace format
/// Maps TraceFieldRef to the appropriate field in the OTLP span structure
fn otlpSpanFieldAccessor(ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8 {
    const span_ctx: *const OtlpSpanContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => if (span_ctx.span.name.len > 0) span_ctx.span.name else null,
            .TRACE_FIELD_TRACE_ID => if (span_ctx.span.trace_id.len > 0) span_ctx.span.trace_id else null,
            .TRACE_FIELD_SPAN_ID => if (span_ctx.span.span_id.len > 0) span_ctx.span.span_id else null,
            .TRACE_FIELD_PARENT_SPAN_ID => if (span_ctx.span.parent_span_id.len > 0) span_ctx.span.parent_span_id else null,
            .TRACE_FIELD_TRACE_STATE => if (span_ctx.span.trace_state.len > 0) span_ctx.span.trace_state else null,
            .TRACE_FIELD_RESOURCE_SCHEMA_URL => if (span_ctx.resource_spans.schema_url.len > 0) span_ctx.resource_spans.schema_url else null,
            .TRACE_FIELD_SCOPE_SCHEMA_URL => if (span_ctx.scope_spans.schema_url.len > 0) span_ctx.scope_spans.schema_url else null,
            .TRACE_FIELD_SCOPE_NAME => if (span_ctx.scope_spans.scope) |scope| (if (scope.name.len > 0) scope.name else null) else null,
            .TRACE_FIELD_SCOPE_VERSION => if (span_ctx.scope_spans.scope) |scope| (if (scope.version.len > 0) scope.version else null) else null,
            else => null,
        },
        .span_attribute => |attr_path| findNestedAttribute(span_ctx.span.attributes.items, attr_path.path.items),
        .resource_attribute => |attr_path| if (span_ctx.resource_spans.resource) |res| findNestedAttribute(res.attributes.items, attr_path.path.items) else null,
        .scope_attribute => |attr_path| if (span_ctx.scope_spans.scope) |scope| findNestedAttribute(scope.attributes.items, attr_path.path.items) else null,
        .span_kind => |requested_kind| blk: {
            // Compare by integer value — OTel SpanKind and policy SpanKind share values
            break :blk if (@intFromEnum(span_ctx.span.kind) == @intFromEnum(requested_kind))
                @tagName(requested_kind)
            else
                null;
        },
        .span_status => |requested_status| blk: {
            const status = span_ctx.span.status orelse break :blk null;
            // OTel StatusCode and policy SpanStatusCode share integer values
            break :blk if (@intFromEnum(status.code) == @intFromEnum(requested_status))
                @tagName(requested_status)
            else
                null;
        },
        .event_name => |name| blk: {
            // Check if any event has the given name
            for (span_ctx.span.events.items) |event| {
                if (std.mem.eql(u8, event.name, name)) {
                    break :blk name; // Return the name itself as match indicator
                }
            }
            break :blk null;
        },
        .event_attribute => |attr_path| blk: {
            // Check if any event has an attribute with the given path
            for (span_ctx.span.events.items) |event| {
                if (findNestedAttribute(event.attributes.items, attr_path.path.items)) |val| {
                    break :blk val;
                }
            }
            break :blk null;
        },
        .link_trace_id => |_| blk: {
            // Check if span has any links - return first linked trace_id as hex
            if (span_ctx.span.links.items.len == 0) break :blk null;
            const S = struct {
                threadlocal var buf: [32]u8 = undefined;
            };
            break :blk traceIdToHex(span_ctx.span.links.items[0].trace_id, &S.buf);
        },
    };
}

const TraceMutateOp = policy.TraceMutateOp;

/// Field mutator for OTLP trace format
/// Handles tracestate updates from the sampling engine.
fn otlpSpanFieldMutator(ctx: *anyopaque, op: TraceMutateOp) bool {
    const span_ctx: *OtlpSpanContext = @ptrCast(@alignCast(ctx));
    switch (op) {
        .set => |s| {
            switch (s.field) {
                .trace_field => |tf| {
                    if (tf == .TRACE_FIELD_TRACE_STATE) {
                        // The engine writes the raw threshold hex value.
                        // Merge it into the W3C tracestate as ot=th:VALUE.
                        span_ctx.span.trace_state = mergeOTTracestate(span_ctx.allocator, span_ctx.span.trace_state, s.value);
                        return true;
                    }
                },
                else => {},
            }
        },
        else => {},
    }
    return false;
}

/// Merge a sampling threshold into W3C tracestate as ot=th:VALUE.
/// Preserves existing vendor entries and other ot sub-keys (like rv).
fn mergeOTTracestate(allocator: std.mem.Allocator, tracestate: []const u8, th_value: []const u8) []const u8 {
    var ot_parts: std.ArrayListUnmanaged(u8) = .empty;
    var other_vendors: std.ArrayListUnmanaged(u8) = .empty;

    if (tracestate.len > 0) {
        var vendors = std.mem.splitScalar(u8, tracestate, ',');
        while (vendors.next()) |vendor_raw| {
            const vendor = std.mem.trim(u8, vendor_raw, " ");
            if (vendor.len == 0) continue;
            if (std.mem.startsWith(u8, vendor, "ot=")) {
                const ot_value = vendor[3..];
                var parts = std.mem.splitScalar(u8, ot_value, ';');
                while (parts.next()) |part_raw| {
                    const part = std.mem.trim(u8, part_raw, " ");
                    if (part.len == 0) continue;
                    // Skip existing th: sub-key (we're replacing it)
                    if (std.mem.startsWith(u8, part, "th:")) continue;
                    if (ot_parts.items.len > 0) ot_parts.appendSlice(allocator, ";") catch {};
                    ot_parts.appendSlice(allocator, part) catch {};
                }
            } else {
                if (other_vendors.items.len > 0) other_vendors.appendSlice(allocator, ",") catch {};
                other_vendors.appendSlice(allocator, vendor) catch {};
            }
        }
    }

    // Build result: ot=[existing_subkeys;]th:VALUE[,other_vendors]
    var result: std.ArrayListUnmanaged(u8) = .empty;
    result.appendSlice(allocator, "ot=") catch {};
    if (ot_parts.items.len > 0) {
        result.appendSlice(allocator, ot_parts.items) catch {};
        result.appendSlice(allocator, ";") catch {};
    }
    result.appendSlice(allocator, "th:") catch {};
    result.appendSlice(allocator, th_value) catch {};
    if (other_vendors.items.len > 0) {
        result.appendSlice(allocator, ",") catch {};
        result.appendSlice(allocator, other_vendors.items) catch {};
    }
    return result.items;
}

/// Result of filtering traces in-place
const FilterCounts = struct {
    was_transformed: bool,
    original_count: usize,
    dropped_count: usize,
};

/// Filter spans in-place within the TracesData structure
/// This is the shared filtering logic used by both JSON and protobuf processing
///
/// Sampling and tracestate updates are handled by the policy engine via
/// the field mutator callback (mergeOTTracestate).
fn filterSpansInPlace(
    allocator: std.mem.Allocator,
    traces_data: *TracesData,
    registry: *const PolicyRegistry,
    bus: *EventBus,
) FilterCounts {
    const engine = PolicyEngine.init(bus, @constCast(registry));

    var original_count: usize = 0;
    var dropped_count: usize = 0;
    var was_transformed: bool = false;

    // Buffer for matched policy IDs (stack allocated)
    var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;

    // Iterate through the nested structure and filter spans in place
    // Structure: TracesData -> ResourceSpans[] -> ScopeSpans[] -> Span[]
    for (traces_data.resource_spans.items) |*resource_spans| {
        for (resource_spans.scope_spans.items) |*scope_spans| {
            // Count original spans
            original_count += scope_spans.spans.items.len;

            // Filter spans in place by shrinking the list
            var write_idx: usize = 0;
            for (scope_spans.spans.items) |*span| {
                var ctx = OtlpSpanContext{
                    .span = span,
                    .resource_spans = resource_spans,
                    .scope_spans = scope_spans,
                    .allocator = allocator,
                };

                const result = engine.evaluate(.trace, &ctx, otlpSpanFieldAccessor, otlpSpanFieldMutator, &policy_id_buf);

                if (result.was_transformed) {
                    was_transformed = true;
                }

                if (result.decision.shouldContinue()) {
                    // Keep this span - move to write position if needed
                    if (write_idx != scope_spans.spans.items.len - 1) {
                        scope_spans.spans.items[write_idx] = span.*;
                    }

                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_spans.spans.shrinkRetainingCapacity(write_idx);
        }

        // Prune empty scope containers
        var scope_write_idx: usize = 0;
        for (resource_spans.scope_spans.items) |scope_spans_item| {
            if (scope_spans_item.spans.items.len > 0) {
                resource_spans.scope_spans.items[scope_write_idx] = scope_spans_item;
                scope_write_idx += 1;
            }
        }
        resource_spans.scope_spans.shrinkRetainingCapacity(scope_write_idx);
    }

    // Prune empty resource containers
    var resource_write_idx: usize = 0;
    for (traces_data.resource_spans.items) |resource_spans_item| {
        if (resource_spans_item.scope_spans.items.len > 0) {
            traces_data.resource_spans.items[resource_write_idx] = resource_spans_item;
            resource_write_idx += 1;
        }
    }
    traces_data.resource_spans.shrinkRetainingCapacity(resource_write_idx);

    return .{
        .original_count = original_count,
        .dropped_count = dropped_count,
        .was_transformed = was_transformed,
    };
}

fn processJsonTraces(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Parse JSON into TracesData protobuf struct
    proto.protobuf.json.pb_options.emit_oneof_field_name = false;
    var parsed = try TracesData.jsonDecode(data, .{
        .ignore_unknown_fields = true,
    }, allocator);
    defer parsed.deinit();

    // Filter spans in-place (allocator used for tracestate updates)
    const counts = filterSpansInPlace(allocator, &parsed.value, registry, bus);

    // Re-serialize to JSON
    const output = try parsed.value.jsonEncode(.{}, allocator);

    return .{
        .data = @constCast(output),
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
        .was_transformed = counts.was_transformed,
    };
}

fn processProtobufTraces(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
) !ProcessResult {
    // Basic validation
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON - this would cause protobuf decoder to fail
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Use an arena for the protobuf decode/filter/encode cycle
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into TracesData struct using arena
    var traces_data = try TracesData.decode(&reader, arena_alloc);

    // Filter spans in-place (arena_alloc used for tracestate updates)
    const counts = filterSpansInPlace(arena_alloc, &traces_data, registry, bus);

    // Re-serialize to protobuf - use main allocator for output since we return it
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    errdefer output_writer.deinit();

    try traces_data.encode(&output_writer.writer, arena_alloc);

    // Transfer ownership of the written data to caller
    const output = try output_writer.toOwnedSlice();

    return .{
        .data = output,
        .dropped_count = counts.dropped_count,
        .original_count = counts.original_count,
        .was_transformed = counts.was_transformed,
    };
}

// =============================================================================
// Tests
// =============================================================================

// =============================================================================
// mergeOTTracestate tests
// =============================================================================

test "mergeOTTracestate - empty tracestate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8", mergeOTTracestate(arena.allocator(), "", "8"));
}

test "mergeOTTracestate - empty tracestate with zero threshold" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0", mergeOTTracestate(arena.allocator(), "", "0"));
}

test "mergeOTTracestate - empty tracestate with multi-char threshold" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:abc123", mergeOTTracestate(arena.allocator(), "", "abc123"));
}

test "mergeOTTracestate - single vendor preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0,vendor1=abc", mergeOTTracestate(arena.allocator(), "vendor1=abc", "0"));
}

test "mergeOTTracestate - multiple vendors preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0,vendor1=abc,vendor2=xyz", mergeOTTracestate(arena.allocator(), "vendor1=abc,vendor2=xyz", "0"));
}

test "mergeOTTracestate - existing ot=th replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8", mergeOTTracestate(arena.allocator(), "ot=th:4", "8"));
}

test "mergeOTTracestate - existing ot=th:0 replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8", mergeOTTracestate(arena.allocator(), "ot=th:0", "8"));
}

test "mergeOTTracestate - existing ot with rv preserved, th replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc123;th:8", mergeOTTracestate(arena.allocator(), "ot=th:4;rv:abc123", "8"));
}

test "mergeOTTracestate - existing ot with rv only, th added" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc123;th:8", mergeOTTracestate(arena.allocator(), "ot=rv:abc123", "8"));
}

test "mergeOTTracestate - existing ot=th with vendor preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8,vendor=xyz", mergeOTTracestate(arena.allocator(), "ot=th:c,vendor=xyz", "8"));
}

test "mergeOTTracestate - ot with rv and vendor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc;th:8,vendor=xyz", mergeOTTracestate(arena.allocator(), "ot=rv:abc;th:4,vendor=xyz", "8"));
}

test "mergeOTTracestate - vendor before ot entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8,vendor1=abc", mergeOTTracestate(arena.allocator(), "vendor1=abc,ot=th:4", "8"));
}

test "mergeOTTracestate - vendor before and after ot entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:8,v1=a,v2=b", mergeOTTracestate(arena.allocator(), "v1=a,ot=th:4,v2=b", "8"));
}

test "mergeOTTracestate - multiple ot sub-keys preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc;p:8;th:8", mergeOTTracestate(arena.allocator(), "ot=rv:abc;p:8;th:4", "8"));
}

test "mergeOTTracestate - whitespace in vendors trimmed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0,vendor1=abc,vendor2=xyz", mergeOTTracestate(arena.allocator(), " vendor1=abc , vendor2=xyz ", "0"));
}

test "mergeOTTracestate - whitespace in ot sub-keys trimmed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc;th:8", mergeOTTracestate(arena.allocator(), "ot= rv:abc ; th:4 ", "8"));
}

test "mergeOTTracestate - empty vendors between commas ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0,vendor1=abc,vendor2=xyz", mergeOTTracestate(arena.allocator(), "vendor1=abc,,vendor2=xyz", "0"));
}

test "mergeOTTracestate - empty ot sub-keys between semicolons ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=rv:abc;th:8", mergeOTTracestate(arena.allocator(), "ot=rv:abc;;th:4", "8"));
}

test "mergeOTTracestate - ot entry with only th" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("ot=th:0", mergeOTTracestate(arena.allocator(), "ot=th:ffff", "0"));
}

test "processTraces - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const traces =
        \\{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"test-service"}}]},"scopeSpans":[{"scope":{"name":"my-tracer","version":"1.0"},"spans":[{"traceId":"0123456789abcdef0123456789abcdef","spanId":"0123456789abcdef","name":"test-span","kind":1,"startTimeUnixNano":"1000000000","endTimeUnixNano":"2000000000"}]}]}]}
    ;

    const result = try processTraces(allocator, &registry, noop_bus.eventBus(), traces, "application/json");
    defer allocator.free(result.data);

    try std.testing.expect(std.mem.indexOf(u8, result.data, "test-span") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.data, "resourceSpans") != null);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processTraces - malformed JSON returns unchanged (fail-open)" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ invalid json }";

    const result = try processTraces(allocator, &registry, noop_bus.eventBus(), malformed, "application/json");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(malformed, result.data);
    try std.testing.expectEqual(@as(usize, 0), result.dropped_count);
}

test "processTraces - unknown content type returns unchanged" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const data = "some data";

    const result = try processTraces(allocator, &registry, noop_bus.eventBus(), data, "text/plain");
    defer allocator.free(result.data);

    try std.testing.expectEqualStrings(data, result.data);
}
