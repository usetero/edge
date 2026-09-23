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
const stream_io = @import("../stream_io.zig");
const proto = @import("proto");
const policy = @import("policy_zig");
const o11y = @import("o11y");
const otlp_attr = @import("attributes.zig");
const common = @import("common.zig");

const log = std.log.scoped(.otlp_traces);

const TracesData = proto.trace.TracesData;
const ResourceSpans = proto.trace.ResourceSpans;
const ScopeSpans = proto.trace.ScopeSpans;
const Span = proto.trace.Span;

const PolicyEngine = policy.PolicyEngine;
pub const TraceFieldRef = policy.TraceFieldRef;
const MAX_MATCHES_PER_SCAN = policy.max_matches_per_scan;
const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const NoopEventBus = o11y.NoopEventBus;

// =============================================================================
// Public API
// =============================================================================

pub const Format = common.Format;
pub const StreamProcessResult = common.StreamProcessResult;

/// Apply trace policies to an OTLP traces body (JSON or protobuf) and write the result to out_writer.
pub fn processTracesStream(
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
        .json => processJsonTraces(allocator, registry, bus, data, out_writer),
        .protobuf => processProtobufTraces(allocator, registry, bus, data, out_writer),
    };
}

// =============================================================================
// Internal Implementation
// =============================================================================

/// Context for OTLP span field accessor - provides access to span plus parent context.
pub const OtlpSpanContext = struct {
    span: *Span,
    resource_spans: *ResourceSpans,
    scope_spans: *ScopeSpans,
    allocator: std.mem.Allocator,
};

const findNestedAttribute = otlp_attr.findNestedAttribute;

/// String view of a trace field. `traceTypedValue` reads the identifier and
/// attribute fields itself, so those arms return null.
pub fn traceValue(ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8 {
    const span_ctx: *const OtlpSpanContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => span_ctx.span.name,
            .TRACE_FIELD_TRACE_STATE => span_ctx.span.trace_state,
            .TRACE_FIELD_RESOURCE_SCHEMA_URL => span_ctx.resource_spans.schema_url,
            .TRACE_FIELD_SCOPE_SCHEMA_URL => span_ctx.scope_spans.schema_url,
            .TRACE_FIELD_SCOPE_NAME => if (span_ctx.scope_spans.scope) |scope| scope.name else null,
            .TRACE_FIELD_SCOPE_VERSION => if (span_ctx.scope_spans.scope) |scope| scope.version else null,
            else => null,
        },
        .span_attribute, .resource_attribute, .scope_attribute => null,
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
        .link_trace_id => blk: {
            // Return the first linked trace_id as lowercase hex.
            if (span_ctx.span.links.items.len == 0) break :blk null;
            const link_id = span_ctx.span.links.items[0].trace_id;
            if (link_id.len != 16) break :blk null;
            const S = struct {
                threadlocal var buf: [32]u8 = undefined;
            };
            S.buf = std.fmt.bytesToHex(link_id[0..16].*, .lower);
            break :blk &S.buf;
        },
    };
}

/// Typed-value accessor for the OTLP trace context. The policy engine uses
/// it for all matchers and for probabilistic sampling. Identifier fields
/// (trace_id/span_id/parent_span_id) read as raw `TypedValue.bytes`.
/// Attributes keep their scalar type. All other fields read as non-empty
/// strings.
pub fn traceTypedValue(ctx: *const anyopaque, field: TraceFieldRef) ?policy.TypedValue {
    const span_ctx: *const OtlpSpanContext = @ptrCast(@alignCast(ctx));
    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_TRACE_ID => otlp_attr.typedBytes(span_ctx.span.trace_id),
            .TRACE_FIELD_SPAN_ID => otlp_attr.typedBytes(span_ctx.span.span_id),
            .TRACE_FIELD_PARENT_SPAN_ID => otlp_attr.typedBytes(span_ctx.span.parent_span_id),
            else => otlp_attr.typedStr(traceValue(ctx, field)),
        },
        .span_attribute => |attr_path| otlp_attr.findNestedAttributeTyped(
            span_ctx.span.attributes.items,
            attr_path.path.items,
        ),
        .resource_attribute => |attr_path| if (span_ctx.resource_spans.resource) |res|
            otlp_attr.findNestedAttributeTyped(res.attributes.items, attr_path.path.items)
        else
            null,
        .scope_attribute => |attr_path| if (span_ctx.scope_spans.scope) |scope|
            otlp_attr.findNestedAttributeTyped(scope.attributes.items, attr_path.path.items)
        else
            null,
        else => otlp_attr.typedStr(traceValue(ctx, field)),
    };
}

/// Field setter for OTLP trace format. The engine only writes
/// `TRACE_FIELD_TRACE_STATE` (the sampling threshold writeback); we merge
/// the raw hex value into the W3C tracestate as `ot=th:VALUE`.
pub fn traceSet(ctx: *anyopaque, field: TraceFieldRef, value: []const u8) void {
    const span_ctx: *OtlpSpanContext = @ptrCast(@alignCast(ctx));
    switch (field) {
        .trace_field => |tf| if (tf == .TRACE_FIELD_TRACE_STATE) {
            // On allocation failure, keep the original tracestate rather than
            // writing a partially-built (corrupt) value.
            const merged = mergeOtTracestate(
                span_ctx.allocator,
                span_ctx.span.trace_state,
                value,
            ) catch |err| {
                log.warn("traceSet: failed to merge tracestate, keeping original: {}", .{err});
                return;
            };
            span_ctx.span.trace_state = merged;
        },
        else => {},
    }
}

/// TraceAccessor template wiring the OTLP trace primitives.
pub const trace_accessor: policy.TraceAccessor = .{
    .typed_value = traceTypedValue,
    .set = traceSet,
};

/// Merge a sampling threshold into W3C tracestate as ot=th:VALUE.
/// Preserves existing vendor entries and other ot sub-keys (like rv).
fn mergeOtTracestate(allocator: std.mem.Allocator, tracestate: []const u8, th_value: []const u8) ![]const u8 {
    var ot_parts: std.ArrayList(u8) = .empty;
    defer ot_parts.deinit(allocator);
    var other_vendors: std.ArrayList(u8) = .empty;
    defer other_vendors.deinit(allocator);

    // The W3C Trace Context spec (section 3.3.1.1/3.3.1.2) caps a `tracestate`
    // list at 32 list-members. The `ot=...` member we always emit counts as 1,
    // so at most 31 other-vendor members may be carried through. Non-th `ot=`
    // sub-keys (rv:, p:, ...) live inside the single `ot=` member and do not
    // add list-members, so they are preserved without counting against the cap.
    var entry_count: usize = 1;

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
                    if (ot_parts.items.len > 0) try ot_parts.appendSlice(allocator, ";");
                    try ot_parts.appendSlice(allocator, part);
                }
            } else {
                // Enforce the W3C 32-member cap, dropping the least-recent
                // (rightmost) vendor entries once it is reached.
                if (entry_count >= 32) break;
                if (other_vendors.items.len > 0) try other_vendors.appendSlice(allocator, ",");
                try other_vendors.appendSlice(allocator, vendor);
                entry_count += 1;
            }
        }
    }

    // Build result: ot=[existing_subkeys;]th:VALUE[,other_vendors]
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);
    try result.appendSlice(allocator, "ot=");
    if (ot_parts.items.len > 0) {
        try result.appendSlice(allocator, ot_parts.items);
        try result.appendSlice(allocator, ";");
    }
    try result.appendSlice(allocator, "th:");
    try result.appendSlice(allocator, th_value);
    if (other_vendors.items.len > 0) {
        try result.appendSlice(allocator, ",");
        try result.appendSlice(allocator, other_vendors.items);
    }
    return result.toOwnedSlice(allocator);
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
/// the field mutator callback (mergeOtTracestate).
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
                var ctx: OtlpSpanContext = .{
                    .span = span,
                    .resource_spans = resource_spans,
                    .scope_spans = scope_spans,
                    .allocator = allocator,
                };

                const result = engine.evaluate(.trace, &trace_accessor, &ctx, &policy_id_buf, .{ .io = bus.io });

                if (result.was_transformed) {
                    was_transformed = true;
                }

                if (result.decision.shouldContinue()) {
                    scope_spans.spans.items[write_idx] = span.*;
                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_spans.spans.shrinkRetainingCapacity(write_idx);
        }

        common.pruneEmpty(&resource_spans.scope_spans, "spans");
    }

    common.pruneEmpty(&traces_data.resource_spans, "scope_spans");

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
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // OTLP/JSON hex-encodes only the id fields. In memory the ids are raw
    // bytes, as on the protobuf path.
    var parsed = try TracesData.jsonDecodeOpts(data, .{
        .ignore_unknown_fields = true,
    }, .{ .hex_bytes_fields = otlp_attr.hex_id_fields }, allocator);
    defer parsed.deinit();

    // Filter spans in-place (allocator used for tracestate updates).
    const counts = filterSpansInPlace(allocator, &parsed.value, registry, bus);

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

fn processProtobufTraces(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    data: []const u8,
    out_writer: *std.Io.Writer,
) !StreamProcessResult {
    // Basic validation
    if (data.len == 0) {
        return error.EmptyProtobufData;
    }

    // Check if data looks like JSON - this would cause protobuf decoder to fail
    if (data[0] == '{' or data[0] == '[') {
        return error.DataLooksLikeJson;
    }

    // Fast path: if no trace policies, skip decode/encode entirely.
    const snapshot = registry.getSnapshot();
    if (snapshot == null or snapshot.?.trace_index.isEmpty()) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = 0 };
    }

    // Use an arena for the protobuf decode/filter/encode cycle
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    // Create a fixed reader from the protobuf data
    var reader = std.Io.Reader.fixed(data);

    // Decode protobuf into TracesData struct using arena
    var traces_data = try TracesData.decode(&reader, arena_alloc);

    // Filter spans in-place (arena_alloc used for tracestate updates).
    const counts = filterSpansInPlace(arena_alloc, &traces_data, registry, bus);

    // Return the input bytes when nothing changed. A re-encode drops fields
    // the schema does not know.
    if (counts.dropped_count == 0 and !counts.was_transformed) {
        try out_writer.writeAll(data);
        return .{ .dropped_count = 0, .original_count = counts.original_count };
    }

    // Encode into a buffer first, so an encode error writes nothing.
    var output_writer = std.Io.Writer.Allocating.init(allocator);
    defer output_writer.deinit();
    try traces_data.encode(&output_writer.writer, arena_alloc);
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

fn runTraces(
    allocator: std.mem.Allocator,
    registry: *const PolicyRegistry,
    bus: *EventBus,
    input: []const u8,
    format: Format,
) !common.TestRun {
    var in_reader = std.Io.Reader.fixed(input);
    var out_writer: std.Io.Writer.Allocating = .init(allocator);
    defer out_writer.deinit();
    const result = try processTracesStream(allocator, registry, bus, &in_reader, &out_writer.writer, format);
    return .{ .data = try out_writer.toOwnedSlice(), .result = result };
}

// =============================================================================
// mergeOtTracestate tests
// =============================================================================

test "mergeOtTracestate - empty tracestate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8",
        try mergeOtTracestate(arena.allocator(), "", "8"),
    );
}

test "mergeOtTracestate - empty tracestate with zero threshold" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0",
        try mergeOtTracestate(arena.allocator(), "", "0"),
    );
}

test "mergeOtTracestate - empty tracestate with multi-char threshold" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:abc123",
        try mergeOtTracestate(arena.allocator(), "", "abc123"),
    );
}

test "mergeOtTracestate - single vendor preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0,vendor1=abc",
        try mergeOtTracestate(arena.allocator(), "vendor1=abc", "0"),
    );
}

test "mergeOtTracestate - multiple vendors preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0,vendor1=abc,vendor2=xyz",
        try mergeOtTracestate(arena.allocator(), "vendor1=abc,vendor2=xyz", "0"),
    );
}

test "mergeOtTracestate - existing ot=th replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8",
        try mergeOtTracestate(arena.allocator(), "ot=th:4", "8"),
    );
}

test "mergeOtTracestate - existing ot=th:0 replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8",
        try mergeOtTracestate(arena.allocator(), "ot=th:0", "8"),
    );
}

test "mergeOtTracestate - existing ot with rv preserved, th replaced" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc123;th:8",
        try mergeOtTracestate(arena.allocator(), "ot=th:4;rv:abc123", "8"),
    );
}

test "mergeOtTracestate - existing ot with rv only, th added" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc123;th:8",
        try mergeOtTracestate(arena.allocator(), "ot=rv:abc123", "8"),
    );
}

test "mergeOtTracestate - existing ot=th with vendor preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8,vendor=xyz",
        try mergeOtTracestate(arena.allocator(), "ot=th:c,vendor=xyz", "8"),
    );
}

test "mergeOtTracestate - ot with rv and vendor" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc;th:8,vendor=xyz",
        try mergeOtTracestate(arena.allocator(), "ot=rv:abc;th:4,vendor=xyz", "8"),
    );
}

test "mergeOtTracestate - vendor before ot entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8,vendor1=abc",
        try mergeOtTracestate(arena.allocator(), "vendor1=abc,ot=th:4", "8"),
    );
}

test "mergeOtTracestate - vendor before and after ot entry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:8,v1=a,v2=b",
        try mergeOtTracestate(arena.allocator(), "v1=a,ot=th:4,v2=b", "8"),
    );
}

test "mergeOtTracestate - multiple ot sub-keys preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc;p:8;th:8",
        try mergeOtTracestate(arena.allocator(), "ot=rv:abc;p:8;th:4", "8"),
    );
}

test "mergeOtTracestate - whitespace in vendors trimmed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0,vendor1=abc,vendor2=xyz",
        try mergeOtTracestate(arena.allocator(), " vendor1=abc , vendor2=xyz ", "0"),
    );
}

test "mergeOtTracestate - whitespace in ot sub-keys trimmed" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc;th:8",
        try mergeOtTracestate(arena.allocator(), "ot= rv:abc ; th:4 ", "8"),
    );
}

test "mergeOtTracestate - empty vendors between commas ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0,vendor1=abc,vendor2=xyz",
        try mergeOtTracestate(arena.allocator(), "vendor1=abc,,vendor2=xyz", "0"),
    );
}

test "mergeOtTracestate - empty ot sub-keys between semicolons ignored" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=rv:abc;th:8",
        try mergeOtTracestate(arena.allocator(), "ot=rv:abc;;th:4", "8"),
    );
}

test "mergeOtTracestate - ot entry with only th" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings(
        "ot=th:0",
        try mergeOtTracestate(arena.allocator(), "ot=th:ffff", "0"),
    );
}

// =============================================================================
// mergeOtTracestate: W3C 32-member limit
// =============================================================================

// Build a `count`-member vendor-only tracestate ("v0=x,v1=x,...") into `buf`.
fn buildVendorTracestate(buf: []u8, count: usize) ![]const u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        if (pos > 0) {
            buf[pos] = ',';
            pos += 1;
        }
        const tag = try std.fmt.bufPrint(buf[pos..], "v{d}=x", .{i});
        pos += tag.len;
    }
    return buf[0..pos];
}

// Count W3C tracestate list-members (comma-separated). Empty == 0.
fn listMemberCount(tracestate: []const u8) usize {
    if (tracestate.len == 0) return 0;
    return std.mem.count(u8, tracestate, ",") + 1;
}

// A W3C-compliant 32-member vendor-only tracestate (the maximum allowed by
// section 3.3.1.1/3.3.1.2) must NOT grow to 33 members after the `ot=th:` member
// is prepended. The least-recent (rightmost) vendor is dropped to stay at 32.
test "mergeOtTracestate - 32 vendors capped at W3C 32-member limit" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var ts_buf: [4096]u8 = undefined;
    const trace_state = try buildVendorTracestate(&ts_buf, 32);
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(trace_state));

    const out = try mergeOtTracestate(arena.allocator(), trace_state, "0");
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(out));
    try std.testing.expect(std.mem.startsWith(u8, out, "ot=th:0,"));
    try std.testing.expect(std.mem.indexOf(u8, out, "v0=x") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "v30=x") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "v31=x") == null);
}

// The W3C boundary at exactly 31 other vendors: ot= + 31 = 32 members, all
// preserved (no truncation because the cap is reached only by the next append).
test "mergeOtTracestate - 31 vendors stays within cap, all preserved" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var ts_buf: [4096]u8 = undefined;
    const trace_state = try buildVendorTracestate(&ts_buf, 31);

    const out = try mergeOtTracestate(arena.allocator(), trace_state, "0");
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(out));
    try std.testing.expect(std.mem.startsWith(u8, out, "ot=th:0,"));
    try std.testing.expect(std.mem.indexOf(u8, out, "v0=x") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "v30=x") != null);
}

// The cap counts list-members only. The rv: sub-key inside ot= must stay.
test "mergeOtTracestate - ot sub-keys preserved when vendor cap reached" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var ts_buf: [4096]u8 = undefined;
    const vendors = try buildVendorTracestate(&ts_buf, 32); // over the cap once ot= counts
    var ts_full_buf: [8192]u8 = undefined;
    const trace_state = try std.fmt.bufPrint(&ts_full_buf, "ot=rv:abc,{s}", .{vendors});
    try std.testing.expectEqual(@as(usize, 33), listMemberCount(trace_state));

    const out = try mergeOtTracestate(arena.allocator(), trace_state, "8");
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(out));
    try std.testing.expect(std.mem.indexOf(u8, out, "ot=rv:abc;th:8") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "v30=x") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "v31=x") == null);
}

test "processTraces - parses and re-serializes JSON" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const traces =
        "{\"resourceSpans\":[{\"resource\":{\"attributes\":[" ++
        "{\"key\":\"service.name\",\"value\":{\"stringValue\":\"test-service\"}}]}," ++
        "\"scopeSpans\":[{\"scope\":{\"name\":\"my-tracer\",\"version\":\"1.0\"}," ++
        "\"spans\":[{\"traceId\":\"0123456789abcdef0123456789abcdef\"," ++
        "\"spanId\":\"0123456789abcdef\",\"name\":\"test-span\",\"kind\":1," ++
        "\"startTimeUnixNano\":\"1000000000\",\"endTimeUnixNano\":\"2000000000\"}]}]}]}";

    const run = try runTraces(allocator, &registry, noop_bus.eventBus(), traces, .json);
    defer allocator.free(run.data);

    try std.testing.expect(std.mem.indexOf(u8, run.data, "test-span") != null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "resourceSpans") != null);
    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
}

test "traceTypedValue: trace_id reads as raw bytes so the engine can hex-render for matching" {
    const allocator = std.testing.allocator;
    const raw_id = [16]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

    var rs: ResourceSpans = .{};
    var ss: ScopeSpans = .{};

    var span_raw: Span = .{ .trace_id = &raw_id };
    var ctx_raw: OtlpSpanContext = .{
        .span = &span_raw,
        .resource_spans = &rs,
        .scope_spans = &ss,
        .allocator = allocator,
    };
    const raw_got = traceTypedValue(&ctx_raw, .{ .trace_field = .TRACE_FIELD_TRACE_ID }).?.bytes;
    try std.testing.expectEqualSlices(u8, &raw_id, raw_got);
}

test "processTraces - malformed JSON returns an error" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    const malformed = "{ invalid json }";
    try std.testing.expect(std.meta.isError(runTraces(allocator, &registry, noop_bus.eventBus(), malformed, .json)));
}

// =============================================================================
// processTracesStream: tracestate writeback W3C 32-member limit (E2E)
// =============================================================================

// Send a 32-member vendor-only traceState through the JSON path under a
// 100%-keep policy. The writeback adds ot=th:0. The output must stay at the
// W3C limit of 32 members.
test "processTraces - 100%-keep writeback keeps traceState within W3C 32-member limit" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(a, noop_bus.eventBus());
    defer registry.deinit();

    var pol: proto.policy.Policy = .{
        .id = try a.dupe(u8, "trace-keep-100"),
        .name = try a.dupe(u8, "keep-100"),
        .enabled = true,
        .target = .{ .trace = .{ .keep = .{ .percentage = 100.0 } } },
    };
    try pol.target.?.trace.match.append(a, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try a.dupe(u8, ".+") },
    });
    try registry.updatePolicies(&.{pol}, "test", .file);

    // 32 vendor entries (W3C max), no `ot=` entry.
    var ts_buf: [4096]u8 = undefined;
    const trace_state_in = try buildVendorTracestate(&ts_buf, 32);
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(trace_state_in));

    var traces_buf: [8192]u8 = undefined;
    const prefix = "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[" ++
        "{\"traceId\":\"0123456789abcdef0123456789abcdef\"," ++
        "\"spanId\":\"0123456789abcdef\",\"name\":\"test-span\",\"kind\":1," ++
        "\"startTimeUnixNano\":\"1000000000\",\"endTimeUnixNano\":\"2000000000\"," ++
        "\"traceState\":\"";
    const suffix = "\"}]}]}]}";
    @memcpy(traces_buf[0..prefix.len], prefix);
    @memcpy(traces_buf[prefix.len..][0..trace_state_in.len], trace_state_in);
    @memcpy(traces_buf[prefix.len + trace_state_in.len ..][0..suffix.len], suffix);
    const traces = traces_buf[0 .. prefix.len + trace_state_in.len + suffix.len];

    // Use the arena for the stream. The merged trace_state is a separate
    // allocation that the JSON encoder only references. The arena frees it.
    var in_reader = std.Io.Reader.fixed(traces);
    var out_writer: std.Io.Writer.Allocating = .init(a);
    const stream_result = try processTracesStream(
        a,
        &registry,
        noop_bus.eventBus(),
        &in_reader,
        &out_writer.writer,
        .json,
    );
    const out = try out_writer.toOwnedSlice();

    const ts_key = "\"traceState\":\"";
    const ts_start = std.mem.indexOf(u8, out, ts_key).? + ts_key.len;
    const ts_end = std.mem.indexOfScalarPos(u8, out, ts_start, '"').?;
    const trace_state_out = out[ts_start..ts_end];

    try std.testing.expect(stream_result.was_transformed); // writeback fired
    try std.testing.expectEqual(@as(usize, 32), listMemberCount(trace_state_out)); // W3C cap honored
    try std.testing.expect(std.mem.startsWith(u8, trace_state_out, "ot=th:0,"));
    try std.testing.expect(std.mem.indexOf(u8, trace_state_out, "v31=x") == null);
}

/// Builds a trace policy that keeps 100% of matching spans but never matches
/// (regex is a literal that no span name will contain). Using a loaded-but-
/// non-matching policy exercises the decode → filterSpansInPlace → guard path
/// without dropping or transforming any span.
fn loadNoMatchTracePolicy(allocator: std.mem.Allocator, registry: *PolicyRegistry) !void {
    var no_match_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "no-match"),
        .name = try allocator.dupe(u8, "no-match"),
        .enabled = true,
        .target = .{ .trace = .{ .keep = .{ .percentage = 100 } } },
    };
    try no_match_policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "zzz-never-matches-zzz") },
    });
    defer no_match_policy.deinit(allocator);
    try registry.updatePolicies(&.{no_match_policy}, "file-provider", .file);
}

test "processJsonTraces preserves unknown span fields when policies don't match" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try loadNoMatchTracePolicy(allocator, &registry);

    const traces =
        "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"traceId\":\"0123456789abcdef0123456789abcdef\"," ++
        "\"spanId\":\"0123456789abcdef\",\"name\":\"span-1\",\"kind\":1," ++
        "\"startTimeUnixNano\":\"1000000000\",\"endTimeUnixNano\":\"2000000000\"," ++
        "\"futureOtelField\":42}]}]}]}";

    const run = try runTraces(allocator, &registry, noop_bus.eventBus(), traces, .json);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
    // Nothing modified → original bytes returned verbatim, unknown field intact.
    try std.testing.expectEqualStrings(traces, run.data);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "futureOtelField") != null);
}

test "processProtobufTraces preserves unknown span fields when policies don't match" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();
    try loadNoMatchTracePolicy(allocator, &registry);

    // Hand-encoded TracesData: one ResourceSpans > ScopeSpans > Span with
    // trace_id="abcd" (field 1, LEN 4) + unknown field 999 (varint 42). The
    // generated Span struct has no _unknown_fields, so a re-encode would drop
    // the (184, 62, 42) bytes; the nothing-modified guard must return the
    // original bytes so the unknown field survives.
    const td = [_]u8{ 10, 13, 18, 11, 18, 9, 10, 4, 97, 98, 99, 100, 184, 62, 42 };

    const run = try runTraces(allocator, &registry, noop_bus.eventBus(), &td, .protobuf);
    defer allocator.free(run.data);

    try std.testing.expectEqual(@as(usize, 0), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 1), run.result.original_count);
    try std.testing.expect(!run.result.wasModified());
    // Nothing modified → original bytes returned verbatim, unknown field intact.
    try std.testing.expectEqualSlices(u8, &td, run.data);
    try std.testing.expect(std.mem.indexOf(u8, run.data, &[_]u8{ 184, 62 }) != null);
}

test "processJsonTraces still re-encodes and drops when a policy matches" {
    const allocator = std.testing.allocator;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = PolicyRegistry.init(allocator, noop_bus.eventBus());
    defer registry.deinit();

    // percentage = 0 → keep none → every matching span is dropped (deterministic).
    var drop_policy: proto.policy.Policy = .{
        .id = try allocator.dupe(u8, "drop-by-name"),
        .name = try allocator.dupe(u8, "drop-by-name"),
        .enabled = true,
        .target = .{ .trace = .{ .keep = .{ .percentage = 0 } } },
    };
    try drop_policy.target.?.trace.match.append(allocator, .{
        .field = .{ .trace_field = .TRACE_FIELD_NAME },
        .match = .{ .regex = try allocator.dupe(u8, "drop-me") },
    });
    defer drop_policy.deinit(allocator);
    try registry.updatePolicies(&.{drop_policy}, "file-provider", .file);

    const traces =
        "{\"resourceSpans\":[{\"scopeSpans\":[{\"spans\":[{\"traceId\":\"0123456789abcdef0123456789abcdef\"," ++
        "\"spanId\":\"0123456789abcdef\",\"name\":\"drop-me\",\"kind\":1," ++
        "\"startTimeUnixNano\":\"1000000000\",\"endTimeUnixNano\":\"2000000000\"}," ++
        "{\"traceId\":\"0123456789abcdef0123456789abcdef\",\"spanId\":\"fedcba9876543210\"," ++
        "\"name\":\"keep-me\",\"kind\":1,\"startTimeUnixNano\":\"1000000000\"," ++
        "\"endTimeUnixNano\":\"2000000000\"}]}]}]}";

    const run = try runTraces(allocator, &registry, noop_bus.eventBus(), traces, .json);
    defer allocator.free(run.data);

    // dropped_count > 0 → guard does not fire → re-encode runs.
    try std.testing.expectEqual(@as(usize, 1), run.result.dropped_count);
    try std.testing.expectEqual(@as(usize, 2), run.result.original_count);
    try std.testing.expect(run.result.wasModified());
    try std.testing.expect(std.mem.indexOf(u8, run.data, "drop-me") == null);
    try std.testing.expect(std.mem.indexOf(u8, run.data, "keep-me") != null);
}
