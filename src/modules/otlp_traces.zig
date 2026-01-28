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
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");

const TracesData = proto.trace.TracesData;
const ResourceSpans = proto.trace.ResourceSpans;
const ScopeSpans = proto.trace.ScopeSpans;
const Span = proto.trace.Span;
const SpanKind = proto.trace.SpanKind;
const StatusCode = proto.trace.StatusCode;
const Event = proto.trace.Event;
const Link = proto.trace.Link;
const KeyValue = proto.common.KeyValue;
const AnyValue = proto.common.AnyValue;

const PolicyEngine = policy.PolicyEngine;
const PolicyResult = policy.PolicyResult;
const FilterDecision = policy.FilterDecision;
const TraceFieldRef = policy.TraceFieldRef;
const TraceField = proto.policy.TraceField;
const PolicySpanKind = proto.policy.SpanKind;
const SpanStatusCode = proto.policy.SpanStatusCode;
const MAX_MATCHES_PER_SCAN = policy.MAX_MATCHES_PER_SCAN;
const PolicyRegistry = policy.Registry;
const PolicySnapshot = policy.Snapshot;
const trace_sampler = policy.trace_sampler;
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
    /// Whether any transformations were applied (not yet supported for traces)
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
};

/// Extract string value from an AnyValue
fn getAnyValueString(value: ?AnyValue) ?[]const u8 {
    const v = value orelse return null;
    const val_union = v.value orelse return null;
    return switch (val_union) {
        .string_value => |s| s,
        else => null,
    };
}

/// Find attribute value by key in a KeyValue list
fn findAttribute(attributes: []const KeyValue, key: []const u8) ?[]const u8 {
    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, key)) {
            return getAnyValueString(kv.value);
        }
    }
    return null;
}

/// Find nested attribute value by path in a KeyValue list
fn findNestedAttribute(attributes: []const KeyValue, path: []const []const u8) ?[]const u8 {
    if (path.len == 0) return null;

    for (attributes) |kv| {
        if (std.mem.eql(u8, kv.key, path[0])) {
            if (path.len == 1) {
                return getAnyValueString(kv.value);
            }
            const val = kv.value orelse return null;
            const inner = val.value orelse return null;
            switch (inner) {
                .kvlist_value => |kvlist| {
                    return findNestedAttribute(kvlist.values.items, path[1..]);
                },
                else => return null,
            }
        }
    }
    return null;
}

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

/// Convert span ID bytes to hex string (8 bytes -> 16 chars)
fn spanIdToHex(span_id: []const u8, buf: *[16]u8) ?[]const u8 {
    if (span_id.len != 8) return null;
    const hex_chars = "0123456789abcdef";
    for (span_id, 0..) |byte, i| {
        buf[i * 2] = hex_chars[byte >> 4];
        buf[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return buf[0..16];
}

/// Get span kind as string for regex matching
fn spanKindToString(kind: SpanKind) ?[]const u8 {
    return switch (kind) {
        .SPAN_KIND_UNSPECIFIED => "unspecified",
        .SPAN_KIND_INTERNAL => "internal",
        .SPAN_KIND_SERVER => "server",
        .SPAN_KIND_CLIENT => "client",
        .SPAN_KIND_PRODUCER => "producer",
        .SPAN_KIND_CONSUMER => "consumer",
        _ => null,
    };
}

/// Get span status code as string for regex matching
fn statusCodeToString(code: StatusCode) ?[]const u8 {
    return switch (code) {
        .STATUS_CODE_UNSET => "unset",
        .STATUS_CODE_OK => "ok",
        .STATUS_CODE_ERROR => "error",
        _ => null,
    };
}

/// Field accessor for OTLP trace format
/// Maps TraceFieldRef to the appropriate field in the OTLP span structure
fn otlpSpanFieldAccessor(ctx: *const anyopaque, field: TraceFieldRef) ?[]const u8 {
    const span_ctx: *const OtlpSpanContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .trace_field => |tf| switch (tf) {
            .TRACE_FIELD_NAME => if (span_ctx.span.name.len > 0) span_ctx.span.name else null,
            .TRACE_FIELD_TRACE_ID => blk: {
                // Return hex-encoded trace_id - use thread-local buffer
                const S = struct {
                    threadlocal var buf: [32]u8 = undefined;
                };
                break :blk traceIdToHex(span_ctx.span.trace_id, &S.buf);
            },
            .TRACE_FIELD_SPAN_ID => blk: {
                const S = struct {
                    threadlocal var buf: [16]u8 = undefined;
                };
                break :blk spanIdToHex(span_ctx.span.span_id, &S.buf);
            },
            .TRACE_FIELD_PARENT_SPAN_ID => blk: {
                if (span_ctx.span.parent_span_id.len == 0) break :blk null;
                const S = struct {
                    threadlocal var buf: [16]u8 = undefined;
                };
                break :blk spanIdToHex(span_ctx.span.parent_span_id, &S.buf);
            },
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
        .span_kind => |_| spanKindToString(span_ctx.span.kind),
        .span_status => |_| if (span_ctx.span.status) |status| statusCodeToString(status.code) else null,
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
/// Currently only supports drop decision (keep=false), no transforms
fn otlpSpanFieldMutator(_: *anyopaque, _: TraceMutateOp) bool {
    // Trace transforms not yet implemented for OTLP
    return false;
}

/// Result of filtering traces in-place
const FilterCounts = struct {
    original_count: usize,
    dropped_count: usize,
};

/// Filter spans in-place within the TracesData structure
/// This is the shared filtering logic used by both JSON and protobuf processing
///
/// When sampling is applied (percentage < 100), updates the span's tracestate
/// with the sampling threshold following OTel probability sampling spec.
fn filterSpansInPlace(
    allocator: std.mem.Allocator,
    traces_data: *TracesData,
    registry: *const PolicyRegistry,
    bus: *EventBus,
) FilterCounts {
    const engine = PolicyEngine.init(bus, @constCast(registry));
    const snapshot = registry.getSnapshot();

    var original_count: usize = 0;
    var dropped_count: usize = 0;

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
                };

                const result = engine.evaluate(.trace, &ctx, otlpSpanFieldAccessor, otlpSpanFieldMutator, &policy_id_buf);

                if (result.decision.shouldContinue()) {
                    // Keep this span - move to write position if needed
                    if (write_idx != scope_spans.spans.items.len - 1) {
                        scope_spans.spans.items[write_idx] = span.*;
                    }

                    // Update tracestate if sampling was applied
                    // Look up the matched policy to get sampling config
                    if (result.matched_policy_ids.len > 0 and snapshot != null) {
                        updateSpanTracestate(allocator, span, result.matched_policy_ids, snapshot.?);
                    }

                    write_idx += 1;
                } else {
                    dropped_count += 1;
                }
            }

            // Shrink the list to only kept items (zero allocation)
            scope_spans.spans.shrinkRetainingCapacity(write_idx);
        }
    }

    return .{
        .original_count = original_count,
        .dropped_count = dropped_count,
    };
}

/// Thread-local buffer for tracestate updates (avoids allocation)
const TracestateBuffer = struct {
    threadlocal var buf: [trace_sampler.MAX_TRACESTATE_LEN]u8 = undefined;
};

/// Update span's tracestate with sampling threshold from matched policies.
/// Per OTel spec, we record the sampling threshold so downstream samplers can respect it.
///
/// Note: This uses a thread-local buffer to avoid allocation. The result is copied
/// into the arena allocator that owns the span data.
fn updateSpanTracestate(
    arena_alloc: std.mem.Allocator,
    span: *Span,
    matched_policy_ids: []const []const u8,
    snapshot: *const PolicySnapshot,
) void {
    // Find the first matched trace policy with sampling config
    for (snapshot.policies) |*pol| {
        // Check if this policy matches any of our matched IDs
        for (matched_policy_ids) |matched_id| {
            if (std.mem.eql(u8, pol.id, matched_id)) {
                // Found a matching policy - check if it's a trace policy with sampling
                if (pol.target) |target| {
                    switch (target) {
                        .trace => |trace_target| {
                            if (trace_target.keep) |sampling_config| {
                                // Only update tracestate if percentage < 100 (actual sampling)
                                if (sampling_config.percentage < 100.0) {
                                    const precision = sampling_config.sampling_precision orelse 4;
                                    const threshold_hex = trace_sampler.thresholdHexFromPercentage(
                                        sampling_config.percentage,
                                        precision,
                                    );

                                    // Update tracestate using thread-local buffer (no allocation)
                                    if (trace_sampler.updateTracestateInPlace(
                                        &TracestateBuffer.buf,
                                        span.trace_state,
                                        threshold_hex,
                                    )) |new_tracestate| {
                                        // Copy the result into the arena so it persists
                                        // with the span data through serialization
                                        const owned = arena_alloc.dupe(u8, new_tracestate) catch return;
                                        span.trace_state = owned;
                                    }
                                }
                            }
                            return; // Done after finding first trace policy
                        },
                        else => {},
                    }
                }
            }
        }
    }
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
    };
}

// =============================================================================
// Tests
// =============================================================================

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
