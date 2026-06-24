//! Transport-neutral outcome execution (PLAN-FRONTEND-SWAP.md §3).
//!
//! Everything here speaks `*std.Io.Reader` / `*std.Io.Writer` / arena
//! allocators and the shared upstream client — never an inbound server type.
//! Frontends (stdio's std.http.Server driver, httpz) own connection state,
//! body acquisition, and response writing; they call into this module for
//! routing, planning, upstream opening, batch transforms, and per-record
//! policy evaluation so filter semantics are identical regardless of which
//! frontend the binary was composed with.
const std = @import("std");
const policy = @import("policy_zig");
const o11y = @import("o11y");

const service_mod = @import("../service/service.zig");
const router_mod = @import("../service/router.zig");
const upstream_mod = @import("upstream.zig");
const pipeline_mod = @import("../pipeline/pipeline.zig");
const encoding_mod = @import("../pipeline/encoding.zig");
const framer_mod = @import("../pipeline/framer.zig");
const limits_mod = @import("../core/limits.zig");
const runtime_metrics_mod = @import("../runtime/runtime_metrics.zig");
const dd_logs = @import("../signals/datadog/logs.zig");
const dd_metrics = @import("../signals/datadog/metrics.zig");
const otlp_logs = @import("../signals/otlp/logs.zig");
const otlp_metrics = @import("../signals/otlp/metrics.zig");
const otlp_traces = @import("../signals/otlp/traces.zig");

const log = std.log.scoped(.exec);

const EventBus = o11y.EventBus;

// Named event payloads: the type name is the telemetry event name.
const UpstreamConnectionError = struct { err: []const u8, phase: []const u8 };

/// Resolved upstream table; built once at startup from config URLs
/// (logs_url/metrics_url orelse upstream_url, per the old app.zig wiring).
pub const UpstreamIds = struct {
    default: upstream_mod.UpstreamId,
    logs: upstream_mod.UpstreamId,
    metrics: upstream_mod.UpstreamId,

    pub fn resolve(self: UpstreamIds, choice: service_mod.UpstreamChoice) upstream_mod.UpstreamId {
        return switch (choice) {
            .default => self.default,
            .logs => self.logs,
            .metrics => self.metrics,
        };
    }
};

/// A debug tap: while armed, data-plane threads copy each record's bytes
/// (before and/or after policy evaluation) into a sink owned by a waiting
/// `/_edge/tap/{pre,post}` request, then it disarms itself. One tap at a time.
///
/// Memory is never retained between taps: there is no ring and nothing
/// preallocated — the sink is the waiting request's buffer, freed when that
/// request returns. The whole thing is gated behind a config flag; when the
/// flag is off, `SharedCtx.tap` is null and the hot path never sees it.
pub const TapState = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    /// null = no tap armed. Written only under `mutex`, read unlocked on the
    /// hot path (a stale read just costs one extra lock+recheck, or a skip).
    sink: ?*std.Io.Writer = null,
    stage: Stage = .pre,
    remaining: u32 = 0,
    seq: u32 = 0,

    pub const Stage = enum { pre, post };

    /// Hot path. Called from every onRecord on every data-plane thread. When
    /// no tap is armed this is one acquire-load + a not-taken branch.
    pub fn capture(
        self: *TapState,
        stage: Stage,
        signal: []const u8,
        format: []const u8,
        decision: []const u8,
        bytes: []const u8,
    ) void {
        if (@atomicLoad(?*std.Io.Writer, &self.sink, .acquire) == null) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const sink = self.sink orelse return;
        if (self.stage != stage or self.remaining == 0) return;
        self.seq += 1;
        // Best-effort: a write failure (e.g. OOM growing the sink) just ends
        // the batch early rather than faulting the data plane.
        writeFrame(sink, self.seq, signal, format, decision, bytes) catch {
            self.remaining = 0;
        };
        if (self.remaining > 0) self.remaining -= 1;
        if (self.remaining == 0) @atomicStore(?*std.Io.Writer, &self.sink, null, .release);
    }

    /// Endpoint side: claim the single tap slot. Returns false if one is
    /// already armed (the caller answers 409).
    pub fn arm(self: *TapState, stage: Stage, n: u32, sink: *std.Io.Writer) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.sink != null) return false;
        self.stage = stage;
        self.remaining = n;
        self.seq = 0;
        @atomicStore(?*std.Io.Writer, &self.sink, sink, .release);
        return true;
    }

    /// True once the batch is full or the slot was released.
    pub fn finished(self: *TapState) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.sink == null or self.remaining == 0;
    }

    /// Release the slot. After this returns, no producer will touch the sink,
    /// so the endpoint can safely read what was collected. Idempotent.
    pub fn disarm(self: *TapState) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        @atomicStore(?*std.Io.Writer, &self.sink, null, .release);
    }

    fn writeFrame(
        w: *std.Io.Writer,
        seq: u32,
        signal: []const u8,
        format: []const u8,
        decision: []const u8,
        bytes: []const u8,
    ) !void {
        // Length-prefixed framing: a text header line, then `len` raw bytes
        // (records may be binary protobuf), then a newline. No base64, no
        // allocation — just two writes.
        try w.print("--- seq={d} signal={s} format={s} decision={s} len={d}\n", .{
            seq, signal, format, decision, bytes.len,
        });
        try w.writeAll(bytes);
        try w.writeByte('\n');
    }
};

/// Shared, read-only state for every connection, regardless of frontend.
/// Frontend-specific state (the stdio conn slab and arena pool) lives in the
/// frontend's own server struct, NOT here — see PLAN-FRONTEND-SWAP.md §2.
pub const SharedCtx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    router: *const router_mod.Router,
    services: []const service_mod.Service,
    upstreams: *upstream_mod.UpstreamManager,
    upstream_ids: UpstreamIds,
    registry: *policy.Registry,
    bus: *EventBus,
    metrics: ?*runtime_metrics_mod.RuntimeMetrics,
    limits: limits_mod.Limits,
    /// Debug tap, or null when disabled by config. See `TapState`.
    tap: ?*TapState = null,
};

/// Routes and plans a request from transport-neutral parts. Returns null
/// when no route matches (the frontend answers 404).
pub fn planRequest(
    ctx: *SharedCtx,
    method: service_mod.HttpMethod,
    path: []const u8,
    content_type: []const u8,
    content_encoding: []const u8,
) ?service_mod.Outcome {
    const match = ctx.router.route(path, method) orelse return null;
    const plan_request: service_mod.PlanRequest = .{
        .method = method,
        .path = path,
        .content_type = content_type,
        .content_encoding = content_encoding,
    };
    const svc = &ctx.services[@intFromEnum(match.service)];
    return svc.plan(plan_request);
}

/// Known-path classification for low-cardinality request metrics. Ported
/// verbatim from the old proxy/server.zig classifyKnownPath.
pub fn classifyKnownPath(path: []const u8, method: service_mod.HttpMethod) runtime_metrics_mod.KnownPathLabel {
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/logs")) return .api_v2_logs;
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/series")) return .api_v2_series;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/logs")) return .v1_logs;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/metrics")) return .v1_metrics;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/traces")) return .v1_traces;
    if (method == .GET and
        (std.mem.eql(u8, path, "/metrics") or std.mem.startsWith(u8, path, "/metrics/"))) return .metrics;
    if (method == .GET and std.mem.eql(u8, path, "/_health")) return .health;
    if (method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) return .edge_metrics;
    return .other;
}

pub fn methodLabel(method: service_mod.HttpMethod) runtime_metrics_mod.MethodLabel {
    return switch (method) {
        .GET => .get,
        .POST => .post,
        .PUT => .put,
        .DELETE => .delete,
        .PATCH => .patch,
        .HEAD => .head,
        .OPTIONS => .options,
        .OTHER => .other,
    };
}

/// Maps std's parsed Content-Encoding back to the header string our codec
/// layer understands. identity covers the absent-header case.
pub fn contentEncodingName(ce: std.http.ContentEncoding) []const u8 {
    return switch (ce) {
        .identity => "",
        .gzip => "gzip",
        .zstd => "zstd",
        // Not supported by the codec layer: plan() fail-opens to forward_raw.
        .deflate => "deflate",
        .compress => "compress",
    };
}

/// Opens a request against the configured upstream. `headers` must already
/// be hop-by-hop-filtered and arena-duped by the frontend (it owns the
/// inbound header iterator); `target` is the verbatim request target.
pub fn openUpstream(
    ctx: *SharedCtx,
    arena: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |i| target[0..i] else target;
    const query = if (query_start) |i| target[i + 1 ..] else "";

    const upstream_id = ctx.upstream_ids.resolve(choice);
    const uri_str = try ctx.upstreams.buildUpstreamUri(arena, upstream_id, path, query);
    const uri = try std.Uri.parse(uri_str);

    return ctx.upstreams.getHttpClient().request(method, uri, .{
        .extra_headers = headers,
        .headers = .{ .accept_encoding = .omit },
    }) catch |err| {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.err(UpstreamConnectionError{ .err = @errorName(err), .phase = "connect" });
        return err;
    };
}

/// Collects the upstream response headers a frontend should relay to the
/// client: hop-by-hop and transport-owned headers skipped, values arena-duped
/// (head strings die when the response body reader is created).
pub fn collectUpstreamResponseHeaders(
    upstream_res: *std.http.Client.Response,
    arena: std.mem.Allocator,
    buffer: []std.http.Header,
) ![]std.http.Header {
    var count: usize = 0;
    var it = upstream_res.head.iterateHeaders();
    while (it.next()) |header| {
        if (upstream_mod.shouldSkipResponseHeader(header.name)) continue;
        if (count >= buffer.len) break;
        buffer[count] = .{
            .name = try arena.dupe(u8, header.name),
            .value = try arena.dupe(u8, header.value),
        };
        count += 1;
    }
    return buffer[0..count];
}

/// One atomic snapshot load per request: when no loaded policy targets the
/// signal, both execution paths forward records verbatim instead of paying
/// the decode → evaluate → re-encode round-trip. Same observable output —
/// zero policies transform nothing — minus all the per-record work. (The
/// old stack's prefilter went further and short-circuited per record even
/// with policies loaded; that port is tracked in TODO.md.)
pub fn policiesActiveFor(registry: *policy.Registry, signal: service_mod.Signal) bool {
    const snapshot = registry.getSnapshot() orelse return false;
    return switch (signal) {
        .log => snapshot.getLogTargetIndices().len > 0,
        .metric => snapshot.getMetricTargetIndices().len > 0,
        .trace => snapshot.trace_target_indices.len > 0,
    };
}

pub const BufferedResult = struct {
    body: []const u8,
    all_dropped: bool,
};

/// Signal-agnostic view of the per-signal StreamProcessResult types.
const BatchSummary = struct {
    original_count: usize,
    dropped_count: usize,
    all_dropped: bool,

    fn of(result: anytype) BatchSummary {
        return .{
            .original_count = result.original_count,
            .dropped_count = result.dropped_count,
            .all_dropped = result.allDropped(),
        };
    }
};

/// Decode → batch transform → re-encode, all arena-bounded. The batch fns
/// are the same code the old modules ran, so filter semantics are identical.
pub fn processBuffered(
    ctx: *SharedCtx,
    pipe: service_mod.PipeBuffered,
    arena: std.mem.Allocator,
    raw_body: []const u8,
) !BufferedResult {
    if (!policiesActiveFor(ctx.registry, pipe.signal)) {
        return .{ .body = raw_body, .all_dropped = false };
    }
    var raw_reader = std.Io.Reader.fixed(raw_body);
    const decode_buf = try arena.alloc(u8, pipe.codec.decoderBufferLen(ctx.limits.zstd_window_len));
    var decoder: encoding_mod.Decoder = .init(pipe.codec, &raw_reader, decode_buf, ctx.limits.zstd_window_len);
    var decoded_capture: std.Io.Writer.Allocating = .init(arena);
    _ = try pipeline_mod.streamReaderToWriter(decoder.reader(), &decoded_capture.writer, ctx.limits.max_body_size);

    var decoded_reader = std.Io.Reader.fixed(decoded_capture.written());
    var transformed: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const registry = ctx.registry;
    // The per-signal StreamProcessResult types are distinct; normalize.
    const in = &decoded_reader;
    const out = &transformed.writer;
    const ct = "application/json";
    const summary: BatchSummary = switch (pipe.kind) {
        .datadog_metrics_json => .of(try dd_metrics.processMetricsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_logs_json => .of(try otlp_logs.processLogsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_metrics_json => .of(try otlp_metrics.processMetricsStream(arena, registry, ctx.bus, in, out, ct)),
        .otlp_traces_json => .of(try otlp_traces.processTracesStream(arena, registry, ctx.bus, in, out, ct)),
    };

    if (ctx.metrics) |metrics| {
        metrics.recordPolicyBatch(bufferedRouteLabel(pipe.kind), summary.original_count, summary.dropped_count);
    }
    if (summary.all_dropped) return .{ .body = &.{}, .all_dropped = true };

    // Re-encode in the original codec so the forwarded content-encoding
    // header stays truthful.
    var encoded: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const encode_buf = try arena.alloc(u8, pipe.codec.encoderBufferLen());
    var encoder: encoding_mod.Encoder = try .init(pipe.codec, &encoded.writer, encode_buf);
    defer encoder.deinit();
    try encoder.writer().writeAll(transformed.written());
    try encoder.finish();
    return .{ .body = encoded.written(), .all_dropped = false };
}

/// Per-record policy evaluation: wraps each record as a minimal one-element
/// batch and runs it through the SAME batch transform the old modules used.
/// Semantics are therefore identical to the buffered path; memory is bounded
/// by one record (the arena resets between records). A future pass can bind
/// the engine directly per record to shave the wrap/parse overhead.
pub const RecordSink = struct {
    ctx: *SharedCtx,
    signal: service_mod.Signal,
    format: framer_mod.WireFormat,
    record_arena: std.heap.ArenaAllocator,
    /// Snapshot emptiness for this request's signal, resolved once at init;
    /// false short-circuits onRecord to .keep without decoding.
    active: bool,
    /// Batch totals for recordPolicyBatch.
    records: u64 = 0,
    dropped: u64 = 0,

    pub fn init(ctx: *SharedCtx, signal: service_mod.Signal, format: framer_mod.WireFormat) RecordSink {
        return .{
            .ctx = ctx,
            .signal = signal,
            .format = format,
            .record_arena = .init(ctx.gpa),
            .active = policiesActiveFor(ctx.registry, signal),
        };
    }

    pub fn deinit(self: *RecordSink) void {
        self.record_arena.deinit();
        self.* = undefined;
    }

    pub fn onRecord(self: *RecordSink, bytes: []const u8) !framer_mod.Decision {
        self.records += 1;
        const sig = @tagName(self.signal);
        const fmt = @tagName(self.format);
        if (self.ctx.tap) |tap| tap.capture(.pre, sig, fmt, "", bytes);

        const decision: framer_mod.Decision = blk: {
            if (!self.active) break :blk .keep;

            // Replace bytes from the PREVIOUS record die here; the framer has
            // already written them (emit happens before the next onRecord).
            _ = self.record_arena.reset(.retain_capacity);
            const arena = self.record_arena.allocator();

            break :blk switch (self.format) {
                .json_array => try self.evalJsonRecord(arena, bytes),
                .otlp_protobuf => try self.evalProtobufRecord(arena, bytes),
                // raw/ndjson/prom_text never reach a policy sink today.
                else => .keep,
            };
        };

        if (self.ctx.tap) |tap| {
            const after: []const u8 = switch (decision) {
                .keep => bytes,
                .drop => "",
                .replace => |r| r,
            };
            tap.capture(.post, sig, fmt, @tagName(decision), after);
        }
        return decision;
    }

    fn evalJsonRecord(self: *RecordSink, arena: std.mem.Allocator, bytes: []const u8) !framer_mod.Decision {
        // One-element batch: "[<record>]".
        const wrapped = try std.mem.concat(arena, u8, &.{ "[", bytes, "]" });
        var reader = std.Io.Reader.fixed(wrapped);
        var out: std.Io.Writer.Allocating = .init(arena);
        const result = try dd_logs.processLogsStream(
            arena,
            self.ctx.registry,
            self.ctx.bus,
            &reader,
            &out.writer,
            "application/json",
        );
        if (result.allDropped()) {
            self.dropped += 1;
            return .drop;
        }
        const written = std.mem.trim(u8, out.written(), " \t\r\n");
        if (written.len < 2 or written[0] != '[' or written[written.len - 1] != ']') {
            return .keep; // unexpected shape: fail safe, forward original
        }
        const inner = std.mem.trim(u8, written[1 .. written.len - 1], " \t\r\n");
        if (inner.len == 0) {
            self.dropped += 1;
            return .drop;
        }
        if (std.mem.eql(u8, inner, bytes)) return .keep;
        return .{ .replace = inner };
    }

    fn evalProtobufRecord(self: *RecordSink, arena: std.mem.Allocator, bytes: []const u8) !framer_mod.Decision {
        // One-element batch: field 1, LEN, payload — a valid Export*Request.
        var wrapped: std.Io.Writer.Allocating = try .initCapacity(arena, bytes.len + 12);
        try wrapped.writer.writeByte(0x0A);
        try writeVarint(&wrapped.writer, bytes.len);
        try wrapped.writer.writeAll(bytes);

        var reader = std.Io.Reader.fixed(wrapped.written());
        var out: std.Io.Writer.Allocating = .init(arena);
        const registry = self.ctx.registry;
        // The per-signal StreamProcessResult types are distinct; normalize.
        const in = &reader;
        const ow = &out.writer;
        const ct = "application/x-protobuf";
        const all_dropped = switch (self.signal) {
            .log => blk: {
                const result = try otlp_logs.processLogsStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
            .metric => blk: {
                const result = try otlp_metrics.processMetricsStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
            .trace => blk: {
                const result = try otlp_traces.processTracesStream(arena, registry, self.ctx.bus, in, ow, ct);
                break :blk result.allDropped();
            },
        };
        if (all_dropped) {
            self.dropped += 1;
            return .drop;
        }
        const payload = stripLenField(out.written()) orelse return .keep;
        if (payload.len == 0) {
            self.dropped += 1;
            return .drop;
        }
        if (std.mem.eql(u8, payload, bytes)) return .keep;
        return .{ .replace = payload };
    }
};

/// Unwraps a single field-1 LEN message: returns the payload, or null when
/// the buffer isn't exactly one such field (caller fails safe with .keep).
fn stripLenField(buffer: []const u8) ?[]const u8 {
    if (buffer.len < 2 or buffer[0] != 0x0A) return null;
    var len: usize = 0;
    var shift: u6 = 0;
    var i: usize = 1;
    while (i < buffer.len) : (i += 1) {
        const byte = buffer[i];
        len |= @as(usize, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) break;
        shift += 7;
        if (shift > 35) return null;
    } else return null;
    const payload_start = i + 1;
    if (payload_start + len != buffer.len) return null;
    return buffer[payload_start..][0..len];
}

fn writeVarint(out: *std.Io.Writer, value: usize) !void {
    var v: u64 = value;
    while (v >= 0x80) {
        try out.writeByte(@intCast((v & 0x7f) | 0x80));
        v >>= 7;
    }
    try out.writeByte(@intCast(v));
}

pub fn routeLabel(signal: service_mod.Signal, format: framer_mod.WireFormat) runtime_metrics_mod.PolicyTelemetryLabel {
    return switch (format) {
        .json_array => .datadog_logs,
        .otlp_protobuf => switch (signal) {
            .log => .otlp_logs,
            .metric => .otlp_metrics,
            .trace => .otlp_traces,
        },
        // raw/ndjson/prom_text outcomes never run the record pipeline.
        else => unreachable,
    };
}

pub fn bufferedRouteLabel(kind: service_mod.BufferedKind) runtime_metrics_mod.PolicyTelemetryLabel {
    return switch (kind) {
        .datadog_metrics_json => .datadog_metrics,
        .otlp_logs_json => .otlp_logs,
        .otlp_metrics_json => .otlp_metrics,
        .otlp_traces_json => .otlp_traces,
    };
}

// ============================== Tests ==============================

const testing = std.testing;

test "stripLenField unwraps single-field messages" {
    const buf = [_]u8{ 0x0A, 0x03, 'a', 'b', 'c' };
    try testing.expectEqualStrings("abc", stripLenField(&buf).?);

    // Empty payload
    const empty = [_]u8{ 0x0A, 0x00 };
    try testing.expectEqualStrings("", stripLenField(&empty).?);

    // Trailing garbage -> null
    const trailing = [_]u8{ 0x0A, 0x01, 'x', 0x55 };
    try testing.expectEqual(@as(?[]const u8, null), stripLenField(&trailing));

    // Wrong tag -> null
    const wrong = [_]u8{ 0x12, 0x01, 'x' };
    try testing.expectEqual(@as(?[]const u8, null), stripLenField(&wrong));
}

test "policiesActiveFor is false on an empty registry" {
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(std.Options.debug_io);
    var registry = policy.Registry.init(testing.allocator, noop_bus.eventBus());
    defer registry.deinit();

    // No snapshot loaded at all, and after that no policies per signal:
    // every signal must short-circuit so empty deployments skip the
    // per-record decode entirely.
    try testing.expect(!policiesActiveFor(&registry, .log));
    try testing.expect(!policiesActiveFor(&registry, .metric));
    try testing.expect(!policiesActiveFor(&registry, .trace));
}

test "classifyKnownPath matches core routes" {
    // Parity with the old classifyRoute/classifyKnownPath tests.
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.api_v2_logs, classifyKnownPath("/api/v2/logs", .POST));
    const series = classifyKnownPath("/api/v2/series", .POST);
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.api_v2_series, series);
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.v1_logs, classifyKnownPath("/v1/logs", .POST));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.metrics, classifyKnownPath("/metrics", .GET));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.health, classifyKnownPath("/_health", .GET));
    try testing.expectEqual(runtime_metrics_mod.KnownPathLabel.other, classifyKnownPath("/anything", .GET));
}

test "contentEncodingName round-trips through the codec layer" {
    try testing.expectEqual(
        encoding_mod.ContentEncoding.identity,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.identity)).?,
    );
    try testing.expectEqual(
        encoding_mod.ContentEncoding.gzip,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.gzip)).?,
    );
    try testing.expectEqual(
        encoding_mod.ContentEncoding.zstd,
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.zstd)).?,
    );
    // deflate/compress are unsupported by the codec layer: plan() fail-opens.
    try testing.expectEqual(
        @as(?encoding_mod.ContentEncoding, null),
        encoding_mod.ContentEncoding.fromHeader(contentEncodingName(.deflate)),
    );
}

test "TapState: arm captures matching-stage records, auto-disarms after n" {
    const io = std.testing.io;
    var tap: TapState = .{ .io = io };

    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();

    try testing.expect(tap.arm(.pre, 2, &buf.writer));
    // A second arm while one is active is rejected.
    var other: std.Io.Writer.Allocating = .init(testing.allocator);
    defer other.deinit();
    try testing.expect(!tap.arm(.post, 5, &other.writer));

    // Wrong-stage capture is ignored; matching-stage ones fill the batch.
    tap.capture(.post, "log", "json_array", "drop", "IGNORED");
    tap.capture(.pre, "log", "json_array", "", "AAA");
    try testing.expect(!tap.finished());
    tap.capture(.pre, "metric", "otlp_protobuf", "", "BBBB");
    // n reached -> auto-disarmed; further captures are dropped.
    try testing.expect(tap.finished());
    tap.capture(.pre, "log", "json_array", "", "CCC");

    const out = buf.written();
    try testing.expect(std.mem.indexOf(u8, out, "seq=1 signal=log format=json_array decision= len=3\nAAA\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "seq=2 signal=metric format=otlp_protobuf decision= len=4\nBBBB\n") != null);
    try testing.expect(std.mem.indexOf(u8, out, "IGNORED") == null);
    try testing.expect(std.mem.indexOf(u8, out, "CCC") == null);
}
