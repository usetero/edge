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
const codec = @import("../codec/root.zig");
const thread_bufs = @import("thread_bufs.zig");
const framer_mod = @import("../pipeline/framer.zig");
const tap_mod = @import("../pipeline/tap.zig");
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

/// Debug tap (`/_edge/tap/{pre,post}`), defined in the pipeline layer.
pub const TapState = tap_mod.TapState;

/// Shared, read-only state for every connection, regardless of frontend.
/// Frontend-specific state (the stdio conn slab and arena pool) lives in the
/// frontend's own server struct, NOT here — see PLAN-FRONTEND-SWAP.md §2.
/// Policies in the snapshot that the matcher refused to compile. Named type,
/// so the event carries the name `policies.rejected`.
const PoliciesRejected = struct { count: usize };

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
    /// Extension dispatch sink (s3-dump), or null when extensions are off.
    /// Threaded into per-record policy evaluation on the Datadog log path.
    extension_sink: ?policy.ExtensionSink = null,
    /// Last reported count of policies the matcher refused, so the warning
    /// fires on a change rather than on every scrape.
    rejected_policies: std.atomic.Value(u32) = .init(0),
    /// One bit per `head_repair.Reason` already reported. A sender spells an
    /// encoding the same way on every request, so the warning is worth one
    /// line for the deployment, not one per request.
    head_repairs_seen: std.atomic.Value(u8) = .init(0),
    /// Whether a whole batch has already been reported as dropped by policy.
    /// Same reasoning as above: the rate belongs to
    /// `edge_policy_records_dropped_total`, and the operator needs the fact
    /// once.
    batch_dropped_seen: std.atomic.Value(bool) = .init(false),
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
    // The control paths are labelled by path, not by method. A HEAD probe is
    // a health check, and a rejected POST to an observability endpoint is not
    // customer data: labelling either as `other` puts control traffic in the
    // data-path series and hides it from the ones that matter.
    if (std.mem.eql(u8, path, "/_health")) return .health;
    if (std.mem.startsWith(u8, path, "/_edge/")) return .edge_metrics;
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
/// be hop-by-hop-filtered and remain valid for the request lifetime; `target`
/// is the verbatim request target.
pub fn openUpstream(
    ctx: *SharedCtx,
    arena: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    choice: service_mod.UpstreamChoice,
) !std.http.Client.Request {
    return openUpstreamWithClient(ctx, arena, method, target, headers, choice, ctx.upstreams.getHttpClient());
}

/// Retry callers select the dedicated client with no idle connections.
pub fn openUpstreamWithClient(
    ctx: *SharedCtx,
    arena: std.mem.Allocator,
    method: std.http.Method,
    target: []const u8,
    headers: []const std.http.Header,
    choice: service_mod.UpstreamChoice,
    client: *std.http.Client,
) !std.http.Client.Request {
    const query_start = std.mem.findScalar(u8, target, '?');
    const path = if (query_start) |i| target[0..i] else target;
    const query = if (query_start) |i| target[i + 1 ..] else "";

    const upstream_id = ctx.upstream_ids.resolve(choice);
    const uri_str = try ctx.upstreams.buildUpstreamUri(arena, upstream_id, path, query);
    const uri = try std.Uri.parse(uri_str);

    return client.request(method, uri, .{
        .extra_headers = headers,
        .redirect_behavior = .unhandled,
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
    // RFC 7230 §6.1: headers listed in the Connection field are hop-by-hop
    // and must not be forwarded.  Collect all Connection-option tokens first.
    var conn_opts: std.ArrayList([]const u8) = .empty;
    {
        var it = upstream_res.head.iterateHeaders();
        while (it.next()) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
            var tok_it = std.mem.tokenizeScalar(u8, header.value, ',');
            while (tok_it.next()) |tok| {
                const name = std.mem.trim(u8, tok, " \t");
                if (name.len > 0) try conn_opts.append(arena, name);
            }
        }
    }

    var count: usize = 0;
    var it = upstream_res.head.iterateHeaders();
    while (it.next()) |header| {
        if (upstream_mod.shouldSkipResponseHeader(header.name)) continue;
        // Also skip any header nominated as hop-by-hop via Connection.
        var skip = false;
        for (conn_opts.items) |opt| {
            if (std.ascii.eqlIgnoreCase(header.name, opt)) {
                skip = true;
                break;
            }
        }
        if (skip) continue;
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

/// Mirror the active snapshot's per-signal policy counts into the gauge. Called
/// at scrape time so the gauge always reflects the live snapshot without hooking
/// the loader's reload path. Counts match `policiesActiveFor` (the fast-path
/// gate), so a 0 here is exactly when that signal is raw-forwarded untouched.
pub fn refreshPolicyGauge(ctx: *SharedCtx) void {
    const metrics = ctx.metrics orelse return;
    const snapshot = ctx.registry.getSnapshot();
    metrics.setPoliciesLoaded(.log, if (snapshot) |s| @intCast(s.getLogTargetIndices().len) else 0);
    metrics.setPoliciesLoaded(.metric, if (snapshot) |s| @intCast(s.getMetricTargetIndices().len) else 0);
    metrics.setPoliciesLoaded(.trace, if (snapshot) |s| @intCast(s.trace_target_indices.len) else 0);

    // A policy whose pattern the engine refused is in the snapshot and does
    // nothing. Without this it reads as a live rule: the loader counts it as
    // loaded, and the debug endpoint lists it as enabled.
    const rejected = rejectedPolicyCount(ctx);
    metrics.setPoliciesRejected(rejected);
    const previous = ctx.rejected_policies.swap(@intCast(rejected), .monotonic);
    if (rejected > 0 and previous != @as(u32, @intCast(rejected))) {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        ctx.bus.warn(PoliciesRejected{ .count = rejected });
    }
}

/// Policies the matcher could not compile. `collectStats` copies into the
/// arena, so this pays one small allocation per scrape and frees it here.
pub fn rejectedPolicyCount(ctx: *SharedCtx) usize {
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const stats = ctx.registry.collectStats(arena.allocator()) catch return 0;
    var count: usize = 0;
    for (stats) |entry| {
        if (entry.errors.len > 0) count += 1;
    }
    return count;
}

/// Names the policies the matcher refused, with the reason, at the top of the
/// dump. A rule that cannot compile is in the snapshot and evaluates nothing,
/// so listing it as enabled without this is misleading.
fn writeRejectedPolicies(registry: *policy.Registry, w: *std.Io.Writer) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const stats = registry.collectStats(arena.allocator()) catch return;
    for (stats) |entry| {
        if (entry.errors.len == 0) continue;
        for (entry.errors) |message| {
            try w.print("# REJECTED id={s}: {s}\n", .{ entry.id, message });
        }
    }
}

/// Dump the loaded policies in the active snapshot, for the `/_edge/policies`
/// debug endpoint. `json=true` emits the full policy tree (match rules, keep,
/// transform — via the proto type's own jsonStringify); otherwise a one-line
/// text summary per policy (id, signal, enabled, name).
pub fn writePolicies(registry: *policy.Registry, w: *std.Io.Writer, json: bool) !void {
    const snapshot = registry.getSnapshot();
    if (json) {
        // std.json's default struct serializer over the proto types. Repeated
        // fields surface as {"items":[...],"capacity":N} (raw ArrayList) — fine
        // for a debug dump; the policy data is all there.
        try w.print("{{\"version\":{d},\"policies\":", .{if (snapshot) |s| s.version else 0});
        try std.json.Stringify.value(if (snapshot) |s| s.policies else &.{}, .{}, w);
        try w.writeAll("}\n");
        return;
    }
    const s = snapshot orelse {
        try w.writeAll("# no policy snapshot loaded (0 policies)\n");
        return;
    };
    try writeRejectedPolicies(registry, w);
    try w.print("# snapshot version={d} policies={d} (log={d} metric={d} trace={d})\n", .{
        s.version,
        s.policies.len,
        s.getLogTargetIndices().len,
        s.getMetricTargetIndices().len,
        s.trace_target_indices.len,
    });
    for (s.policies) |*p| {
        const signal = if (p.target) |t| @tagName(std.meta.activeTag(t)) else "none";
        try w.print("id={s} signal={s} enabled={} name={s}\n", .{
            p.id, signal, p.enabled, p.name,
        });
    }
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
    const decoded = try decodeWhole(ctx, pipe.codec, arena, raw_body);

    var decoded_reader = std.Io.Reader.fixed(decoded);
    var transformed: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const registry = ctx.registry;
    // The per-signal StreamProcessResult types are distinct; normalize.
    const in = &decoded_reader;
    const out = &transformed.writer;
    const ct = "application/json";
    const summary: BatchSummary = switch (pipe.kind) {
        .datadog_metrics_json => .of(try dd_metrics.processMetricsStream(arena, registry, ctx.bus, in, out)),
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
    const which = pipe.codec.codec() orelse return .{ .body = transformed.written(), .all_dropped = false };
    var encoded: std.Io.Writer.Allocating = try .initCapacity(arena, 4096);
    const pooled = try thread_bufs.encoder_pool.acquire(ctx.gpa);
    defer thread_bufs.encoder_pool.release(ctx.gpa, pooled);
    try pooled.encoder.begin(which, &encoded.writer);
    try pooled.encoder.writer.writeAll(transformed.written());
    try pooled.encoder.finish();
    return .{ .body = encoded.written(), .all_dropped = false };
}

/// The whole of a complete body, decoded into `arena` with this thread's
/// decoder. Output past `max_decoded_bytes` is `DecodedBodyTooLarge`, which
/// the caller fails open on, as it does on every other decode error.
fn decodeWhole(
    ctx: *SharedCtx,
    encoding: codec.ContentEncoding,
    arena: std.mem.Allocator,
    raw_body: []const u8,
) ![]const u8 {
    const which = encoding.codec() orelse return raw_body;
    const bufs = try thread_bufs.get(ctx.io, ctx.gpa, ctx.limits);
    const decoder = try bufs.ensureDecoder(ctx.gpa);
    try decoder.begin(which, raw_body, .{
        .max_output = ctx.limits.max_decoded_bytes,
        .window_len = ctx.limits.zstd_window_len,
    });
    var out: std.ArrayList(u8) = .empty;
    decoder.readAll(arena, &out) catch |err| return switch (err) {
        error.OutputTooLarge => error.DecodedBodyTooLarge,
        else => |e| e,
    };
    return out.items;
}

/// Long-lived scratch for the per-record path: zimdjson's structural buffers
/// and the record arena. Owned by the frontend and reused across requests
/// (thread-local in the httpz frontend), so steady-state request handling
/// pays zero setup allocations. The arena's retained capacity is bounded by
/// the largest single record evaluated (records themselves are bounded by
/// limits.record_scratch).
pub const RecordScratch = struct {
    gpa: std.mem.Allocator,
    parser: dd_logs.Parser,
    arena: std.heap.ArenaAllocator,

    pub fn init(gpa: std.mem.Allocator) RecordScratch {
        return .{ .gpa = gpa, .parser = .init, .arena = .init(gpa) };
    }

    pub fn deinit(self: *RecordScratch) void {
        self.parser.deinit(self.gpa);
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Per-record policy evaluation. JSON log records are parsed and evaluated in
/// place (dd_logs.evalLogRecord): the keep path forwards the original bytes
/// with no copy. Protobuf records still round-trip through the batch
/// transform. Memory is bounded by one record (the arena resets between
/// records).
pub const RecordSink = struct {
    ctx: *SharedCtx,
    signal: service_mod.Signal,
    format: framer_mod.WireFormat,
    /// Parser + arena reused across records AND requests; see RecordScratch.
    scratch: *RecordScratch,
    /// Snapshot emptiness for this request's signal, resolved once at init;
    /// false short-circuits onRecord to .keep without decoding.
    active: bool,
    /// Batch totals for recordPolicyBatch.
    records: u64 = 0,
    dropped: u64 = 0,
    /// Probe mode: the caller only wants to know *whether* this batch changes,
    /// so the first drop or replace aborts with `error.BatchChanged` instead of
    /// producing output. Tap capture is suppressed, since the real pass that
    /// follows a positive probe captures every record anyway.
    probe: bool = false,

    pub fn init(
        ctx: *SharedCtx,
        signal: service_mod.Signal,
        format: framer_mod.WireFormat,
        scratch: *RecordScratch,
    ) RecordSink {
        return .{
            .ctx = ctx,
            .signal = signal,
            .format = format,
            .scratch = scratch,
            .active = policiesActiveFor(ctx.registry, signal),
        };
    }

    pub fn deinit(self: *RecordSink) void {
        // The scratch outlives the sink (frontend-owned); nothing to free.
        self.* = undefined;
    }

    pub fn onRecord(self: *RecordSink, bytes: []const u8) !framer_mod.Decision {
        self.records += 1;
        const sig = @tagName(self.signal);
        const fmt = @tagName(self.format);
        if (!self.probe) {
            if (self.ctx.tap) |tap| tap.capture(.pre, sig, fmt, "", bytes);
        }

        const decision: framer_mod.Decision = blk: {
            if (!self.active) break :blk .keep;

            // Replace bytes from the PREVIOUS record die here; the framer has
            // already written them (emit happens before the next onRecord).
            _ = self.scratch.arena.reset(.retain_capacity);
            const arena = self.scratch.arena.allocator();

            break :blk switch (self.format) {
                .json_array => try self.evalJsonRecord(arena, bytes),
                .otlp_protobuf => try self.evalProtobufRecord(arena, bytes),
                // ndjson/prom_text never reach a policy sink today.
                else => .keep,
            };
        };

        if (self.probe) {
            // Unwind as soon as the answer is known, so a batch that changes
            // early pays only for the records up to that point.
            if (decision != .keep) return error.BatchChanged;
            return decision;
        }
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
        const verdict = try dd_logs.evalLogRecord(
            arena,
            &self.scratch.parser,
            self.ctx.gpa,
            self.ctx.registry,
            self.ctx.bus,
            bytes,
            // A probe is a dry run: the real pass that follows dispatches
            // these actions, and a sink that saw both would record every
            // record before the first change twice.
            if (self.probe) null else self.ctx.extension_sink,
        );
        switch (verdict) {
            .keep => return .keep,
            .drop => {
                self.dropped += 1;
                return .drop;
            },
            .replace => |replacement| return .{ .replace = replacement },
        }
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
        // ndjson/prom_text outcomes never run the record pipeline.
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
        codec.ContentEncoding.identity,
        codec.ContentEncoding.fromHeader(contentEncodingName(.identity)).?,
    );
    try testing.expectEqual(
        codec.ContentEncoding.gzip,
        codec.ContentEncoding.fromHeader(contentEncodingName(.gzip)).?,
    );
    try testing.expectEqual(
        codec.ContentEncoding.zstd,
        codec.ContentEncoding.fromHeader(contentEncodingName(.zstd)).?,
    );
    // deflate/compress are unsupported by the codec layer: plan() fail-opens.
    try testing.expectEqual(
        @as(?codec.ContentEncoding, null),
        codec.ContentEncoding.fromHeader(contentEncodingName(.deflate)),
    );
}

test "collectUpstreamResponseHeaders strips hop-by-hop Connection and transport headers" {
    const response_bytes = "HTTP/1.1 200 OK\r\n" ++
        "content-type: application/json\r\n" ++
        "connection: close\r\n" ++
        "x-foo: bar\r\n" ++
        "content-length: 42\r\n" ++
        "transfer-encoding: chunked\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var upstream_res: std.http.Client.Response = .{ .request = undefined, .head = head };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buffer: [16]std.http.Header = undefined;
    const relayed = try collectUpstreamResponseHeaders(&upstream_res, arena.allocator(), &buffer);

    // Exactly the two end-to-end headers survive; hop-by-hop Connection and
    // transport-owned content-length/transfer-encoding are dropped.
    try testing.expectEqual(@as(usize, 2), relayed.len);

    var saw_content_type = false;
    var saw_x_foo = false;
    for (relayed) |header| {
        try testing.expect(!upstream_mod.shouldSkipResponseHeader(header.name));
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            try testing.expectEqualStrings("application/json", header.value);
            saw_content_type = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-foo")) {
            try testing.expectEqualStrings("bar", header.value);
            saw_x_foo = true;
        } else {
            return error.UnexpectedRelayedHeader;
        }
    }
    try testing.expect(saw_content_type);
    try testing.expect(saw_x_foo);
}

test "collectUpstreamResponseHeaders strips Connection-nominated hop-by-hop headers" {
    // An upstream that uses Connection: X-Upstream-State to mark a
    // per-connection field.  That field must not be relayed downstream.
    const response_bytes = "HTTP/1.1 200 OK\r\n" ++
        "content-type: text/plain\r\n" ++
        "connection: X-Upstream-State, Keep-Alive\r\n" ++
        "x-upstream-state: active\r\n" ++
        "keep-alive: timeout=5\r\n" ++
        "x-end-to-end: ok\r\n" ++
        "content-length: 5\r\n\r\n";

    const head = try std.http.Client.Response.Head.parse(response_bytes);
    var upstream_res: std.http.Client.Response = .{ .request = undefined, .head = head };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var buffer: [16]std.http.Header = undefined;
    const relayed = try collectUpstreamResponseHeaders(&upstream_res, arena.allocator(), &buffer);

    // Only the two genuine end-to-end headers should survive.
    // content-length, connection, x-upstream-state, and keep-alive are all dropped.
    try testing.expectEqual(@as(usize, 2), relayed.len);

    var saw_content_type = false;
    var saw_x_end_to_end = false;
    for (relayed) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
            try testing.expectEqualStrings("text/plain", header.value);
            saw_content_type = true;
        } else if (std.ascii.eqlIgnoreCase(header.name, "x-end-to-end")) {
            try testing.expectEqualStrings("ok", header.value);
            saw_x_end_to_end = true;
        } else {
            return error.UnexpectedRelayedHeader;
        }
    }
    try testing.expect(saw_content_type);
    try testing.expect(saw_x_end_to_end);
}
