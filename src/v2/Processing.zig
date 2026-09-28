//! Transactional, bounded candidate construction; the caller retains encoded input.
const std = @import("std");
const policy = @import("policy_zig");
const PolicyStore = @import("PolicyStore.zig");
const Scratch = @import("Scratch.zig");
const encoding = @import("../pipeline/encoding.zig");
const framing = @import("../pipeline/framer.zig");
const dd_logs = @import("../signals/datadog/logs.zig");
const Envelope = @import("Envelope.zig");
const Prometheus = @import("Prometheus.zig");
const dd_metrics = @import("../signals/datadog/metrics.zig");
const otlp_logs = @import("../signals/otlp/logs.zig");
const otlp_metrics = @import("../signals/otlp/metrics.zig");
const otlp_traces = @import("../signals/otlp/traces.zig");

pub const Format = enum { datadog_metrics, otlp_logs, otlp_metrics, otlp_traces };

pub const Limits = struct {
    output_bytes: u32 = 2 * 1024 * 1024,
    scratch_bytes: u32 = 2 * 1024 * 1024,
    parser_bytes: u32 = 1024 * 1024,
    record_bytes: u32 = 256 * 1024,
    decoded_bytes: u32 = 16 * 1024 * 1024,
    zstd_window_bytes: u32 = 256 * 1024,
};
pub const Reason = enum { none, no_policies, unsupported, busy, unavailable, malformed, capacity };
pub const Result = struct {
    body: []const u8,
    changed: bool = false,
    all_dropped: bool = false,
    evaluated: u64 = 0,
    dropped: u64 = 0,
    skipped: u64 = 0,
    reason: Reason = .none,
};

pub const Workspace = struct {
    tap: ?*@import("../pipeline/tap.zig").TapState = null,
    storage: []u8,
    output: []u8,
    scratch: Scratch,
    parser_scratch: Scratch,
    record: []u8,
    decoder: []u8,
    encoder: []u8,
    limits: Limits,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) !Workspace {
        const bytes = try requiredBytes(limits) - @sizeOf(Workspace);
        const storage = try allocator.alloc(u8, @intCast(bytes));
        var remaining = storage;
        const output = take(&remaining, limits.output_bytes);
        const scratch = take(&remaining, limits.scratch_bytes);
        const parser_scratch = take(&remaining, limits.parser_bytes);
        const record = take(&remaining, limits.record_bytes);
        const decoder = take(&remaining, encoding.maxCodecBufferLen(limits.zstd_window_bytes));
        return .{
            .storage = storage,
            .output = output,
            .scratch = .init(scratch),
            .parser_scratch = .init(parser_scratch),
            .record = record,
            .decoder = decoder,
            .encoder = remaining,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Workspace, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn requiredBytes(limits: Limits) !u64 {
        if (limits.record_bytes == 0 or limits.decoded_bytes == 0 or
            limits.zstd_window_bytes < 32768 or limits.zstd_window_bytes > 64 * 1024 * 1024) return error.InvalidLimits;
        return @sizeOf(Workspace) + @as(u64, limits.output_bytes) + limits.scratch_bytes + limits.parser_bytes +
            limits.record_bytes + 2 * @as(u64, encoding.maxCodecBufferLen(limits.zstd_window_bytes));
    }

    fn take(remaining: *[]u8, count: usize) []u8 {
        const result = remaining.*[0..count];
        remaining.* = remaining.*[count..];
        return result;
    }
};

/// The guard spans the whole candidate, so no policy snapshot or callback result
/// crosses a publication boundary. Network IO happens after this function returns.
pub fn logs(
    io: std.Io,
    store: *PolicyStore,
    workspace: *Workspace,
    original: []const u8,
    content_encoding: []const u8,
    extension_sink: ?policy.ExtensionSink,
) Result {
    var guard = switch (store.tryRead(io)) {
        .ready => |guard| guard,
        .busy => return .{ .body = original, .reason = .busy },
        .unavailable => return .{ .body = original, .reason = .unavailable },
    };
    defer guard.deinit(io);
    if (workspace.tap == null) {
        const snapshot = guard.snapshot() orelse return .{ .body = original, .reason = .no_policies };
        if (snapshot.getLogTargetIndices().len == 0) return .{ .body = original, .reason = .no_policies };
    }
    const codec = encoding.ContentEncoding.fromHeader(content_encoding) orelse
        return .{ .body = original, .reason = .unsupported };
    workspace.scratch.reset();
    workspace.parser_scratch.reset();
    var sink: LogSink = .{ .workspace = workspace, .store = store, .extension_sink = extension_sink };
    defer sink.parser.deinit(workspace.parser_scratch.allocator());
    const stats = run(workspace, original, codec, &sink) catch |err| return .{
        .body = original,
        .evaluated = sink.evaluated,
        .reason = switch (err) {
            error.OutOfMemory, error.WriteFailed, error.DecodedBodyTooLarge => .capacity,
            else => .malformed,
        },
    };
    if (stats.desynced) return .{ .body = original, .evaluated = sink.evaluated, .reason = .malformed };
    const changed = stats.dropped != 0 or stats.replaced != 0;
    return .{
        .body = if (changed) workspace.output[0..sink.output_len] else original,
        .changed = changed,
        .all_dropped = stats.records > 0 and stats.records == stats.dropped,
        .evaluated = sink.evaluated,
        .dropped = stats.dropped,
        .skipped = stats.failed_open + sink.skipped,
    };
}

/// Nested formats use their established accessors in a bounded request arena.
/// All input/output remains private, including errors caught inside an accessor.
pub fn nested(
    io: std.Io,
    store: *PolicyStore,
    workspace: *Workspace,
    original: []const u8,
    content_encoding: []const u8,
    content_type: []const u8,
    format: Format,
) Result {
    var guard = switch (store.tryRead(io)) {
        .ready => |guard| guard,
        .busy => return .{ .body = original, .reason = .busy },
        .unavailable => return .{ .body = original, .reason = .unavailable },
    };
    defer guard.deinit(io);
    const snapshot = guard.snapshot() orelse return .{ .body = original, .reason = .no_policies };
    const targets = switch (format) {
        .otlp_logs => snapshot.getLogTargetIndices(),
        .datadog_metrics, .otlp_metrics => snapshot.getMetricTargetIndices(),
        .otlp_traces => snapshot.trace_target_indices,
    };
    if (targets.len == 0) return .{ .body = original, .reason = .no_policies };
    const codec = encoding.ContentEncoding.fromHeader(content_encoding) orelse
        return .{ .body = original, .reason = .unsupported };
    workspace.scratch.reset();
    return runNested(workspace, store, original, codec, content_type, format) catch |err| .{
        .body = original,
        .reason = if (workspace.scratch.denied or err == error.WriteFailed or
            err == error.StreamTooLong) .capacity else .malformed,
    };
}

fn runNested(
    workspace: *Workspace,
    store: *PolicyStore,
    original: []const u8,
    codec: encoding.ContentEncoding,
    content_type: []const u8,
    format: Format,
) !Result {
    const allocator = workspace.scratch.allocator();
    var source: std.Io.Reader = .fixed(original);
    var decoder: encoding.Decoder = .init(codec, &source, workspace.decoder, workspace.limits.zstd_window_bytes);
    const decoded = try decoder.reader().allocRemaining(allocator, .limited(workspace.limits.decoded_bytes));
    if (std.mem.indexOf(u8, content_type, "application/json") != null) {
        var stack_bytes: [512]u8 = undefined;
        var stack: std.heap.FixedBufferAllocator = .init(&stack_bytes);
        var validator: std.json.Scanner = .initCompleteInput(stack.allocator(), decoded);
        defer validator.deinit();
        try validateAvailable(&validator);
    }
    var input: std.Io.Reader = .fixed(decoded);
    var output: std.Io.Writer = .fixed(workspace.output);
    if (codec == .gzip and workspace.output.len <= 8) return error.WriteFailed;
    var encoder: encoding.Encoder = try .init(codec, &output, workspace.encoder);
    defer encoder.deinit();
    var candidate: std.Io.Writer.Allocating = .init(allocator);
    defer candidate.deinit();
    const counts = switch (format) {
        inline else => |selected| result: {
            const process = switch (selected) {
                .datadog_metrics => dd_metrics.processMetricsStream,
                .otlp_logs => otlp_logs.processLogsStream,
                .otlp_metrics => otlp_metrics.processMetricsStream,
                .otlp_traces => otlp_traces.processTracesStream,
            };
            const stats = try process(
                allocator,
                &store.registry,
                store.registry.bus,
                &input,
                &candidate.writer,
                content_type,
            );
            const converted: Result = .{
                .body = original,
                .changed = stats.wasModified(),
                .all_dropped = stats.allDropped(),
                .evaluated = stats.original_count,
                .dropped = stats.dropped_count,
            };
            break :result converted;
        },
    };
    if (workspace.scratch.denied) return error.OutOfMemory;
    var result = counts;
    if (!result.changed) return result;
    if (format == .datadog_metrics) {
        try encoder.writer().writeAll(candidate.written());
    } else if (std.mem.indexOf(u8, content_type, "application/json") != null) {
        try Envelope.json(allocator, decoded, candidate.written(), encoder.writer());
    } else try Envelope.protobuf(decoded, candidate.written(), encoder.writer());
    try encoder.finish();
    result.body = output.buffered();
    return result;
}

/// Finite scrape transaction. Decode and encode caps fail open to original bytes.
pub fn prometheus(
    io: std.Io,
    store: *PolicyStore,
    workspace: *Workspace,
    original: []const u8,
    content_encoding: []const u8,
    input_cap: usize,
    output_cap: usize,
) Result {
    var guard = switch (store.tryRead(io)) {
        .ready => |guard| guard,
        .busy => return .{ .body = original, .reason = .busy },
        .unavailable => return .{ .body = original, .reason = .unavailable },
    };
    defer guard.deinit(io);
    const snapshot = guard.snapshot() orelse return .{ .body = original, .reason = .no_policies };
    if (snapshot.getMetricTargetIndices().len == 0) return .{ .body = original, .reason = .no_policies };
    const codec = encoding.ContentEncoding.fromHeader(content_encoding) orelse
        return .{ .body = original, .reason = .unsupported };
    workspace.scratch.reset();
    workspace.parser_scratch.reset();
    return runPrometheus(store, workspace, original, codec, input_cap, output_cap) catch |err| .{
        .body = original,
        .reason = if (err == error.ReadFailed) .malformed else .capacity,
    };
}

fn runPrometheus(
    store: *PolicyStore,
    workspace: *Workspace,
    original: []const u8,
    codec: encoding.ContentEncoding,
    input_cap: usize,
    output_cap: usize,
) !Result {
    var source: std.Io.Reader = .fixed(original);
    var decoder: encoding.Decoder = .init(codec, &source, workspace.decoder, workspace.limits.zstd_window_bytes);
    const configured_limit = @min(input_cap, workspace.limits.decoded_bytes);
    const limit = if (input_cap == 0) workspace.limits.decoded_bytes else configured_limit;
    const decoded = try decoder.reader().allocRemaining(workspace.parser_scratch.allocator(), .limited(limit));
    const output_limit = if (output_cap == 0) workspace.output.len else @min(output_cap, workspace.output.len);
    var output: std.Io.Writer = .fixed(workspace.output[0..output_limit]);
    if (codec == .gzip and output_limit <= 8) return error.WriteFailed;
    var encoder: encoding.Encoder = try .init(codec, &output, workspace.encoder);
    defer encoder.deinit();
    const counts = try Prometheus.filter(store, &workspace.scratch, decoded, encoder.writer(), workspace.record.len);
    try encoder.finish();
    return .{
        .body = if (counts.dropped > 0) output.buffered() else original,
        .changed = counts.dropped > 0,
        .evaluated = counts.evaluated,
        .dropped = counts.dropped,
        .skipped = counts.skipped,
    };
}

const LogSink = struct {
    workspace: *Workspace,
    store: *PolicyStore,
    extension_sink: ?policy.ExtensionSink,
    parser: dd_logs.Parser = .init,
    evaluated: u64 = 0,
    skipped: u64 = 0,
    output_len: usize = 0,

    pub fn onRecord(self: *LogSink, bytes: []const u8) !framing.Decision {
        const record = std.mem.trim(u8, bytes, " \r\n\t");
        if (record.len == 0 or record[0] != '{') {
            self.skipped += 1;
            return .keep;
        }
        if (self.workspace.tap) |tap| tap.capture(.pre, "log", "json_array", "", bytes);
        self.workspace.scratch.reset();
        self.evaluated += 1;
        const verdict = try dd_logs.evalLogRecord(
            self.workspace.scratch.allocator(),
            &self.parser,
            self.workspace.parser_scratch.allocator(),
            &self.store.registry,
            self.store.registry.bus,
            bytes,
            self.extension_sink,
        );
        // Accessors/engine intentionally keep on some internal errors. Their
        // swallowed OOM must invalidate every earlier candidate transformation.
        if (self.workspace.scratch.denied or self.workspace.parser_scratch.denied) return error.OutOfMemory;
        if (self.workspace.tap) |tap| tap.capture(.post, "log", "json_array", @tagName(verdict), if (verdict == .replace) verdict.replace else bytes);
        return switch (verdict) {
            .keep => .keep,
            .drop => .drop,
            .replace => |value| .{ .replace = value },
        };
    }
};

fn run(workspace: *Workspace, original: []const u8, codec: encoding.ContentEncoding, sink: *LogSink) !framing.Stats {
    if (codec == .gzip and workspace.output.len <= 8) return error.WriteFailed;
    var source: std.Io.Reader = .fixed(original);
    var decoder: encoding.Decoder = .init(codec, &source, workspace.decoder, workspace.limits.zstd_window_bytes);
    var output: std.Io.Writer = .fixed(workspace.output);
    var encoder: encoding.Encoder = try .init(codec, &output, workspace.encoder);
    defer encoder.deinit();
    var framer: framing.Framer = .init(.json_array, workspace.record);
    var stack_bytes: [512]u8 = undefined;
    var stack: std.heap.FixedBufferAllocator = .init(&stack_bytes);
    var validator: std.json.Scanner = .initStreaming(stack.allocator());
    defer validator.deinit();
    var chunk: [4096]u8 = undefined;
    var total: usize = 0;
    while (true) {
        const count = try decoder.reader().readSliceShort(&chunk);
        if (count == 0) break;
        total += count;
        if (total > workspace.limits.decoded_bytes) return error.DecodedBodyTooLarge;
        validator.feedInput(chunk[0..count]);
        try validateAvailable(&validator);
        try framer.ingest(chunk[0..count], encoder.writer(), sink);
    }
    validator.endInput();
    try validateAvailable(&validator);
    try framer.finish(encoder.writer(), sink);
    try encoder.finish();
    sink.output_len = output.buffered().len;
    return framer.stats();
}

fn validateAvailable(scanner: *std.json.Scanner) !void {
    while (true) {
        const token = scanner.next() catch |err| switch (err) {
            error.BufferUnderrun => return,
            else => return err,
        };
        if (scanner.stackHeight() > 64) return error.NestingLimit;
        if (token == .end_of_document) return;
    }
}

const testing = std.testing;
const Fixture = struct {
    bus: policy.observability.NoopEventBus = undefined,
    store: PolicyStore = undefined,

    fn init(self: *Fixture) void {
        self.bus.init(testing.io);
        self.store = .init(testing.allocator, self.bus.eventBus());
    }

    fn load(self: *Fixture, json: []const u8) !void {
        const policies = try policy.parser.parsePoliciesBytes(testing.allocator, json);
        defer {
            for (policies) |*p| p.deinit(testing.allocator);
            testing.allocator.free(policies);
        }
        try self.store.update(testing.io, .{ .provider_id = "test", .policies = policies }, .file);
    }

    fn deinit(self: *Fixture) void {
        _ = self.store.deinit(testing.io);
        self.* = undefined;
    }
};
const DROP =
    \\{"policies":[{"id":"drop","name":"drop","log":{"match":[{"log_field":"body","regex":"drop"}],"keep":"none"}}]}
;

test "v2 processing commits drops once and preserves unchanged bytes" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(DROP);
    var workspace = try Workspace.init(testing.allocator, .{});
    defer workspace.deinit(testing.allocator);
    const result = logs(
        testing.io,
        &fixture.store,
        &workspace,
        "[ {\"message\":\"keep\"}, {\"message\":\"drop\"} ]",
        "",
        null,
    );
    try testing.expect(result.changed);
    try testing.expectEqual(2, result.evaluated);
    try testing.expectEqual(1, result.dropped);
    try testing.expectEqualStrings("[{\"message\":\"keep\"}]", result.body);
    const all = logs(testing.io, &fixture.store, &workspace, "[{\"message\":\"drop\"}]", "", null);
    try testing.expect(all.all_dropped);
    const original = "[  {\"message\":\"keep\"}  ]";
    const unchanged = logs(testing.io, &fixture.store, &workspace, original, "", null);
    try testing.expect(!unchanged.changed);
    try testing.expectEqual(@intFromPtr(original.ptr), @intFromPtr(unchanged.body.ptr));
}

test "v2 processing rejects malformed suffix and output exhaustion as whole-body fallback" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(DROP);
    var workspace = try Workspace.init(testing.allocator, .{ .output_bytes = 8 });
    defer workspace.deinit(testing.allocator);
    const originals = [_][]const u8{
        "[{\"message\":\"drop\"},{\"message\":\"keep\"}]",
        "[{\"message\":\"drop\"},]",
        "[{\"message\":\"drop\"}] garbage",
    };
    for (originals) |original| {
        const result = logs(testing.io, &fixture.store, &workspace, original, "", null);
        try testing.expect(!result.changed);
        try testing.expect(result.reason != .none);
        try testing.expectEqual(@intFromPtr(original.ptr), @intFromPtr(result.body.ptr));
    }
}

test "v2 processing no-policy and opaque-codec paths skip evaluation" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    var workspace = try Workspace.init(testing.allocator, .{});
    defer workspace.deinit(testing.allocator);
    const original = "opaque bytes";
    try testing.expectEqual(
        Reason.no_policies,
        logs(testing.io, &fixture.store, &workspace, original, "gzip", null).reason,
    );
    try fixture.load(DROP);
    try testing.expectEqual(
        Reason.unsupported,
        logs(testing.io, &fixture.store, &workspace, original, "alien", null).reason,
    );
    _ = fixture.store.pending_updates.fetchAdd(1, .acq_rel);
    defer _ = fixture.store.pending_updates.fetchSub(1, .release);
    try testing.expectEqual(Reason.busy, logs(testing.io, &fixture.store, &workspace, original, "", null).reason);
}

test "v2 processing transform and swallowed allocation failure retain transaction boundary" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(
        \\{"policies":[{"id":"redact","name":"redact","log":{"match":[{"log_field":"body","regex":"test"}],
        \\"keep":"all","transform":{"remove":[{"log_attribute":"service"}]}}}]}
    );
    const original = "[{\"message\":\"test\",\"service\":\"secret\"}]";
    var workspace = try Workspace.init(testing.allocator, .{});
    defer workspace.deinit(testing.allocator);
    const changed = logs(testing.io, &fixture.store, &workspace, original, "", null);
    try testing.expect(changed.changed);
    try testing.expect(std.mem.indexOf(u8, changed.body, "secret") == null);
    try testing.expectEqual(1, changed.evaluated);
    var tiny = try Workspace.init(testing.allocator, .{ .scratch_bytes = 1 });
    defer tiny.deinit(testing.allocator);
    const fallback = logs(testing.io, &fixture.store, &tiny, original, "", null);
    try testing.expectEqual(Reason.capacity, fallback.reason);
    try testing.expectEqualStrings(original, fallback.body);
}

test "v2 processing gzip and zstd candidates round trip and corrupt input stays encoded" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(DROP);
    var workspace = try Workspace.init(testing.allocator, .{ .zstd_window_bytes = 2 * 1024 * 1024 });
    defer workspace.deinit(testing.allocator);
    for ([_]encoding.ContentEncoding{ .gzip, .zstd }) |codec| {
        var bytes: [4096]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&bytes);
        var encoder: encoding.Encoder = try .init(codec, &writer, workspace.encoder);
        defer encoder.deinit();
        try encoder.writer().writeAll("[{\"message\":\"drop\"},{\"message\":\"keep\"}]");
        try encoder.finish();
        const result = logs(testing.io, &fixture.store, &workspace, writer.buffered(), @tagName(codec), null);
        try testing.expect(result.changed);
        var source: std.Io.Reader = .fixed(result.body);
        var decoder: encoding.Decoder = .init(codec, &source, workspace.decoder, workspace.limits.zstd_window_bytes);
        var decoded: [128]u8 = undefined;
        const count = try decoder.reader().readSliceShort(&decoded);
        try testing.expectEqualStrings("[{\"message\":\"keep\"}]", decoded[0..count]);
        const invalid = logs(testing.io, &fixture.store, &workspace, "broken", @tagName(codec), null);
        try testing.expect(!invalid.changed);
        try testing.expectEqualStrings("broken", invalid.body);
    }
}

const DeliveryProbe = struct {
    calls: usize = 0,
    before_transform: bool = true,

    fn resolve(
        _: std.Io,
        _: *anyopaque,
        _: policy.TelemetryType,
        _: []const u8,
        _: *const policy.proto.policy.Extension,
    ) ?policy.types.ExtensionResolution {
        return .{ .handler = 0, .slot = 0 };
    }

    fn deliver(
        ctx: *anyopaque,
        _: ?std.Io,
        _: policy.TelemetryType,
        record: *const anyopaque,
        _: *const policy.types.ExtensionBinding,
        _: policy.types.ExtensionSlice,
    ) void {
        const self: *DeliveryProbe = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.before_transform = self.before_transform and dd_logs.log_accessor.typed_value(record, .{
            .log_attribute = .{ .path = .{ .items = @constCast(&[_][]const u8{"service"}), .capacity = 1 } },
        }) != null;
    }
};

test "v2 extension delivery occurs once before transform even when output rolls back" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    var probe: DeliveryProbe = .{};
    try fixture.store.setExtensionResolver(testing.io, .{ .ctx = &probe, .resolve = DeliveryProbe.resolve });
    try fixture.load(
        \\{"policies":[{"id":"transform","name":"transform","log":{"match":[{"log_field":"body",
        \\"regex":"test"}],"keep":"all","transform":{"remove":[{"log_attribute":"service"}]}},
        \\"extensions":[{"type":"test/probe","mode":"all"}]}]}
    );
    var workspace = try Workspace.init(testing.allocator, .{ .output_bytes = 8 });
    defer workspace.deinit(testing.allocator);
    const original = "[{\"message\":\"test\",\"service\":\"secret\"}]";
    const result = logs(testing.io, &fixture.store, &workspace, original, "", .{
        .ctx = &probe,
        .deliver = DeliveryProbe.deliver,
    });
    try testing.expectEqualStrings(original, result.body);
    try testing.expectEqual(1, probe.calls);
    try testing.expect(probe.before_transform);
    try testing.expectEqual(1, result.evaluated);
}

test "v2 nested formats apply policies and preserve unchanged original envelopes" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(DROP);
    var workspace = try Workspace.init(testing.allocator, .{});
    defer workspace.deinit(testing.allocator);
    const original =
        \\{"resourceLogs":[{"resource":{"attributes":[]},"scopeLogs":[{"logRecords":[
        \\{"body":{"stringValue":"drop"}},{"body":{"stringValue":"keep"}}]}]}]}
    ;
    const result = nested(testing.io, &fixture.store, &workspace, original, "", "application/json", .otlp_logs);
    try testing.expect(result.changed);
    try testing.expectEqual(2, result.evaluated);
    try testing.expectEqual(1, result.dropped);
    try testing.expect(std.mem.indexOf(u8, result.body, "drop") == null);
    try testing.expect(std.mem.indexOf(u8, result.body, "keep") != null);
    const invalid = nested(testing.io, &fixture.store, &workspace, "{invalid", "", "application/json", .otlp_logs);
    try testing.expectEqualStrings("{invalid", invalid.body);
    try testing.expect(!invalid.changed);
}

test "v2 prometheus preserves metadata and long lines while filtering complete samples" {
    var fixture: Fixture = .{};
    fixture.init();
    defer fixture.deinit();
    try fixture.load(
        \\{"policies":[{"id":"metric","name":"metric","metric":{
        \\"match":[{"metric_field":"name","regex":"^drop$"}],"keep":false}}]}
    );
    var workspace = try Workspace.init(testing.allocator, .{ .record_bytes = 64 });
    defer workspace.deinit(testing.allocator);
    const original = "# HELP drop description\n# TYPE drop counter\ndrop 1\nkeep 2\n" ++
        "drop{label=\"" ++ "x" ** 100 ++ "\"} 3\n";
    const result = prometheus(testing.io, &fixture.store, &workspace, original, "", 0, 0);
    try testing.expect(result.changed);
    try testing.expectEqual(1, result.dropped);
    try testing.expectEqual(1, result.skipped);
    try testing.expect(std.mem.indexOf(u8, result.body, "drop 1") == null);
    try testing.expect(std.mem.indexOf(u8, result.body, "x" ** 100) != null);
    try testing.expect(std.mem.indexOf(u8, result.body, "# HELP drop description") != null);
    const limited = prometheus(testing.io, &fixture.store, &workspace, original, "", 10, 0);
    try testing.expectEqualStrings(original, limited.body);
}
