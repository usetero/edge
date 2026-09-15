//! Measured stack and dependency state sizes that thread stack budgets rely on.
//! The probe paints a fresh thread stack, runs one workload, and scans for the
//! deepest clobbered byte; ceilings below are locked to the recorded numbers.
const std = @import("std");
const policy = @import("policy_zig");
const flate = std.compress.flate;
const c = @cImport(@cInclude("zstd.h"));

/// Thread stack used while running the probe workloads; the painted region
/// must exceed the largest expected high-water with a page of slack each side.
pub const probe_stack_bytes: usize = 4 * 1024 * 1024;
const paint_bytes: usize = 3 * 1024 * 1024;
const paint: u8 = 0x5A;

pub const Workload = enum { gzip_compress, gzip_decompress, policy_evaluate };

const Probe = struct {
    io: std.Io,
    workload: Workload,
    /// Compiled on the calling thread so the data-path measurement excludes
    /// registry compilation, which is control-plane work.
    registry: ?*policy.Registry = null,
    used_bytes: usize = 0,
    err: ?anyerror = null,
};

/// Run one workload on a fresh thread and report its stack high-water mark.
pub fn measure(io: std.Io, workload: Workload) !usize {
    var probe: Probe = .{ .io = io, .workload = workload };
    var bus: policy.observability.NoopEventBus = undefined;
    bus.init(io);
    var registry: policy.Registry = .init(std.heap.page_allocator, bus.eventBus());
    defer registry.deinit();
    if (workload == .policy_evaluate) {
        try compileProbePolicy(&registry);
        probe.registry = &registry;
    }
    const thread = try std.Thread.spawn(.{ .stack_size = probe_stack_bytes }, run, .{&probe});
    thread.join();
    if (probe.err) |err| return err;
    return probe.used_bytes;
}

fn run(probe: *Probe) void {
    @call(.never_inline, paintBelow, .{});
    const base = @frameAddress();
    @call(.never_inline, execute, .{probe}) catch |err| {
        probe.err = err;
    };
    probe.used_bytes = @call(.never_inline, scanBelow, .{base});
}

/// Paint the region the workload frames will grow into.
fn paintBelow() void {
    var canvas: [paint_bytes]u8 = undefined;
    @memset(&canvas, paint);
    std.mem.doNotOptimizeAway(&canvas);
}

/// Deepest byte no longer holding the paint marks the high-water; the top and
/// bottom pages are excluded because sibling frames straddle them.
fn scanBelow(base: usize) usize {
    const page = 4096;
    const bytes: [*]const u8 = @ptrFromInt(base - paint_bytes);
    var index: usize = page;
    while (index < paint_bytes - page and bytes[index] == paint) index += 1;
    return paint_bytes - index;
}

fn execute(probe: *Probe) !void {
    // Never inline: otherwise ReleaseSafe merges every workload's locals into
    // one frame and each measurement reports the union (~600 KiB).
    switch (probe.workload) {
        .gzip_compress => try @call(.never_inline, gzipCompress, .{}),
        .gzip_decompress => try @call(.never_inline, gzipDecompress, .{}),
        .policy_evaluate => try @call(.never_inline, policyEvaluate, .{ probe.io, probe.registry.? }),
    }
}

fn payload() [64 * 1024]u8 {
    var bytes: [64 * 1024]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(7);
    for (&bytes, 0..) |*byte, i| byte.* = if (i % 3 == 0) prng.random().int(u8) else 'a';
    return bytes;
}

fn gzipCompress() !void {
    var sink: [64]u8 = undefined;
    var discarding: std.Io.Writer.Discarding = .init(&sink);
    var window: [flate.max_window_len]u8 = undefined;
    var compress = try flate.Compress.init(&discarding.writer, &window, .gzip, .default);
    const bytes = payload();
    try compress.writer.writeAll(&bytes);
    try compress.finish();
}

fn gzipDecompress() !void {
    var compressed: [80 * 1024]u8 = undefined;
    var fixed: std.Io.Writer = .fixed(&compressed);
    var window: [flate.max_window_len]u8 = undefined;
    {
        var compress = try flate.Compress.init(&fixed, &window, .gzip, .default);
        const bytes = payload();
        try compress.writer.writeAll(&bytes);
        try compress.finish();
    }
    var reader: std.Io.Reader = .fixed(fixed.buffered());
    var decompress: flate.Decompress = .init(&reader, .gzip, &window);
    var sink: [64]u8 = undefined;
    var discarding: std.Io.Writer.Discarding = .init(&sink);
    _ = try decompress.reader.streamRemaining(&discarding.writer);
}

fn compileProbePolicy(registry: *policy.Registry) !void {
    const policies = try policy.parser.parsePoliciesBytes(std.heap.page_allocator,
        \\{"policies":[{"id":"drop-errors","name":"drop-errors","log":{
        \\  "match":[{"log_field":"body","regex":"error [0-9]+"}],"keep":"none"
        \\}}]}
    );
    defer {
        for (policies) |*p| p.deinit(std.heap.page_allocator);
        std.heap.page_allocator.free(policies);
    }
    try registry.updatePolicies(policies, "probe", .file);
}

fn policyEvaluate(io: std.Io, registry: *policy.Registry) !void {
    var engine: policy.PolicyEngine = .init(registry.bus, registry);
    var ids: [256][]const u8 = undefined;
    var record: TestLog = .{ .body = "error 500 while probing" };
    const outcome = engine.evaluate(.log, &TestLog.accessor, &record, &ids, .{ .io = io });
    if (outcome.decision != .drop) return error.ProbePolicyDidNotMatch;
}

const TestLog = struct {
    body: []const u8,
    const accessor: policy.LogAccessor = .{ .typed_value = typedValue };

    fn typedValue(ctx: *const anyopaque, field: policy.FieldRef) ?policy.TypedValue {
        const record: *const TestLog = @ptrCast(@alignCast(ctx));
        return switch (field) {
            .log_field => |f| if (f == .LOG_FIELD_BODY) .{ .string = record.body } else null,
            else => null,
        };
    }
};

/// Bytes libzstd holds for one compression context after a level-3 compress.
pub fn zstdContextBytes() !usize {
    const cctx = c.ZSTD_createCCtx() orelse return error.OutOfMemory;
    defer _ = c.ZSTD_freeCCtx(cctx);
    if (c.ZSTD_isError(c.ZSTD_CCtx_setParameter(cctx, c.ZSTD_c_compressionLevel, 3)) != 0) return error.ZstdParameter;
    const bytes = payload();
    var out: [80 * 1024]u8 = undefined;
    const written = c.ZSTD_compress2(cctx, &out, out.len, &bytes, bytes.len);
    if (c.ZSTD_isError(written) != 0) return error.ZstdCompress;
    return c.ZSTD_sizeof_CCtx(cctx);
}

const testing = std.testing;

test "v2 stack probe: dependency state sizes are recorded" {
    // std flate compressor state alone exceeds a 256 KiB thread stack reservation
    // once frames are added; these are the exact Debug sizes on this toolchain.
    try testing.expect(@sizeOf(flate.Compress) > 200 * 1024);
    try testing.expect(@sizeOf(flate.Compress) < 320 * 1024);
    try testing.expect(@sizeOf(flate.Decompress) < 64 * 1024);
    try testing.expect(@sizeOf(std.compress.zstd.Decompress) < 64 * 1024);
    try testing.expect(@sizeOf(std.crypto.tls.Client) < 4 * 1024);
    try testing.expect(@sizeOf(policy.PolicyEngine) < 1024);
}

test "v2 stack probe: gzip and policy workloads fit the measured ceilings" {
    const io = testing.io;
    const compress = try measure(io, .gzip_compress);
    const decompress = try measure(io, .gzip_decompress);
    const evaluate = try measure(io, .policy_evaluate);
    // Measured 2026-09-14 (macOS arm64 / Linux aarch64 musl, 64 KiB payload):
    //   Debug        compress 1,118,272  decompress 1,207,200  evaluate 20,160
    //   ReleaseSafe  compress   533,216  decompress   625,184  evaluate  7,728
    // A 256 KiB stack cannot host gzip in either mode before request frames.
    try testing.expect(compress > @sizeOf(flate.Compress));
    try testing.expect(compress < 2 * 1024 * 1024);
    try testing.expect(decompress < 2 * 1024 * 1024);
    try testing.expect(evaluate < 64 * 1024);
}

test "v2 stack probe: libzstd context bytes are observable through the C API" {
    const bytes = try zstdContextBytes();
    try testing.expect(bytes > 64 * 1024);
    try testing.expect(bytes < 8 * 1024 * 1024);
}
