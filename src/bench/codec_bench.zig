//! Decode and encode of gzip and zstd request bodies: `codec` against the
//! std implementations. The std decoders are unsafe on bad input in Zig
//! 0.16.0 and the edge does not use them; they are here as the reference
//! for why. The comparison with the code `codec` replaced is in
//! bench/matrix/lab-notebook.md ("Codec rewrite").
//!
//! Every decode reads 4 KiB chunks (`CHUNK_BUF_BYTES`), as the pipeline does.
//! The bodies are JSON log batches, shaped like Datadog agent output.
//!
//! Run with: `zig build codec-bench -Doptimize=ReleaseFast`.
const std = @import("std");
const zbench = @import("zbench");
const edge = @import("edge");

const codec = edge.codec;
const buffered = codec.fixtures;
const CHUNK = edge.core_limits.CHUNK_BUF_BYTES;
/// `ZSTD_WINDOW_MAX`. A 2 MiB single-segment frame needs a 2 MiB window, so
/// the 1 MiB default would refuse it on both paths.
const WINDOW: usize = 8 << 20;
const MAX_OUTPUT: usize = 16 << 20;

/// One body at one size: its plain bytes and each compressed form.
const Body = struct {
    label: []const u8,
    plain: []u8,
    gzip: []u8,
    zstd: []u8,
    zstd_unsized: []u8,
};

const levels = [_][]const u8{ "INFO", "DEBUG", "WARN", "ERROR" };
const statuses = [_]u16{ 200, 201, 404, 500 };

fn jsonLogs(gpa: std.mem.Allocator, rand: std.Random, approx: usize) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    try out.writer.writeByte('[');
    var n: usize = 0;
    while (out.written().len < approx) : (n += 1) {
        if (n != 0) try out.writer.writeByte(',');
        const level = levels[rand.uintLessThan(usize, levels.len)];
        const status = statuses[rand.uintLessThan(usize, statuses.len)];
        try out.writer.print(
            "{{\"message\":\"{s} orders-api request id={x} path=/api/v2/items/{d} status={d} took={d}ms\"," ++
                "\"status\":\"{s}\",\"service\":\"orders-api\",\"ddsource\":\"java\"," ++
                "\"ddtags\":\"env:prod,cell:one,version:1.32.0\",\"hostname\":\"ip-10-0-{d}-{d}\"}}",
            .{
                level,                           rand.int(u64),
                rand.uintLessThan(u32, 100_000), status,
                rand.uintLessThan(u32, 900),     level,
                rand.uintLessThan(u8, 255),      rand.uintLessThan(u8, 255),
            },
        );
    }
    try out.writer.writeByte(']');
    return out.toOwnedSlice();
}

// ------------------------------------------------------------- decode

var chunk_buf: [CHUNK]u8 = undefined;
var window_buf: []u8 = undefined;
var new_decoder: codec.Decoder = undefined;

const StdGzipDecode = struct {
    raw: []const u8,

    pub fn run(self: *StdGzipDecode, _: std.mem.Allocator) void {
        var in: std.Io.Reader = .fixed(self.raw);
        const window = window_buf[0..std.compress.flate.max_window_len];
        var decompress: std.compress.flate.Decompress = .init(&in, .gzip, window);
        var total: usize = 0;
        while (true) {
            const n = decompress.reader.readSliceShort(&chunk_buf) catch |err| std.debug.panic("std gzip: {t}", .{err});
            if (n == 0) break;
            total += n;
        }
        std.mem.doNotOptimizeAway(total);
    }
};

const StdZstdDecode = struct {
    raw: []const u8,

    pub fn run(self: *StdZstdDecode, _: std.mem.Allocator) void {
        var in: std.Io.Reader = .fixed(self.raw);
        var decompress: std.compress.zstd.Decompress = .init(&in, window_buf, .{ .window_len = WINDOW });
        var total: usize = 0;
        while (true) {
            const n = decompress.reader.readSliceShort(&chunk_buf) catch |err| std.debug.panic("std zstd: {t}", .{err});
            if (n == 0) break;
            total += n;
        }
        std.mem.doNotOptimizeAway(total);
    }
};

const NewDecode = struct {
    which: codec.Codec,
    raw: []const u8,

    pub fn run(self: *NewDecode, _: std.mem.Allocator) void {
        new_decoder.begin(self.which, self.raw, .{ .max_output = MAX_OUTPUT, .window_len = WINDOW }) catch |err|
            std.debug.panic("new begin: {t}", .{err});
        var total: usize = 0;
        while (true) {
            const n = new_decoder.read(&chunk_buf) catch |err| std.debug.panic("new decode: {t}", .{err});
            if (n == 0) break;
            total += n;
        }
        std.mem.doNotOptimizeAway(total);
    }
};

// ------------------------------------------------------------- encode

var out_buf: []u8 = undefined;
var staging: [CHUNK]u8 = undefined;
var new_encoder: codec.Encoder = undefined;

const StdGzipEncode = struct {
    plain: []const u8,

    pub fn run(self: *StdGzipEncode, _: std.mem.Allocator) void {
        var out: std.Io.Writer = .fixed(out_buf);
        const window = window_buf[0..std.compress.flate.max_window_len];
        var compress = std.compress.flate.Compress.init(&out, window, .gzip, .default) catch |err|
            std.debug.panic("std encoder: {t}", .{err});
        writeChunks(&compress.writer, self.plain);
        compress.finish() catch |err| std.debug.panic("std finish: {t}", .{err});
        std.mem.doNotOptimizeAway(out.end);
    }
};

const NewEncode = struct {
    which: codec.Codec,
    plain: []const u8,

    pub fn run(self: *NewEncode, _: std.mem.Allocator) void {
        var out: std.Io.Writer = .fixed(out_buf);
        new_encoder.begin(self.which, &out) catch |err| std.debug.panic("new encoder: {t}", .{err});
        writeChunks(&new_encoder.writer, self.plain);
        new_encoder.finish() catch |err| std.debug.panic("new finish: {t}", .{err});
        std.mem.doNotOptimizeAway(out.end);
    }
};

/// The framer writes records one at a time, so write in record-sized pieces.
fn writeChunks(w: *std.Io.Writer, plain: []const u8) void {
    var rest = plain;
    while (rest.len != 0) {
        const n = @min(rest.len, 200);
        w.writeAll(rest[0..n]) catch |err| std.debug.panic("write: {t}", .{err});
        rest = rest[n..];
    }
}

fn encodedLen(which: codec.Codec, gpa: std.mem.Allocator, plain: []const u8) !usize {
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try new_encoder.begin(which, &out.writer);
    try new_encoder.writer.writeAll(plain);
    try new_encoder.finish();
    return out.written().len;
}

fn stdGzipLen(gpa: std.mem.Allocator, plain: []const u8) !usize {
    // std flate asserts that its output can hold at least 8 bytes.
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer out.deinit();
    const window = window_buf[0..std.compress.flate.max_window_len];
    var compress: std.compress.flate.Compress = try .init(&out.writer, window, .gzip, .default);
    try compress.writer.writeAll(plain);
    try compress.finish();
    return out.written().len;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var prng: std.Random.DefaultPrng = .init(0xbe4c);
    const rand = prng.random();

    window_buf = try gpa.alloc(u8, WINDOW + std.compress.zstd.block_size_max);
    defer gpa.free(window_buf);
    new_decoder = try .init(gpa);
    defer new_decoder.deinit(gpa);
    new_encoder = try .init(gpa, &staging);
    defer new_encoder.deinit(gpa);

    var bodies: [3]Body = undefined;
    const sizes = [_]struct { []const u8, usize }{
        .{ "16 KiB", 16 << 10 },
        .{ "256 KiB", 256 << 10 },
        .{ "2 MiB", 2 << 20 },
    };
    for (&bodies, sizes) |*body, size| {
        const plain = try jsonLogs(gpa, rand, size[1]);
        body.* = .{
            .label = size[0],
            .plain = plain,
            .gzip = try buffered.compressGzip(gpa, plain),
            .zstd = try buffered.compressZstdWith(gpa, plain, .{}),
            .zstd_unsized = try buffered.compressZstdWith(gpa, plain, .{ .content_size = false }),
        };
    }
    defer for (bodies) |body| {
        gpa.free(body.plain);
        gpa.free(body.gzip);
        gpa.free(body.zstd);
        gpa.free(body.zstd_unsized);
    };
    out_buf = try gpa.alloc(u8, bodies[2].plain.len + (1 << 16));
    defer gpa.free(out_buf);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
    const stdout = &stdout_writer.interface;
    try stdout.print("Compressed sizes (plain -> std gzip / codec gzip / codec zstd):\n", .{});
    for (bodies) |body| {
        try stdout.print("  {s:<8} {d:>8} -> {d:>7} / {d:>7} / {d:>7}\n", .{
            body.label,
            body.plain.len,
            try stdGzipLen(gpa, body.plain),
            try encodedLen(.gzip, gpa, body.plain),
            try encodedLen(.zstd, gpa, body.plain),
        });
    }
    try stdout.print("\n", .{});
    try stdout.flush();

    var bench = zbench.Benchmark.init(gpa, .{ .time_budget_ns = 1 * std.time.ns_per_s });
    defer bench.deinit();

    var std_gz: [3]StdGzipDecode = undefined;
    var new_gz: [3]NewDecode = undefined;
    var std_zs: [3]StdZstdDecode = undefined;
    var new_zs: [3]NewDecode = undefined;
    var new_zs_unsized: [3]NewDecode = undefined;
    var std_enc_gz: [3]StdGzipEncode = undefined;
    var new_enc_gz: [3]NewEncode = undefined;
    var new_enc_zs: [3]NewEncode = undefined;
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |name| gpa.free(name);
        names.deinit(gpa);
    }
    for (bodies, 0..) |body, i| {
        std_gz[i] = .{ .raw = body.gzip };
        new_gz[i] = .{ .which = .gzip, .raw = body.gzip };
        std_zs[i] = .{ .raw = body.zstd };
        new_zs[i] = .{ .which = .zstd, .raw = body.zstd };
        new_zs_unsized[i] = .{ .which = .zstd, .raw = body.zstd_unsized };
        std_enc_gz[i] = .{ .plain = body.plain };
        new_enc_gz[i] = .{ .which = .gzip, .plain = body.plain };
        new_enc_zs[i] = .{ .which = .zstd, .plain = body.plain };
    }
    for (0..3) |i| {
        const label = bodies[i].label;
        try addNamed(&bench, gpa, &names, "gzip decode, std  ", label, &std_gz[i]);
        try addNamed(&bench, gpa, &names, "gzip decode, codec", label, &new_gz[i]);
        try addNamed(&bench, gpa, &names, "zstd decode, std  ", label, &std_zs[i]);
        try addNamed(&bench, gpa, &names, "zstd decode, codec", label, &new_zs[i]);
        try addNamed(&bench, gpa, &names, "zstd decode, codec, no size", label, &new_zs_unsized[i]);
        try addNamed(&bench, gpa, &names, "gzip encode, std  ", label, &std_enc_gz[i]);
        try addNamed(&bench, gpa, &names, "gzip encode, codec", label, &new_enc_gz[i]);
        try addNamed(&bench, gpa, &names, "zstd encode, codec", label, &new_enc_zs[i]);
    }
    try bench.run(init.io, std.Io.File.stdout());
}

fn addNamed(
    bench: *zbench.Benchmark,
    gpa: std.mem.Allocator,
    names: *std.ArrayList([]u8),
    what: []const u8,
    label: []const u8,
    benchmark: anytype,
) !void {
    const name = try std.fmt.allocPrint(gpa, "{s} {s}", .{ what, label });
    try names.append(gpa, name);
    try bench.addParam(name, @as(*const @TypeOf(benchmark.*), benchmark), .{});
}
