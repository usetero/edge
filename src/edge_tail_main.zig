const std = @import("std");
const zonfig = @import("zonfig/root.zig");
const crash = @import("runtime/crash.zig");

// ReleaseFast turns std's crash handler off. Keep it on, so a crash prints
// the fault and a stack unwound from it. See runtime/crash.zig.
pub const std_options: std.Options = .{ .enable_segfault_handler = true };
pub const debug = crash.debug;
const tail_mod = @import("tail/mod.zig");

const RuntimeTailConfig = tail_mod.types.TailConfig;
const ReadFrom = tail_mod.types.ReadFrom;
const InputFormat = tail_mod.types.InputFormat;
const IoEngine = tail_mod.types.IoEngine;

/// Numeric CLI flags. Each value is parsed with the type of its config field.
const NumericFlag = struct { flag: []const u8, field: []const u8 };
const numeric_flags = [_]NumericFlag{
    .{ .flag = "--poll-ms", .field = "poll_ms" },
    .{ .flag = "--glob-interval-ms", .field = "glob_interval_ms" },
    .{ .flag = "--rotate-wait-ms", .field = "rotate_wait_ms" },
    .{ .flag = "--removed-expire-ms", .field = "removed_expire_ms" },
    .{ .flag = "--checkpoint-interval-ms", .field = "checkpoint_interval_ms" },
    .{ .flag = "--checkpoint-sync-batch", .field = "checkpoint_sync_batch" },
    .{ .flag = "--checkpoint-snapshot-interval-ms", .field = "checkpoint_snapshot_interval_ms" },
    .{ .flag = "--checkpoint-ttl-ms", .field = "checkpoint_ttl_ms" },
    .{ .flag = "--checkpoint-max-slots", .field = "checkpoint_max_slots" },
    .{ .flag = "--read-buf", .field = "read_buf" },
    .{ .flag = "--max-line", .field = "max_line" },
    .{ .flag = "--write-buf", .field = "write_buf" },
    .{ .flag = "--flush-interval-ms", .field = "flush_interval_ms" },
    .{ .flag = "--flush-lines", .field = "flush_line_threshold" },
};

const CliOptions = struct {
    config_path: ?[]const u8 = null,
    output_override: ?[]const u8 = null,
    read_from_override: ?ReadFrom = null,
    format_override: ?InputFormat = null,
    policy_path_override: ?[]const u8 = null,
    io_engine_override: ?IoEngine = null,
    verbose_increment: u8 = 0,
    state_dir_override: ?[]const u8 = null,
    numeric: [numeric_flags.len]?u64 = @splat(null),
    inputs: std.ArrayList([]const u8),

    fn deinit(self: *CliOptions, allocator: std.mem.Allocator) void {
        if (self.config_path) |path| allocator.free(path);
        if (self.output_override) |path| allocator.free(path);
        if (self.policy_path_override) |path| allocator.free(path);
        if (self.state_dir_override) |path| allocator.free(path);
        for (self.inputs.items) |input| allocator.free(input);
        self.inputs.deinit(allocator);
        self.* = undefined;
    }
};

fn printUsage(io: std.Io) !void {
    var stderr_buf: [2300]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    try stderr.writeAll(
        \\Usage: edge-tail [OPTIONS] [PATH...]
        \\
        \\Options:
        \\  -c, --config <PATH>      Config JSON path (zonfig)
        \\  -o, --output <PATH>      Output path ('-' for stdout)
        \\      --read-from <MODE>   head|tail|checkpoint
        \\  -f, --format <FMT>       raw|json|logfmt
        \\  -p, --policy <PATH>      Policy JSON file path
        \\      --io-engine <ENG>    auto|uring|kqueue|poll|inotify|epoll
        \\      --poll-ms <MS>       Poll interval in milliseconds
        \\      --glob-interval-ms <MS>  Glob re-evaluation interval
        \\      --rotate-wait-ms <MS>  Drain old fd before switching on rotation
        \\      --removed-expire-ms <MS>  Expire unmatched tracked files after grace
        \\      --checkpoint-interval-ms <MS>  Background checkpoint flush cadence
        \\      --checkpoint-sync-batch <N>    WAL records before sync
        \\      --checkpoint-snapshot-interval-ms <MS>  Snapshot rewrite cadence
        \\      --checkpoint-ttl-ms <MS>   Expire stale checkpoint entries after age
        \\      --checkpoint-max-slots <N> Max tracked checkpoint slots
        \\      --state-dir <PATH>      Checkpoint state directory
        \\      --read-buf <BYTES>   Read buffer size in bytes
        \\      --max-line <BYTES>   Max line length in bytes
        \\      --write-buf <BYTES>  Write buffer size in bytes
        \\      --flush-interval-ms <MS> Writer flush cadence in milliseconds
        \\      --flush-lines <N>     Flush writer after this many processed events
        \\      PATH                 Input file path(s), or '-' for stdin
        \\  -v, --verbose            Increase startup verbosity
        \\  -h, --help               Show this help
        \\
        \\Config precedence: CLI > env (TERO_*) > config file > defaults
        \\
    );

    try stderr.flush();
}

fn parseCliOptions(init: std.process.Init) !CliOptions {
    const allocator = init.gpa;
    const io = init.io;

    var it = init.minimal.args.iterate();
    _ = it.skip(); // program name

    var opts: CliOptions = .{ .inputs = .empty };
    errdefer opts.deinit(allocator);

    args: while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printUsage(io);
            return error.HelpRequested;
        }

        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            const v = it.next() orelse return error.MissingOptionValue;
            if (opts.config_path) |old| allocator.free(old);
            opts.config_path = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            const v = it.next() orelse return error.MissingOptionValue;
            if (opts.output_override) |old| allocator.free(old);
            opts.output_override = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--read-from")) {
            const v = it.next() orelse return error.MissingOptionValue;
            opts.read_from_override = std.meta.stringToEnum(ReadFrom, v) orelse return error.InvalidReadFrom;
            continue;
        }
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--format")) {
            const v = it.next() orelse return error.MissingOptionValue;
            opts.format_override = std.meta.stringToEnum(InputFormat, v) orelse return error.InvalidFormat;
            continue;
        }
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--policy")) {
            const v = it.next() orelse return error.MissingOptionValue;
            if (opts.policy_path_override) |old| allocator.free(old);
            opts.policy_path_override = try allocator.dupe(u8, v);
            continue;
        }
        if (std.mem.eql(u8, arg, "--io-engine")) {
            const v = it.next() orelse return error.MissingOptionValue;
            opts.io_engine_override = std.meta.stringToEnum(IoEngine, v) orelse return error.InvalidIoEngine;
            continue;
        }
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            if (opts.verbose_increment < std.math.maxInt(u8)) opts.verbose_increment += 1;
            continue;
        }
        inline for (numeric_flags, 0..) |nf, i| {
            if (std.mem.eql(u8, arg, nf.flag)) {
                const v = it.next() orelse return error.MissingOptionValue;
                opts.numeric[i] = try std.fmt.parseInt(@FieldType(RuntimeTailConfig, nf.field), v, 10);
                continue :args;
            }
        }
        if (std.mem.eql(u8, arg, "--state-dir")) {
            const v = it.next() orelse return error.MissingOptionValue;
            if (opts.state_dir_override) |old| allocator.free(old);
            opts.state_dir_override = try allocator.dupe(u8, v);
            continue;
        }

        if (!std.mem.eql(u8, arg, "-") and std.mem.startsWith(u8, arg, "-")) return error.UnknownOption;

        try opts.inputs.append(allocator, try allocator.dupe(u8, arg));
    }

    return opts;
}

fn useStdinMode(inputs: []const []const u8) bool {
    if (inputs.len == 0) return true;
    return inputs.len == 1 and std.mem.eql(u8, inputs[0], "-");
}

fn validate(opts: CliOptions, cfg: RuntimeTailConfig) !void {
    if (opts.inputs.items.len > 1) {
        for (opts.inputs.items) |input| {
            if (std.mem.eql(u8, input, "-")) return error.InvalidInputCombination;
        }
    }

    try tail_mod.types.validateConfig(cfg);
}

pub fn main(init: std.process.Init) !void {
    crash.setDistribution("tail");
    const allocator = init.gpa;
    const io = init.io;

    var opts = parseCliOptions(init) catch |err| switch (err) {
        error.HelpRequested => return,
        else => return err,
    };
    defer opts.deinit(allocator);

    const loaded_cfg = try zonfig.load(RuntimeTailConfig, allocator, io, .{
        .json_path = opts.config_path,
        .env_prefix = "TERO",
        .allow_env_only = opts.config_path == null,
        .environ = init.environ_map,
    });
    defer zonfig.deinit(RuntimeTailConfig, allocator, loaded_cfg);

    var cfg = loaded_cfg.*;
    if (opts.output_override) |v| cfg.output_path = v;
    if (opts.read_from_override) |v| cfg.read_from = v;
    if (opts.format_override) |v| cfg.input_format = v;
    if (opts.policy_path_override) |v| cfg.policy_path = v;
    if (opts.io_engine_override) |v| cfg.io_engine = v;
    if (opts.state_dir_override) |v| cfg.state_dir = v;
    inline for (numeric_flags, opts.numeric) |nf, value| {
        if (value) |v| @field(cfg, nf.field) = @intCast(v);
    }
    cfg.io_engine = tail_mod.types.normalizeIoEngine(cfg.io_engine);

    try validate(opts, cfg);

    if (opts.verbose_increment > 0) {
        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = std.Io.File.stderr().writer(io, &stderr_buf);
        const stderr = &stderr_writer.interface;
        try stderr.print(
            "edge-tail: read_from={s} format={s} io_engine={s} poll_ms={d} " ++
                "glob_interval_ms={d} state_dir={s} policy={s}\n",
            .{
                @tagName(cfg.read_from),
                @tagName(cfg.input_format),
                @tagName(cfg.io_engine),
                cfg.poll_ms,
                cfg.glob_interval_ms,
                cfg.state_dir,
                cfg.policy_path orelse "(none)",
            },
        );
        try stderr.flush();
    }

    if (useStdinMode(opts.inputs.items)) {
        try tail_mod.runtime.runStdinToOutput(allocator, io, init.environ_map, cfg);
        return;
    }

    try tail_mod.runtime.runFilesToOutput(allocator, io, init.environ_map, cfg, opts.inputs.items);
}
