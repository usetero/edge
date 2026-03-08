const std = @import("std");
const zonfig = @import("zonfig/root.zig");
const tail_mod = @import("tail/mod.zig");

const RuntimeTailConfig = tail_mod.types.TailConfig;
const ReadFrom = tail_mod.types.ReadFrom;
const InputFormat = tail_mod.types.InputFormat;
const IoEngine = tail_mod.types.IoEngine;

const CliOptions = struct {
    config_path: ?[]const u8 = null,
    output_override: ?[]const u8 = null,
    read_from_override: ?ReadFrom = null,
    format_override: ?InputFormat = null,
    policy_path_override: ?[]const u8 = null,
    io_engine_override: ?IoEngine = null,
    verbose_increment: u8 = 0,
    poll_ms_override: ?u64 = null,
    glob_interval_ms_override: ?u64 = null,
    rotate_wait_ms_override: ?u64 = null,
    removed_expire_ms_override: ?u64 = null,
    checkpoint_interval_ms_override: ?u64 = null,
    checkpoint_sync_batch_override: ?u32 = null,
    checkpoint_snapshot_interval_ms_override: ?u64 = null,
    checkpoint_ttl_ms_override: ?u64 = null,
    checkpoint_max_slots_override: ?usize = null,
    state_dir_override: ?[]const u8 = null,
    read_buf_override: ?usize = null,
    max_line_override: ?usize = null,
    write_buf_override: ?usize = null,
    flush_interval_ms_override: ?u64 = null,
    flush_line_threshold_override: ?usize = null,
    inputs: std.ArrayList([]const u8),

    fn deinit(self: *CliOptions, allocator: std.mem.Allocator) void {
        if (self.config_path) |path| allocator.free(path);
        if (self.output_override) |path| allocator.free(path);
        if (self.policy_path_override) |path| allocator.free(path);
        if (self.state_dir_override) |path| allocator.free(path);
        for (self.inputs.items) |input| allocator.free(input);
        self.inputs.deinit(allocator);
    }
};

fn printUsage() !void {
    var stderr_buf: [2300]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
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

fn parseReadFrom(value: []const u8) !ReadFrom {
    if (std.mem.eql(u8, value, "head")) return .head;
    if (std.mem.eql(u8, value, "tail")) return .tail;
    if (std.mem.eql(u8, value, "checkpoint")) return .checkpoint;
    return error.InvalidReadFrom;
}

fn parseInputFormat(value: []const u8) !InputFormat {
    if (std.mem.eql(u8, value, "raw")) return .raw;
    if (std.mem.eql(u8, value, "json")) return .json;
    if (std.mem.eql(u8, value, "logfmt")) return .logfmt;
    return error.InvalidFormat;
}

fn parseIoEngine(value: []const u8) !IoEngine {
    if (std.mem.eql(u8, value, "auto")) return .auto;
    if (std.mem.eql(u8, value, "uring")) return .uring;
    if (std.mem.eql(u8, value, "kqueue")) return .kqueue;
    if (std.mem.eql(u8, value, "poll")) return .poll;
    if (std.mem.eql(u8, value, "inotify")) return .inotify;
    if (std.mem.eql(u8, value, "epoll")) return .epoll;
    return error.InvalidIoEngine;
}

fn parseCliOptions(allocator: std.mem.Allocator) !CliOptions {
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var opts = CliOptions{ .inputs = .{} };
    errdefer opts.deinit(allocator);

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printUsage();
            return error.HelpRequested;
        }

        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            if (opts.config_path) |old| allocator.free(old);
            opts.config_path = try allocator.dupe(u8, args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            if (opts.output_override) |old| allocator.free(old);
            opts.output_override = try allocator.dupe(u8, args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--read-from")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.read_from_override = try parseReadFrom(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--format")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.format_override = try parseInputFormat(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--policy")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            if (opts.policy_path_override) |old| allocator.free(old);
            opts.policy_path_override = try allocator.dupe(u8, args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--io-engine")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.io_engine_override = try parseIoEngine(args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--verbose")) {
            if (opts.verbose_increment < std.math.maxInt(u8)) opts.verbose_increment += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--poll-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.poll_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--glob-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.glob_interval_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--rotate-wait-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.rotate_wait_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--removed-expire-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.removed_expire_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkpoint-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.checkpoint_interval_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkpoint-sync-batch")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.checkpoint_sync_batch_override = try std.fmt.parseInt(u32, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkpoint-snapshot-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.checkpoint_snapshot_interval_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkpoint-ttl-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.checkpoint_ttl_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--checkpoint-max-slots")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.checkpoint_max_slots_override = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--state-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            if (opts.state_dir_override) |old| allocator.free(old);
            opts.state_dir_override = try allocator.dupe(u8, args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--read-buf")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.read_buf_override = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-line")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.max_line_override = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--write-buf")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.write_buf_override = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--flush-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.flush_interval_ms_override = try std.fmt.parseInt(u64, args[i], 10);
            continue;
        }
        if (std.mem.eql(u8, arg, "--flush-lines")) {
            i += 1;
            if (i >= args.len) return error.MissingOptionValue;
            opts.flush_line_threshold_override = try std.fmt.parseInt(usize, args[i], 10);
            continue;
        }

        if (std.mem.eql(u8, arg, "-")) {
            try opts.inputs.append(allocator, try allocator.dupe(u8, arg));
            continue;
        }
        if (std.mem.startsWith(u8, arg, "-")) return error.UnknownOption;

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

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var opts = parseCliOptions(allocator) catch |err| switch (err) {
        error.HelpRequested => return,
        else => return err,
    };
    defer opts.deinit(allocator);

    const loaded_cfg = zonfig.load(RuntimeTailConfig, allocator, .{
        .json_path = opts.config_path,
        .env_prefix = "TERO",
        .allow_env_only = opts.config_path == null,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer zonfig.deinit(RuntimeTailConfig, allocator, loaded_cfg);

    var cfg = loaded_cfg.*;
    if (opts.output_override) |v| cfg.output_path = v;
    if (opts.read_from_override) |v| cfg.read_from = v;
    if (opts.format_override) |v| cfg.input_format = v;
    if (opts.policy_path_override) |v| cfg.policy_path = v;
    if (opts.io_engine_override) |v| cfg.io_engine = v;
    if (opts.poll_ms_override) |v| cfg.poll_ms = v;
    if (opts.glob_interval_ms_override) |v| cfg.glob_interval_ms = v;
    if (opts.rotate_wait_ms_override) |v| cfg.rotate_wait_ms = v;
    if (opts.removed_expire_ms_override) |v| cfg.removed_expire_ms = v;
    if (opts.checkpoint_interval_ms_override) |v| cfg.checkpoint_interval_ms = v;
    if (opts.checkpoint_sync_batch_override) |v| cfg.checkpoint_sync_batch = v;
    if (opts.checkpoint_snapshot_interval_ms_override) |v| cfg.checkpoint_snapshot_interval_ms = v;
    if (opts.checkpoint_ttl_ms_override) |v| cfg.checkpoint_ttl_ms = v;
    if (opts.checkpoint_max_slots_override) |v| cfg.checkpoint_max_slots = v;
    if (opts.state_dir_override) |v| cfg.state_dir = v;
    if (opts.read_buf_override) |v| cfg.read_buf = v;
    if (opts.max_line_override) |v| cfg.max_line = v;
    if (opts.write_buf_override) |v| cfg.write_buf = v;
    if (opts.flush_interval_ms_override) |v| cfg.flush_interval_ms = v;
    if (opts.flush_line_threshold_override) |v| cfg.flush_line_threshold = v;
    cfg.io_engine = tail_mod.types.normalizeIoEngine(cfg.io_engine);

    try validate(opts, cfg);

    if (opts.verbose_increment > 0) {
        var stderr_buf: [1024]u8 = undefined;
        var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
        const stderr = &stderr_writer.interface;
        try stderr.print(
            "edge-tail: read_from={s} format={s} io_engine={s} poll_ms={d} glob_interval_ms={d} state_dir={s} policy={s}\n",
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
        try tail_mod.runtime.runStdinToOutput(allocator, cfg);
        return;
    }

    try tail_mod.runtime.runFilesToOutput(allocator, cfg, opts.inputs.items);
}
