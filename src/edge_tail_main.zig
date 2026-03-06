const std = @import("std");
const zonfig = @import("zonfig/root.zig");
const glob_mod = @import("tail/glob.zig");
const watcher_mod = @import("tail/watcher.zig");
const reader_mod = @import("tail/reader.zig");

const ReadFrom = watcher_mod.ReadFrom;

const TailConfig = struct {
    output_path: []const u8 = "-",
    read_from: ReadFrom = .tail,
    poll_ms: u64 = 200,
    glob_interval_ms: u64 = 5_000,
    rotate_wait_ms: u64 = 5_000,
    removed_expire_ms: u64 = 60_000,
    read_buf: usize = 64 * 1024,
    max_line: usize = 256 * 1024,
};

const CliOptions = struct {
    config_path: ?[]const u8 = null,
    output_override: ?[]const u8 = null,
    read_from_override: ?ReadFrom = null,
    poll_ms_override: ?u64 = null,
    glob_interval_ms_override: ?u64 = null,
    rotate_wait_ms_override: ?u64 = null,
    removed_expire_ms_override: ?u64 = null,
    read_buf_override: ?usize = null,
    max_line_override: ?usize = null,
    inputs: std.ArrayList([]const u8),

    fn deinit(self: *CliOptions, allocator: std.mem.Allocator) void {
        if (self.config_path) |path| allocator.free(path);
        if (self.output_override) |path| allocator.free(path);
        for (self.inputs.items) |input| {
            allocator.free(input);
        }
        self.inputs.deinit(allocator);
    }
};

fn printUsage() !void {
    var stderr_buf: [2048]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer.interface;

    try stderr.writeAll(
        \\Usage: edge-tail [OPTIONS] [PATH...]
        \\
        \\Options:
        \\  -c, --config <PATH>      Config JSON path (zonfig)
        \\  -o, --output <PATH>      Output path ('-' for stdout)
        \\      --read-from <MODE>   head|tail
        \\      --poll-ms <MS>       Poll interval in milliseconds
        \\      --glob-interval-ms <MS>  Glob re-evaluation interval
        \\      --rotate-wait-ms <MS>  Drain old fd before switching on rotation
        \\      --removed-expire-ms <MS>  Expire unmatched tracked files after grace
        \\      --read-buf <BYTES>   Read buffer size in bytes
        \\      --max-line <BYTES>   Max line length in bytes
        \\      PATH                 Input file path(s), or '-' for stdin
        \\  -h, --help               Show this help
        \\
        \\Config precedence: CLI > env (TERO_TAIL_*) > config file > defaults
        \\
    );

    try stderr.flush();
}

fn parseReadFrom(value: []const u8) !ReadFrom {
    if (std.mem.eql(u8, value, "head")) return .head;
    if (std.mem.eql(u8, value, "tail")) return .tail;
    return error.InvalidReadFrom;
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

        if (std.mem.eql(u8, arg, "-")) {
            try opts.inputs.append(allocator, try allocator.dupe(u8, arg));
            continue;
        }

        if (std.mem.startsWith(u8, arg, "-")) {
            return error.UnknownOption;
        }

        try opts.inputs.append(allocator, try allocator.dupe(u8, arg));
    }

    return opts;
}

fn useStdinMode(inputs: []const []const u8) bool {
    if (inputs.len == 0) return true;
    return inputs.len == 1 and std.mem.eql(u8, inputs[0], "-");
}

fn validate(opts: CliOptions, cfg: TailConfig) !void {
    if (cfg.read_buf == 0 or cfg.max_line == 0 or cfg.poll_ms == 0 or cfg.glob_interval_ms == 0) {
        return error.InvalidValue;
    }

    if (opts.inputs.items.len > 1) {
        for (opts.inputs.items) |input| {
            if (std.mem.eql(u8, input, "-")) return error.InvalidInputCombination;
        }
    }
}

fn runStdinLoop(allocator: std.mem.Allocator, reader: *reader_mod.LineReader, stdin_reader: *std.Io.Reader, output_writer: *std.Io.Writer, read_limit: usize) !void {
    while (true) {
        var chunk_writer: std.Io.Writer.Allocating = .init(allocator);
        defer chunk_writer.deinit();

        const n = stdin_reader.stream(&chunk_writer.writer, std.Io.Limit.limited(read_limit)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        try reader.ingestChunk(chunk_writer.written(), output_writer);
        try output_writer.flush();
    }
    try reader.finish(output_writer);
    try output_writer.flush();
}

fn shouldTrackPath(output_path: []const u8, candidate_path: []const u8) bool {
    if (std.mem.eql(u8, output_path, "-")) return true;
    return !std.mem.eql(u8, output_path, candidate_path);
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

    const loaded_cfg = zonfig.load(TailConfig, allocator, .{
        .json_path = opts.config_path,
        .env_prefix = "TERO",
        .allow_env_only = opts.config_path == null,
    }) catch |err| switch (err) {
        error.FileNotFound => return error.FileNotFound,
        else => return err,
    };
    defer zonfig.deinit(TailConfig, allocator, loaded_cfg);

    var cfg = loaded_cfg.*;
    if (opts.output_override) |v| cfg.output_path = v;
    if (opts.read_from_override) |v| cfg.read_from = v;
    if (opts.poll_ms_override) |v| cfg.poll_ms = v;
    if (opts.glob_interval_ms_override) |v| cfg.glob_interval_ms = v;
    if (opts.rotate_wait_ms_override) |v| cfg.rotate_wait_ms = v;
    if (opts.removed_expire_ms_override) |v| cfg.removed_expire_ms = v;
    if (opts.read_buf_override) |v| cfg.read_buf = v;
    if (opts.max_line_override) |v| cfg.max_line = v;

    try validate(opts, cfg);

    var output_buf: [64 * 1024]u8 = undefined;
    var output_file: ?std.fs.File = null;
    defer if (output_file) |file| file.close();

    var output_writer = blk: {
        if (std.mem.eql(u8, cfg.output_path, "-")) {
            break :blk std.fs.File.stdout().writer(&output_buf);
        }
        const file = try std.fs.cwd().createFile(cfg.output_path, .{});
        output_file = file;
        break :blk file.writer(&output_buf);
    };
    defer output_writer.interface.flush() catch {};

    var reader = try reader_mod.LineReader.init(allocator, cfg.read_buf, cfg.max_line);
    defer reader.deinit();

    if (useStdinMode(opts.inputs.items)) {
        const stdin_buf = try allocator.alloc(u8, cfg.read_buf);
        defer allocator.free(stdin_buf);
        var stdin_file_reader = std.fs.File.stdin().reader(stdin_buf);
        try runStdinLoop(allocator, &reader, &stdin_file_reader.interface, &output_writer.interface, cfg.read_buf);
        return;
    }

    var expanded = try glob_mod.expandPatterns(allocator, opts.inputs.items);
    defer expanded.deinit();

    var path_count: usize = 0;
    for (expanded.items.items) |p| {
        if (shouldTrackPath(cfg.output_path, p)) path_count += 1;
    }

    var init_paths = try allocator.alloc([]const u8, path_count);
    defer allocator.free(init_paths);
    var init_idx: usize = 0;
    for (expanded.items.items) |p| {
        if (!shouldTrackPath(cfg.output_path, p)) continue;
        init_paths[init_idx] = p;
        init_idx += 1;
    }

    var watcher = try watcher_mod.Watcher.init(allocator, init_paths, cfg.read_from, cfg.rotate_wait_ms);
    defer watcher.deinit();

    const sleep_ns = cfg.poll_ms * std.time.ns_per_ms;
    const glob_interval_ns: i128 = @as(i128, @intCast(cfg.glob_interval_ms)) * std.time.ns_per_ms;
    const removed_expire_ns: i128 = @as(i128, @intCast(cfg.removed_expire_ms)) * std.time.ns_per_ms;
    var next_glob_refresh_ns: i128 = std.time.nanoTimestamp() + glob_interval_ns;

    while (true) {
        const now_ns = std.time.nanoTimestamp();
        if (now_ns >= next_glob_refresh_ns) {
            var rescan = try glob_mod.expandPatterns(allocator, opts.inputs.items);
            defer rescan.deinit();
            var rescan_paths: std.ArrayList([]const u8) = .{};
            defer rescan_paths.deinit(allocator);
            for (rescan.items.items) |p| {
                if (!shouldTrackPath(cfg.output_path, p)) continue;
                try rescan_paths.append(allocator, p);
            }
            try watcher.reconcilePaths(rescan_paths.items, cfg.read_from, removed_expire_ns);
            next_glob_refresh_ns = now_ns + glob_interval_ns;
        }

        const events = try watcher.poll(cfg.read_from);
        var had_events = false;

        for (events) |event| {
            had_events = true;
            const file = watcher.fileForEvent(event);
            try reader.readRange(file, event.start_offset, event.end_offset, &output_writer.interface);
        }

        if (had_events) {
            try output_writer.interface.flush();
        }

        std.Thread.sleep(sleep_ns);
    }
}
