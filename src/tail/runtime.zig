const std = @import("std");
const o11y = @import("o11y");
const types = @import("types.zig");
const io_mod = @import("io.zig");
const framer_mod = @import("framer.zig");
const eval_stream = @import("eval_stream.zig");
const watch_mod = @import("watch.zig");
const read_scheduler = @import("read_scheduler.zig");
const checkpoint_mod = @import("checkpoint.zig");

var stop_requested = std.atomic.Value(bool).init(false);

fn initEventBus() o11y.StdioEventBus {
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init();
    stdio_bus.eventBus().setLevel(o11y.Level.parseFromEnv("TERO_LOG_LEVEL", .warn));
    return stdio_bus;
}

fn handleSignal(_: c_int) callconv(.c) void {
    stop_requested.store(true, .release);
}

fn installSignalHandlers() void {
    if (@hasDecl(std.posix, "SIG")) {
        const action = std.posix.Sigaction{
            .handler = .{ .handler = handleSignal },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.TERM, &action, null);
        std.posix.sigaction(std.posix.SIG.INT, &action, null);
    }
}

/// Runtime scaffold for edge-tail.
///
/// This first implementation is intentionally narrow and IO-interface focused:
/// Reader endpoint -> framer -> Writer endpoint.
/// Watch/discovery/checkpoint modules will plug in as the next step.
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    cfg: types.TailConfig,
    watch_backend: watch_mod.BackendKind = .poll,

    pub fn init(allocator: std.mem.Allocator, cfg: types.TailConfig) !Runtime {
        try types.validateConfig(cfg);
        const backend: watch_mod.BackendKind = switch (types.normalizeIoEngine(cfg.io_engine)) {
            .poll => .poll,
            .uring => .uring,
            .kqueue => .kqueue,
            .auto, .inotify, .epoll => unreachable,
        };
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .watch_backend = backend,
        };
    }

    fn evalLineFilter(ctx: *anyopaque, line: []const u8, meta: types.LineMeta) anyerror!bool {
        _ = meta;
        const evaluator: *eval_stream.StreamEvaluator = @ptrCast(@alignCast(ctx));
        return evaluator.evalLine(line);
    }

    pub fn runStream(self: *Runtime, input: *io_mod.Input, output: *io_mod.Output) !void {
        var stdio_bus = initEventBus();
        var evaluator = try eval_stream.StreamEvaluator.init(
            self.allocator,
            self.cfg.input_format,
            self.cfg.policy_path,
            stdio_bus.eventBus(),
        );
        defer evaluator.deinit();

        var framer = try framer_mod.LineFramer.init(self.allocator, self.cfg.read_buf, self.cfg.max_line);
        defer framer.deinit();

        try framer.pump(
            self.allocator,
            input.reader(),
            output.writer(),
            self.cfg.read_buf,
            &evaluator,
            evalLineFilter,
        );
        try output.flush();
    }

    /// File tail loop using the concrete watcher backend.
    pub fn runFilesLoop(self: *Runtime, inputs: []const []const u8, output: *io_mod.Output) !void {
        switch (self.watch_backend) {
            .poll => try self.runFilesLoopBackend(.poll, inputs, output),
            .uring => try self.runFilesLoopBackend(.uring, inputs, output),
            .kqueue => try self.runFilesLoopBackend(.kqueue, inputs, output),
        }
    }

    fn runFilesLoopBackend(
        self: *Runtime,
        comptime backend: watch_mod.BackendKind,
        inputs: []const []const u8,
        output: *io_mod.Output,
    ) !void {
        stop_requested.store(false, .release);
        installSignalHandlers();

        var stdio_bus = initEventBus();
        var framer = try framer_mod.LineFramer.init(self.allocator, self.cfg.read_buf, self.cfg.max_line);
        defer framer.deinit();
        var evaluator = try eval_stream.StreamEvaluator.init(
            self.allocator,
            self.cfg.input_format,
            self.cfg.policy_path,
            stdio_bus.eventBus(),
        );
        defer evaluator.deinit();
        var scheduler = try read_scheduler.EngineScheduler.init(self.allocator, self.cfg.io_engine);
        defer scheduler.deinit();

        var watcher = try watch_mod.Watcher.init(
            self.allocator,
            backend,
            inputs,
            self.cfg.output_path,
            self.cfg.read_from,
            self.cfg.glob_interval_ms,
            self.cfg.rotate_wait_ms,
            self.cfg.removed_expire_ms,
        );
        defer watcher.deinit();

        var checkpoint = try checkpoint_mod.Lane.init(
            self.allocator,
            self.cfg.state_dir,
            4096,
            self.cfg.checkpoint_interval_ms,
            self.cfg.checkpoint_ttl_ms,
        );
        defer checkpoint.deinit();
        try checkpoint.start();
        const checkpoint_lane: ?*checkpoint_mod.Lane = if (self.cfg.read_from == .checkpoint) &checkpoint else null;
        if (checkpoint_lane) |lane| watcher.applyCheckpointLane(lane);

        var events: std.ArrayList(watch_mod.Event) = .{};
        defer events.deinit(self.allocator);

        const sleep_ns = self.cfg.poll_ms * std.time.ns_per_ms;
        const flush_ns = self.cfg.flush_interval_ms * std.time.ns_per_ms;
        var next_flush_ns: i128 = std.time.nanoTimestamp() + @as(i128, @intCast(flush_ns));
        var buffered_lines: usize = 0;
        while (true) {
            if (stop_requested.load(.acquire)) break;
            try watcher.collect(&events, self.cfg.read_from, checkpoint_lane);
            const processed = try scheduler.processBatch(
                &framer,
                output.writer(),
                events.items,
                &evaluator,
                evalLineFilter,
            );

            if (processed > 0) {
                for (events.items) |evt| {
                    if (evt.identity) |id| {
                        _ = checkpoint.enqueue(.{
                            .identity = id,
                            .byte_offset = evt.end_offset,
                            .last_seen_size = evt.end_offset,
                            .last_seen_ns = @intCast(std.time.nanoTimestamp()),
                        }) catch false;
                    }
                }
                buffered_lines += processed;
            }

            const now = std.time.nanoTimestamp();
            const due_timer = now >= next_flush_ns;
            const due_threshold = buffered_lines >= self.cfg.flush_line_threshold;
            if (due_timer or due_threshold) {
                try output.flush();
                buffered_lines = 0;
                next_flush_ns = now + @as(i128, @intCast(flush_ns));
            }
            std.Thread.sleep(sleep_ns);
        }
        try output.flush();
    }
};

pub fn runStdinToOutput(allocator: std.mem.Allocator, cfg: types.TailConfig) !void {
    var runtime = try Runtime.init(allocator, cfg);

    var input = try io_mod.Input.init(allocator, .stdin, cfg.read_buf);
    defer input.deinit();

    const out_target: io_mod.OutputTarget = if (std.mem.eql(u8, cfg.output_path, "-"))
        .stdout
    else
        .{ .file_append = cfg.output_path };

    var output = try io_mod.Output.init(allocator, out_target, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);
}

pub fn runFilesToOutput(allocator: std.mem.Allocator, cfg: types.TailConfig, inputs: []const []const u8) !void {
    var runtime = try Runtime.init(allocator, cfg);

    const out_target: io_mod.OutputTarget = if (std.mem.eql(u8, cfg.output_path, "-"))
        .stdout
    else
        .{ .file_append = cfg.output_path };

    var output = try io_mod.Output.init(allocator, out_target, cfg.write_buf);
    defer output.deinit();

    try runtime.runFilesLoop(inputs, &output);
}

const testing = std.testing;

test "runtime public API: runStream copies framed bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const in_path = "in.log";
    const out_path = "out.log";
    {
        const f = try tmp.dir.createFile(in_path, .{});
        defer f.close();
        try f.writeAll("a\nb\n");
    }

    const abs_in = try tmp.dir.realpathAlloc(testing.allocator, in_path);
    defer testing.allocator.free(abs_in);
    const cwd_abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    const cfg = types.TailConfig{
        .output_path = abs_out,
        .read_buf = 16,
        .max_line = 1024,
        .write_buf = 16,
    };
    var runtime = try Runtime.init(testing.allocator, cfg);

    var input = try io_mod.Input.init(testing.allocator, .{ .file = abs_in }, cfg.read_buf);
    defer input.deinit();
    var output = try io_mod.Output.init(testing.allocator, .{ .file_append = abs_out }, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);

    const got = try tmp.dir.readFileAlloc(testing.allocator, out_path, 1024);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("a\nb\n", got);
}

test "runtime public API: runStream applies policy drops" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const in_path = "in.log";
    const out_path = "out.log";
    const policy_path = "policies.json";
    {
        const f = try tmp.dir.createFile(in_path, .{});
        defer f.close();
        try f.writeAll("ok\ndebug line\nnext\n");
    }
    {
        const f = try tmp.dir.createFile(policy_path, .{});
        defer f.close();
        try f.writeAll(
            \\{
            \\  "policies": [
            \\    {
            \\      "id": "drop-debug",
            \\      "name": "drop-debug",
            \\      "log": {
            \\        "match": [{ "log_field": "body", "regex": "debug" }],
            \\        "keep": "none"
            \\      }
            \\    }
            \\  ]
            \\}
        );
    }

    const abs_in = try tmp.dir.realpathAlloc(testing.allocator, in_path);
    defer testing.allocator.free(abs_in);
    const abs_policy = try tmp.dir.realpathAlloc(testing.allocator, policy_path);
    defer testing.allocator.free(abs_policy);
    const cwd_abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    const cfg = types.TailConfig{
        .output_path = abs_out,
        .policy_path = abs_policy,
        .input_format = .raw,
        .read_buf = 32,
        .max_line = 1024,
        .write_buf = 32,
    };
    var runtime = try Runtime.init(testing.allocator, cfg);

    var input = try io_mod.Input.init(testing.allocator, .{ .file = abs_in }, cfg.read_buf);
    defer input.deinit();
    var output = try io_mod.Output.init(testing.allocator, .{ .file_append = abs_out }, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);

    const got = try tmp.dir.readFileAlloc(testing.allocator, out_path, 1024);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("ok\nnext\n", got);
}
