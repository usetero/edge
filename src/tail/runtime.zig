const std = @import("std");
const builtin = @import("builtin");
const o11y = @import("o11y");
const types = @import("types.zig");
const io_mod = @import("io.zig");
const framer_mod = @import("framer.zig");
const eval_stream = @import("eval_stream.zig");
const watch_mod = @import("watch.zig");
const read_scheduler = @import("read_scheduler.zig");
const checkpoint_mod = @import("checkpoint/mod.zig");
const lifecycle_mod = @import("../core/lifecycle.zig");

const log = std.log.scoped(.tail_runtime);

fn initEventBus(io: std.Io, environ_map: *const std.process.Environ.Map) o11y.StdioEventBus {
    var stdio_bus: o11y.StdioEventBus = undefined;
    stdio_bus.init(io);
    stdio_bus.eventBus().setLevel(o11y.Level.parseFromEnv(environ_map, "TERO_LOG_LEVEL", .warn));
    return stdio_bus;
}

// =============================================================================
// Signal handling: sigwait thread requests structured shutdown through the
// Lifecycle (PLAN.md §9 Phase 6 — same pattern as runtime/app.zig); the old
// async-signal handler + polled atomic are gone. Second INT/TERM force-exits.
// USR1 wakes the waiter for clean teardown.
// =============================================================================

const SignalWaiterContext = struct {
    io: std.Io,
    lifecycle: *lifecycle_mod.Lifecycle,
    signal_count: *std.atomic.Value(u32),
    shutdown_waiter: *std.atomic.Value(bool),
    signal_set: std.posix.sigset_t,
};

const SignalWaiterHandle = struct {
    thread: std.Thread,
    previous_mask: std.posix.sigset_t,
};

const SignalWaiterError = error{UnsupportedPlatform} || std.Thread.SpawnError;

fn installSignalWaiter(
    io: std.Io,
    lifecycle: *lifecycle_mod.Lifecycle,
    signal_count: *std.atomic.Value(u32),
    shutdown_waiter: *std.atomic.Value(bool),
) SignalWaiterError!SignalWaiterHandle {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedPlatform;

    var signal_set = std.posix.sigemptyset();
    std.posix.sigaddset(&signal_set, std.posix.SIG.INT);
    std.posix.sigaddset(&signal_set, std.posix.SIG.TERM);
    std.posix.sigaddset(&signal_set, std.posix.SIG.USR1);
    var previous_mask = std.posix.sigemptyset();
    std.posix.sigprocmask(std.posix.SIG.BLOCK, &signal_set, &previous_mask);

    const waiter = try std.Thread.spawn(.{}, signalWaiterThread, .{SignalWaiterContext{
        .io = io,
        .lifecycle = lifecycle,
        .signal_count = signal_count,
        .shutdown_waiter = shutdown_waiter,
        .signal_set = signal_set,
    }});
    return .{
        .thread = waiter,
        .previous_mask = previous_mask,
    };
}

fn signalWaiterThread(ctx: SignalWaiterContext) void {
    while (true) {
        var sig: c_int = 0;
        if (std.c.sigwait(@constCast(&ctx.signal_set), &sig) != 0) continue;
        if (sig == @intFromEnum(std.posix.SIG.USR1) and ctx.shutdown_waiter.load(.acquire)) return;

        const count = ctx.signal_count.fetchAdd(1, .acq_rel) + 1;
        if (count == 1) {
            ctx.lifecycle.requestShutdown(ctx.io);
            continue;
        }
        std.process.exit(1);
    }
}

fn teardownSignalWaiter(handle: SignalWaiterHandle, shutdown_waiter: *std.atomic.Value(bool)) void {
    shutdown_waiter.store(true, .release);
    std.posix.kill(std.c.getpid(), std.posix.SIG.USR1) catch |err|
        log.warn("failed to wake signal waiter: {}", .{err});
    handle.thread.join();
    std.posix.sigprocmask(std.posix.SIG.SETMASK, &handle.previous_mask, null);
}

/// Runtime scaffold for edge-tail.
///
/// This first implementation is intentionally narrow and IO-interface focused:
/// Reader endpoint -> framer -> Writer endpoint.
/// Watch/discovery/checkpoint modules will plug in as the next step.
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
    watch_backend: watch_mod.BackendKind = .poll,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        environ_map: *const std.process.Environ.Map,
        cfg: types.TailConfig,
    ) !Runtime {
        try types.validateConfig(cfg);
        const backend: watch_mod.BackendKind = switch (types.normalizeIoEngine(cfg.io_engine)) {
            .poll => .poll,
            .uring => .uring,
            .kqueue => .kqueue,
            .auto, .inotify, .epoll => unreachable,
        };
        return .{
            .allocator = allocator,
            .io = io,
            .environ_map = environ_map,
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
        var stdio_bus = initEventBus(self.io, self.environ_map);
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
        var stdio_bus = initEventBus(self.io, self.environ_map);
        var framer = try framer_mod.LineFramer.init(self.allocator, self.cfg.read_buf, self.cfg.max_line);
        defer framer.deinit();
        var evaluator = try eval_stream.StreamEvaluator.init(
            self.allocator,
            self.cfg.input_format,
            self.cfg.policy_path,
            stdio_bus.eventBus(),
        );
        defer evaluator.deinit();
        var scheduler = try read_scheduler.EngineScheduler.init(self.allocator, self.io, self.cfg.io_engine);
        defer scheduler.deinit();

        var watcher = try watch_mod.Watcher.init(
            self.allocator,
            self.io,
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
            self.io,
            self.cfg.state_dir,
            4096,
            self.cfg.checkpoint_max_slots,
            self.cfg.checkpoint_interval_ms,
            self.cfg.checkpoint_ttl_ms,
            self.cfg.checkpoint_sync_batch,
            self.cfg.checkpoint_snapshot_interval_ms,
        );
        defer checkpoint.deinit();
        const checkpoint_lane: ?*checkpoint_mod.Lane = if (self.cfg.read_from == .checkpoint) &checkpoint else null;
        if (checkpoint_lane) |lane| watcher.applyCheckpointLane(lane);

        // Both long-lived tasks — the checkpoint lane worker and the poll
        // loop — run as concurrent tasks in one lifecycle group; shutdown is
        // a single structured cancel (PLAN.md §9 Phase 6).
        var lifecycle: lifecycle_mod.Lifecycle = .init;
        try checkpoint.start(&lifecycle);

        var loop: PollLoop = .{
            .runtime = self,
            .framer = &framer,
            .evaluator = &evaluator,
            .scheduler = &scheduler,
            .watcher = &watcher,
            .checkpoint = &checkpoint,
            .checkpoint_lane = checkpoint_lane,
            .output = output,
            .lifecycle = &lifecycle,
        };
        try lifecycle.spawn(self.io, PollLoop.run, .{&loop});

        var signal_count = std.atomic.Value(u32).init(0);
        var shutdown_waiter = std.atomic.Value(bool).init(false);
        var signal_waiter: ?SignalWaiterHandle = null;
        if (installSignalWaiter(self.io, &lifecycle, &signal_count, &shutdown_waiter)) |waiter| {
            signal_waiter = waiter;
        } else |err| switch (err) {
            error.UnsupportedPlatform => {},
            else => {
                lifecycle.requestShutdown(self.io);
                lifecycle.shutdown(self.io);
                return err;
            },
        }

        lifecycle.awaitShutdown(self.io) catch |err| switch (err) {
            error.Canceled => {},
        };
        lifecycle.shutdown(self.io);

        if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);

        // The canceled tasks can't reliably do final file IO; drain and
        // flush on this (uncanceled) thread.
        checkpoint.finalize();
        try output.flush();
        if (loop.failure) |err| return err;
    }
};

/// The poll loop as a lifecycle task: collect → batch-read/filter →
/// checkpoint → cadenced flush. Cancellation lands as error.Canceled out of
/// the sleep (or mid-batch through the Io file ops) and unwinds cleanly; a
/// non-cancel failure is recorded and requests shutdown so the runtime exits
/// with it — same observable behavior as the old `try`-driven loop.
const PollLoop = struct {
    runtime: *Runtime,
    framer: *framer_mod.LineFramer,
    evaluator: *eval_stream.StreamEvaluator,
    scheduler: *read_scheduler.EngineScheduler,
    watcher: *watch_mod.Watcher,
    checkpoint: *checkpoint_mod.Lane,
    checkpoint_lane: ?*checkpoint_mod.Lane,
    output: *io_mod.Output,
    lifecycle: *lifecycle_mod.Lifecycle,
    failure: ?anyerror = null,

    fn run(self: *PollLoop) std.Io.Cancelable!void {
        self.runIteration() catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                self.failure = err;
                self.lifecycle.requestShutdown(self.runtime.io);
                return;
            },
        };
    }

    fn runIteration(self: *PollLoop) !void {
        const rt = self.runtime;
        const io = rt.io;

        var events: std.ArrayList(watch_mod.Event) = .empty;
        defer events.deinit(rt.allocator);

        const sleep_ns = rt.cfg.poll_ms * std.time.ns_per_ms;
        const flush_ns = rt.cfg.flush_interval_ms * std.time.ns_per_ms;
        var next_flush_ns: i128 = std.Io.Timestamp.now(io, .awake).toNanoseconds() + @as(i128, @intCast(flush_ns));
        var buffered_lines: usize = 0;
        while (!self.lifecycle.isShuttingDown()) {
            try self.watcher.collect(&events, rt.cfg.read_from, self.checkpoint_lane);
            const processed = try self.scheduler.processBatch(
                self.framer,
                self.output.writer(),
                events.items,
                self.evaluator,
                Runtime.evalLineFilter,
            );

            if (processed > 0) {
                for (events.items) |evt| {
                    if (evt.identity) |id| {
                        _ = self.checkpoint.enqueue(.{
                            .identity = id,
                            .byte_offset = evt.end_offset,
                            .last_seen_size = evt.end_offset,
                            .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
                        }) catch false;
                    }
                }
                buffered_lines += processed;
            }

            const now = std.Io.Timestamp.now(io, .awake).toNanoseconds();
            const due_timer = now >= next_flush_ns;
            const due_threshold = buffered_lines >= rt.cfg.flush_line_threshold;
            if (due_timer or due_threshold) {
                try self.output.flush();
                buffered_lines = 0;
                next_flush_ns = now + @as(i128, @intCast(flush_ns));
            }
            try io.sleep(.fromNanoseconds(@intCast(sleep_ns)), .awake);
        }
    }
};

pub fn runStdinToOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
) !void {
    var runtime = try Runtime.init(allocator, io, environ_map, cfg);

    var input = try io_mod.Input.init(allocator, io, .stdin, cfg.read_buf);
    defer input.deinit();

    const out_target: io_mod.OutputTarget = if (std.mem.eql(u8, cfg.output_path, "-"))
        .stdout
    else
        .{ .file_append = cfg.output_path };

    var output = try io_mod.Output.init(allocator, io, out_target, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);
}

pub fn runFilesToOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
    inputs: []const []const u8,
) !void {
    var runtime = try Runtime.init(allocator, io, environ_map, cfg);

    const out_target: io_mod.OutputTarget = if (std.mem.eql(u8, cfg.output_path, "-"))
        .stdout
    else
        .{ .file_append = cfg.output_path };

    var output = try io_mod.Output.init(allocator, io, out_target, cfg.write_buf);
    defer output.deinit();

    try runtime.runFilesLoop(inputs, &output);
}

const testing = std.testing;

test "runtime public API: runStream copies framed bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.Options.debug_io;
    const in_path = "in.log";
    const out_path = "out.log";
    {
        const f = try tmp.dir.createFile(io, in_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "a\nb\n");
    }

    const abs_in = try tmp.dir.realPathFileAlloc(io, in_path, testing.allocator);
    defer testing.allocator.free(abs_in);
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    const cfg: types.TailConfig = .{
        .output_path = abs_out,
        .read_buf = 16,
        .max_line = 1024,
        .write_buf = 16,
    };
    var env_map = std.process.Environ.Map.init(testing.allocator);
    defer env_map.deinit();
    var runtime = try Runtime.init(testing.allocator, io, &env_map, cfg);

    var input = try io_mod.Input.init(testing.allocator, io, .{ .file = abs_in }, cfg.read_buf);
    defer input.deinit();
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);

    const got = try tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("a\nb\n", got);
}

test "runtime public API: runStream applies policy drops" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.Options.debug_io;
    const in_path = "in.log";
    const out_path = "out.log";
    const policy_path = "policies.json";
    {
        const f = try tmp.dir.createFile(io, in_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "ok\ndebug line\nnext\n");
    }
    {
        const f = try tmp.dir.createFile(io, policy_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io,
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

    const abs_in = try tmp.dir.realPathFileAlloc(io, in_path, testing.allocator);
    defer testing.allocator.free(abs_in);
    const abs_policy = try tmp.dir.realPathFileAlloc(io, policy_path, testing.allocator);
    defer testing.allocator.free(abs_policy);
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    const cfg: types.TailConfig = .{
        .output_path = abs_out,
        .policy_path = abs_policy,
        .input_format = .raw,
        .read_buf = 32,
        .max_line = 1024,
        .write_buf = 32,
    };
    var env_map = std.process.Environ.Map.init(testing.allocator);
    defer env_map.deinit();
    var runtime = try Runtime.init(testing.allocator, io, &env_map, cfg);

    var input = try io_mod.Input.init(testing.allocator, io, .{ .file = abs_in }, cfg.read_buf);
    defer input.deinit();
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, cfg.write_buf);
    defer output.deinit();

    try runtime.runStream(&input, &output);

    const got = try tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("ok\nnext\n", got);
}
