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
// Signal handling: a sigwait thread requests shutdown through the Lifecycle.
// A second INT or TERM exits the process. USR1 wakes the waiter for teardown.
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

/// Runtime for edge-tail: input, framer, policy filter, output.
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
    watch_backend: watch_mod.BackendKind,

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

    fn evalLineFilter(ctx: *anyopaque, line: []const u8) anyerror!bool {
        const evaluator: *eval_stream.StreamEvaluator = @ptrCast(@alignCast(ctx));
        return evaluator.evalLine(line);
    }

    /// File tail loop using the concrete watcher backend.
    pub fn runFilesLoop(self: *Runtime, inputs: []const []const u8, output: *io_mod.Output) !void {
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
            self.watch_backend,
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

        // The checkpoint worker and the poll loop run in one lifecycle group.
        // One cancel stops both.
        var lifecycle: lifecycle_mod.Lifecycle = .init;

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

        // If startup fails after this point, stop the lifecycle and the
        // signal waiter. This restores the signal mask.
        var startup_done = false;
        errdefer if (!startup_done) {
            lifecycle.requestShutdown(self.io);
            lifecycle.shutdown(self.io);
            if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);
        };

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
        startup_done = true;

        lifecycle.awaitShutdown(self.io) catch |err| switch (err) {
            error.Canceled => {},
        };
        lifecycle.shutdown(self.io);

        if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);

        // The canceled tasks can't reliably do final file IO; drain and
        // flush on this (uncanceled) thread.
        checkpoint.finalize();
        // Drain before the flush: the framer may still hold a trailing record
        // with no newline, and `deinit` would drop it.
        try Runtime.drainFramer(self.cfg.read_from, &framer, output, &evaluator);
        if (loop.failure) |err| return err;
    }
    /// Emit the partial records that the framer holds, then flush. Events end
    /// at the stat size, so a last record without a newline stays in scratch.
    /// `.head` skips this because it re-reads from 0 on restart. Parse errors
    /// from a partial record do not stop the flush.
    fn drainFramer(
        read_from: types.ReadFrom,
        framer: *framer_mod.LineFramer,
        output: *io_mod.Output,
        evaluator: *eval_stream.StreamEvaluator,
    ) !void {
        if (read_from != .head) {
            framer.finish(output.writer(), evaluator, Runtime.evalLineFilter) catch |err| switch (err) {
                error.OutOfMemory, error.WriteFailed => return err,
                else => {}, // half-record parse errors must not block the flush
            };
        }
        try output.flush();
    }
};

/// Poll loop task: collect, read and filter, checkpoint, flush. A cancel
/// unwinds as error.Canceled. Other errors go to `failure` and request
/// shutdown.
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
                            .offset = evt.end_offset,
                            .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
                        });
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

/// Stdin pump as a lifecycle task. `pumpFileStreaming` does one short readv
/// per iteration with no prefetch, so a cancel stops the readv as
/// error.Canceled and strands no bytes. After the join, the main thread
/// flushes the write buffer. Stdin EOF requests shutdown.
///
/// `runStdinToOutput` has two constraints:
///
/// 1. The pump runs on a worker thread. The Threaded Io backend cancels
///    syscalls only on its worker threads.
///
/// 2. `installSignalWaiter` runs before the spawn. The worker inherits the
///    blocked mask, so `sigwait` receives INT and TERM.
const StdinLoop = struct {
    runtime: *Runtime,
    file: std.Io.File,
    output: *io_mod.Output,
    framer: *framer_mod.LineFramer,
    evaluator: *eval_stream.StreamEvaluator,
    lifecycle: *lifecycle_mod.Lifecycle,
    failure: ?anyerror = null,

    fn run(self: *StdinLoop) std.Io.Cancelable!void {
        self.framer.pumpFileStreaming(
            self.runtime.io,
            self.file,
            self.output.writer(),
            self.evaluator,
            Runtime.evalLineFilter,
        ) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => {
                // During structured shutdown a cancel can surface as a
                // non-Canceled error if a writer drain was interrupted
                // mid-writev; reconcile any error seen while shutting down
                // with the cancel that caused it.
                if (self.lifecycle.isShuttingDown()) return error.Canceled;
                self.failure = err;
                self.lifecycle.requestShutdown(self.runtime.io);
                return;
            },
        };
        // Normal stdin EOF: wake the main thread's `awaitShutdown`. Use the
        // quiet variant so a plain `echo ... | edge-tail -` keeps stderr clean;
        // the signal path logs via `requestShutdown` from the waiter thread.
        self.lifecycle.requestShutdownQuiet(self.runtime.io);
    }
};

fn outputTarget(cfg: types.TailConfig) io_mod.OutputTarget {
    return if (std.mem.eql(u8, cfg.output_path, "-")) .stdout else .{ .file_append = cfg.output_path };
}

pub fn runStdinToOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
) !void {
    var runtime = try Runtime.init(allocator, io, environ_map, cfg);

    var output = try io_mod.Output.init(allocator, io, outputTarget(cfg), cfg.write_buf);
    defer output.deinit();

    var stdio_bus = initEventBus(io, environ_map);
    var evaluator = try eval_stream.StreamEvaluator.init(
        allocator,
        cfg.input_format,
        cfg.policy_path,
        stdio_bus.eventBus(),
    );
    defer evaluator.deinit();
    var framer = try framer_mod.LineFramer.init(allocator, cfg.read_buf, cfg.max_line);
    defer framer.deinit();

    var lifecycle: lifecycle_mod.Lifecycle = .init;
    var loop: StdinLoop = .{
        .runtime = &runtime,
        .file = std.Io.File.stdin(),
        .output = &output,
        .framer = &framer,
        .evaluator = &evaluator,
        .lifecycle = &lifecycle,
    };

    var signal_count = std.atomic.Value(u32).init(0);
    var shutdown_waiter = std.atomic.Value(bool).init(false);
    var signal_waiter: ?SignalWaiterHandle = null;
    if (installSignalWaiter(io, &lifecycle, &signal_count, &shutdown_waiter)) |waiter| {
        signal_waiter = waiter;
    } else |err| switch (err) {
        error.UnsupportedPlatform => {},
        else => return err,
    }

    lifecycle.spawn(io, StdinLoop.run, .{&loop}) catch |err| {
        if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);
        return err;
    };

    lifecycle.awaitShutdown(io) catch |err| switch (err) {
        error.Canceled => {},
    };
    // Cancel the group directly. `lifecycle.shutdown` logs on every run and
    // pollutes stderr on a clean EOF.
    std.debug.assert(lifecycle.isShuttingDown());
    lifecycle.group.cancel(io);

    if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);

    // Flush on this uncanceled thread, so a signal loses no written bytes.
    try output.flush();
    if (loop.failure) |err| return err;
}

pub fn runFilesToOutput(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *const std.process.Environ.Map,
    cfg: types.TailConfig,
    inputs: []const []const u8,
) !void {
    var runtime = try Runtime.init(allocator, io, environ_map, cfg);

    var output = try io_mod.Output.init(allocator, io, outputTarget(cfg), cfg.write_buf);
    defer output.deinit();

    try runtime.runFilesLoop(inputs, &output);
}

const testing = std.testing;

// Runs the StdinLoop coordination without the signal waiter, so the test
// runner's signal mask stays unchanged. Returns the output bytes.
fn runStdinLoopForTest(
    io: std.Io,
    tmp: *testing.TmpDir,
    in_path: []const u8,
    policy_path: ?[]const u8,
    buf_size: usize,
) ![]u8 {
    const out_path = "out.log";
    const abs_in = try tmp.dir.realPathFileAlloc(io, in_path, testing.allocator);
    defer testing.allocator.free(abs_in);
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    const cfg: types.TailConfig = .{
        .output_path = abs_out,
        .policy_path = policy_path,
        .read_buf = buf_size,
        .max_line = 1024,
        .write_buf = buf_size,
    };
    var env_map = std.process.Environ.Map.init(testing.allocator);
    defer env_map.deinit();
    var runtime = try Runtime.init(testing.allocator, io, &env_map, cfg);
    const in_file = try std.Io.Dir.cwd().openFile(io, abs_in, .{ .mode = .read_only });
    defer in_file.close(io);
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, cfg.write_buf);
    defer output.deinit();

    var stdio_bus = initEventBus(io, &env_map);
    var evaluator = try eval_stream.StreamEvaluator.init(
        testing.allocator,
        cfg.input_format,
        cfg.policy_path,
        stdio_bus.eventBus(),
    );
    defer evaluator.deinit();
    var framer = try framer_mod.LineFramer.init(testing.allocator, cfg.read_buf, cfg.max_line);
    defer framer.deinit();

    var lifecycle: lifecycle_mod.Lifecycle = .init;
    var loop: StdinLoop = .{
        .runtime = &runtime,
        .file = in_file,
        .output = &output,
        .framer = &framer,
        .evaluator = &evaluator,
        .lifecycle = &lifecycle,
    };
    try lifecycle.spawn(io, StdinLoop.run, .{&loop});

    lifecycle.awaitShutdown(io) catch |err| switch (err) {
        error.Canceled => {},
    };
    // Cancel the group directly, as `runStdinToOutput` does.
    lifecycle.group.cancel(io);

    try output.flush();
    if (loop.failure) |err| return err;

    return tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
}

test "runtime stdin path: StdinLoop applies policy drops" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "in.log", .data = "ok\ndebug line\nnext\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "policies.json", .data =
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
    });
    const abs_policy = try tmp.dir.realPathFileAlloc(io, "policies.json", testing.allocator);
    defer testing.allocator.free(abs_policy);

    const got = try runStdinLoopForTest(io, &tmp, "in.log", abs_policy, 32);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("ok\nnext\n", got);
}

test "runtime stdin path: structured StdinLoop task flushes residual on EOF" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "in.log", .data = "a\nb\n" });

    const got = try runStdinLoopForTest(io, &tmp, "in.log", null, 16);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("a\nb\n", got);
}
