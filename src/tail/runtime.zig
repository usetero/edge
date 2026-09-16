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

    /// File-tail shutdown drain: emit any trailing partial line the framer is
    /// holding in scratch, then flush output. The watcher sizes events to raw
    /// stat size (not a newline boundary), so a trailing record without a `\n`
    /// is buffered in scratch; without this `finish()` it would be freed by
    /// `deinit` and silently dropped. Scoped to `.tail`/`.checkpoint`: `.head`
    /// re-reads the whole file from 0 on restart, so emitting at shutdown would
    /// duplicate it on the next run (status quo for `.head` is unchanged).
    /// `catch {}` keeps `output.flush()` running even if the trailing partial
    /// is a half-record that fails parsing under `.json`/`.logfmt`.
    fn drainFramer(
        read_from: types.ReadFrom,
        framer: *framer_mod.LineFramer,
        output: *io_mod.Output,
        evaluator: *eval_stream.StreamEvaluator,
    ) !void {
        if (read_from != .head) {
            // ziglint-ignore: Z026 (intentional: swallow a half-record's parse error so flush still runs)
            framer.finish(output.writer(), evaluator, Runtime.evalLineFilter) catch {};
        }
        try output.flush();
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

        // Block SIGINT/SIGTERM/SIGUSR1 (and start the sigwait waiter) on this
        // thread BEFORE spawning the checkpoint worker and poll loop tasks.
        // Spawned threads inherit this thread's signal mask, so they block
        // these signals too; only the sigwait thread catches them and requests
        // a structured shutdown. If the mask is set only after the workers are
        // spawned (as it was here previously), a worker thread that did not
        // inherit the block receives SIGTERM by default action and terminates
        // the process before the sigwait thread can drive the clean shutdown —
        // so the shutdown drain below never runs and any trailing partial line
        // held in the framer's scratch is lost anyway, defeating the drain's
        // finish().
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

        lifecycle.awaitShutdown(self.io) catch |err| switch (err) {
            error.Canceled => {},
        };
        lifecycle.shutdown(self.io);

        if (signal_waiter) |waiter| teardownSignalWaiter(waiter, &shutdown_waiter);

        // The canceled tasks can't reliably do final file IO; drain and
        // flush on this (uncanceled) thread. See drainFramer for why the
        // trailing partial is finished only in .tail/.checkpoint.
        checkpoint.finalize();
        try Runtime.drainFramer(self.cfg.read_from, &framer, output, &evaluator);
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

// =============================================================================
// File-tail shutdown drain: the framer buffers a trailing non-newline-terminated
// record in scratch (the watcher sizes events to raw stat size, not a newline
// boundary). `runFilesLoopBackend` used to flush output without `finish()`-ing
// the framer, so `defer framer.deinit()` freed and silently dropped that
// partial. In the default `.tail` and `.checkpoint` modes the offset/checkpoint
// advances to the raw size, so the dropped bytes were never re-read on restart
// — permanently lost. `Runtime.drainFramer` is the fix; these tests exercise
// it directly (and, for .tail/.checkpoint, through the real Watcher +
// EngineScheduler that produce the mid-line event in the first place).
// =============================================================================

// Returns a StreamEvaluator backed by `bus`, which the caller owns and must
// keep alive for the lifetime of the returned evaluator (an active evaluator
// stores the event-bus pointer). Mirrors eval_stream's testBus pattern but lets
// the bus live in the caller so the retained pointer stays valid.
fn initEvaluator(
    io: std.Io,
    bus: *o11y.StdioEventBus,
    format: types.InputFormat,
    policy_path: ?[]const u8,
) !eval_stream.StreamEvaluator {
    bus.init(io);
    bus.eventBus().setLevel(.err);
    return eval_stream.StreamEvaluator.init(testing.allocator, format, policy_path, bus.eventBus());
}

test "runtime public API: .tail drain finishes trailing partial and restart does not re-read it" {
    // Reproduces the bug's permanent-loss scenario in the DEFAULT mode and
    // verifies the fix end-to-end through the real watcher/scheduler/drain:
    //   run 1 : .tail opens at size 5 (no event), append "part" (no \n) -> event
    //           [5..9), processBatch buffers "part" in scratch, drainFramer
    //           finish()es it -> out1 = "part" (was 0 bytes before the fix).
    //   restart: fresh .tail watcher re-opens at size 9 -> size<=offset -> no
    //           event -> out2 = 0 bytes. The partial is NOT re-read, but it was
    //           already emitted on run 1, so there is no loss AND no duplication.
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const in_path = "tail.log";
    const out1_path = "out1.log";
    const out2_path = "out2.log";

    // Pre-seed "done\n" (5 bytes, newline-aligned prefix).
    {
        const f = try tmp.dir.createFile(io, in_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "done\n");
    }

    const abs_in = try tmp.dir.realPathFileAlloc(io, in_path, testing.allocator);
    defer testing.allocator.free(abs_in);
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out1 = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out1_path });
    defer testing.allocator.free(abs_out1);
    const abs_out2 = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out2_path });
    defer testing.allocator.free(abs_out2);

    // ---- Run 1: .tail default mode. ----
    {
        var stdio_bus: o11y.StdioEventBus = undefined;
        var evaluator = try initEvaluator(io, &stdio_bus, .raw, null);
        defer evaluator.deinit();
        var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
        defer framer.deinit();
        var scheduler = try read_scheduler.EngineScheduler.init(testing.allocator, io, .poll);
        defer scheduler.deinit();
        var watcher = try watch_mod.Watcher.init(
            testing.allocator,
            io,
            .poll,
            &.{abs_in},
            abs_out1,
            .tail,
            1000,
            50,
            1000,
        );
        defer watcher.deinit();
        var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out1 }, 16);
        defer output.deinit();

        var events: std.ArrayList(watch_mod.Event) = .empty;
        defer events.deinit(testing.allocator);

        // .tail opens at size 5 -> size <= offset -> no event for the prefix.
        try watcher.collect(&events, .tail, null);
        try testing.expectEqual(@as(usize, 0), events.items.len);

        // Append "part" (no trailing newline) -> file is 9 bytes.
        {
            const f = try tmp.dir.openFile(io, in_path, .{ .mode = .read_write });
            defer f.close(io);
            const size = (try f.stat(io)).size;
            try f.writePositionalAll(io, "part", size);
        }

        // Second collect: event [5..9) covering the trailing partial, sized to
        // raw stat size (mid-line) — the root cause.
        try watcher.collect(&events, .tail, null);
        try testing.expectEqual(@as(usize, 1), events.items.len);
        try testing.expectEqual(@as(u64, 5), events.items[0].start_offset);
        try testing.expectEqual(@as(u64, 9), events.items[0].end_offset);

        // processBatch: "part" enters scratch (no newline -> not emitted yet).
        _ = try scheduler.processBatch(&framer, output.writer(), events.items, &evaluator, Runtime.evalLineFilter);
        try testing.expectEqual(@as(usize, 4), framer.inner.scratch_len);

        // Production shutdown drain (the fix): finish() emits "part".
        try Runtime.drainFramer(.tail, &framer, &output, &evaluator);
        try testing.expectEqual(@as(usize, 0), framer.inner.scratch_len);
    }

    const got1 = try tmp.dir.readFileAlloc(io, out1_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got1);
    try testing.expectEqualStrings("part", got1); // before the fix: 0 bytes (dropped)

    // ---- Simulated restart: fresh Watcher + framer in .tail mode. ----
    {
        var stdio_bus: o11y.StdioEventBus = undefined;
        var evaluator = try initEvaluator(io, &stdio_bus, .raw, null);
        defer evaluator.deinit();
        var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
        defer framer.deinit();
        var scheduler = try read_scheduler.EngineScheduler.init(testing.allocator, io, .poll);
        defer scheduler.deinit();
        var watcher = try watch_mod.Watcher.init(
            testing.allocator,
            io,
            .poll,
            &.{abs_in},
            abs_out2,
            .tail,
            1000,
            50,
            1000,
        );
        defer watcher.deinit();
        var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out2 }, 16);
        defer output.deinit();

        var events: std.ArrayList(watch_mod.Event) = .empty;
        defer events.deinit(testing.allocator);

        // .tail re-opens at the current size (9) -> size <= offset -> no event:
        // the partial is not re-read (it was already emitted on run 1).
        try watcher.collect(&events, .tail, null);
        try testing.expectEqual(@as(usize, 0), events.items.len);
        _ = try scheduler.processBatch(&framer, output.writer(), events.items, &evaluator, Runtime.evalLineFilter);
        try testing.expectEqual(@as(usize, 0), framer.inner.scratch_len);
        try Runtime.drainFramer(.tail, &framer, &output, &evaluator);
    }

    const got2 = try tmp.dir.readFileAlloc(io, out2_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got2);
    try testing.expectEqual(@as(usize, 0), got2.len); // no re-read, no duplication
}

test "runtime public API: file-tail drain finishes trailing partial in .checkpoint mode" {
    // .checkpoint advances to the stored raw size on restart, so (like .tail)
    // a trailing partial is never re-read; the drain must finish() it out.
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const in_path = "tail.log";
    const out_path = "out.log";
    {
        const f = try tmp.dir.createFile(io, in_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "done\npart"); // 9 bytes, non-newline-aligned
    }

    const abs_in = try tmp.dir.realPathFileAlloc(io, in_path, testing.allocator);
    defer testing.allocator.free(abs_in);
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    var stdio_bus: o11y.StdioEventBus = undefined;
    var evaluator = try initEvaluator(io, &stdio_bus, .raw, null);
    defer evaluator.deinit();
    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var scheduler = try read_scheduler.EngineScheduler.init(testing.allocator, io, .poll);
    defer scheduler.deinit();
    var watcher = try watch_mod.Watcher.init(
        testing.allocator,
        io,
        .poll,
        &.{abs_in},
        abs_out,
        .checkpoint,
        1000,
        50,
        1000,
    );
    defer watcher.deinit();
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, 16);
    defer output.deinit();

    var events: std.ArrayList(watch_mod.Event) = .empty;
    defer events.deinit(testing.allocator);

    // No checkpoint lane -> .checkpoint opens at 0 -> reads [0..9), the whole
    // file. "done\n" is emitted; "part" buffers in scratch.
    try watcher.collect(&events, .checkpoint, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 9), events.items[0].end_offset); // raw st.size, mid-line

    _ = try scheduler.processBatch(&framer, output.writer(), events.items, &evaluator, Runtime.evalLineFilter);
    try testing.expectEqual(@as(usize, 4), framer.inner.scratch_len);

    try Runtime.drainFramer(.checkpoint, &framer, &output, &evaluator);
    try testing.expectEqual(@as(usize, 0), framer.inner.scratch_len);

    const got = try tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("done\npart", got); // before the fix: "done\n" only
}

test "runtime public API: file-tail drain skips finish() in .head mode (recovered on restart)" {
    // .head re-reads the whole file from 0 on restart, so emitting the trailing
    // partial at shutdown would duplicate it on the next run. The drain guard
    // (read_from != .head) leaves the partial buffered; a fresh .head watcher
    // re-reads it from 0 on the next run. Status quo for .head is unchanged.
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const out_path = "out.log";
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    var stdio_bus: o11y.StdioEventBus = undefined;
    var evaluator = try initEvaluator(io, &stdio_bus, .raw, null);
    defer evaluator.deinit();
    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, 16);
    defer output.deinit();

    // Ingest "done\npart": "done\n" is emitted during ingest, "part" buffers.
    try framer.ingestChunk("done\npart", output.writer(), &evaluator, Runtime.evalLineFilter);
    try testing.expectEqual(@as(usize, 4), framer.inner.scratch_len);

    // drainFramer(.head) must NOT finish(): the partial stays in scratch.
    try Runtime.drainFramer(.head, &framer, &output, &evaluator);
    try testing.expectEqual(@as(usize, 4), framer.inner.scratch_len);

    const got = try tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("done\n", got); // "part" intentionally not emitted in .head
}

test "runtime public API: file-tail drain swallows half-record parse error (.json policy)" {
    // Under .json with an active policy, finish() runs the trailing partial
    // through evalLine -> parseJsonAttrs -> std.json.parseFromSliceLeaky, which
    // errors on a half-record. drainFramer's catch {} swallows that error so
    // output.flush() still runs and the already-emitted complete record is not
    // lost (at-worst-neutral for .json/.logfmt; a valid trailing record still
    // emits normally).
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Keep-all policy: every parsed line matches and is kept. Required so the
    // parser actually runs (a disabled evaluator never parses and would keep a
    // half-record without erroring, hiding the catch {} path).
    const policy_path = "policies.json";
    {
        const f = try tmp.dir.createFile(io, policy_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io,
            // ziglint-ignore: Z024 (single-line JSON policy record)
            \\{"policies":[{"id":"keep-all","name":"keep-all","log":{"match":[{"log_field":"body","regex":"."}],"keep":"all"}}]}
        );
    }
    const abs_policy = try tmp.dir.realPathFileAlloc(io, policy_path, testing.allocator);
    defer testing.allocator.free(abs_policy);
    const out_path = "out.log";
    const cwd_abs = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(cwd_abs);
    const abs_out = try std.fs.path.join(testing.allocator, &.{ cwd_abs, out_path });
    defer testing.allocator.free(abs_out);

    var stdio_bus: o11y.StdioEventBus = undefined;
    var evaluator = try initEvaluator(io, &stdio_bus, .json, abs_policy);
    defer evaluator.deinit();
    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var output = try io_mod.Output.init(testing.allocator, io, .{ .file_append = abs_out }, 64);
    defer output.deinit();

    // A complete JSON record then a half-record (no newline): the complete
    // record emits during ingest; the half-record buffers in scratch.
    try framer.ingestChunk("{\"message\":\"x\"}\n{\"ms", output.writer(), &evaluator, Runtime.evalLineFilter);
    try testing.expectEqual(@as(usize, 4), framer.inner.scratch_len); // "{\"ms" buffered

    // drainFramer(.tail): finish() tries to eval "{\"ms" -> JSON parse error,
    // caught -> output.flush() still runs. drainFramer must NOT return error.
    try Runtime.drainFramer(.tail, &framer, &output, &evaluator);

    const got = try tmp.dir.readFileAlloc(io, out_path, testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("{\"message\":\"x\"}\n", got); // complete record kept; half-record not emitted
}
