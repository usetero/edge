//! Structured shutdown for the whole process: every long-lived task (accept
//! loop, connection tasks, tail lanes) is spawned into one Io.Group, and
//! shutdown is a single Group.cancel — in-flight IO returns error.Canceled
//! and unwinds through normal defers. This replaces hand-rolled stop threads
//! and atomic state machines; signal handlers' only job is to call
//! `requestShutdown`.
const std = @import("std");

const log = std.log.scoped(.lifecycle);

pub const Lifecycle = struct {
    /// All long-lived tasks. Spawn with `spawn`; connection tasks MUST be
    /// concurrent (Group.async tasks are not guaranteed to run until the
    /// group is awaited — verified against 0.16 docs, see
    /// .rewrite/zigdoc-notes.md).
    group: std.Io.Group,
    /// Flipped exactly once; pollable from accept loops between blocking ops.
    shutdown_requested: std.atomic.Value(bool),
    /// Wakes `awaitShutdown` sleepers (e.g. the main thread).
    shutdown_event: std.Io.Event,

    pub const init: Lifecycle = .{
        .group = .init,
        .shutdown_requested = .init(false),
        .shutdown_event = .unset,
    };

    pub const SpawnError = std.Io.ConcurrentError;

    /// Spawns `function` as a concurrent task tied to process shutdown.
    /// error.ConcurrencyUnavailable is the caller's load-shed signal.
    pub fn spawn(
        self: *Lifecycle,
        io: std.Io,
        function: anytype,
        args: std.meta.ArgsTuple(@TypeOf(function)),
    ) SpawnError!void {
        return self.group.concurrent(io, function, args);
    }

    /// Idempotent; safe from any task or signal-watcher thread.
    pub fn requestShutdown(self: *Lifecycle, io: std.Io) void {
        if (self.shutdown_requested.swap(true, .acq_rel)) return;
        log.info("shutdown requested", .{});
        self.shutdown_event.set(io);
    }

    pub fn isShuttingDown(self: *const Lifecycle) bool {
        return self.shutdown_requested.load(.acquire);
    }

    /// Blocks until `requestShutdown` is called. Cancelable.
    pub fn awaitShutdown(self: *Lifecycle, io: std.Io) std.Io.Cancelable!void {
        try self.shutdown_event.wait(io);
    }

    /// Cancels every spawned task and waits for all of them to unwind.
    /// Call exactly once, after `requestShutdown`.
    pub fn shutdown(self: *Lifecycle, io: std.Io) void {
        std.debug.assert(self.isShuttingDown());
        self.group.cancel(io);
        log.info("all tasks drained", .{});
    }
};

const testing = std.testing;

fn blockUntilCanceled(event: *std.Io.Event, io: std.Io, started: *std.Io.Event) std.Io.Cancelable!void {
    started.set(io);
    try event.wait(io); // never set: only cancellation releases this task
}

test "shutdown cancels blocked tasks" {
    const io = testing.io;
    var lifecycle: Lifecycle = .init;

    var never_set: std.Io.Event = .unset;
    var started: std.Io.Event = .unset;
    try lifecycle.spawn(io, blockUntilCanceled, .{ &never_set, io, &started });
    started.waitUncancelable(io);

    lifecycle.requestShutdown(io);
    try testing.expect(lifecycle.isShuttingDown());
    lifecycle.shutdown(io); // must not hang: cancel interrupts event.wait
    try testing.expect(!never_set.isSet());
}

test "requestShutdown is idempotent and wakes awaitShutdown" {
    const io = testing.io;
    var lifecycle: Lifecycle = .init;

    lifecycle.requestShutdown(io);
    lifecycle.requestShutdown(io);
    try lifecycle.awaitShutdown(io); // already set: returns immediately
    lifecycle.shutdown(io);
}
