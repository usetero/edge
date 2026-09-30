//! Opt-in dumps of upstream requests that failed, for replay.
//!
//! The edge writes a dump on a relayed upstream 408, 400 or 413 (see
//! `capturesStatus`), on any error out of the upstream exchange except a
//! sender that left mid-relay, and when a policy stage cannot read a batch
//! and forwards it untouched. A dump is two files in the capture directory:
//!
//!   <unix_ms>-<seq>.body   the body as the edge sent it, still compressed
//!   <unix_ms>-<seq>.json   method, URL, headers, outcome and body framing
//!
//! A dump shows what the edge meant to send. It does not prove what reached
//! the intake: a send that failed part way wrote less than the dump holds.
//!
//! The request path only builds a dump in memory and queues it; one writer
//! thread does the disk work (see `Capture`). Memory is bounded twice: by
//! `max_copies` streamed-body copies in flight, and by `queue_len` queued
//! dumps.
//!
//! Credentials never reach the disk. A header or query parameter whose name
//! looks like a credential keeps its name and loses its value.
//!
//! `max_dumps` caps the dumps in the directory, the files from earlier runs
//! included, so a crash loop cannot fill the disk. A dump counts once for its
//! `<stem>`, whether both files are there or only one, so a body orphaned by a
//! crash still takes its slot. A write that fails removes what it wrote.
//! While the directory is full the writer counts it again every 5 s, so
//! deleting dumps arms the capture again without a restart.
const std = @import("std");
const builtin = @import("builtin");
const o11y = @import("o11y");
const EventBus = o11y.EventBus;

// Named event payloads: the type name is the telemetry event name.
/// A failed upstream request was dumped. `file` is the `.json` name.
const UpstreamFailureCaptured = struct { path: []const u8, file: []const u8 };
/// The dump could not be written. The failure itself is still reported.
const UpstreamFailureCaptureFailed = struct { path: []const u8, err: []const u8 };
/// The directory holds `max_dumps` dumps. Warned once per process.
const UpstreamFailureCaptureFull = struct { dir: []const u8, max_dumps: u32 };
/// The capture directory already existed and its mode could not be narrowed.
/// The dump files are still created `0600`.
const FailureCaptureDirPermissions = struct { dir: []const u8, err: []const u8 };
/// A dump was dropped because `queue_len` dumps were already waiting for the
/// disk. Warned once until the writer writes again.
const UpstreamFailureCaptureDropped = struct { path: []const u8, queued: usize };
/// The writer did not finish at shutdown, most likely on a stalled volume.
const FailureCaptureStalled = struct { dir: []const u8, queued: usize };
/// Dumps were deleted from a full directory, and the capture writes again.
const FailureCaptureRearmed = struct { dir: []const u8, free: u32 };

/// Dumps hold customer payloads, so only the edge's own user may read them.
const dir_permissions: std.Io.File.Permissions = @enumFromInt(0o700);
const file_permissions: std.Io.File.Permissions = @enumFromInt(0o600);

pub const redacted = "[redacted]";

/// Upstream statuses worth a dump. 408: the intake waited for bytes it never
/// got. 400 and 413: the Datadog agent drops the batch for good, so the dump is
/// the only copy left. 401 and 403 are about the key, not the payload.
pub fn capturesStatus(status: ?u16) bool {
    const code = status orelse return false;
    return code == 408 or code == 400 or code == 413;
}

/// How the body went upstream.
pub const Framing = enum { none, content_length, chunked };

/// One failed exchange, as `exchange.zig` saw it.
pub const Failure = struct {
    method: std.http.Method,
    /// Path plus query, as the frontend received it.
    target: []const u8,
    /// Path only, for the log line.
    path: []const u8,
    /// Full upstream URL. The query is redacted here.
    url: []const u8,
    /// Forwarded headers. std adds `host` and the framing header itself.
    headers: []const std.http.Header,
    framing: Framing,
    body: []const u8,
    /// The length the edge declared upstream, when it declared one.
    declared_len: ?usize,
    /// False when the edge holds less than the whole body: the inbound body
    /// ended or stalled while it streamed, or the copy ran out of memory.
    complete: bool,
    /// Upstream status, when a response head arrived.
    status: ?u16,
    /// The error that ended the exchange, when one did.
    err: ?[]const u8,
    /// Where the exchange stopped: `dial`, `send_or_head`, `relay` or
    /// `response`. `policy_probe`, `policy_encode` or `policy_buffered` names
    /// the policy stage that could not read the batch.
    phase: []const u8,
    attempts: usize,
    /// The error of an earlier attempt that was retried.
    retried_err: ?[]const u8,
    /// The watchdog shut the upstream socket down. A status with this set
    /// came after our own deadline, not before it.
    watchdog_fired: bool,
    elapsed_ms: f64,
};

/// Streamed bodies copied at once, at most. Each copy is one declared body
/// length, so the copies never hold more than `max_copies` bodies of memory.
/// Past this a streamed failure is dumped without its body.
pub const max_copies = 4;

/// Dumps waiting for the writer, at most. A dump that finds the queue full is
/// dropped with a warning, so a stalled volume costs dumps, never requests.
pub const queue_len = 8;

/// How long the writer sleeps when nothing wakes it.
const idle_wait: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(1000), .clock = .awake } };
/// How long `close` waits for the writer, in 50 ms steps.
const close_wait_steps = 40;
/// How often a full directory is counted again, so deleted dumps free their
/// slots without a restart.
const rescan_interval_ns: i96 = 5 * std.time.ns_per_s;

/// One dump, owned by the capture from `record` until the writer frees it.
const Job = struct {
    stem: []u8,
    /// The request path, for the log line.
    path: []u8,
    body: []u8,
    meta: []u8,

    fn deinit(self: Job, gpa: std.mem.Allocator) void {
        gpa.free(self.stem);
        gpa.free(self.path);
        gpa.free(self.body);
        gpa.free(self.meta);
    }
};

/// The request path only prepares a dump in memory and queues it. One writer
/// thread does every disk operation, so a slow or stalled volume never holds
/// a request, before or after its forward.
pub const Capture = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    bus: *EventBus,
    dir: std.Io.Dir,
    path: []const u8,
    max_dumps: u32,
    /// Bytes the streamed-body copies may hold at once.
    copy_budget: usize,
    copy_used: std.atomic.Value(usize) = .init(0),
    /// Dumps on disk plus `pending`. Changed only under `mutex`; `armed`
    /// reads it without the lock.
    used: std.atomic.Value(u32),
    /// Dumps reserved and not yet on disk: being prepared, queued or being
    /// written. Guarded by `mutex`. A rescan keeps these, so it never frees a
    /// slot that a dump in flight still needs.
    pending: u32 = 0,
    /// When the writer last counted a full directory. Writer thread only.
    last_rescan_ns: i96 = 0,
    seq: std.atomic.Value(u32) = .init(0),
    full_reported: std.atomic.Value(bool) = .init(false),
    /// Set when a dump was dropped on a full queue; cleared by the next write.
    drop_reported: std.atomic.Value(bool) = .init(false),

    mutex: std.Io.Mutex = .init,
    queue: [queue_len]Job = undefined,
    queue_head: usize = 0,
    queue_count: usize = 0,
    wake: std.Io.Event = .unset,
    stopping: std.atomic.Value(bool) = .init(false),
    stopped: std.Io.Event = .unset,
    writer: ?std.Io.Future(void) = null,
    /// Test hook: every file write blocks, as on a stalled volume, until the
    /// writer is canceled.
    test_stall_writes: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    /// Test hook: every file write stops half way with `NoSpaceLeft`.
    test_short_write: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},
    /// Test hook: removing a failed write's file fails.
    test_remove_fails: if (builtin.is_test) bool else void = if (builtin.is_test) false else {},

    /// Creates `path` when it is missing and counts the dumps already in it.
    /// `max_body_size` sizes the copy budget for streamed bodies. Call
    /// `start` once the capture is at its final address.
    pub fn open(
        io: std.Io,
        gpa: std.mem.Allocator,
        bus: *EventBus,
        path: []const u8,
        max_dumps: u32,
        max_body_size: usize,
    ) !Capture {
        const dir = try std.Io.Dir.cwd().createDirPathOpen(io, path, .{
            .permissions = dir_permissions,
            .open_options = .{ .iterate = true },
        });
        errdefer dir.close(io);
        // A directory that already existed keeps its own mode, which is often
        // world-readable (a Kubernetes emptyDir is 0777).
        dir.setPermissions(io, dir_permissions) catch |err| {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            bus.warn(FailureCaptureDirPermissions{ .dir = path, .err = @errorName(err) });
        };
        const existing = try countDumps(io, gpa, dir);
        return .{
            .io = io,
            .gpa = gpa,
            .bus = bus,
            .dir = dir,
            .path = path,
            .max_dumps = max_dumps,
            .copy_budget = max_copies * max_body_size,
            .used = .init(existing),
        };
    }

    /// Starts the writer as an Io task, so `close` can interrupt it.
    pub fn start(self: *Capture) !void {
        self.writer = try self.io.concurrent(run, .{self});
    }

    /// Stops the writer, and returns only once it has stopped: the writer
    /// uses this capture, its allocator, the bus and the directory, so none
    /// of them may go before it. The writer gets 2 s to write what is queued.
    /// After that it is canceled, which interrupts a write blocked on a
    /// stalled volume, and it does no more disk work. A volume that ignores
    /// the interrupt (an uninterruptible hard NFS mount) holds shutdown.
    pub fn close(self: *Capture) void {
        if (self.writer) |*writer| {
            self.stopping.store(true, .release);
            self.wake.set(self.io);
            if (self.waitStopped()) {
                writer.await(self.io);
            } else {
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                self.bus.warn(FailureCaptureStalled{ .dir = self.path, .queued = self.queue_count });
                writer.cancel(self.io);
            }
            self.writer = null;
        }
        while (self.dequeue()) |job| job.deinit(self.gpa);
        self.dir.close(self.io);
    }

    fn waitStopped(self: *Capture) bool {
        const step: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
        var steps: u32 = 0;
        while (!self.stopped.isSet() and steps < close_wait_steps) : (steps += 1) {
            self.stopped.waitTimeout(self.io, step) catch |err| switch (err) {
                // A timeout or a spurious wakeup: look again.
                error.Timeout => {},
                error.Canceled => break,
            };
        }
        return self.stopped.isSet();
    }

    /// A buffer to copy one streamed body into, or null: the directory is
    /// full, the copy budget is spent, or memory is short. The request
    /// forwards either way. Give it back with `releaseCopy`.
    pub fn acquireCopy(self: *Capture, len: usize) ?[]u8 {
        if (!self.armed()) return null;
        if (self.copy_used.fetchAdd(len, .monotonic) + len > self.copy_budget) {
            _ = self.copy_used.fetchSub(len, .monotonic);
            return null;
        }
        return self.gpa.alloc(u8, len) catch {
            _ = self.copy_used.fetchSub(len, .monotonic);
            return null;
        };
    }

    pub fn releaseCopy(self: *Capture, buf: []u8) void {
        self.gpa.free(buf);
        _ = self.copy_used.fetchSub(buf.len, .monotonic);
    }

    /// True while the budget has room. A streamed body is copied only when
    /// this holds, so a full directory costs the data path nothing.
    pub fn armed(self: *const Capture) bool {
        return self.used.load(.monotonic) < self.max_dumps;
    }

    fn reserve(self: *Capture) bool {
        self.mutex.lockUncancelable(self.io);
        const used = self.used.load(.monotonic);
        const room = used < self.max_dumps;
        if (room) {
            self.used.store(used + 1, .monotonic);
            self.pending += 1;
        }
        self.mutex.unlock(self.io);
        if (!room and !self.full_reported.swap(true, .monotonic)) {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            self.bus.warn(UpstreamFailureCaptureFull{ .dir = self.path, .max_dumps = self.max_dumps });
        }
        return room;
    }

    fn refund(self: *Capture) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.used.store(self.used.load(.monotonic) - 1, .monotonic);
        self.pending -= 1;
    }

    /// A dump reached the disk: its slot stays spent, and it is no longer
    /// in flight.
    fn settle(self: *Capture) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.pending -= 1;
    }

    fn rescanIfFull(self: *Capture) void {
        if (self.armed()) return;
        const now_ns = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
        if (now_ns - self.last_rescan_ns < rescan_interval_ns) return;
        self.last_rescan_ns = now_ns;
        self.rescan();
    }

    /// Counts the directory again, so dumps an operator deleted free their
    /// slots. Runs on the writer between writes, so no dump is half written.
    fn rescan(self: *Capture) void {
        const on_disk = countDumps(self.io, self.gpa, self.dir) catch |err| {
            self.warnFailed(self.path, err);
            return;
        };
        self.mutex.lockUncancelable(self.io);
        const before = self.used.load(.monotonic);
        const after = on_disk + self.pending;
        self.used.store(after, .monotonic);
        self.mutex.unlock(self.io);
        if (before >= self.max_dumps and after < self.max_dumps) {
            self.full_reported.store(false, .monotonic);
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            self.bus.info(FailureCaptureRearmed{ .dir = self.path, .free = self.max_dumps - after });
        }
    }

    fn warnFailed(self: *Capture, path: []const u8, err: anyerror) void {
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        self.bus.warn(UpstreamFailureCaptureFailed{ .path = path, .err = @errorName(err) });
    }

    /// Queues one dump and returns at once; the writer does the disk work.
    /// Errors are reported on the bus: the capture must not change how the
    /// request itself fails.
    pub fn record(self: *Capture, arena: std.mem.Allocator, failure: Failure) void {
        if (!self.reserve()) return;
        const job = self.prepare(arena, failure) catch |err| {
            self.refund();
            self.warnFailed(failure.path, err);
            return;
        };
        if (!self.enqueue(job)) {
            job.deinit(self.gpa);
            self.refund();
            if (!self.drop_reported.swap(true, .monotonic)) {
                // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
                self.bus.warn(UpstreamFailureCaptureDropped{ .path = failure.path, .queued = queue_len });
            }
            return;
        }
        self.wake.set(self.io);
    }

    /// Everything a dump needs, in memory the capture owns: the request
    /// arena is reset once the request is answered.
    fn prepare(self: *Capture, arena: std.mem.Allocator, failure: Failure) !Job {
        const now_ms = std.Io.Clock.real.now(self.io).toMilliseconds();
        const stem = try std.fmt.allocPrint(self.gpa, "{d}-{d}", .{ now_ms, self.seq.fetchAdd(1, .monotonic) });
        errdefer self.gpa.free(stem);
        const body_name = try std.fmt.allocPrint(arena, "{s}.body", .{stem});
        var json: std.Io.Writer.Allocating = .init(arena);
        const meta_value = try metaOf(arena, failure, body_name, now_ms);
        try std.json.Stringify.value(meta_value, .{ .whitespace = .indent_2 }, &json.writer);
        try json.writer.writeByte('\n');
        const meta = try self.gpa.dupe(u8, json.written());
        errdefer self.gpa.free(meta);
        const body = try self.gpa.dupe(u8, failure.body);
        errdefer self.gpa.free(body);
        const path = try self.gpa.dupe(u8, failure.path);
        return .{ .stem = stem, .path = path, .body = body, .meta = meta };
    }

    fn enqueue(self: *Capture, job: Job) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.queue_count == queue_len) return false;
        self.queue[(self.queue_head + self.queue_count) % queue_len] = job;
        self.queue_count += 1;
        return true;
    }

    fn dequeue(self: *Capture) ?Job {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.queue_count == 0) return null;
        const job = self.queue[self.queue_head];
        self.queue_head = (self.queue_head + 1) % queue_len;
        self.queue_count -= 1;
        return job;
    }

    /// The writer: drain the queue, then sleep until woken. Once `close` has
    /// asked it to stop, a failed write ends all disk work: after a cancel,
    /// the next disk call is not interrupted again, and on a stalled volume
    /// it would block for good. A dump left half written then counts at the
    /// next start.
    fn run(self: *Capture) void {
        defer self.stopped.set(self.io);
        while (true) {
            self.wake.waitTimeout(self.io, idle_wait) catch |err| switch (err) {
                // A timeout or a spurious wakeup: look at the queue.
                error.Timeout => {},
                error.Canceled => return self.dropQueued(),
            };
            // Reset before draining: a dump queued after this point sets the
            // event again, so no wakeup is lost.
            self.wake.reset();
            while (self.dequeue()) |job| {
                const keep_going = self.writeJob(job);
                job.deinit(self.gpa);
                if (!keep_going) return self.dropQueued();
            }
            if (self.stopping.load(.acquire)) return;
            self.rescanIfFull();
        }
    }

    /// Frees what is still queued without writing it. Shutdown only.
    fn dropQueued(self: *Capture) void {
        while (self.dequeue()) |job| job.deinit(self.gpa);
    }

    /// Writes one dump. False when the writer must stop all disk work.
    fn writeJob(self: *Capture, job: Job) bool {
        var name_buf: [64]u8 = undefined;
        var left = false;
        const name = self.writeFiles(job, &name_buf, &left) catch |err| {
            self.warnFailed(job.path, err);
            if (self.stopping.load(.acquire)) return false;
            // A file that could not be removed is still on disk, so its slot
            // stays spent: refunding it would let the directory outgrow the cap.
            if (left) self.settle() else self.refund();
            return true;
        };
        self.settle();
        self.drop_reported.store(false, .monotonic);
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        self.bus.warn(UpstreamFailureCaptured{ .path = job.path, .file = name });
        return true;
    }

    /// The body goes first: a `.json` file means the dump is whole. Each file
    /// is removed on failure from the moment it exists, so a write that
    /// fails part way leaves nothing. `left` is set when a file could not be
    /// removed.
    fn writeFiles(self: *Capture, job: Job, name_buf: *[64]u8, left: *bool) ![]const u8 {
        var body_buf: [64]u8 = undefined;
        const body_name = try std.fmt.bufPrint(&body_buf, "{s}.body", .{job.stem});
        const meta_name = try std.fmt.bufPrint(name_buf, "{s}.json", .{job.stem});
        if (builtin.is_test and self.test_stall_writes) try self.io.sleep(.fromSeconds(60), .awake);
        try self.writeNew(job.path, body_name, job.body, left);
        errdefer self.discard(job.path, body_name, left);
        try self.writeNew(job.path, meta_name, job.meta, left);
        return meta_name;
    }

    /// Creates `name` and writes `data` to it, and removes the file again if
    /// the write fails after the create.
    fn writeNew(self: *Capture, path: []const u8, name: []const u8, data: []const u8, left: *bool) !void {
        const file = try self.dir.createFile(self.io, name, .{ .exclusive = true, .permissions = file_permissions });
        errdefer self.discard(path, name, left);
        defer file.close(self.io);
        if (builtin.is_test and self.test_short_write) {
            try file.writeStreamingAll(self.io, data[0 .. data.len / 2]);
            return error.NoSpaceLeft;
        }
        try file.writeStreamingAll(self.io, data);
    }

    /// Removes a file a failed write left. Sets `left` when the file stays.
    /// During shutdown the file stays: the writer does no more disk work,
    /// and the file counts against the cap at the next start.
    fn discard(self: *Capture, path: []const u8, name: []const u8, left: *bool) void {
        if (self.stopping.load(.acquire) or (builtin.is_test and self.test_remove_fails)) {
            left.* = true;
            return;
        }
        self.dir.deleteFile(self.io, name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => {
                left.* = true;
                self.warnFailed(path, err);
            },
        };
    }
};

/// Dumps in `dir`: distinct stems of `.body` and `.json` files, so a dump
/// missing either half still counts once.
fn countDumps(io: std.Io, gpa: std.mem.Allocator, dir: std.Io.Dir) !u32 {
    var stems: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var keys = stems.keyIterator();
        while (keys.next()) |key| gpa.free(key.*);
        stems.deinit(gpa);
    }
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const stem = if (std.mem.endsWith(u8, entry.name, ".json"))
            entry.name[0 .. entry.name.len - ".json".len]
        else if (std.mem.endsWith(u8, entry.name, ".body"))
            entry.name[0 .. entry.name.len - ".body".len]
        else
            continue;
        const slot = try stems.getOrPut(gpa, stem);
        if (!slot.found_existing) {
            // The key still points into the iterator's buffer; replace it
            // with an owned copy, or take the entry out before returning.
            slot.key_ptr.* = gpa.dupe(u8, stem) catch |err| {
                _ = stems.remove(stem);
                return err;
            };
        }
    }
    return @intCast(stems.count());
}

const Meta = struct {
    unix_ms: i64,
    method: []const u8,
    url: []const u8,
    target: []const u8,
    headers: []const std.http.Header,
    outcome: struct {
        status: ?u16,
        err: ?[]const u8,
        phase: []const u8,
        attempts: usize,
        retried_err: ?[]const u8,
        watchdog_fired: bool,
        elapsed_ms: f64,
    },
    body: struct {
        file: []const u8,
        framing: Framing,
        declared_bytes: ?usize,
        captured_bytes: usize,
        complete: bool,
    },
};

fn metaOf(arena: std.mem.Allocator, failure: Failure, body_file: []const u8, now_ms: i64) !Meta {
    const headers = try arena.alloc(std.http.Header, failure.headers.len);
    for (failure.headers, headers) |header, *out| {
        out.* = .{ .name = header.name, .value = if (sensitiveName(header.name)) redacted else header.value };
    }
    return .{
        .unix_ms = now_ms,
        .method = @tagName(failure.method),
        .url = try redactQuery(arena, failure.url),
        .target = try redactQuery(arena, failure.target),
        .headers = headers,
        .outcome = .{
            .status = failure.status,
            .err = failure.err,
            .phase = failure.phase,
            .attempts = failure.attempts,
            .retried_err = failure.retried_err,
            .watchdog_fired = failure.watchdog_fired,
            .elapsed_ms = failure.elapsed_ms,
        },
        .body = .{
            .file = body_file,
            .framing = failure.framing,
            .declared_bytes = failure.declared_len,
            .captured_bytes = failure.body.len,
            .complete = failure.complete,
        },
    };
}

/// A header or query name that may carry a credential. Deliberately broad:
/// a redacted value costs a replay one manual step, a leaked key costs more.
pub fn sensitiveName(name: []const u8) bool {
    const needles = [_][]const u8{
        "key",      "token",     "secret",  "auth",       "cookie",
        "password", "signature", "session", "credential",
    };
    for (needles) |needle| {
        if (std.ascii.findIgnoreCase(name, needle) != null) return true;
    }
    return false;
}

/// A query parameter name that may carry a credential. The name is checked
/// as written and after percent-decoding, repeated, so `dd-api-%6b%65%79`
/// is caught. A name too long to decode here is treated as sensitive.
fn sensitiveQueryName(name: []const u8) bool {
    if (sensitiveName(name)) return true;
    var buf: [256]u8 = undefined;
    if (name.len > buf.len) return true;
    @memcpy(buf[0..name.len], name);
    var decoded: []u8 = buf[0..name.len];
    while (std.mem.findScalar(u8, decoded, '%') != null) {
        const next = std.Uri.percentDecodeInPlace(decoded);
        if (next.len == decoded.len) break; // nothing left that decodes
        decoded = next;
        if (sensitiveName(decoded)) return true;
    }
    return false;
}

/// `url` with the value of every sensitive query parameter replaced.
pub fn redactQuery(arena: std.mem.Allocator, url: []const u8) ![]const u8 {
    const q = std.mem.findScalar(u8, url, '?') orelse return url;
    var out: std.Io.Writer.Allocating = .init(arena);
    try out.writer.writeAll(url[0 .. q + 1]);
    var params = std.mem.splitScalar(u8, url[q + 1 ..], '&');
    var first = true;
    while (params.next()) |param| {
        if (!first) try out.writer.writeByte('&');
        first = false;
        const eq = std.mem.findScalar(u8, param, '=') orelse param.len;
        if (eq < param.len and sensitiveQueryName(param[0..eq])) {
            try out.writer.print("{s}={s}", .{ param[0..eq], redacted });
        } else {
            try out.writer.writeAll(param);
        }
    }
    return out.toOwnedSlice();
}

/// Copies every byte a streamed body yields, so a failed send can still be
/// dumped. A body that streams cannot be read again afterwards. The copy is a
/// fixed buffer of the declared length from `Capture.acquireCopy`.
pub const Tee = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    inner: *std.Io.Reader,
    copy: []u8,
    copied: usize = 0,
    /// Set when the body ran past the buffer. The body still streams; only
    /// the dump is short.
    copy_failed: bool = false,

    pub fn written(self: *const Tee) []const u8 {
        return self.copy[0..self.copied];
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Tee = @alignCast(@fieldParentPtr("interface", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        var vec = [_][]u8{dest};
        // Zero means the bytes landed in `inner`'s buffer; the next call
        // returns them.
        while (true) {
            const n = try self.inner.readVec(&vec);
            if (n == 0) continue;
            const take = @min(n, self.copy.len - self.copied);
            @memcpy(self.copy[self.copied..][0..take], dest[0..take]);
            self.copied += take;
            if (take < n) self.copy_failed = true;
            w.advance(n);
            return n;
        }
    }
};

// ============================== Tests ==============================

const testing = std.testing;

test "only the statuses that lose or stall a batch are captured" {
    try testing.expect(capturesStatus(408));
    try testing.expect(capturesStatus(400));
    try testing.expect(capturesStatus(413));
    for ([_]u16{ 200, 202, 401, 403, 429, 500, 503 }) |code| try testing.expect(!capturesStatus(code));
    try testing.expect(!capturesStatus(null));
}

test "credential names are redacted, other names are kept" {
    try testing.expect(sensitiveName("DD-API-KEY"));
    try testing.expect(sensitiveName("dd-application-key"));
    try testing.expect(sensitiveName("Authorization"));
    try testing.expect(sensitiveName("Cookie"));
    try testing.expect(sensitiveName("X-Amz-Security-Token"));
    try testing.expect(!sensitiveName("Content-Encoding"));
    try testing.expect(!sensitiveName("DD-EVP-ORIGIN"));

    const url = try redactQuery(testing.allocator, "https://h/api/v2/logs?dd-api-key=abc&ddsource=x&flag");
    defer testing.allocator.free(url);
    try testing.expectEqualStrings("https://h/api/v2/logs?dd-api-key=[redacted]&ddsource=x&flag", url);
    try testing.expectEqualStrings("https://h/p", try redactQuery(testing.allocator, "https://h/p"));
}

test "percent-encoded query names are redacted" {
    const cases = [_][2][]const u8{
        .{ "https://h/p?dd-api-%6b%65%79=SECRET", "https://h/p?dd-api-%6b%65%79=[redacted]" },
        .{ "https://h/p?dd-api-%256b%2565%2579=SECRET", "https://h/p?dd-api-%256b%2565%2579=[redacted]" },
        .{ "https://h/p?%41uthorization=SECRET&x=1", "https://h/p?%41uthorization=[redacted]&x=1" },
        .{ "https://h/p?ddsource=%6bey", "https://h/p?ddsource=%6bey" },
    };
    for (cases) |case| {
        const url = try redactQuery(testing.allocator, case[0]);
        defer testing.allocator.free(url);
        try testing.expectEqualStrings(case[1], url);
    }
}

test "the tee forwards every byte and keeps a copy" {
    var source: std.Io.Reader = .fixed("0123456789" ** 100);
    var buf: [1000]u8 = undefined;
    var tee: Tee = .{ .inner = &source, .copy = &buf };
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    try tee.interface.streamExact(&sink.writer, 1000);
    try testing.expectEqualStrings("0123456789" ** 100, sink.written());
    try testing.expectEqualStrings("0123456789" ** 100, tee.written());
    try testing.expect(!tee.copy_failed);
}

test "the streamed-body copies stay inside their budget" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var capture: Capture = try .open(io, testing.allocator, noop_bus.eventBus(), path, 10, 100);

    var held: [max_copies][]u8 = undefined;
    for (&held) |*slot| slot.* = capture.acquireCopy(100).?;
    try testing.expect(capture.acquireCopy(1) == null); // budget spent
    capture.releaseCopy(held[0]);
    const again = capture.acquireCopy(100).?; // released bytes come back
    capture.releaseCopy(again);
    for (held[1..]) |buf| capture.releaseCopy(buf);
    try testing.expectEqual(@as(usize, 0), capture.copy_used.load(.monotonic));
    capture.close();
}

test "a dump holds the body unchanged and the metadata redacted, up to the cap" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    const bus = noop_bus.eventBus();

    const path = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var capture: Capture = try .open(io, testing.allocator, bus, path, 1, 1024);
    try capture.start();
    const body = "\x28\xb5\x2f\xfd compressed bytes";
    const failure: Failure = .{
        .method = .POST,
        .target = "/api/v2/logs?dd-api-key=abc",
        .path = "/api/v2/logs",
        .url = "https://intake/api/v2/logs?dd-api-key=abc",
        .headers = &.{
            .{ .name = "DD-API-KEY", .value = "secret-value" },
            .{ .name = "Content-Encoding", .value = "zstd" },
        },
        .framing = .content_length,
        .body = body,
        .declared_len = body.len,
        .complete = true,
        .status = 408,
        .err = null,
        .phase = "response",
        .attempts = 1,
        .retried_err = null,
        .watchdog_fired = false,
        .elapsed_ms = 30012.5,
    };
    capture.record(arena, failure);
    capture.record(arena, failure); // over the cap: no second dump
    try testing.expect(!capture.armed());
    capture.close(); // the writer writes what is queued, then stops

    var bodies: usize = 0;
    var metas: usize = 0;
    var dir = try tmp.dir.openDir(io, ".", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        const data = try dir.readFileAlloc(io, entry.name, arena, .unlimited);
        if (std.mem.endsWith(u8, entry.name, ".body")) {
            bodies += 1;
            try testing.expectEqualStrings(body, data);
        } else {
            metas += 1;
            try testing.expect(std.mem.find(u8, data, "secret-value") == null);
            try testing.expect(std.mem.find(u8, data, "abc") == null);
            try testing.expect(std.mem.find(u8, data, "\"status\": 408") != null);
            try testing.expect(std.mem.find(u8, data, "\"complete\": true") != null);
        }
    }
    try testing.expectEqual(@as(usize, 1), bodies);
    try testing.expectEqual(@as(usize, 1), metas);

    // Only the edge's own user may read a dump.
    if (builtin.os.tag != .windows) {
        // `stat` carries the file type bits too; compare the mode only.
        const mode = struct {
            fn of(p: std.Io.File.Permissions) u32 {
                return @as(u32, @intCast(@intFromEnum(p))) & 0o777;
            }
        }.of;
        try testing.expectEqual(mode(dir_permissions), mode((try dir.stat(io)).permissions));
        var files = dir.iterate();
        while (try files.next(io)) |entry| {
            const stat = try dir.statFile(io, entry.name, .{});
            try testing.expectEqual(mode(file_permissions), mode(stat.permissions));
        }
    }

    // A restart counts what is already on disk.
    var reopened: Capture = try .open(io, testing.allocator, bus, path, 1, 1024);
    defer reopened.close();
    try testing.expect(!reopened.armed());
    // The dump reached the disk, and the writer's slot stayed spent.
    try testing.expectEqual(@as(u32, 1), reopened.used.load(.monotonic));
}

fn testFailure(body: []const u8) Failure {
    return .{
        .method = .POST,
        .target = "/api/v2/logs",
        .path = "/api/v2/logs",
        .url = "https://intake/api/v2/logs",
        .headers = &.{},
        .framing = .content_length,
        .body = body,
        .declared_len = body.len,
        .complete = true,
        .status = 408,
        .err = null,
        .phase = "response",
        .attempts = 1,
        .retried_err = null,
        .watchdog_fired = false,
        .elapsed_ms = 1,
    };
}

test "a failed write leaves no file behind and refunds its slot" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    const bus = noop_bus.eventBus();

    const path = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var capture: Capture = try .open(io, testing.allocator, bus, path, 1, 1024);
    defer capture.close();
    // A directory where the metadata file must go makes the second write fail
    // after the body is on disk.
    try capture.dir.createDir(io, "stuck.json", .default_dir);
    const job: Job = .{
        .stem = try arena.dupe(u8, "stuck"),
        .path = try arena.dupe(u8, "/api/v2/logs"),
        .body = try arena.dupe(u8, "payload"),
        .meta = try arena.dupe(u8, "{}"),
    };
    var name_buf: [64]u8 = undefined;
    var left = false;
    try testing.expectError(error.PathAlreadyExists, capture.writeFiles(job, &name_buf, &left));
    try testing.expectError(error.FileNotFound, capture.dir.statFile(io, "stuck.body", .{}));
    try testing.expect(!left);
}

test "a body orphaned by a crash still counts against the cap" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    const bus = noop_bus.eventBus();
    try tmp.dir.writeFile(io, .{ .sub_path = "1-0.body", .data = "orphan" });
    try tmp.dir.writeFile(io, .{ .sub_path = "2-0.body", .data = "whole" });
    try tmp.dir.writeFile(io, .{ .sub_path = "2-0.json", .data = "{}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "notes.txt", .data = "not a dump" });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var capture: Capture = try .open(io, testing.allocator, bus, path, 2, 1024);
    defer capture.close();
    try testing.expectEqual(@as(u32, 2), capture.used.load(.monotonic));
    try testing.expect(!capture.armed());
}

test "a full queue drops a dump at once instead of waiting for the disk" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    // No writer: the queue stands in for a stalled volume.
    var capture: Capture = try .open(io, testing.allocator, noop_bus.eventBus(), path, 100, 1024);
    for (0..queue_len + 1) |_| capture.record(arena_state.allocator(), testFailure("payload"));
    try testing.expectEqual(@as(usize, queue_len), capture.queue_count);
    // The dropped dump gave its slot back.
    try testing.expectEqual(@as(u32, queue_len), capture.used.load(.monotonic));
    try testing.expect(capture.drop_reported.load(.monotonic));
    capture.close(); // frees the queued jobs; the testing allocator checks
}

test "deleting dumps from a full directory frees their slots" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    try tmp.dir.writeFile(io, .{ .sub_path = "1-0.body", .data = "old" });
    try tmp.dir.writeFile(io, .{ .sub_path = "1-0.json", .data = "{}" });
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var capture: Capture = try .open(io, testing.allocator, noop_bus.eventBus(), path, 2, 1024);
    defer capture.close();

    // One dump on disk and one in flight: the directory is full.
    capture.record(arena_state.allocator(), testFailure("queued"));
    try testing.expect(!capture.armed());
    capture.full_reported.store(true, .monotonic);

    // The operator deletes the old dump. A rescan frees that slot, and keeps
    // the one the queued dump still needs.
    try tmp.dir.deleteFile(io, "1-0.body");
    try tmp.dir.deleteFile(io, "1-0.json");
    capture.rescan();
    try testing.expectEqual(@as(u32, 1), capture.used.load(.monotonic));
    try testing.expect(capture.armed());
    try testing.expect(!capture.full_reported.load(.monotonic));
}

test "close stops a writer stalled on the disk before it returns" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var capture: Capture = try .open(io, testing.allocator, noop_bus.eventBus(), path, 10, 1024);
    capture.test_stall_writes = true;
    try capture.start();
    capture.record(arena_state.allocator(), testFailure("stalled"));
    capture.record(arena_state.allocator(), testFailure("queued behind it"));

    const started = std.Io.Timestamp.now(io, .awake).toNanoseconds();
    capture.close();
    const took_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds() - started;
    // The writer has returned, so nothing uses the capture after this; the
    // testing allocator also checks that both jobs were freed.
    try testing.expect(capture.writer == null);
    try testing.expect(capture.stopped.isSet());
    try testing.expect(took_ns < 10 * std.time.ns_per_s);
}

test "a write that fails part way removes its file, or keeps its slot" {
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const io = testing.io;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var noop_bus: o11y.NoopEventBus = undefined;
    noop_bus.init(io);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var capture: Capture = try .open(io, testing.allocator, noop_bus.eventBus(), path, 1, 1024);
    defer capture.close();
    capture.test_short_write = true;
    const job: Job = .{
        .stem = try arena.dupe(u8, "short"),
        .path = try arena.dupe(u8, "/api/v2/logs"),
        .body = try arena.dupe(u8, "payload bytes"),
        .meta = try arena.dupe(u8, "{}"),
    };

    // The body file is created, half written, then the disk is full: the
    // file goes, and the slot comes back.
    try testing.expect(capture.reserve());
    try testing.expect(capture.writeJob(job));
    try testing.expectError(error.FileNotFound, capture.dir.statFile(io, "short.body", .{}));
    try testing.expectEqual(@as(u32, 0), capture.used.load(.monotonic));

    // The same, but the file cannot be removed: it stays on disk and keeps
    // its slot, so the directory cannot outgrow the cap.
    capture.test_remove_fails = true;
    try testing.expect(capture.reserve());
    try testing.expect(capture.writeJob(job));
    _ = try capture.dir.statFile(io, "short.body", .{});
    try testing.expectEqual(@as(u32, 1), capture.used.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), capture.pending);
    try testing.expect(!capture.armed());
}
