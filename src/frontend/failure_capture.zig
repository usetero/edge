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
//! Credentials never reach the disk. A header or query parameter whose name
//! looks like a credential keeps its name and loses its value.
//!
//! `max_dumps` caps the `.json` files in the directory, the files from earlier
//! runs included, so a crash loop cannot fill the disk. Delete dumps to arm
//! the capture again.
const std = @import("std");
const o11y = @import("o11y");
const EventBus = o11y.EventBus;

// Named event payloads: the type name is the telemetry event name.
/// A failed upstream request was dumped. `file` is the `.json` name.
const UpstreamFailureCaptured = struct { path: []const u8, file: []const u8 };
/// The dump could not be written. The failure itself is still reported.
const UpstreamFailureCaptureFailed = struct { path: []const u8, err: []const u8 };
/// The directory holds `max_dumps` dumps. Warned once per process.
const UpstreamFailureCaptureFull = struct { dir: []const u8, max_dumps: u32 };

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

pub const Capture = struct {
    io: std.Io,
    dir: std.Io.Dir,
    path: []const u8,
    max_dumps: u32,
    /// Dumps in the directory, counted at open, plus dumps reserved since.
    used: std.atomic.Value(u32),
    seq: std.atomic.Value(u32) = .init(0),
    full_reported: std.atomic.Value(bool) = .init(false),

    /// Creates `path` when it is missing and counts the dumps already in it.
    pub fn open(io: std.Io, path: []const u8, max_dumps: u32) !Capture {
        const dir = try std.Io.Dir.cwd().createDirPathOpen(io, path, .{ .open_options = .{ .iterate = true } });
        errdefer dir.close(io);
        var existing: u32 = 0;
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json")) existing += 1;
        }
        return .{ .io = io, .dir = dir, .path = path, .max_dumps = max_dumps, .used = .init(existing) };
    }

    pub fn close(self: *Capture) void {
        self.dir.close(self.io);
    }

    /// True while the budget has room. A streamed body is copied only when
    /// this holds, so a full directory costs the data path nothing.
    pub fn armed(self: *const Capture) bool {
        return self.used.load(.monotonic) < self.max_dumps;
    }

    fn reserve(self: *Capture, bus: *EventBus) bool {
        if (self.used.fetchAdd(1, .monotonic) < self.max_dumps) return true;
        _ = self.used.fetchSub(1, .monotonic);
        if (!self.full_reported.swap(true, .monotonic)) {
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            bus.warn(UpstreamFailureCaptureFull{ .dir = self.path, .max_dumps = self.max_dumps });
        }
        return false;
    }

    /// Writes one dump. Errors are reported on the bus: the capture must not
    /// change how the request itself fails.
    pub fn record(self: *Capture, bus: *EventBus, arena: std.mem.Allocator, failure: Failure) void {
        if (!self.reserve(bus)) return;
        const name = self.write(arena, failure) catch |err| {
            _ = self.used.fetchSub(1, .monotonic);
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            bus.warn(UpstreamFailureCaptureFailed{ .path = failure.path, .err = @errorName(err) });
            return;
        };
        // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
        bus.warn(UpstreamFailureCaptured{ .path = failure.path, .file = name });
    }

    fn write(self: *Capture, arena: std.mem.Allocator, failure: Failure) ![]const u8 {
        const now_ms = std.Io.Clock.real.now(self.io).toMilliseconds();
        const seq = self.seq.fetchAdd(1, .monotonic);
        const stem = try std.fmt.allocPrint(arena, "{d}-{d}", .{ now_ms, seq });
        const body_name = try std.fmt.allocPrint(arena, "{s}.body", .{stem});
        const meta_name = try std.fmt.allocPrint(arena, "{s}.json", .{stem});

        // The body goes first: a `.json` file means the dump is whole.
        const exclusive: std.Io.Dir.CreateFileOptions = .{ .exclusive = true };
        try self.dir.writeFile(self.io, .{ .sub_path = body_name, .data = failure.body, .flags = exclusive });
        var json: std.Io.Writer.Allocating = .init(arena);
        const meta = try metaOf(arena, failure, body_name, now_ms);
        try std.json.Stringify.value(meta, .{ .whitespace = .indent_2 }, &json.writer);
        try json.writer.writeByte('\n');
        try self.dir.writeFile(self.io, .{ .sub_path = meta_name, .data = json.written(), .flags = exclusive });
        return meta_name;
    }
};

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
        if (eq < param.len and sensitiveName(param[0..eq])) {
            try out.writer.print("{s}={s}", .{ param[0..eq], redacted });
        } else {
            try out.writer.writeAll(param);
        }
    }
    return out.toOwnedSlice();
}

/// Copies every byte a streamed body yields, so a failed send can still be
/// dumped. A body that streams cannot be read again afterwards.
pub const Tee = struct {
    interface: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    inner: *std.Io.Reader,
    copy: std.Io.Writer.Allocating,
    /// Set when `inner` reported the end of the body.
    ended: bool = false,
    /// Set when the copy ran out of memory. The body still streams; only the
    /// dump is short.
    copy_failed: bool = false,

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *Tee = @alignCast(@fieldParentPtr("interface", r));
        const dest = limit.slice(try w.writableSliceGreedy(1));
        var vec = [_][]u8{dest};
        // Zero means the bytes landed in `inner`'s buffer; the next call
        // returns them.
        while (true) {
            const n = self.inner.readVec(&vec) catch |err| {
                if (err == error.EndOfStream) self.ended = true;
                return err;
            };
            if (n == 0) continue;
            if (!self.copy_failed) {
                self.copy.writer.writeAll(dest[0..n]) catch {
                    self.copy_failed = true;
                };
            }
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

test "the tee forwards every byte and keeps a copy" {
    var source: std.Io.Reader = .fixed("0123456789" ** 100);
    var tee: Tee = .{ .inner = &source, .copy = .init(testing.allocator) };
    defer tee.copy.deinit();
    var sink: std.Io.Writer.Allocating = .init(testing.allocator);
    defer sink.deinit();
    try tee.interface.streamExact(&sink.writer, 1000);
    try testing.expectEqualStrings("0123456789" ** 100, sink.written());
    try testing.expectEqualStrings("0123456789" ** 100, tee.copy.written());
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
    var capture: Capture = try .open(io, path, 1);
    defer capture.close();
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
    capture.record(bus, arena, failure);
    capture.record(bus, arena, failure); // over the cap: no second dump
    try testing.expect(!capture.armed());

    var bodies: usize = 0;
    var metas: usize = 0;
    var it = capture.dir.iterate();
    while (try it.next(io)) |entry| {
        const data = try capture.dir.readFileAlloc(io, entry.name, arena, .unlimited);
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

    // A restart counts what is already on disk.
    var reopened: Capture = try .open(io, path, 1);
    defer reopened.close();
    try testing.expect(!reopened.armed());
}
