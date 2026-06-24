//! Debug tap for in-flight telemetry records (see `TapState`). Lives in the
//! pipeline layer because it observes records as they cross the per-record
//! evaluation boundary; the frontend just owns the `/_edge/tap/{pre,post}`
//! endpoints that arm it and drain the batch.
const std = @import("std");

/// A debug tap: while armed, data-plane threads copy each record's bytes
/// (before and/or after policy evaluation) into a sink owned by a waiting
/// `/_edge/tap/{pre,post}` request, then it disarms itself. One tap at a time.
///
/// Memory is never retained between taps: there is no ring and nothing
/// preallocated — the sink is the waiting request's buffer, freed when that
/// request returns. The whole thing is gated behind a config flag; when the
/// flag is off, `SharedCtx.tap` is null and the hot path never sees it.
pub const TapState = struct {
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    /// null = no tap armed. Written only under `mutex`, read unlocked on the
    /// hot path (a stale read just costs one extra lock+recheck, or a skip).
    sink: ?*std.Io.Writer = null,
    stage: Stage = .pre,
    remaining: u32 = 0,
    seq: u32 = 0,
    /// Payload bytes captured so far this batch; bounds total memory held
    /// regardless of `remaining` or record size (a single record can be up to
    /// max_decoded_bytes). The last frame is truncated to fit, then the batch
    /// ends.
    written: usize = 0,

    /// Total payload-byte ceiling per tap batch. `n` bounds frame count;
    /// without this, n=1000 large records could buffer gigabytes before the
    /// endpoint's 1s deadline or disarm fires.
    pub const max_tap_bytes: usize = 8 * 1024 * 1024;

    pub const Stage = enum { pre, post };

    /// Hot path. Called from every onRecord on every data-plane thread. When
    /// no tap is armed this is one acquire-load + a not-taken branch.
    pub fn capture(
        self: *TapState,
        stage: Stage,
        signal: []const u8,
        format: []const u8,
        decision: []const u8,
        bytes: []const u8,
    ) void {
        if (@atomicLoad(?*std.Io.Writer, &self.sink, .acquire) == null) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const sink = self.sink orelse return;
        if (self.stage != stage or self.remaining == 0) return;

        // Total-byte ceiling: truncate the payload to the remaining budget so a
        // burst of large records can't exhaust memory. The header reports the
        // (possibly truncated) length, so the stream stays parseable. Hitting
        // the ceiling ends the batch.
        const budget = max_tap_bytes -| self.written;
        if (budget == 0) {
            self.remaining = 0;
            @atomicStore(?*std.Io.Writer, &self.sink, null, .release);
            return;
        }
        const payload = if (bytes.len > budget) bytes[0..budget] else bytes;

        self.seq += 1;
        // Best-effort: a write failure (e.g. OOM growing the sink) just ends
        // the batch early rather than faulting the data plane.
        writeFrame(sink, self.seq, signal, format, decision, payload) catch {
            self.remaining = 0;
        };
        self.written += payload.len;
        if (self.remaining > 0) self.remaining -= 1;
        if (self.remaining == 0 or payload.len < bytes.len) {
            @atomicStore(?*std.Io.Writer, &self.sink, null, .release);
        }
    }

    /// Endpoint side: claim the single tap slot. Returns false if one is
    /// already armed (the caller answers 409).
    pub fn arm(self: *TapState, stage: Stage, n: u32, sink: *std.Io.Writer) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.sink != null) return false;
        self.stage = stage;
        self.remaining = n;
        self.seq = 0;
        self.written = 0;
        @atomicStore(?*std.Io.Writer, &self.sink, sink, .release);
        return true;
    }

    /// True once the batch is full or the slot was released.
    pub fn finished(self: *TapState) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.sink == null or self.remaining == 0;
    }

    /// Release the slot. After this returns, no producer will touch the sink,
    /// so the endpoint can safely read what was collected. Idempotent.
    pub fn disarm(self: *TapState) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        @atomicStore(?*std.Io.Writer, &self.sink, null, .release);
    }

    fn writeFrame(
        w: *std.Io.Writer,
        seq: u32,
        signal: []const u8,
        format: []const u8,
        decision: []const u8,
        bytes: []const u8,
    ) !void {
        // Length-prefixed framing: a text header line, then `len` raw bytes
        // (records may be binary protobuf), then a newline. No base64, no
        // allocation — just two writes.
        try w.print("--- seq={d} signal={s} format={s} decision={s} len={d}\n", .{
            seq, signal, format, decision, bytes.len,
        });
        try w.writeAll(bytes);
        try w.writeByte('\n');
    }
};

const testing = std.testing;

test "TapState: arm captures matching-stage records, auto-disarms after n" {
    const io = std.testing.io;
    var tap: TapState = .{ .io = io };

    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();

    try testing.expect(tap.arm(.pre, 2, &buf.writer));
    // A second arm while one is active is rejected.
    var other: std.Io.Writer.Allocating = .init(testing.allocator);
    defer other.deinit();
    try testing.expect(!tap.arm(.post, 5, &other.writer));

    // Wrong-stage capture is ignored; matching-stage ones fill the batch.
    tap.capture(.post, "log", "json_array", "drop", "IGNORED");
    tap.capture(.pre, "log", "json_array", "", "AAA");
    try testing.expect(!tap.finished());
    tap.capture(.pre, "metric", "otlp_protobuf", "", "BBBB");
    // n reached -> auto-disarmed; further captures are dropped.
    try testing.expect(tap.finished());
    tap.capture(.pre, "log", "json_array", "", "CCC");

    const out = buf.written();
    const frame1 = "seq=1 signal=log format=json_array decision= len=3\nAAA\n";
    const frame2 = "seq=2 signal=metric format=otlp_protobuf decision= len=4\nBBBB\n";
    try testing.expect(std.mem.indexOf(u8, out, frame1) != null);
    try testing.expect(std.mem.indexOf(u8, out, frame2) != null);
    try testing.expect(std.mem.indexOf(u8, out, "IGNORED") == null);
    try testing.expect(std.mem.indexOf(u8, out, "CCC") == null);
}

test "TapState: total-byte ceiling caps payload and ends the batch" {
    const io = std.testing.io;
    var tap: TapState = .{ .io = io };

    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();

    // High frame count so only the byte ceiling can stop it. Records sized so
    // it takes several to reach the ceiling, with the last one overshooting.
    try testing.expect(tap.arm(.pre, 1000, &buf.writer));
    const chunk = TapState.max_tap_bytes / 3;
    const rec = try testing.allocator.alloc(u8, chunk + 1024);
    defer testing.allocator.free(rec);
    @memset(rec, 'x');

    var i: usize = 0;
    while (i < 100 and !tap.finished()) : (i += 1) {
        tap.capture(.pre, "log", "json_array", "", rec);
    }

    // Captured payload never exceeds the ceiling, and the batch ended.
    try testing.expect(tap.finished());
    try testing.expect(tap.written <= TapState.max_tap_bytes);
    // ...but it got close: it consumed within one record of the ceiling.
    try testing.expect(tap.written > TapState.max_tap_bytes - rec.len);
}

test "TapState: oversized record is truncated to the remaining budget" {
    const io = std.testing.io;
    var tap: TapState = .{ .io = io };

    var buf: std.Io.Writer.Allocating = .init(testing.allocator);
    defer buf.deinit();

    try testing.expect(tap.arm(.pre, 1000, &buf.writer));

    const over = try testing.allocator.alloc(u8, TapState.max_tap_bytes + 4096);
    defer testing.allocator.free(over);
    @memset(over, 'y');

    // One oversized record: truncated to the ceiling, batch ends immediately.
    tap.capture(.pre, "log", "json_array", "", over);
    try testing.expect(tap.finished());
    try testing.expectEqual(TapState.max_tap_bytes, tap.written);
    // Header reports the truncated length, so the frame stays parseable.
    var lenbuf: [32]u8 = undefined;
    const needle = std.fmt.bufPrint(&lenbuf, "len={d}\n", .{TapState.max_tap_bytes}) catch unreachable;
    try testing.expect(std.mem.indexOf(u8, buf.written(), needle) != null);
}
