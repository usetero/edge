//! Per-thread scratch for both frontends, and the watchdog that interrupts a
//! stalled upstream exchange.
//!
//! One `ThreadBufs` per thread that runs requests (an httpz handler thread, a
//! stdio connection task's pool thread), created on first use and retained
//! for the thread's life. Everything body-sized lives here on purpose: draining a
//! lazy body into the per-connection request arena freed correctly, but the
//! production allocator is libc malloc, which kept the nodes mapped, and RSS
//! grew with connections instead of threads.
const std = @import("std");
const exec = @import("exec.zig");
const codec = @import("../codec/root.zig");
const limits_mod = @import("../core/limits.zig");

const log = std.log.scoped(.httpz_server);

// Named event payloads: the type name is the telemetry event name.
/// The watchdog reached an upstream past its deadline and could not shut the
/// socket down. The handler thread stays blocked, so this is the last record
/// of it.
const UpstreamInterruptFailed = struct { err: []const u8 };

pub const upstream_attempt_timeout_ns: i128 = 30 * std.time.ns_per_s;
/// The watchdog only needs to catch a wedged upstream; 100 ms is far below
/// the 30 s attempt timeout and costs nothing.
pub const watchdog_interval_ms: u64 = 100;

/// Chunk size for pumping a streamed body client socket -> upstream socket.
/// `Reader.stream` reads straight into the upstream writer's buffer, so this
/// is the read granularity of the whole pump. Measured: 20 KiB gave a third
/// of the buffered path's throughput, 512 KiB about half, 1 MiB was slower
/// again (reads are capped by what the kernel has queued).
pub const pump_buffer_bytes: usize = 512 * 1024;

pub const ThreadBufs = struct {
    /// Decodes this thread's bodies. It keeps its zlib and libzstd state
    /// between bodies, up to one zstd window (`zstd_window_len`).
    decoder: ?codec.Decoder = null,
    /// Record workspaces, grown on demand by `prepare`.
    scratch: []u8 = &.{},
    chunk: []u8 = &.{},
    /// Upstream write buffer; also the response read buffer.
    upstream: []u8,
    record: exec.RecordScratch,
    /// Staging for a streamed body. See `pump_buffer_bytes`.
    pump: []u8 = &.{},
    /// Landing buffer for a lazy body a policy path must hold resident.
    /// Sized to max_body_size, so bounded by threads alone.
    body: []u8 = &.{},

    /// Upstream deadline tracking, read by the watchdog from another thread.
    deadline_lock: std.Io.Mutex = .init,
    connection: ?*std.http.Client.Connection = null,
    deadline_ns: i128 = 0,
    timed_out: std.atomic.Value(bool) = .init(false),

    pub fn ensurePump(self: *ThreadBufs, allocator: std.mem.Allocator) ![]u8 {
        if (self.pump.len == 0) self.pump = try allocator.alloc(u8, pump_buffer_bytes);
        return self.pump;
    }

    pub fn ensureBody(self: *ThreadBufs, allocator: std.mem.Allocator, max_body_size: usize) ![]u8 {
        if (self.body.len == 0) self.body = try allocator.alloc(u8, max_body_size);
        return self.body;
    }

    pub fn ensureDecoder(self: *ThreadBufs, allocator: std.mem.Allocator) !*codec.Decoder {
        if (self.decoder == null) self.decoder = try .init(allocator);
        return &self.decoder.?;
    }

    pub fn prepare(self: *ThreadBufs, allocator: std.mem.Allocator, limits: limits_mod.Limits) !void {
        try growBuffer(allocator, &self.scratch, limits.record_scratch);
        try growBuffer(allocator, &self.chunk, limits.chunk_buf);
    }
};

threadlocal var tl_bufs: ?*ThreadBufs = null;
/// Encoders for every thread. A zstd context is too large to keep one per
/// thread; see `codec.EncoderPool`.
pub var encoder_pool: codec.EncoderPool = .{};
var registry_mutex: std.Io.Mutex = .init;
var registry: std.ArrayList(*ThreadBufs) = .empty;

pub fn growBuffer(allocator: std.mem.Allocator, buffer: *[]u8, len: usize) !void {
    if (buffer.len < len) buffer.* = try allocator.realloc(buffer.*, len);
}

/// This thread's scratch, created on first call.
pub fn get(io: std.Io, allocator: std.mem.Allocator, limits: limits_mod.Limits) !*ThreadBufs {
    if (tl_bufs) |bufs| return bufs;
    const bufs = try allocator.create(ThreadBufs);
    errdefer allocator.destroy(bufs);
    const upstream = try allocator.alloc(u8, limits.upstream_write_buf);
    errdefer allocator.free(upstream);
    bufs.* = .{ .upstream = upstream, .record = .init(allocator) };
    errdefer bufs.record.deinit();
    registry_mutex.lockUncancelable(io);
    defer registry_mutex.unlock(io);
    try registry.append(allocator, bufs);
    tl_bufs = bufs;
    return bufs;
}

/// Called only after every handler thread has been joined.
pub fn freeAll(io: std.Io, allocator: std.mem.Allocator) void {
    registry_mutex.lockUncancelable(io);
    defer registry_mutex.unlock(io);
    for (registry.items) |bufs| {
        if (bufs.decoder) |*decoder| decoder.deinit(allocator);
        allocator.free(bufs.scratch);
        allocator.free(bufs.chunk);
        allocator.free(bufs.upstream);
        allocator.free(bufs.pump);
        allocator.free(bufs.body);
        bufs.record.deinit();
        allocator.destroy(bufs);
    }
    registry.deinit(allocator);
    registry = .empty;
    encoder_pool.freeIdle(allocator);
    tl_bufs = null;
}

/// Register (or clear, with null) the upstream connection this thread is
/// blocked on, so the watchdog can shut it down past the attempt deadline.
pub fn trackUpstream(io: std.Io, bufs: *ThreadBufs, connection: ?*std.http.Client.Connection) void {
    bufs.deadline_lock.lockUncancelable(io);
    defer bufs.deadline_lock.unlock(io);
    bufs.connection = connection;
    if (connection) |_| {
        // From now, not from when the inbound request arrived. A slow client
        // that took most of the request timeout to deliver its body would
        // otherwise leave the upstream almost no budget, and a healthy
        // upstream would be cut off and reported as a 504.
        bufs.deadline_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds() + upstream_attempt_timeout_ns;
        bufs.timed_out.store(false, .release);
    }
}

/// Shut down every tracked upstream past its deadline (all of them when
/// `force`). Shutdown unblocks the handler's read; it observes `timed_out`.
pub fn expireTrackedUpstreams(ctx: *exec.SharedCtx, force: bool) void {
    const now = std.Io.Timestamp.now(ctx.io, .awake).toNanoseconds();
    registry_mutex.lockUncancelable(ctx.io);
    defer registry_mutex.unlock(ctx.io);
    for (registry.items) |bufs| {
        bufs.deadline_lock.lockUncancelable(ctx.io);
        defer bufs.deadline_lock.unlock(ctx.io);
        const connection = bufs.connection orelse continue;
        if (!force and now < bufs.deadline_ns) continue;
        if (bufs.timed_out.swap(true, .acq_rel)) continue;
        connection.closing = true;
        connection.stream_reader.stream.shutdown(ctx.io, .both) catch |err| {
            // The handler stays blocked on a socket nothing can interrupt, so
            // this is the last record of that thread.
            // ziglint-ignore: Z010 (named type sets EventBus telemetry name)
            ctx.bus.warn(UpstreamInterruptFailed{ .err = @errorName(err) });
        };
    }
}
