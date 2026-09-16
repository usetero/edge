//! Per-handler-thread scratch for the httpz frontend, and the watchdog that
//! interrupts a stalled upstream exchange.
//!
//! One `ThreadBufs` per handler thread, created on first use and retained for
//! the thread's life. Everything body-sized lives here on purpose: draining a
//! lazy body into the per-connection request arena freed correctly, but the
//! production allocator is libc malloc, which kept the nodes mapped, and RSS
//! grew with connections instead of threads.
const std = @import("std");
const exec = @import("../exec.zig");
const encoding_mod = @import("../../pipeline/encoding.zig");
const limits_mod = @import("../../core/limits.zig");

const log = std.log.scoped(.httpz_server);

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
    /// Codec and record workspaces, grown on demand by `prepare`.
    decode: []u8 = &.{},
    encode: []u8 = &.{},
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

    pub fn prepare(
        self: *ThreadBufs,
        allocator: std.mem.Allocator,
        limits: limits_mod.Limits,
        codec: encoding_mod.ContentEncoding,
    ) !void {
        try growBuffer(allocator, &self.decode, codec.decoderBufferLen(limits.zstd_window_len));
        try growBuffer(allocator, &self.encode, codec.encoderBufferLen());
        try growBuffer(allocator, &self.scratch, limits.record_scratch);
        try growBuffer(allocator, &self.chunk, limits.chunk_buf);
    }
};

threadlocal var tl_bufs: ?*ThreadBufs = null;
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
        allocator.free(bufs.decode);
        allocator.free(bufs.encode);
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
            log.debug("failed to interrupt upstream: {s}", .{@errorName(err)});
        };
    }
}
