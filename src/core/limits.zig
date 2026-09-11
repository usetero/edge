//! Single source of truth for every buffer size and bound in the data plane.
//! No other file in src/core, src/http, src/pipeline, or src/service may
//! define a size constant; importing from here keeps the steady-state memory
//! budget a closed-form function of configuration (see `Limits.steadyStateBytes`).
const std = @import("std");

const log = std.log.scoped(.limits);

/// Sized to hold one TLS ciphertext record so the HTTP reader never splits a
/// record across refills (std.crypto.tls.max_ciphertext_record_len is 16645;
/// rounded to the next 4 KiB page multiple).
pub const RECV_BUF_BYTES: usize = 20 * 1024;
pub const SEND_BUF_BYTES: usize = 20 * 1024;
pub const UPSTREAM_WRITE_BUF_BYTES: usize = 20 * 1024;

/// One framed record (a Datadog log, an OTLP ResourceLogs submessage, …) must
/// fit here for policy evaluation; larger records fail open per PLAN §6.5.
pub const RECORD_SCRATCH_BYTES: usize = 256 * 1024;

/// Streaming encoder window/staging: must cover flate.max_window_len (64 KiB)
/// and one zstd block (128 KiB) with slack. encoding.zig's tests assert this
/// stays >= its actual requirement so the layers can't drift apart.
pub const ENCODE_BUF_BYTES: usize = 192 * 1024;

/// Decoder needs the zstd window (config-derived, see Limits.zstd_window_len)
/// plus one block of slack; this constant is the non-window part.
pub const DECODE_SLACK_BYTES: usize = 192 * 1024;

/// HTTP body reader staging (chunked-decoding side, std.http.Server).
pub const BODY_BUF_BYTES: usize = 8 * 1024;

/// Staging between the decoder and the framer.
pub const CHUNK_BUF_BYTES: usize = 4 * 1024;

/// zstd frames declare their window; producers cap it at min(content_size,
/// 8 MiB default). Bounding by max_body_size matches what a fully-buffered
/// decompress would have admitted anyway.
pub const ZSTD_WINDOW_MIN: usize = 256 * 1024;
pub const ZSTD_WINDOW_MAX: usize = 8 * 1024 * 1024;

/// Per-connection arena budget for cold allocations (header copies, upstream
/// URL strings, error bodies). Debug builds assert the high-water mark.
pub const CONN_ARENA_RESERVE_BYTES: usize = 16 * 1024;

pub const DEFAULT_MAX_CONNECTIONS: u32 = 256;
pub const MAX_CONNECTIONS_CAP: u32 = 65534;
/// Datadog agents batch up to 5 MB uncompressed, about 1 MB compressed.
pub const DEFAULT_MAX_BODY_BYTES: u32 = 1536 * 1024;
/// Decompressed bodies may grow to this multiple of `max_body_size`.
pub const DECODED_BODY_RATIO: usize = 10;
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u32 = 30_000;
/// Used when neither config nor the cgroup provides a memory limit.
pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
pub const MIN_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
/// Handler threads per event-loop worker (httpz default).
pub const HANDLER_THREADS_PER_WORKER: u16 = 32;
/// One event loop with 32 handler threads saturates the CPU at 50 connections;
/// four workers measured 4-10% slower and 2.5x the RSS (per-worker pools and scratch).
pub const DEFAULT_WORKERS: u16 = 1;
/// Ceilings for the benchmark-only TERO_WORKER_COUNT / TERO_THREAD_POOL_COUNT overrides.
pub const MAX_WORKERS: u16 = 64;
pub const MAX_HANDLER_THREADS: u16 = 256;
/// The startup manifest warns below this many concurrent maximum-size bodies.
pub const MIN_CONCURRENT_BODIES: usize = 32;
pub const LARGE_BODY_BUFFER_BYTES: u32 = 64 * 1024;
/// httpz response staging buffer, one per handler thread (httpz default).
pub const HANDLER_THREAD_BUF_BYTES: usize = 32 * 1024;

// Compile-time sanity: the recv buffer holds a whole TLS record and buffers
// stay cache-line friendly.
comptime {
    std.debug.assert(RECV_BUF_BYTES >= std.crypto.tls.max_ciphertext_record_len);
    std.debug.assert(RECORD_SCRATCH_BYTES % 64 == 0);
}

pub const Limits = struct {
    /// Inbound connection cap; also sizes the stdio connection slab.
    max_connections: usize,
    /// Whole-process ceiling the HTTP budget derives from.
    memory_limit_bytes: u64,
    /// Charged HTTP allocations: half of `memory_limit_bytes`.
    http_budget_bytes: usize,
    retry_log_intake: bool,
    upstream_timeout_ms: u32,
    /// Per-request body ceiling, from the frozen `ProxyConfig.max_body_size`.
    max_body_size: u32,
    /// Post-decompression body ceiling: `DECODED_BODY_RATIO` x `max_body_size`.
    max_decoded_bytes: usize,
    /// httpz event-loop workers (DEFAULT_WORKERS unless a benchmark override is set).
    worker_count: u16,
    /// httpz handler threads per worker.
    thread_pool_count: u16,
    record_scratch: usize,
    recv_buf: usize,
    send_buf: usize,
    upstream_write_buf: usize,
    /// Streaming decoder window region (zstd window + slack).
    decode_buf: usize,
    encode_buf: usize,
    body_buf: usize,
    chunk_buf: usize,
    /// zstd decode window cap; frames declaring more fail the decode.
    zstd_window_len: usize,
    conn_arena_reserve: usize,
    /// A small reusable body pool per event-loop worker. Receiving and queued
    /// bodies also use it; overflow allocations share the HTTP allocation cap.
    large_body_buffer_count: u16,
    /// Large bodies allocate their actual size instead of pinning max_body_size
    /// for every pool entry. Chunked bodies grow from this small initial buffer.
    large_body_buffer_size: u32,

    /// Inputs to `resolve` that originate from config (`ProxyConfig`), with
    /// the `TERO_*` env overrides already applied by zonfig. No env reads here.
    pub const ResolveOptions = struct {
        max_body_size: u32 = DEFAULT_MAX_BODY_BYTES,
        max_connections: u32 = DEFAULT_MAX_CONNECTIONS,
        memory_limit_bytes: u64 = DEFAULT_MEMORY_LIMIT_BYTES,
        retry_log_intake: bool = true,
        upstream_timeout_ms: u32 = DEFAULT_UPSTREAM_TIMEOUT_MS,
        /// Benchmark-only overrides, clamped to [1, MAX_WORKERS] / [1, MAX_HANDLER_THREADS].
        worker_count: ?u16 = null,
        thread_pool_count: ?u16 = null,
    };

    pub fn resolve(opts: ResolveOptions) Limits {
        std.debug.assert(opts.max_connections > 0);
        const worker_count: u16 = if (opts.worker_count) |w|
            std.math.clamp(w, @as(u16, 1), MAX_WORKERS)
        else
            DEFAULT_WORKERS;
        const thread_pool_count: u16 = if (opts.thread_pool_count) |t|
            std.math.clamp(t, @as(u16, 1), MAX_HANDLER_THREADS)
        else
            HANDLER_THREADS_PER_WORKER;
        const zstd_window_len = std.math.clamp(
            @as(usize, opts.max_body_size),
            ZSTD_WINDOW_MIN,
            ZSTD_WINDOW_MAX,
        );
        return .{
            .max_connections = opts.max_connections,
            .memory_limit_bytes = opts.memory_limit_bytes,
            .http_budget_bytes = @intCast(opts.memory_limit_bytes / 2),
            .retry_log_intake = opts.retry_log_intake,
            .upstream_timeout_ms = opts.upstream_timeout_ms,
            .max_body_size = opts.max_body_size,
            .max_decoded_bytes = @as(usize, opts.max_body_size) * DECODED_BODY_RATIO,
            .worker_count = worker_count,
            .thread_pool_count = thread_pool_count,
            .record_scratch = RECORD_SCRATCH_BYTES,
            .recv_buf = RECV_BUF_BYTES,
            .send_buf = SEND_BUF_BYTES,
            .upstream_write_buf = UPSTREAM_WRITE_BUF_BYTES,
            .decode_buf = zstd_window_len + DECODE_SLACK_BYTES,
            .encode_buf = ENCODE_BUF_BYTES,
            .body_buf = BODY_BUF_BYTES,
            .chunk_buf = CHUNK_BUF_BYTES,
            .zstd_window_len = zstd_window_len,
            .conn_arena_reserve = CONN_ARENA_RESERVE_BYTES,
            // Split eight cached buffers across event-loop workers, with one
            // minimum per worker. All pools are charged to the same budget.
            .large_body_buffer_count = @max(1, @min(thread_pool_count, 8) / worker_count),
            .large_body_buffer_size = @min(opts.max_body_size, LARGE_BODY_BUFFER_BYTES),
        };
    }

    /// Bytes the slab pre-allocates for one connection's fixed buffers.
    /// Pages are reserved up front but only consume RSS once touched, so
    /// actual residency tracks concurrent connection load.
    pub fn perConnBytes(self: Limits) usize {
        return self.recv_buf + self.send_buf + self.upstream_write_buf +
            self.record_scratch + self.decode_buf + self.encode_buf +
            self.body_buf + self.chunk_buf;
    }

    /// Closed-form steady-state budget for the data plane. Logged once at
    /// startup; THE number that makes memory predictable. Excludes cold,
    /// config-proportional state (router tables, policy snapshots) and
    /// libzstd contexts, which are bounded separately and logged by their
    /// owners.
    pub fn steadyStateBytes(self: Limits) usize {
        return self.max_connections * (self.perConnBytes() + self.conn_arena_reserve);
    }

    pub fn logStartup(self: Limits) void {
        log.info("steady-state data-plane budget: {d} bytes ({d} conns x {d} per-conn)", .{
            self.steadyStateBytes(),
            self.max_connections,
            self.perConnBytes() + self.conn_arena_reserve,
        });
    }
};

test "Limits budget formula is locked" {
    const limits: Limits = .resolve(.{});

    // Hand-computed with the default 1.5 MiB max_body_size:
    //   zstd window = clamp(1.5M, 256K, 8M)      = 1536 KiB
    //   per conn = 20K+20K+20K (io bufs)
    //            + 256K (record scratch)
    //            + 1536K+192K (decode) + 192K (encode)
    //            + 8K (body) + 4K (chunk)         = 2248 KiB
    //   steady state = 256 x (2248K + 16K arena)
    // Any change to a buffer constant must show up as a diff in this test.
    try std.testing.expectEqual(@as(usize, 256), limits.max_connections);
    try std.testing.expectEqual(@as(usize, 1536 * 1024), limits.zstd_window_len);
    try std.testing.expectEqual(@as(usize, 2248 * 1024), limits.perConnBytes());
    try std.testing.expectEqual(@as(usize, 256 * 2264 * 1024), limits.steadyStateBytes());
    try std.testing.expectEqual(DEFAULT_MAX_BODY_BYTES, limits.max_body_size);
    try std.testing.expectEqual(@as(usize, 15 * 1024 * 1024), limits.max_decoded_bytes);
    try std.testing.expectEqual(@as(usize, 128 * 1024 * 1024), limits.http_budget_bytes);
    try std.testing.expectEqual(DEFAULT_UPSTREAM_TIMEOUT_MS, limits.upstream_timeout_ms);
    try std.testing.expectEqual(DEFAULT_WORKERS, limits.worker_count);
    try std.testing.expectEqual(HANDLER_THREADS_PER_WORKER, limits.thread_pool_count);
    // httpz caches small bodies; the maximum payload does not size the pool.
    try std.testing.expectEqual(@as(u16, 8), limits.large_body_buffer_count);
    try std.testing.expectEqual(LARGE_BODY_BUFFER_BYTES, limits.large_body_buffer_size);
}

test "Limits defaults to one worker and clamps benchmark overrides" {
    try std.testing.expectEqual(DEFAULT_WORKERS, Limits.resolve(.{}).worker_count);
    const overridden: Limits = .resolve(.{ .worker_count = 1000, .thread_pool_count = 0 });
    try std.testing.expectEqual(MAX_WORKERS, overridden.worker_count);
    try std.testing.expectEqual(@as(u16, 1), overridden.thread_pool_count);
}

test "Limits caps the body pool below the handler count" {
    const limits: Limits = .resolve(.{ .max_body_size = 2 * 1024 * 1024 });
    // Cached bodies are small even when the maximum request is large.
    try std.testing.expectEqual(@as(u16, 8), limits.large_body_buffer_count);
    try std.testing.expectEqual(LARGE_BODY_BUFFER_BYTES, limits.large_body_buffer_size);

    const small: Limits = .resolve(.{ .thread_pool_count = 2 });
    try std.testing.expectEqual(@as(u16, 2), small.large_body_buffer_count);

    // Many workers: per-worker count floors at 1 (pool can't be empty).
    const many_workers: Limits = .resolve(.{ .worker_count = 16 });
    try std.testing.expectEqual(@as(u16, 1), many_workers.large_body_buffer_count);
}
