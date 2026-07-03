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

pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

// Compile-time sanity: the recv buffer holds a whole TLS record and buffers
// stay cache-line friendly.
comptime {
    std.debug.assert(RECV_BUF_BYTES >= std.crypto.tls.max_ciphertext_record_len);
    std.debug.assert(RECORD_SCRATCH_BYTES % 64 == 0);
}

pub const Limits = struct {
    /// Connection slab capacity; claims beyond it are load-shed with 503.
    max_connections: usize,
    /// Per-request body ceiling, from the frozen `ProxyConfig.max_body_size`.
    max_body_size: u32,
    /// Post-decompression body ceiling; defaults to `max_body_size`.
    max_decoded_bytes: usize = 0,
    /// httpz event-loop worker count (null = httpz default).
    worker_count: ?u16 = null,
    /// httpz request-handler thread-pool count (null = httpz default).
    thread_pool_count: ?u16 = null,
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
    /// httpz large-body buffer pool: pooled buffers for request bodies that
    /// outgrow the per-connection static buffer (recv_buf). A pool miss falls
    /// back to an exact-size per-request arena allocation inside httpz, so
    /// this caps steady-state memory, not body size — bodies up to
    /// max_body_size always work. Left to httpz's default (16) this pool
    /// alone cost 16 x max_body_size eagerly at startup.
    large_body_buffer_count: u16,
    /// Each pooled buffer holds one max-size body, so large uncompressed
    /// intakes (1-2 MiB customer payloads) ride the pool instead of falling
    /// through to per-request allocation.
    large_body_buffer_size: u32,

    /// Inputs to `resolve` that originate from config (`ProxyConfig`), with
    /// the `TERO_*` env overrides already applied by zonfig. No env reads here.
    pub const ResolveOptions = struct {
        max_body_size: u32,
        max_decoded_bytes: ?u32 = null,
        max_connections: u32 = DEFAULT_MAX_CONNECTIONS,
        worker_count: ?u16 = null,
        thread_pool_count: ?u16 = null,
    };

    pub fn resolve(opts: ResolveOptions) Limits {
        std.debug.assert(opts.max_connections > 0);
        const zstd_window_len = std.math.clamp(
            @as(usize, opts.max_body_size),
            ZSTD_WINDOW_MIN,
            ZSTD_WINDOW_MAX,
        );
        return .{
            .max_connections = opts.max_connections,
            .max_body_size = opts.max_body_size,
            .max_decoded_bytes = opts.max_decoded_bytes orelse opts.max_body_size,
            .worker_count = opts.worker_count,
            .thread_pool_count = opts.thread_pool_count,
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
            // Only handler threads consume bodies concurrently, so pool one
            // buffer per handler, capped at 8 total — beyond that, misses are
            // an exact-size arena alloc, cheaper than pinning more max-size
            // buffers forever. httpz builds one pool PER WORKER, so the cap
            // is divided across workers to keep the process-wide total at
            // ~8 x max_body_size regardless of worker_count.
            .large_body_buffer_count = @max(
                1,
                @min(opts.thread_pool_count orelse 8, 8) / (opts.worker_count orelse 1),
            ),
            .large_body_buffer_size = opts.max_body_size,
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
    const limits: Limits = .resolve(.{ .max_body_size = 1024 * 1024 });

    // Hand-computed with the default 1 MiB max_body_size:
    //   zstd window = clamp(1M, 256K, 8M)        = 1024 KiB
    //   per conn = 20K+20K+20K (io bufs)
    //            + 256K (record scratch)
    //            + 1024K+192K (decode) + 192K (encode)
    //            + 8K (body) + 4K (chunk)         = 1736 KiB
    //   steady state = 256 x (1736K + 16K arena) = 438.0 MiB reserved
    // Any change to a buffer constant must show up as a diff in this test.
    try std.testing.expectEqual(@as(usize, 256), limits.max_connections);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), limits.zstd_window_len);
    try std.testing.expectEqual(@as(usize, 1736 * 1024), limits.perConnBytes());
    try std.testing.expectEqual(@as(usize, 256 * 1752 * 1024), limits.steadyStateBytes());
    try std.testing.expectEqual(@as(u32, 1024 * 1024), limits.max_body_size);
    // max_decoded_bytes defaults to max_body_size; thread knobs default off.
    try std.testing.expectEqual(@as(usize, 1024 * 1024), limits.max_decoded_bytes);
    try std.testing.expectEqual(@as(?u16, null), limits.worker_count);
    try std.testing.expectEqual(@as(?u16, null), limits.thread_pool_count);
    // httpz body pool: 8 x max_body_size eager (was httpz's 16 x default).
    try std.testing.expectEqual(@as(u16, 8), limits.large_body_buffer_count);
    try std.testing.expectEqual(@as(u32, 1024 * 1024), limits.large_body_buffer_size);
}

test "Limits resolves config-supplied knobs" {
    const limits: Limits = .resolve(.{
        .max_body_size = 1024 * 1024,
        .max_decoded_bytes = 4 * 1024 * 1024,
        .max_connections = 32,
        .worker_count = 2,
        .thread_pool_count = 8,
    });
    try std.testing.expectEqual(@as(usize, 32), limits.max_connections);
    try std.testing.expectEqual(@as(usize, 4 * 1024 * 1024), limits.max_decoded_bytes);
    try std.testing.expectEqual(@as(?u16, 2), limits.worker_count);
    try std.testing.expectEqual(@as(?u16, 8), limits.thread_pool_count);
    // Per-worker pool: 8-buffer total cap split across 2 workers.
    try std.testing.expectEqual(@as(u16, 4), limits.large_body_buffer_count);
}

test "Limits caps the body pool below the handler count" {
    const limits: Limits = .resolve(.{
        .max_body_size = 2 * 1024 * 1024,
        .thread_pool_count = 32,
    });
    // 32 handlers don't get 32 x 2 MiB pinned; overflow bodies arena-alloc.
    try std.testing.expectEqual(@as(u16, 8), limits.large_body_buffer_count);
    try std.testing.expectEqual(@as(u32, 2 * 1024 * 1024), limits.large_body_buffer_size);

    const small: Limits = .resolve(.{
        .max_body_size = 2 * 1024 * 1024,
        .thread_pool_count = 2,
    });
    try std.testing.expectEqual(@as(u16, 2), small.large_body_buffer_count);

    // Many workers: per-worker count floors at 1 (pool can't be empty).
    const many_workers: Limits = .resolve(.{
        .max_body_size = 2 * 1024 * 1024,
        .worker_count = 16,
    });
    try std.testing.expectEqual(@as(u16, 1), many_workers.large_body_buffer_count);
}
