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

    pub fn resolve(
        max_body_size: u32,
        environ_map: *const std.process.Environ.Map,
    ) Limits {
        const max_connections = parseEnvUsize(
            environ_map,
            "TERO_MAX_CONNECTIONS",
            DEFAULT_MAX_CONNECTIONS,
        );
        std.debug.assert(max_connections > 0);
        const zstd_window_len = std.math.clamp(
            @as(usize, max_body_size),
            ZSTD_WINDOW_MIN,
            ZSTD_WINDOW_MAX,
        );
        return .{
            .max_connections = max_connections,
            .max_body_size = max_body_size,
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

fn parseEnvUsize(
    environ_map: *const std.process.Environ.Map,
    key: []const u8,
    default: usize,
) usize {
    const raw = environ_map.get(key) orelse return default;
    return std.fmt.parseUnsigned(usize, raw, 10) catch |err| {
        log.warn("ignoring {s}={s}: {s}", .{ key, raw, @errorName(err) });
        return default;
    };
}

test "Limits budget formula is locked" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    const limits: Limits = .resolve(1024 * 1024, &env_map);

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
}

test "Limits respects TERO_MAX_CONNECTIONS override and rejects garbage" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("TERO_MAX_CONNECTIONS", "32");

    const limits: Limits = .resolve(1024 * 1024, &env_map);
    try std.testing.expectEqual(@as(usize, 32), limits.max_connections);

    try env_map.put("TERO_MAX_CONNECTIONS", "not-a-number");
    const fallback: Limits = .resolve(1024 * 1024, &env_map);
    try std.testing.expectEqual(DEFAULT_MAX_CONNECTIONS, fallback.max_connections);
}
