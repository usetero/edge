//! Single source of truth for every buffer size and bound in the data plane.
//! No other file in src/core, src/http, src/pipeline, or src/service may
//! define a size constant; importing from here keeps the steady-state memory
//! budget a closed-form function of configuration (see `Limits.steadyStateBytes`).
const std = @import("std");
const config_types = @import("../config/types.zig");

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

/// zlib inflate window (windowBits=15 → 32 KiB) plus stream state slack.
pub const FLATE_WINDOW_BYTES: usize = 48 * 1024;

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
    conn_arena_reserve: usize,

    pub fn fromConfig(
        cfg: *const config_types.ProxyConfig,
        environ_map: *const std.process.Environ.Map,
    ) Limits {
        const max_connections = parseEnvUsize(
            environ_map,
            "TERO_MAX_CONNECTIONS",
            DEFAULT_MAX_CONNECTIONS,
        );
        std.debug.assert(max_connections > 0);
        return .{
            .max_connections = max_connections,
            .max_body_size = cfg.max_body_size,
            .record_scratch = RECORD_SCRATCH_BYTES,
            .recv_buf = RECV_BUF_BYTES,
            .send_buf = SEND_BUF_BYTES,
            .upstream_write_buf = UPSTREAM_WRITE_BUF_BYTES,
            .conn_arena_reserve = CONN_ARENA_RESERVE_BYTES,
        };
    }

    /// Bytes the slab pre-allocates for one connection's fixed buffers.
    pub fn perConnBytes(self: Limits) usize {
        return self.recv_buf + self.send_buf + self.upstream_write_buf + self.record_scratch;
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
    const cfg: config_types.ProxyConfig = .{};
    const limits: Limits = .fromConfig(&cfg, &env_map);

    // Hand-computed: 256 conns x (20K + 20K + 20K + 256K + 16K) = 256 x 339,968.
    // Any change to a buffer constant must show up as a diff in this test.
    try std.testing.expectEqual(@as(usize, 256), limits.max_connections);
    try std.testing.expectEqual(@as(usize, 316 * 1024), limits.perConnBytes());
    try std.testing.expectEqual(@as(usize, 256 * 332 * 1024), limits.steadyStateBytes());
    try std.testing.expectEqual(@as(u32, 1024 * 1024), limits.max_body_size);
}

test "Limits respects TERO_MAX_CONNECTIONS override and rejects garbage" {
    var env_map = std.process.Environ.Map.init(std.testing.allocator);
    defer env_map.deinit();
    try env_map.put("TERO_MAX_CONNECTIONS", "32");

    const cfg: config_types.ProxyConfig = .{};
    const limits: Limits = .fromConfig(&cfg, &env_map);
    try std.testing.expectEqual(@as(usize, 32), limits.max_connections);

    try env_map.put("TERO_MAX_CONNECTIONS", "not-a-number");
    const fallback: Limits = .fromConfig(&cfg, &env_map);
    try std.testing.expectEqual(DEFAULT_MAX_CONNECTIONS, fallback.max_connections);
}
