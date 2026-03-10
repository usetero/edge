const std = @import("std");
const builtin = @import("builtin");

pub const ReadFrom = enum {
    head,
    tail,
    checkpoint,
};

pub const IoEngine = enum {
    auto,
    poll,
    uring,
    kqueue,
    inotify, // compatibility alias for Linux uring watcher
    epoll, // compatibility alias for poll watcher
};

pub const InputFormat = enum {
    raw,
    json,
    logfmt,
};

pub const FileIdentity = struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,
};

pub fn identityHash(identity: FileIdentity) u64 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(std.mem.asBytes(&identity.dev));
    hasher.update(std.mem.asBytes(&identity.inode));
    hasher.update(std.mem.asBytes(&identity.fingerprint));
    return hasher.final();
}

pub fn inodeIdentityHash(identity: FileIdentity) u64 {
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(std.mem.asBytes(&identity.dev));
    hasher.update(std.mem.asBytes(&identity.inode));
    return hasher.final();
}

pub const LineMeta = struct {
    identity: ?FileIdentity = null,
    truncated: bool = false,
};

pub const TailConfig = struct {
    output_path: []const u8 = "-",
    read_from: ReadFrom = .tail,
    input_format: InputFormat = .raw,
    policy_path: ?[]const u8 = null,
    io_engine: IoEngine = .auto,
    poll_ms: u64 = 200,
    glob_interval_ms: u64 = 5_000,
    rotate_wait_ms: u64 = 5_000,
    removed_expire_ms: u64 = 60_000,
    checkpoint_interval_ms: u64 = 5_000,
    checkpoint_sync_batch: u32 = 64,
    checkpoint_snapshot_interval_ms: u64 = 60_000,
    checkpoint_ttl_ms: u64 = 72 * 60 * 60 * 1000,
    checkpoint_max_slots: usize = 256,
    state_dir: []const u8 = ".tero",
    read_buf: usize = 64 * 1024,
    max_line: usize = 256 * 1024,
    write_buf: usize = 64 * 1024,
    flush_interval_ms: u64 = 100,
    flush_line_threshold: usize = 1024,
};

pub fn validateConfig(cfg: TailConfig) !void {
    if (cfg.poll_ms == 0) return error.InvalidPollInterval;
    if (cfg.glob_interval_ms == 0) return error.InvalidGlobInterval;
    if (cfg.read_buf == 0) return error.InvalidReadBuffer;
    if (cfg.max_line == 0) return error.InvalidMaxLine;
    if (cfg.write_buf == 0) return error.InvalidWriteBuffer;
    if (cfg.flush_interval_ms == 0) return error.InvalidFlushInterval;
    if (cfg.flush_line_threshold == 0) return error.InvalidFlushThreshold;
    if (cfg.checkpoint_sync_batch == 0) return error.InvalidCheckpointSyncBatch;
    if (cfg.checkpoint_snapshot_interval_ms == 0) return error.InvalidCheckpointSnapshotInterval;
}

pub const NativeIoEngine: IoEngine = switch (builtin.os.tag) {
    .linux => .uring,
    .macos => .kqueue,
    else => .poll,
};

pub fn normalizeIoEngine(engine: IoEngine) IoEngine {
    return switch (engine) {
        .auto => NativeIoEngine,
        .inotify => if (builtin.os.tag == .linux) .uring else .poll,
        .epoll => .poll,
        .uring => if (builtin.os.tag == .linux) .uring else .poll,
        .kqueue => if (builtin.os.tag == .macos) .kqueue else .poll,
        .poll => .poll,
    };
}

const testing = std.testing;

test "types public API: validateConfig rejects zero limits" {
    var cfg = TailConfig{};
    cfg.read_buf = 0;
    try testing.expectError(error.InvalidReadBuffer, validateConfig(cfg));
}

test "types public API: identity hash helpers are stable" {
    const id = FileIdentity{ .dev = 42, .inode = 9, .fingerprint = 1234 };
    try testing.expect(identityHash(id) != 0);
    try testing.expect(inodeIdentityHash(id) != 0);
}
