const std = @import("std");
const builtin = @import("builtin");
const log = std.log.scoped(.tail_watch);
const types = @import("types.zig");
const checkpoint_mod = @import("checkpoint/mod.zig");
const poll_backend = @import("watch_backend/poll.zig");
const uring_backend = @import("watch_backend/uring_linux.zig");
const kqueue_backend = @import("watch_backend/kqueue_macos.zig");

pub const BackendKind = enum {
    poll,
    uring,
    kqueue,
};

pub const Event = struct {
    file: *const std.Io.File,
    start_offset: u64,
    end_offset: u64,
    identity: ?types.FileIdentity,
};

const Backend = union(BackendKind) {
    poll: void,
    uring: uring_backend.State,
    kqueue: kqueue_backend.State,
};

/// Data-oriented watcher state:
/// - cold data: `paths`
/// - hot data: parallel arrays for fd/offset/identity/flags
pub const Watcher = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    backend: BackendKind,
    inputs: std.ArrayList([]u8),
    output_path: []u8,

    paths: std.ArrayList([]u8),
    files: std.ArrayList(?std.Io.File),
    pending_files: std.ArrayList(?std.Io.File),
    identities: std.ArrayList(?types.FileIdentity),
    pending_identities: std.ArrayList(?types.FileIdentity),
    offsets: std.ArrayList(u64),
    head_prefix_hashes: std.ArrayList(u64),
    head_prefix_lens: std.ArrayList(u8),
    seen_once: std.ArrayList(bool),
    pending_detected_ns: std.ArrayList(i128),
    matched: std.ArrayList(bool),
    last_match_ns: std.ArrayList(i128),
    dirty: std.DynamicBitSetUnmanaged,
    dirty_queue: std.ArrayList(u32),

    glob_interval_ns: i128,
    rotate_wait_ns: i128,
    removed_expire_ns: i128,
    next_glob_refresh_ns: i128,

    backend_state: Backend = .{ .poll = {} },

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        kind: BackendKind,
        inputs: []const []const u8,
        output_path: []const u8,
        read_from: types.ReadFrom,
        glob_interval_ms: u64,
        rotate_wait_ms: u64,
        removed_expire_ms: u64,
    ) !Watcher {
        var input_copy: std.ArrayList([]u8) = .empty;
        errdefer {
            for (input_copy.items) |p| allocator.free(p);
            input_copy.deinit(allocator);
        }
        for (inputs) |p| try input_copy.append(allocator, try allocator.dupe(u8, p));
        const out_copy = try allocator.dupe(u8, output_path);
        // No errdefer: the literal below moves out_copy into self, and
        // errdefer self.deinit() frees it.

        var self: Watcher = .{
            .allocator = allocator,
            .io = io,
            .backend = kind,
            .inputs = input_copy,
            .output_path = out_copy,
            .paths = .empty,
            .files = .empty,
            .pending_files = .empty,
            .identities = .empty,
            .pending_identities = .empty,
            .offsets = .empty,
            .head_prefix_hashes = .empty,
            .head_prefix_lens = .empty,
            .seen_once = .empty,
            .pending_detected_ns = .empty,
            .matched = .empty,
            .last_match_ns = .empty,
            .dirty = .{},
            .dirty_queue = .empty,
            .glob_interval_ns = @as(i128, @intCast(glob_interval_ms)) * std.time.ns_per_ms,
            .rotate_wait_ns = @as(i128, @intCast(rotate_wait_ms)) * std.time.ns_per_ms,
            .removed_expire_ns = @as(i128, @intCast(removed_expire_ms)) * std.time.ns_per_ms,
            .next_glob_refresh_ns = std.Io.Timestamp.now(io, .awake).toNanoseconds(),
            .backend_state = .{ .poll = {} },
        };
        // self owns input_copy now. Clear the local so its errdefer does not
        // free the paths twice.
        input_copy = .empty;
        errdefer self.deinit();

        try self.initBackend();

        try self.refreshPaths(read_from, null);
        return self;
    }

    pub fn deinit(self: *Watcher) void {
        self.deinitBackend();

        for (self.inputs.items) |p| self.allocator.free(p);
        self.inputs.deinit(self.allocator);

        var i: usize = 0;
        while (i < self.paths.items.len) : (i += 1) {
            if (self.files.items[i]) |f| f.close(self.io);
            if (self.pending_files.items[i]) |f| f.close(self.io);
            self.allocator.free(self.paths.items[i]);
        }
        self.paths.deinit(self.allocator);
        self.files.deinit(self.allocator);
        self.pending_files.deinit(self.allocator);
        self.identities.deinit(self.allocator);
        self.pending_identities.deinit(self.allocator);
        self.offsets.deinit(self.allocator);
        self.head_prefix_hashes.deinit(self.allocator);
        self.head_prefix_lens.deinit(self.allocator);
        self.seen_once.deinit(self.allocator);
        self.pending_detected_ns.deinit(self.allocator);
        self.matched.deinit(self.allocator);
        self.last_match_ns.deinit(self.allocator);
        self.dirty.deinit(self.allocator);
        self.dirty_queue.deinit(self.allocator);
        self.allocator.free(self.output_path);
        self.* = undefined;
    }

    fn initBackend(self: *Watcher) !void {
        self.backend_state = switch (self.backend) {
            .poll => .{ .poll = {} },
            .uring => .{ .uring = try uring_backend.init(self.allocator, self.io) },
            .kqueue => .{ .kqueue = try kqueue_backend.init(self.allocator, self.io) },
        };
    }

    fn deinitBackend(self: *Watcher) void {
        switch (self.backend_state) {
            .poll => {},
            .uring => |*u| uring_backend.deinit(u),
            .kqueue => |*kq| kqueue_backend.deinit(kq),
        }
    }

    pub fn collect(
        self: *Watcher,
        out: *std.ArrayList(Event),
        read_from: types.ReadFrom,
        checkpoint_lane: ?*checkpoint_mod.Lane,
    ) !void {
        out.clearRetainingCapacity();

        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
        if (now >= self.next_glob_refresh_ns) {
            try self.refreshPaths(read_from, checkpoint_lane);
            self.next_glob_refresh_ns = now + self.glob_interval_ns;
        }

        try self.collectBackendDirtyCandidates();
        self.markPendingDirty();

        var q: usize = 0;
        while (q < self.dirty_queue.items.len) : (q += 1) {
            // markDirty rejects bad indexes, and removeTracked clears the queue.
            const idx = self.dirty_queue.items[q];
            self.dirty.unset(idx);
            try self.processDirtyIndex(out, idx, read_from, checkpoint_lane);
        }
        self.dirty_queue.clearRetainingCapacity();
    }

    /// Restore startup cursors once, before collecting any live ranges.
    pub fn applyCheckpointLane(self: *Watcher, lane: *checkpoint_mod.Lane) void {
        var i: usize = 0;
        while (i < self.paths.items.len) : (i += 1) {
            self.applyCheckpointOffsetOne(@intCast(i), lane);
        }
    }

    fn applyCheckpointOffsetOne(self: *Watcher, idx: u32, lane: *checkpoint_mod.Lane) void {
        const id = self.identities.items[idx] orelse return;
        const off = lane.getOffset(id) orelse return;
        if (off <= self.offsets.items[idx]) return;
        self.markDirty(idx);
        // An offset above the size means the file shrank while nothing
        // watched it. The prefix seen now cannot vouch for the old bytes, so
        // keep the cursor and re-emit from it (at-least-once).
        const file = self.files.items[idx] orelse return;
        const st = fstatHandle(file.handle) catch |err| {
            log.warn("checkpoint restore skipped for {s}: {s}", .{ self.paths.items[idx], @errorName(err) });
            return;
        };
        if (off > st.size) return;
        self.offsets.items[idx] = off;
    }

    fn collectBackendDirtyCandidates(self: *Watcher) !void {
        switch (self.backend) {
            .poll => poll_backend.collectDirty(self),
            .uring => try uring_backend.collectDirty(self),
            .kqueue => try kqueue_backend.collectDirty(self),
        }
    }

    fn markPendingDirty(self: *Watcher) void {
        var i: usize = 0;
        while (i < self.pending_files.items.len) : (i += 1) {
            if (self.pending_files.items[i] != null) {
                self.markDirty(@intCast(i));
            }
        }
    }

    fn processDirtyIndex(
        self: *Watcher,
        out: *std.ArrayList(Event),
        idx: u32,
        read_from: types.ReadFrom,
        checkpoint_lane: ?*checkpoint_mod.Lane,
    ) !void {
        try self.openTracked(idx, read_from, checkpoint_lane);
        if (self.files.items[idx] == null) return;

        try self.detectPathReplacement(idx);
        const size = self.readActiveSizeOrReset(idx) orelse return;
        try self.maybeHandleContentRewrite(idx, size);

        const emitted = try self.emitReadableRange(out, idx, size);
        if (!emitted) {
            try self.maybeSwitchPending(idx, checkpoint_lane);
            try self.openTracked(idx, read_from, checkpoint_lane);
        }
    }

    fn readActiveSizeOrReset(self: *Watcher, idx: u32) ?u64 {
        const file = self.files.items[idx] orelse return null;
        const st = fstatHandle(file.handle) catch {
            file.close(self.io);
            self.files.items[idx] = null;
            self.identities.items[idx] = null;
            self.offsets.items[idx] = 0;
            self.clearPending(idx);
            return null;
        };
        return st.size;
    }

    fn emitReadableRange(self: *Watcher, out: *std.ArrayList(Event), idx: u32, size: u64) !bool {
        if (size <= self.offsets.items[idx]) return false;
        try out.append(self.allocator, .{
            .file = &self.files.items[idx].?,
            .start_offset = self.offsets.items[idx],
            .end_offset = size,
            .identity = self.identities.items[idx],
        });
        self.offsets.items[idx] = size;
        return true;
    }

    fn refreshPaths(self: *Watcher, read_from: types.ReadFrom, checkpoint_lane: ?*checkpoint_mod.Lane) !void {
        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
        for (self.matched.items) |*m| m.* = false;

        var expanded = try expandPatterns(self.allocator, self.io, self.inputs.items);
        defer {
            for (expanded.items) |p| self.allocator.free(p);
            expanded.deinit(self.allocator);
        }

        for (expanded.items) |p| {
            if (!shouldTrackPath(self.output_path, p)) continue;
            if (self.findIndexByPath(p)) |idx| {
                self.markExistingPathMatched(@intCast(idx), now);
                continue;
            }
            try self.addNewTrackedPath(p, now, read_from, checkpoint_lane);
        }

        self.evictExpiredUnmatched(now);
    }

    fn markExistingPathMatched(self: *Watcher, idx: u32, now: i128) void {
        self.matched.items[idx] = true;
        self.last_match_ns.items[idx] = now;
        self.markDirty(idx);
    }

    fn addNewTrackedPath(
        self: *Watcher,
        path: []const u8,
        now: i128,
        read_from: types.ReadFrom,
        checkpoint_lane: ?*checkpoint_mod.Lane,
    ) !void {
        try self.appendTracked(path, now);
        const idx: u32 = @intCast(self.paths.items.len - 1);
        try self.openTracked(idx, read_from, checkpoint_lane);
        self.markDirty(idx);
    }

    fn evictExpiredUnmatched(self: *Watcher, now: i128) void {
        var i: usize = self.paths.items.len;
        while (i > 0) {
            i -= 1;
            if (self.matched.items[i]) continue;
            if (now - self.last_match_ns.items[i] < self.removed_expire_ns) continue;
            self.removeTracked(i);
        }
    }

    fn appendTracked(self: *Watcher, path: []const u8, now: i128) !void {
        const p = try self.allocator.dupe(u8, path);
        errdefer self.allocator.free(p);

        try self.paths.append(self.allocator, p);
        try self.files.append(self.allocator, null);
        try self.pending_files.append(self.allocator, null);
        try self.identities.append(self.allocator, null);
        try self.pending_identities.append(self.allocator, null);
        try self.offsets.append(self.allocator, 0);
        try self.head_prefix_hashes.append(self.allocator, 0);
        try self.head_prefix_lens.append(self.allocator, 0);
        try self.seen_once.append(self.allocator, false);
        try self.pending_detected_ns.append(self.allocator, 0);
        try self.matched.append(self.allocator, true);
        try self.last_match_ns.append(self.allocator, now);

        const n = self.paths.items.len;
        if (self.dirty.capacity() < n) {
            try self.dirty.resize(self.allocator, n, false);
        } else {
            self.dirty.setValue(@intCast(n - 1), false);
        }
    }

    fn removeTracked(self: *Watcher, idx: usize) void {
        if (self.files.items[idx]) |f| f.close(self.io);
        self.clearPending(@intCast(idx));

        self.allocator.free(self.paths.items[idx]);
        _ = self.paths.swapRemove(idx);
        _ = self.files.swapRemove(idx);
        _ = self.pending_files.swapRemove(idx);
        _ = self.identities.swapRemove(idx);
        _ = self.pending_identities.swapRemove(idx);
        _ = self.offsets.swapRemove(idx);
        _ = self.head_prefix_hashes.swapRemove(idx);
        _ = self.head_prefix_lens.swapRemove(idx);
        _ = self.seen_once.swapRemove(idx);
        _ = self.pending_detected_ns.swapRemove(idx);
        _ = self.matched.swapRemove(idx);
        _ = self.last_match_ns.swapRemove(idx);

        self.rebuildBackendIndexesAfterSwap();
    }

    fn rebuildBackendIndexesAfterSwap(self: *Watcher) void {
        self.backendRebuildIndexes();
        self.dirty_queue.clearRetainingCapacity();
        self.dirty.unsetAll();
    }

    fn openTracked(self: *Watcher, idx: u32, read_from: types.ReadFrom, checkpoint_lane: ?*checkpoint_mod.Lane) !void {
        if (self.files.items[idx] != null) return;

        const file = std.Io.Dir.cwd().openFile(
            self.io,
            self.paths.items[idx],
            .{ .mode = .read_only },
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer {
            file.close(self.io);
            self.files.items[idx] = null;
        }

        const st = try fstatHandle(file.handle);
        const size: u64 = st.size;
        self.identities.items[idx] = .{
            .dev = @intCast(st.dev),
            .inode = @intCast(st.ino),
            .fingerprint = try computeFingerprint(self.io, file),
        };
        self.files.items[idx] = file;
        self.initHeadPrefix(idx, size) catch |err| log.warn("initHeadPrefix on open failed: {}", .{err});
        self.offsets.items[idx] = if (!self.seen_once.items[idx] and read_from == .tail) size else 0;
        self.seen_once.items[idx] = true;
        // Checkpoints initialize a newly opened file; the watcher owns its
        // cursor from then on, including across truncation and regrowth.
        if (checkpoint_lane) |lane| self.applyCheckpointOffsetOne(idx, lane);

        try self.backendTrackOpenFile(idx, self.paths.items[idx], file.handle);
    }

    fn detectPathReplacement(self: *Watcher, idx: u32) !void {
        if (self.files.items[idx] == null) return;
        if (self.pending_files.items[idx] != null) return;

        var path_file = std.Io.Dir.cwd().openFile(
            self.io,
            self.paths.items[idx],
            .{ .mode = .read_only },
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer path_file.close(self.io);

        const path_st = try fstatHandle(path_file.handle);
        const cur_st = try fstatHandle(self.files.items[idx].?.handle);
        if (path_st.dev == cur_st.dev and path_st.ino == cur_st.ino) {
            path_file.close(self.io);
            return;
        }

        self.pending_identities.items[idx] = .{
            .dev = @intCast(path_st.dev),
            .inode = @intCast(path_st.ino),
            .fingerprint = try computeFingerprint(self.io, path_file),
        };
        self.pending_files.items[idx] = path_file;
        self.pending_detected_ns.items[idx] = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
    }

    /// Recompute the fingerprint after a same-inode rewrite. Checkpoints use
    /// the fingerprint as a key. A stale fingerprint files new offsets under
    /// the old content.
    fn refreshIdentityFingerprint(self: *Watcher, idx: u32, file: std.Io.File) !void {
        if (self.identities.items[idx]) |id| {
            self.identities.items[idx] = .{
                .dev = id.dev,
                .inode = id.inode,
                .fingerprint = try computeFingerprint(self.io, file),
            };
        }
    }

    fn maybeHandleContentRewrite(self: *Watcher, idx: u32, size: u64) !void {
        const file = self.files.items[idx] orelse return;
        const prefix_len: u64 = self.head_prefix_lens.items[idx];
        if (prefix_len == 0 or size < prefix_len) {
            // First observation, empty file, or a shrink below the prefix.
            if (size == 0 or size < prefix_len) self.offsets.items[idx] = 0;
            try self.initHeadPrefix(idx, size);
            if (size > 0) try self.refreshIdentityFingerprint(idx, file);
            return;
        }

        const observed = try prefixHash(self.io, file, prefix_len);
        if (observed == self.head_prefix_hashes.items[idx]) {
            // Prefix unchanged: the file may have shrunk. Clamp the offset to
            // the size, so no delivered bytes are re-emitted.
            if (size < self.offsets.items[idx]) self.offsets.items[idx] = size;
        } else {
            self.offsets.items[idx] = 0;
            self.head_prefix_hashes.items[idx] = observed;
        }
        // The fingerprint can come from a shorter file. Refresh it so
        // checkpoints cover the current content.
        try self.refreshIdentityFingerprint(idx, file);
    }

    fn maybeSwitchPending(self: *Watcher, idx: u32, checkpoint_lane: ?*checkpoint_mod.Lane) !void {
        if (self.pending_files.items[idx] == null) return;

        if (self.files.items[idx]) |cur_file| {
            if (fstatHandle(cur_file.handle)) |cur_st| {
                // Drain the old file, and wait for the rotate delay.
                if (cur_st.size > self.offsets.items[idx]) return;
                const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
                if (now - self.pending_detected_ns.items[idx] < self.rotate_wait_ns) return;
            } else |err| {
                log.warn("fstat of the rotated file failed for {s}: {s}. Switch now.", .{
                    self.paths.items[idx],
                    @errorName(err),
                });
            }
            cur_file.close(self.io);
        }
        try self.switchToPending(idx, checkpoint_lane);
        self.markDirty(idx);
    }

    /// Put the pending file in the slot. The caller closes the old handle.
    fn switchToPending(self: *Watcher, idx: u32, checkpoint_lane: ?*checkpoint_mod.Lane) !void {
        const next_file = self.pending_files.items[idx] orelse return;
        // Unregister the old handle, so the backend watches only the new file.
        self.backendRemoveTracked(idx);
        self.files.items[idx] = next_file;
        self.identities.items[idx] = self.pending_identities.items[idx];
        self.pending_files.items[idx] = null;
        self.pending_identities.items[idx] = null;
        self.pending_detected_ns.items[idx] = 0;
        self.offsets.items[idx] = 0;

        const st = try fstatHandle(next_file.handle);
        try self.initHeadPrefix(idx, st.size);
        if (checkpoint_lane) |lane| self.applyCheckpointOffsetOne(idx, lane);
        try self.backendTrackOpenFile(idx, self.paths.items[idx], next_file.handle);
    }

    fn clearPending(self: *Watcher, idx: u32) void {
        if (self.pending_files.items[idx]) |f| f.close(self.io);
        self.pending_files.items[idx] = null;
        self.pending_identities.items[idx] = null;
        self.pending_detected_ns.items[idx] = 0;
    }

    pub fn markDirty(self: *Watcher, idx: u32) void {
        if (idx >= self.paths.items.len) return;
        if (self.dirty.isSet(idx)) return;
        self.dirty.set(idx);
        self.dirty_queue.append(self.allocator, idx) catch |err| log.warn("dirty_queue append failed: {}", .{err});
    }

    /// Mark every tracked path in `dir_path` dirty.
    pub fn markDirDirty(self: *Watcher, dir_path: []const u8) void {
        for (self.paths.items, 0..) |path, i| {
            const tracked_dir = std.fs.path.dirname(path) orelse ".";
            if (std.mem.eql(u8, tracked_dir, dir_path)) self.markDirty(@intCast(i));
        }
    }

    fn backendTrackOpenFile(self: *Watcher, idx: u32, path: []const u8, fd: std.posix.fd_t) !void {
        switch (self.backend) {
            .poll => {},
            .uring => try uring_backend.trackOpenFile(self, idx, path),
            .kqueue => try kqueue_backend.trackOpenFile(self, idx, path, fd),
        }
    }

    fn backendRemoveTracked(self: *Watcher, idx: u32) void {
        switch (self.backend) {
            .poll => {},
            .uring => uring_backend.removeTracked(self, idx),
            .kqueue => kqueue_backend.removeTracked(self, idx),
        }
    }

    fn backendRebuildIndexes(self: *Watcher) void {
        switch (self.backend) {
            .poll => {},
            .uring => uring_backend.rebuildIndexes(self),
            .kqueue => kqueue_backend.rebuildIndexes(self),
        }
    }

    fn findIndexByPath(self: *Watcher, path: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.paths.items.len) : (i += 1) {
            if (std.mem.eql(u8, self.paths.items[i], path)) return i;
        }
        return null;
    }

    fn initHeadPrefix(self: *Watcher, idx: u32, size: u64) !void {
        const len: u64 = @min(@as(u64, 64), size);
        self.head_prefix_lens.items[idx] = @intCast(len);
        if (len == 0) {
            self.head_prefix_hashes.items[idx] = 0;
            return;
        }
        self.head_prefix_hashes.items[idx] = try prefixHash(self.io, self.files.items[idx].?, len);
    }
};

fn shouldTrackPath(output_path: []const u8, candidate_path: []const u8) bool {
    if (std.mem.eql(u8, output_path, "-")) return true;
    return !std.mem.eql(u8, output_path, candidate_path);
}

/// Subset of fstat results needed for file identity and size tracking. The
/// std.Io.File.Stat type does not expose the device id, so we call the
/// platform stat syscall directly on the file handle to recover dev/ino/size.
pub const FsStat = struct {
    dev: u64,
    ino: u64,
    size: u64,
};

pub fn fstatHandle(handle: std.posix.fd_t) !FsStat {
    switch (comptime builtin.os.tag) {
        .linux => {
            // std.c.fstat is void on Linux in Zig 0.16; use statx with AT.EMPTY_PATH.
            var stx: std.os.linux.Statx = undefined;
            const rc = std.os.linux.statx(
                handle,
                "",
                std.os.linux.AT.EMPTY_PATH,
                std.os.linux.STATX.BASIC_STATS,
                &stx,
            );
            if (rc != 0) return error.StatFailed;
            return .{
                .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor,
                .ino = stx.ino,
                .size = stx.size,
            };
        },
        else => {
            var st: std.c.Stat = undefined;
            if (std.c.fstat(handle, &st) != 0) return error.StatFailed;
            return .{
                .dev = @intCast(st.dev),
                .ino = @intCast(st.ino),
                .size = @intCast(st.size),
            };
        },
    }
}

fn computeFingerprint(io: std.Io, file: std.Io.File) !u32 {
    var buf: [1024]u8 = undefined;
    const n = try file.readPositionalAll(io, &buf, 0);
    return std.hash.Crc32.hash(buf[0..n]);
}

fn prefixHash(io: std.Io, file: std.Io.File, len: u64) !u64 {
    if (len == 0) return 0;
    var buf: [64]u8 = undefined;
    const want: usize = @intCast(@min(len, buf.len));
    const n = try file.readPositionalAll(io, buf[0..want], 0);
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(buf[0..n]);
    return hasher.final();
}

/// The caller frees each path and the list.
fn expandPatterns(allocator: std.mem.Allocator, io: std.Io, inputs: []const []const u8) !std.ArrayList([]u8) {
    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |p| allocator.free(p);
        out.deinit(allocator);
    }
    for (inputs) |input| {
        if (!isGlobPattern(input)) {
            try out.append(allocator, try allocator.dupe(u8, input));
            continue;
        }
        try expandOnePattern(allocator, io, input, &out);
    }
    return out;
}

fn isGlobPattern(input: []const u8) bool {
    return std.mem.indexOfAny(u8, input, "*?[") != null;
}

fn expandOnePattern(allocator: std.mem.Allocator, io: std.Io, pattern: []const u8, out: *std.ArrayList([]u8)) !void {
    const dir_path = std.fs.path.dirname(pattern) orelse ".";
    const base_pat = std.fs.path.basename(pattern);
    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind == .directory) continue;
        if (!match(base_pat, entry.name)) continue;
        const full = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        try out.append(allocator, full);
    }
}

fn match(pattern: []const u8, value: []const u8) bool {
    var p: usize = 0;
    var v: usize = 0;
    var star_p: ?usize = null;
    var star_v: usize = 0;
    while (v < value.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == value[v])) {
            p += 1;
            v += 1;
            continue;
        }
        if (p < pattern.len and pattern[p] == '*') {
            star_p = p;
            p += 1;
            star_v = v;
            continue;
        }
        if (star_p) |sp| {
            p = sp + 1;
            star_v += 1;
            v = star_v;
            continue;
        }
        return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

const testing = std.testing;

test "watch public API: collect emits appended file bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    var w = try Watcher.init(testing.allocator, std.Options.debug_io, .poll, &.{abs}, "-", .tail, 1000, 50, 1000);
    defer w.deinit();

    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    try w.collect(&events, .tail, null);
    try testing.expectEqual(@as(usize, 0), events.items.len);

    {
        const f = try tmp.dir.openFile(io, "tail.log", .{ .mode = .read_write });
        defer f.close(io);
        const size = (try f.stat(io)).size;
        try f.writePositionalAll(io, "next\n", size);
    }

    try w.collect(&events, .tail, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
}

test "watch public API: init cleans up cleanly when backend registration fails after slot commit (no double-close)" {
    // openTracked stores the handle before backendTrackOpenFile. If that call
    // fails, the errdefer must close the handle and clear the slot, or deinit
    // closes it again. This test injects the failure through the uring
    // backend.
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    // Allocations in [total_poll, total_uring) come from the uring
    // backendTrackOpenFile, after openTracked stores the handle.
    const total_poll: usize = blk: {
        var probe = std.testing.FailingAllocator.init(testing.allocator, .{});
        const pa = probe.allocator();
        var w = Watcher.init(pa, io, .poll, &.{abs}, "-", .tail, 1000, 50, 1000) catch return error.SkipZigTest;
        w.deinit();
        break :blk probe.alloc_index;
    };
    const total_uring: usize = blk: {
        var probe = std.testing.FailingAllocator.init(testing.allocator, .{});
        const pa = probe.allocator();
        var w = Watcher.init(pa, io, .uring, &.{abs}, "-", .tail, 1000, 50, 1000) catch return error.SkipZigTest;
        w.deinit();
        break :blk probe.alloc_index;
    };
    if (total_uring <= total_poll) return error.SkipZigTest; // no post-commit allocs to exercise

    // Each injected failure must return a clean error or succeed. It must
    // not panic.
    var fail_index: usize = total_poll;
    while (fail_index <= total_uring) : (fail_index += 1) {
        var st = std.testing.FailingAllocator.init(testing.allocator, .{
            .fail_index = fail_index,
        });
        const fa = st.allocator();
        if (Watcher.init(fa, io, .uring, &.{abs}, "-", .tail, 1000, 50, 1000)) |w| {
            var watcher = w;
            watcher.deinit();
        } else |_| {
            // Expected: clean error propagation; init's errdefer already ran deinit.
        }
    }
}

test "checkpoint resume after copytruncate emits full new content (no silent skip)" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    // Phase 1: create file with content A, record identity (FP_A).
    const content_a: [8192]u8 = @splat('A');
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = &content_a });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    const id_a = try testIdentity(io, tmp.dir, "tail.log");

    // Phase 2: durably checkpoint offset N under FP_A via the live lane worker.
    const N: u64 = 4096;
    const state_dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const lifecycle_mod = @import("../core/lifecycle.zig");
    {
        var lifecycle: lifecycle_mod.Lifecycle = .init;
        var lane = try checkpoint_mod.Lane.initForTest(io, state_dir);
        try lane.start(&lifecycle);
        _ = lane.enqueue(.{
            .identity = id_a,
            .offset = N,
            .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
        });
        var tries: usize = 0;
        while (tries < 200 and lane.getOffset(id_a) != N) : (tries += 1) {
            try io.sleep(.fromNanoseconds(2 * std.time.ns_per_ms), .awake);
        }
        try testing.expectEqual(N, lane.getOffset(id_a).?);
        lifecycle.requestShutdown(io);
        lifecycle.shutdown(io);
        lane.finalize();
        lane.deinit();
    }

    // Phase 3: copytruncate — replace content A with content B (FP_B != FP_A, size >= N).
    {
        const f = try std.Io.Dir.cwd().openFile(io, abs, .{ .mode = .read_write });
        defer f.close(io);
        try f.setLength(io, 0);
        var buf: [8192]u8 = undefined;
        @memset(buf[0..], 'B');
        try f.writePositionalAll(io, buf[0..], 0);
        try f.sync(io);
    }

    // Phase 4: recover lane from durable state (simulates restart).
    var recovered = try checkpoint_mod.Lane.initForTest(io, state_dir);
    defer recovered.deinit();

    // Restart under .checkpoint. The lane has no offset for the new
    // fingerprint, so the watcher reads from 0.
    var w = try Watcher.init(testing.allocator, io, .poll, &.{abs}, "-", .checkpoint, 1000, 50, 1000);
    defer w.deinit();
    w.applyCheckpointLane(&recovered);

    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    try w.collect(&events, .checkpoint, &recovered);

    // All new content [0, 8192) is emitted, not [N, 8192).
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 0), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 8192), events.items[0].end_offset);
}

// Read the identity of `name` in `dir` the way the watcher computes it.
fn testIdentity(io: std.Io, dir: std.Io.Dir, name: []const u8) !types.FileIdentity {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    const st = try fstatHandle(file.handle);
    return .{ .dev = st.dev, .inode = st.ino, .fingerprint = try computeFingerprint(io, file) };
}

// Open `name` in `dir` for read/write, returning the handle. Caller closes.
fn openRw(io: std.Io, dir: std.Io.Dir, name: []const u8) !std.Io.File {
    return dir.openFile(io, name, .{ .mode = .read_write });
}

// Truncate the tracked log to `len` bytes in place.
fn truncTo(io: std.Io, dir: std.Io.Dir, name: []const u8, len: u64) !void {
    const f = try openRw(io, dir, name);
    defer f.close(io);
    try f.setLength(io, len);
}

// Append `bytes` to the tracked log at its current end.
fn appendBytes(io: std.Io, dir: std.Io.Dir, name: []const u8, bytes: []const u8) !void {
    const f = try openRw(io, dir, name);
    defer f.close(io);
    const size = (try f.stat(io)).size;
    try f.writePositionalAll(io, bytes, size);
}

test "watch: partial truncation with unchanged prefix emits nothing under .head" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed...\n" }); // 8 bytes
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    var w = try Watcher.init(testing.allocator, std.Options.debug_io, .poll, &.{abs}, "-", .head, 1000, 50, 1000);
    defer w.deinit();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);

    try w.collect(&events, .head, null); // Collect #1: emit [0, 8]
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 0), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 8), events.items[0].end_offset);

    try appendBytes(io, tmp.dir, "tail.log", "more...\n"); // -> 16 bytes
    try w.collect(&events, .head, null); // Collect #2: emit [8, 16] (collect clears `events`)
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);

    try truncTo(io, tmp.dir, "tail.log", 8); // partial truncate to 8, prefix "seed...\n" preserved

    events.clearRetainingCapacity();
    try w.collect(&events, .head, null); // Collect #3: must emit nothing
    try testing.expectEqual(@as(usize, 0), events.items.len);
}

test "watch: partial truncation with unchanged prefix does not inject stale bytes under .tail" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.Options.debug_io;
    // Eight bytes exist before start. `.tail` does not deliver them.
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed...\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    var w = try Watcher.init(testing.allocator, std.Options.debug_io, .poll, &.{abs}, "-", .tail, 1000, 50, 1000);
    defer w.deinit();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);

    try w.collect(&events, .tail, null); // Collect #1: .tail starts at offset=size -> 0 events
    try testing.expectEqual(@as(usize, 0), events.items.len);

    try appendBytes(io, tmp.dir, "tail.log", "more...\n"); // -> 16 bytes
    try w.collect(&events, .tail, null); // Collect #2: emit [8, 16]
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);

    try truncTo(io, tmp.dir, "tail.log", 8); // partial truncate to 8, prefix preserved

    events.clearRetainingCapacity();
    try w.collect(&events, .tail, null); // Collect #3: must NOT inject stale [0, 8]
    try testing.expectEqual(@as(usize, 0), events.items.len);

    // Collect #4: the offset must follow the file down to 8, or the next 8
    // bytes are lost.
    try appendBytes(io, tmp.dir, "tail.log", "next...\n"); // -> 16 bytes again
    events.clearRetainingCapacity();
    try w.collect(&events, .tail, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);
}

test "watch: copytruncate to zero then append emits new content from start" {
    // A truncate to zero must still reset the offset to 0.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed...\n" }); // 8 bytes
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    var w = try Watcher.init(testing.allocator, std.Options.debug_io, .poll, &.{abs}, "-", .head, 1000, 50, 1000);
    defer w.deinit();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);

    try w.collect(&events, .head, null); // emit [0, 8]
    try testing.expectEqual(@as(usize, 1), events.items.len);

    try truncTo(io, tmp.dir, "tail.log", 0); // copytruncate to zero
    events.clearRetainingCapacity();
    try w.collect(&events, .head, null); // nothing to emit while empty
    try testing.expectEqual(@as(usize, 0), events.items.len);

    try appendBytes(io, tmp.dir, "tail.log", "fresh\n"); // new content -> 6 bytes
    events.clearRetainingCapacity();
    try w.collect(&events, .head, null); // new content must be emitted from byte 0
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 0), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 6), events.items[0].end_offset);
}

test "watch: checkpoint resume with offset above size re-emits conservatively without looping" {
    // A lane may hold an offset above the file size. The reset and re-emit
    // must terminate; a no-emit would loop forever in collect.
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.Options.debug_io;
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed...\n" }); // 8 bytes
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    // Open once to learn the file identity, then release.
    var w0 = try Watcher.init(
        testing.allocator,
        std.Options.debug_io,
        .poll,
        &.{abs},
        "-",
        .checkpoint,
        1000,
        50,
        1000,
    );
    const id = w0.identities.items[0] orelse return error.NoIdentity;
    w0.deinit();

    // Persist a stale offset (16) above the file size (8), then recover it
    // into a Lane.
    const state_dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);
    {
        var wal = try checkpoint_mod.wal.Wal.init(testing.allocator, io, state_dir);
        // `last_seen_ns` must be recent, or `Store.getOffset` treats the entry
        // as expired.
        const now_ns: i64 = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds());
        try wal.append(1, .{ .identity = id, .offset = 16, .last_seen_ns = now_ns });
        try wal.sync();
        wal.deinit();
    }
    var lane = try checkpoint_mod.Lane.initForTest(io, state_dir);
    defer lane.deinit();
    try testing.expectEqual(@as(?u64, 16), lane.getOffset(id));

    // Restart under .checkpoint; the lane pushes the offset to 16.
    var w = try Watcher.init(testing.allocator, std.Options.debug_io, .poll, &.{abs}, "-", .checkpoint, 1000, 50, 1000);
    defer w.deinit();
    w.applyCheckpointLane(&lane);
    try testing.expectEqual(@as(u64, 0), w.offsets.items[0]);

    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    // Collect must terminate and re-emit the surviving range once from byte 0.
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 0), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 8), events.items[0].end_offset);
    try testing.expectEqual(@as(u64, 8), w.offsets.items[0]);

    // The checkpoint still records the last acknowledgement. It must not
    // overwrite the live cursor, even before the worker drains a new update.
    try testing.expectEqual(@as(?u64, 16), lane.getOffset(id));

    // A second collect must not re-emit the range while the worker has not
    // drained the queue.
    events.clearRetainingCapacity();
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 0), events.items.len);

    // Drain an acknowledgement from before the truncation after the reset.
    // If the file grows past that old offset before collect, restoring it
    // silently skips the first eight newly appended bytes.
    try testing.expect(lane.enqueue(.{
        .identity = id,
        .offset = 16,
        .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
    }));
    lane.finalize();
    try testing.expectEqual(@as(?u64, 16), lane.getOffset(id));
    try appendBytes(io, tmp.dir, "tail.log", "next...\nlast...\n");
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 24), events.items[0].end_offset);
}

test "watch: files discovered after startup still resume their checkpoints" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "pending", .data = "seed...\nnext...\n" });
    const state_dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);
    const pattern = try std.fmt.allocPrint(testing.allocator, "{s}/*.log", .{state_dir});
    defer testing.allocator.free(pattern);

    var w = try Watcher.init(testing.allocator, io, .poll, &.{pattern}, "-", .checkpoint, 1000, 50, 1000);
    defer w.deinit();
    try testing.expectEqual(@as(usize, 0), w.paths.items.len);

    const id = try testIdentity(io, tmp.dir, "pending");
    var lane = try checkpoint_mod.Lane.initForTest(io, state_dir);
    defer lane.deinit();
    try testing.expect(lane.enqueue(.{
        .identity = id,
        .offset = 8,
        .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
    }));
    lane.finalize();

    // The rename preserves identity and makes the file match the glob.
    try tmp.dir.rename("pending", tmp.dir, "tail.log", io);
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);
}

test "watch: rotation drains the old file and resumes the replacement checkpoint" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "old-one\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "replacement", .data = "new-one\nnew-two\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);
    const state_dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    const replacement_id = try testIdentity(io, tmp.dir, "replacement");
    var lane = try checkpoint_mod.Lane.initForTest(io, state_dir);
    defer lane.deinit();
    try testing.expect(lane.enqueue(.{
        .identity = replacement_id,
        .offset = 8,
        .last_seen_ns = @intCast(std.Io.Timestamp.now(io, .awake).toNanoseconds()),
    }));
    lane.finalize();

    var w = try Watcher.init(testing.allocator, io, .poll, &.{abs}, "-", .checkpoint, 1000, 0, 1000);
    defer w.deinit();
    w.applyCheckpointLane(&lane);
    const old_id = w.identities.items[0].?;
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);

    // A writer can still append through the old descriptor after the rename.
    try tmp.dir.rename("tail.log", tmp.dir, "old.log", io);
    try tmp.dir.rename("replacement", tmp.dir, "tail.log", io);
    try appendBytes(io, tmp.dir, "old.log", "old-two\n");
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(old_id.inode, events.items[0].identity.?.inode);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);

    // Switching must use the new inode's checkpoint, without replaying its
    // acknowledged prefix or carrying the old file's cursor across.
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(replacement_id.inode, events.items[0].identity.?.inode);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 0), events.items.len);
}

test "watch: live partial truncation under a checkpoint lane clamps instead of re-emitting" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "seed...\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);
    const state_dir = try tmp.dir.realPathFileAlloc(io, ".", testing.allocator);
    defer testing.allocator.free(state_dir);

    var lane = try checkpoint_mod.Lane.initForTest(io, state_dir);
    defer lane.deinit();
    var w = try Watcher.init(testing.allocator, io, .poll, &.{abs}, "-", .checkpoint, 1000, 50, 1000);
    defer w.deinit();
    w.applyCheckpointLane(&lane);
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);

    try w.collect(&events, .checkpoint, &lane); // emit [0, 8]
    try appendBytes(io, tmp.dir, "tail.log", "more...\n");
    try w.collect(&events, .checkpoint, &lane); // emit [8, 16]
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);

    // The prefix survives, so the bytes left were already delivered.
    try truncTo(io, tmp.dir, "tail.log", 8);
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 0), events.items.len);
    try testing.expectEqual(@as(u64, 8), w.offsets.items[0]);

    try appendBytes(io, tmp.dir, "tail.log", "next...\n");
    try w.collect(&events, .checkpoint, &lane);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);
}

test "watch: kqueue sees appends to a rotated-in file without a glob refresh" {
    if (builtin.os.tag != .macos) return error.SkipZigTest;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "old-one\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "tail.log", testing.allocator);
    defer testing.allocator.free(abs);

    // The long glob interval means only kqueue events mark the file dirty.
    var w = try Watcher.init(testing.allocator, io, .kqueue, &.{abs}, "-", .head, 60_000, 0, 60_000);
    defer w.deinit();
    var events: std.ArrayList(Event) = .empty;
    defer events.deinit(testing.allocator);
    try w.collect(&events, .head, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);

    try tmp.dir.rename("tail.log", tmp.dir, "old.log", io);
    try tmp.dir.writeFile(io, .{ .sub_path = "tail.log", .data = "new-one\n" });
    try w.collect(&events, .head, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    const new_id = try testIdentity(io, tmp.dir, "tail.log");
    try testing.expectEqual(new_id.inode, events.items[0].identity.?.inode);

    // The switch must register the new handle with kqueue.
    try appendBytes(io, tmp.dir, "tail.log", "new-two\n");
    try w.collect(&events, .head, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u64, 8), events.items[0].start_offset);
    try testing.expectEqual(@as(u64, 16), events.items[0].end_offset);
}
