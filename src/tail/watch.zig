const std = @import("std");
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
        errdefer allocator.free(out_copy);

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
        errdefer self.deinit();

        try self.initBackend();

        try self.refreshPaths(read_from);
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
            try self.refreshPaths(read_from);
            self.next_glob_refresh_ns = now + self.glob_interval_ns;
        }

        try self.collectBackendDirtyCandidates();
        self.markPendingDirty();

        var q: usize = 0;
        while (q < self.dirty_queue.items.len) : (q += 1) {
            const idx_u32 = self.dirty_queue.items[q];
            const idx: usize = @intCast(idx_u32);
            if (idx >= self.paths.items.len) continue;
            self.dirty.unset(idx_u32);
            try self.processDirtyIndex(out, idx_u32, read_from, checkpoint_lane);
        }
        self.dirty_queue.clearRetainingCapacity();
    }

    pub fn applyCheckpointLane(self: *Watcher, lane: *checkpoint_mod.Lane) void {
        var i: usize = 0;
        while (i < self.paths.items.len) : (i += 1) {
            self.applyCheckpointOffsetOne(@intCast(i), lane);
        }
    }

    fn applyCheckpointOffsetOne(self: *Watcher, idx: u32, lane: *checkpoint_mod.Lane) void {
        if (idx >= self.identities.items.len) return;
        const i: usize = @intCast(idx);
        const id = self.identities.items[i] orelse return;
        if (lane.getOffset(id)) |off| {
            if (off > self.offsets.items[i]) {
                self.offsets.items[i] = off;
                self.markDirty(idx);
            }
        }
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
        const i: usize = @intCast(idx);
        if (!(try self.ensureOpenWithCheckpoint(idx, read_from, checkpoint_lane))) return;

        try self.detectPathReplacement(idx);
        const size = self.readActiveSizeOrReset(idx) orelse return;
        if (size < self.offsets.items[i]) self.offsets.items[i] = 0;
        try self.maybeHandleContentRewrite(idx, size);

        const emitted = try self.emitReadableRange(out, idx, size);
        if (!emitted) {
            try self.maybeSwitchPending(idx);
            _ = try self.ensureOpenWithCheckpoint(idx, read_from, checkpoint_lane);
        }
    }

    fn ensureOpenWithCheckpoint(
        self: *Watcher,
        idx: u32,
        read_from: types.ReadFrom,
        checkpoint_lane: ?*checkpoint_mod.Lane,
    ) !bool {
        if (self.files.items[idx] == null) {
            try self.openTracked(idx, read_from);
            if (self.files.items[idx] == null) return false;
        }
        if (checkpoint_lane) |lane| self.applyCheckpointOffsetOne(idx, lane);
        return true;
    }

    fn readActiveSizeOrReset(self: *Watcher, idx: u32) ?u64 {
        const i: usize = @intCast(idx);
        const file = self.files.items[i] orelse return null;
        const st = fstatHandle(file.handle) catch {
            file.close(self.io);
            self.files.items[i] = null;
            self.identities.items[i] = null;
            self.offsets.items[i] = 0;
            self.clearPending(idx);
            return null;
        };
        return st.size;
    }

    fn emitReadableRange(self: *Watcher, out: *std.ArrayList(Event), idx: u32, size: u64) !bool {
        const i: usize = @intCast(idx);
        if (size <= self.offsets.items[i]) return false;
        try out.append(self.allocator, .{
            .file = &self.files.items[i].?,
            .start_offset = self.offsets.items[i],
            .end_offset = size,
            .identity = self.identities.items[i],
        });
        self.offsets.items[i] = size;
        return true;
    }

    fn refreshPaths(self: *Watcher, read_from: types.ReadFrom) !void {
        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
        for (self.matched.items) |*m| m.* = false;

        var refs: std.ArrayList([]const u8) = .empty;
        defer refs.deinit(self.allocator);
        try refs.ensureTotalCapacity(self.allocator, self.inputs.items.len);
        for (self.inputs.items) |p| refs.appendAssumeCapacity(p);

        var expanded = try expandPatterns(self.allocator, self.io, refs.items);
        defer expanded.deinit();

        for (expanded.items.items) |p| {
            if (!shouldTrackPath(self.output_path, p)) continue;
            if (self.findIndexByPath(p)) |idx| {
                self.markExistingPathMatched(@intCast(idx), now);
                continue;
            }
            try self.addNewTrackedPath(p, now, read_from);
        }

        self.evictExpiredUnmatched(now);
    }

    fn markExistingPathMatched(self: *Watcher, idx: u32, now: i128) void {
        const i: usize = @intCast(idx);
        if (i >= self.paths.items.len) return;
        self.matched.items[i] = true;
        self.last_match_ns.items[i] = now;
        self.markDirty(idx);
    }

    fn addNewTrackedPath(self: *Watcher, path: []const u8, now: i128, read_from: types.ReadFrom) !void {
        try self.appendTracked(path, now);
        const idx: u32 = @intCast(self.paths.items.len - 1);
        try self.openTracked(idx, read_from);
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
        self.backendRemoveTracked(@intCast(idx));

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

    fn openTracked(self: *Watcher, idx: u32, read_from: types.ReadFrom) !void {
        if (self.files.items[idx] != null) return;

        const file = std.Io.Dir.cwd().openFile(
            self.io,
            self.paths.items[idx],
            .{ .mode = .read_only },
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer file.close(self.io);

        const st = try fstatHandle(file.handle);
        const size: u64 = st.size;
        self.identities.items[idx] = .{
            .dev = @intCast(st.dev),
            .inode = @intCast(st.ino),
            .fingerprint = try computeFingerprint(self.io, file),
        };
        self.files.items[idx] = file;
        self.initHeadPrefix(idx, size) catch |err| log.warn("initHeadPrefix on open failed: {}", .{err});
        self.offsets.items[idx] = if (self.seen_once.items[idx])
            0
        else switch (read_from) {
            .head => 0,
            .tail => size,
            .checkpoint => 0,
        };
        self.seen_once.items[idx] = true;

        try self.backendTrackOpenFile(idx, self.paths.items[idx], file.handle);
    }

    fn detectPathReplacement(self: *Watcher, idx: u32) !void {
        const i: usize = @intCast(idx);
        if (self.files.items[i] == null) return;
        if (self.pending_files.items[i] != null) return;

        var path_file = std.Io.Dir.cwd().openFile(
            self.io,
            self.paths.items[i],
            .{ .mode = .read_only },
        ) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer path_file.close(self.io);

        const path_st = try fstatHandle(path_file.handle);
        const cur_st = try fstatHandle(self.files.items[i].?.handle);
        if (path_st.dev == cur_st.dev and path_st.ino == cur_st.ino) {
            path_file.close(self.io);
            return;
        }

        self.pending_identities.items[i] = .{
            .dev = @intCast(path_st.dev),
            .inode = @intCast(path_st.ino),
            .fingerprint = try computeFingerprint(self.io, path_file),
        };
        self.pending_files.items[i] = path_file;
        self.pending_detected_ns.items[i] = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
    }

    fn maybeHandleContentRewrite(self: *Watcher, idx: u32, size: u64) !void {
        const i: usize = @intCast(idx);
        const file = self.files.items[i] orelse return;
        if (size == 0) {
            self.head_prefix_lens.items[i] = 0;
            self.head_prefix_hashes.items[i] = 0;
            return;
        }

        var prefix_len: u64 = self.head_prefix_lens.items[i];
        if (prefix_len == 0) {
            prefix_len = @min(@as(u64, 64), size);
            self.head_prefix_lens.items[i] = @intCast(prefix_len);
            self.head_prefix_hashes.items[i] = try prefixHash(self.io, file, prefix_len);
            return;
        }

        if (size < prefix_len) {
            if (self.offsets.items[i] > 0) self.offsets.items[i] = 0;
            const new_len: u64 = @min(@as(u64, 64), size);
            self.head_prefix_lens.items[i] = @intCast(new_len);
            self.head_prefix_hashes.items[i] = try prefixHash(self.io, file, new_len);
            return;
        }

        const observed = try prefixHash(self.io, file, prefix_len);
        if (observed == self.head_prefix_hashes.items[i]) return;

        if (self.offsets.items[i] > 0) self.offsets.items[i] = 0;
        self.head_prefix_hashes.items[i] = observed;
    }

    fn maybeSwitchPending(self: *Watcher, idx: u32) !void {
        const i: usize = @intCast(idx);
        if (self.pending_files.items[i] == null) return;

        const cur_file = self.files.items[i] orelse {
            try self.switchToPending(idx);
            self.markDirty(idx);
            return;
        };

        const cur_st = fstatHandle(cur_file.handle) catch {
            cur_file.close(self.io);
            try self.switchToPending(idx);
            self.markDirty(idx);
            return;
        };
        const cur_size: u64 = cur_st.size;
        if (cur_size > self.offsets.items[i]) return;
        const now = std.Io.Timestamp.now(self.io, .awake).toNanoseconds();
        if (now - self.pending_detected_ns.items[i] < self.rotate_wait_ns) return;

        cur_file.close(self.io);
        try self.switchToPending(idx);
        self.markDirty(idx);
    }

    fn switchToPending(self: *Watcher, idx: u32) !void {
        const i: usize = @intCast(idx);
        const next_file = self.pending_files.items[i] orelse return;
        self.files.items[i] = next_file;
        self.identities.items[i] = self.pending_identities.items[i];
        self.pending_files.items[i] = null;
        self.pending_identities.items[i] = null;
        self.pending_detected_ns.items[i] = 0;
        self.offsets.items[i] = 0;

        const st = try fstatHandle(next_file.handle);
        try self.initHeadPrefix(idx, st.size);
    }

    fn clearPending(self: *Watcher, idx: u32) void {
        const i: usize = @intCast(idx);
        if (self.pending_files.items[i]) |f| f.close(self.io);
        self.pending_files.items[i] = null;
        self.pending_identities.items[i] = null;
        self.pending_detected_ns.items[i] = 0;
    }

    pub fn markDirty(self: *Watcher, idx: u32) void {
        if (idx >= self.paths.items.len) return;
        if (self.dirty.isSet(idx)) return;
        self.dirty.set(idx);
        self.dirty_queue.append(self.allocator, idx) catch |err| log.warn("dirty_queue append failed: {}", .{err});
    }

    pub fn parseInotifyEvents(self: *Watcher, wd_to_idx: *const std.AutoHashMap(i32, u32), buf: []const u8) void {
        var off: usize = 0;
        while (off + @sizeOf(std.os.linux.inotify_event) <= buf.len) {
            const ev_size = @sizeOf(std.os.linux.inotify_event);
            const ev = std.mem.bytesAsValue(std.os.linux.inotify_event, buf[off .. off + ev_size]);
            if (wd_to_idx.get(ev.wd)) |idx| self.markDirty(idx);
            off += @sizeOf(std.os.linux.inotify_event) + ev.len;
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
        if (idx >= self.files.items.len) return;
        if (self.files.items[idx] == null) return;
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
/// std.Io.File.Stat type does not expose the device id, so we fall back to a
/// raw libc fstat on the file handle to recover dev/ino/size atomically.
pub const FsStat = struct {
    dev: u64,
    ino: u64,
    size: u64,
};

pub fn fstatHandle(handle: std.posix.fd_t) !FsStat {
    var st: std.c.Stat = undefined;
    if (std.c.fstat(handle, &st) != 0) return error.StatFailed;
    return .{
        .dev = @intCast(st.dev),
        .ino = @intCast(st.ino),
        .size = @intCast(st.size),
    };
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

const ExpandedPaths = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]u8),

    fn init(allocator: std.mem.Allocator) ExpandedPaths {
        return .{ .allocator = allocator, .items = .empty };
    }
    fn deinit(self: *ExpandedPaths) void {
        for (self.items.items) |p| self.allocator.free(p);
        self.items.deinit(self.allocator);
        self.* = undefined;
    }
};

fn expandPatterns(allocator: std.mem.Allocator, io: std.Io, inputs: []const []const u8) !ExpandedPaths {
    var out = ExpandedPaths.init(allocator);
    errdefer out.deinit();
    for (inputs) |input| {
        if (!isGlobPattern(input)) {
            try out.items.append(allocator, try allocator.dupe(u8, input));
            continue;
        }
        try expandOnePattern(allocator, io, input, &out.items);
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
    {
        const f = try tmp.dir.createFile(io, "tail.log", .{});
        defer f.close(io);
        try f.writeStreamingAll(io, "seed\n");
    }
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
