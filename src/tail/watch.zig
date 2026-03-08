const std = @import("std");
const types = @import("types.zig");
const checkpoint_mod = @import("checkpoint.zig");
const poll_backend = @import("watch_backend/poll.zig");
const uring_backend = @import("watch_backend/uring_linux.zig");
const kqueue_backend = @import("watch_backend/kqueue_macos.zig");

pub const BackendKind = enum {
    poll,
    uring,
    kqueue,
};

pub const Event = struct {
    file: *const std.fs.File,
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
    backend: BackendKind,
    inputs: std.ArrayList([]u8),
    output_path: []u8,

    paths: std.ArrayList([]u8),
    files: std.ArrayList(?std.fs.File),
    pending_files: std.ArrayList(?std.fs.File),
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
        kind: BackendKind,
        inputs: []const []const u8,
        output_path: []const u8,
        read_from: types.ReadFrom,
        glob_interval_ms: u64,
        rotate_wait_ms: u64,
        removed_expire_ms: u64,
    ) !Watcher {
        var input_copy: std.ArrayList([]u8) = .{};
        errdefer {
            for (input_copy.items) |p| allocator.free(p);
            input_copy.deinit(allocator);
        }
        for (inputs) |p| try input_copy.append(allocator, try allocator.dupe(u8, p));
        const out_copy = try allocator.dupe(u8, output_path);
        errdefer allocator.free(out_copy);

        var self = Watcher{
            .allocator = allocator,
            .backend = kind,
            .inputs = input_copy,
            .output_path = out_copy,
            .paths = .{},
            .files = .{},
            .pending_files = .{},
            .identities = .{},
            .pending_identities = .{},
            .offsets = .{},
            .head_prefix_hashes = .{},
            .head_prefix_lens = .{},
            .seen_once = .{},
            .pending_detected_ns = .{},
            .matched = .{},
            .last_match_ns = .{},
            .dirty = .{},
            .dirty_queue = .{},
            .glob_interval_ns = @as(i128, @intCast(glob_interval_ms)) * std.time.ns_per_ms,
            .rotate_wait_ns = @as(i128, @intCast(rotate_wait_ms)) * std.time.ns_per_ms,
            .removed_expire_ns = @as(i128, @intCast(removed_expire_ms)) * std.time.ns_per_ms,
            .next_glob_refresh_ns = std.time.nanoTimestamp(),
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
            if (self.files.items[i]) |f| f.close();
            if (self.pending_files.items[i]) |f| f.close();
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
    }

    fn initBackend(self: *Watcher) !void {
        self.backend_state = switch (self.backend) {
            .poll => .{ .poll = {} },
            .uring => .{ .uring = try uring_backend.init(self.allocator) },
            .kqueue => .{ .kqueue = try kqueue_backend.init(self.allocator) },
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

        const now = std.time.nanoTimestamp();
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
        const st = std.posix.fstat(file.handle) catch {
            file.close();
            self.files.items[i] = null;
            self.identities.items[i] = null;
            self.offsets.items[i] = 0;
            self.clearPending(idx);
            return null;
        };
        return @bitCast(st.size);
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
        const now = std.time.nanoTimestamp();
        for (self.matched.items) |*m| m.* = false;

        var refs: std.ArrayList([]const u8) = .{};
        defer refs.deinit(self.allocator);
        try refs.ensureTotalCapacity(self.allocator, self.inputs.items.len);
        for (self.inputs.items) |p| refs.appendAssumeCapacity(p);

        var expanded = try expandPatterns(self.allocator, refs.items);
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
        if (self.files.items[idx]) |f| f.close();
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

        const file = std.fs.cwd().openFile(self.paths.items[idx], .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer file.close();

        const st = try std.posix.fstat(file.handle);
        const size: u64 = @bitCast(st.size);
        self.identities.items[idx] = .{
            .dev = @intCast(st.dev),
            .inode = @intCast(st.ino),
            .fingerprint = try computeFingerprint(file),
        };
        self.files.items[idx] = file;
        self.initHeadPrefix(idx, size) catch {};
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

        var path_file = std.fs.cwd().openFile(self.paths.items[i], .{ .mode = .read_only }) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        errdefer path_file.close();

        const path_st = try std.posix.fstat(path_file.handle);
        const cur_st = try std.posix.fstat(self.files.items[i].?.handle);
        if (@as(u64, @intCast(path_st.dev)) == @as(u64, @intCast(cur_st.dev)) and @as(u64, @intCast(path_st.ino)) == @as(u64, @intCast(cur_st.ino))) {
            path_file.close();
            return;
        }

        self.pending_identities.items[i] = .{
            .dev = @intCast(path_st.dev),
            .inode = @intCast(path_st.ino),
            .fingerprint = try computeFingerprint(path_file),
        };
        self.pending_files.items[i] = path_file;
        self.pending_detected_ns.items[i] = std.time.nanoTimestamp();
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
            self.head_prefix_hashes.items[i] = try prefixHash(file, prefix_len);
            return;
        }

        if (size < prefix_len) {
            if (self.offsets.items[i] > 0) self.offsets.items[i] = 0;
            const new_len: u64 = @min(@as(u64, 64), size);
            self.head_prefix_lens.items[i] = @intCast(new_len);
            self.head_prefix_hashes.items[i] = try prefixHash(file, new_len);
            return;
        }

        const observed = try prefixHash(file, prefix_len);
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

        const cur_st = std.posix.fstat(cur_file.handle) catch {
            cur_file.close();
            try self.switchToPending(idx);
            self.markDirty(idx);
            return;
        };
        const cur_size: u64 = @bitCast(cur_st.size);
        if (cur_size > self.offsets.items[i]) return;
        const now = std.time.nanoTimestamp();
        if (now - self.pending_detected_ns.items[i] < self.rotate_wait_ns) return;

        cur_file.close();
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

        const st = try std.posix.fstat(next_file.handle);
        try self.initHeadPrefix(idx, @bitCast(st.size));
    }

    fn clearPending(self: *Watcher, idx: u32) void {
        const i: usize = @intCast(idx);
        if (self.pending_files.items[i]) |f| f.close();
        self.pending_files.items[i] = null;
        self.pending_identities.items[i] = null;
        self.pending_detected_ns.items[i] = 0;
    }

    pub fn markDirty(self: *Watcher, idx: u32) void {
        if (idx >= self.paths.items.len) return;
        if (self.dirty.isSet(idx)) return;
        self.dirty.set(idx);
        self.dirty_queue.append(self.allocator, idx) catch {};
    }

    pub fn parseInotifyEvents(self: *Watcher, wd_to_idx: *const std.AutoHashMap(i32, u32), buf: []const u8) void {
        var off: usize = 0;
        while (off + @sizeOf(std.os.linux.inotify_event) <= buf.len) {
            const ev = std.mem.bytesAsValue(std.os.linux.inotify_event, buf[off .. off + @sizeOf(std.os.linux.inotify_event)]);
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
        self.head_prefix_hashes.items[idx] = try prefixHash(self.files.items[idx].?, len);
    }
};

fn shouldTrackPath(output_path: []const u8, candidate_path: []const u8) bool {
    if (std.mem.eql(u8, output_path, "-")) return true;
    return !std.mem.eql(u8, output_path, candidate_path);
}

fn computeFingerprint(file: std.fs.File) !u32 {
    var buf: [1024]u8 = undefined;
    const n = try std.posix.pread(file.handle, &buf, 0);
    return std.hash.Crc32.hash(buf[0..n]);
}

fn prefixHash(file: std.fs.File, len: u64) !u64 {
    if (len == 0) return 0;
    var buf: [64]u8 = undefined;
    const want: usize = @intCast(@min(len, buf.len));
    const n = try std.posix.pread(file.handle, buf[0..want], 0);
    var hasher = std.hash.Fnv1a_64.init();
    hasher.update(buf[0..n]);
    return hasher.final();
}

const ExpandedPaths = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList([]u8),

    fn init(allocator: std.mem.Allocator) ExpandedPaths {
        return .{ .allocator = allocator, .items = .{} };
    }
    fn deinit(self: *ExpandedPaths) void {
        for (self.items.items) |p| self.allocator.free(p);
        self.items.deinit(self.allocator);
    }
};

fn expandPatterns(allocator: std.mem.Allocator, inputs: []const []const u8) !ExpandedPaths {
    var out = ExpandedPaths.init(allocator);
    errdefer out.deinit();
    for (inputs) |input| {
        if (!isGlobPattern(input)) {
            try out.items.append(allocator, try allocator.dupe(u8, input));
            continue;
        }
        try expandOnePattern(allocator, input, &out.items);
    }
    return out;
}

fn isGlobPattern(input: []const u8) bool {
    return std.mem.indexOfAny(u8, input, "*?[") != null;
}

fn expandOnePattern(allocator: std.mem.Allocator, pattern: []const u8, out: *std.ArrayList([]u8)) !void {
    const dir_path = std.fs.path.dirname(pattern) orelse ".";
    const base_pat = std.fs.path.basename(pattern);
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next()) |entry| {
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

    {
        const f = try tmp.dir.createFile("tail.log", .{});
        defer f.close();
        try f.writeAll("seed\n");
    }
    const abs = try tmp.dir.realpathAlloc(testing.allocator, "tail.log");
    defer testing.allocator.free(abs);

    var w = try Watcher.init(testing.allocator, .poll, &.{abs}, "-", .tail, 1000, 50, 1000);
    defer w.deinit();

    var events: std.ArrayList(Event) = .{};
    defer events.deinit(testing.allocator);
    try w.collect(&events, .tail, null);
    try testing.expectEqual(@as(usize, 0), events.items.len);

    {
        const f = try tmp.dir.openFile("tail.log", .{ .mode = .read_write });
        defer f.close();
        try f.seekFromEnd(0);
        try f.writeAll("next\n");
    }

    try w.collect(&events, .tail, null);
    try testing.expectEqual(@as(usize, 1), events.items.len);
}
