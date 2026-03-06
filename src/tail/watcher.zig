const std = @import("std");

pub const ReadFrom = enum {
    head,
    tail,
};

pub const FileEvent = struct {
    index: usize,
    start_offset: u64,
    end_offset: u64,
};

const FileIdentity = struct {
    dev: u64,
    inode: u64,
    fingerprint: u32,

    fn eql(a: FileIdentity, b: FileIdentity) bool {
        return a.dev == b.dev and a.inode == b.inode and a.fingerprint == b.fingerprint;
    }

    fn sameFile(a: FileIdentity, b: FileIdentity) bool {
        return a.dev == b.dev and a.inode == b.inode;
    }
};

const PendingRotation = struct {
    file: std.fs.File,
    identity: FileIdentity,
    detected_ns: i128,
};

const TrackedFile = struct {
    path: []u8,
    file: ?std.fs.File,
    identity: ?FileIdentity,
    pending: ?PendingRotation,
    offset: u64,
    seen_once: bool,
    matched_in_rescan: bool,
    last_match_ns: i128,
};

pub const Watcher = struct {
    allocator: std.mem.Allocator,
    files: std.ArrayList(TrackedFile),
    events: std.ArrayList(FileEvent),
    rotate_wait_ns: i128,

    pub fn init(allocator: std.mem.Allocator, paths: []const []const u8, read_from: ReadFrom, rotate_wait_ms: u64) !Watcher {
        var watcher = Watcher{
            .allocator = allocator,
            .files = .{},
            .events = .{},
            .rotate_wait_ns = @as(i128, @intCast(rotate_wait_ms)) * std.time.ns_per_ms,
        };

        for (paths) |path| {
            try watcher.addPath(path, read_from);
        }

        return watcher;
    }

    pub fn addPath(self: *Watcher, path: []const u8, read_from: ReadFrom) !void {
        const now_ns = std.time.nanoTimestamp();
        for (self.files.items) |*tracked| {
            if (std.mem.eql(u8, tracked.path, path)) {
                tracked.matched_in_rescan = true;
                tracked.last_match_ns = now_ns;
                return;
            }
        }

        const path_copy = try self.allocator.dupe(u8, path);
        var tracked = TrackedFile{
            .path = path_copy,
            .file = null,
            .identity = null,
            .pending = null,
            .offset = 0,
            .seen_once = false,
            .matched_in_rescan = true,
            .last_match_ns = now_ns,
        };
        errdefer self.allocator.free(path_copy);

        try self.openTrackedFile(&tracked, read_from);
        try self.files.append(self.allocator, tracked);
    }

    /// Reconcile tracked paths with the latest expanded input set.
    /// Paths absent from `paths` are expired after `removed_expire_ns`.
    pub fn reconcilePaths(self: *Watcher, paths: []const []const u8, read_from: ReadFrom, removed_expire_ns: i128) !void {
        const now_ns = std.time.nanoTimestamp();

        for (self.files.items) |*tracked| {
            tracked.matched_in_rescan = false;
        }

        for (paths) |path| {
            try self.addPath(path, read_from);
        }

        var i: usize = self.files.items.len;
        while (i > 0) {
            i -= 1;
            const tracked = &self.files.items[i];
            if (tracked.matched_in_rescan) continue;

            if (now_ns - tracked.last_match_ns < removed_expire_ns) continue;

            if (tracked.file) |file| file.close();
            if (tracked.pending) |pending| pending.file.close();
            self.allocator.free(tracked.path);
            _ = self.files.swapRemove(i);
        }
    }

    pub fn deinit(self: *Watcher) void {
        for (self.files.items) |*tracked| {
            if (tracked.file) |file| {
                file.close();
            }
            if (tracked.pending) |pending| {
                pending.file.close();
            }
            self.allocator.free(tracked.path);
        }
        self.files.deinit(self.allocator);
        self.events.deinit(self.allocator);
    }

    pub fn poll(self: *Watcher, read_from: ReadFrom) ![]const FileEvent {
        self.events.clearRetainingCapacity();

        for (self.files.items, 0..) |*tracked, idx| {
            var emitted_for_file = false;

            if (tracked.file == null) {
                try self.openTrackedFile(tracked, read_from);
                if (tracked.file == null) continue;
            }

            var current = tracked.file.?;
            const current_stat = std.posix.fstat(current.handle) catch {
                current.close();
                tracked.file = null;
                tracked.identity = null;
                tracked.offset = 0;
                self.clearPending(tracked);
                continue;
            };
            const current_size: u64 = @bitCast(current_stat.size);

            // copytruncate: file got truncated under the same identity.
            if (current_size < tracked.offset) {
                tracked.offset = 0;
            }

            try self.detectPathReplacement(tracked);

            if (current_size > tracked.offset) {
                try self.events.append(self.allocator, .{
                    .index = idx,
                    .start_offset = tracked.offset,
                    .end_offset = current_size,
                });
                tracked.offset = current_size;
                emitted_for_file = true;
            }

            // Do not switch file handles in the same poll cycle that emitted an
            // event, otherwise fileForEvent() could return a different backing
            // file than the event's offsets refer to.
            if (!emitted_for_file) {
                self.maybeSwitchToPending(tracked, current_size);
            }
        }

        return self.events.items;
    }

    pub fn fileForEvent(self: *Watcher, event: FileEvent) *const std.fs.File {
        return &self.files.items[event.index].file.?;
    }

    fn openTrackedFile(self: *Watcher, tracked: *TrackedFile, read_from: ReadFrom) !void {
        if (tracked.file != null) return;

        const opened = try self.openPathWithIdentity(tracked.path) orelse return;
        tracked.file = opened.file;
        tracked.identity = opened.identity;

        // First open follows user intent. Reopens after disappearance/rotation start at 0.
        tracked.offset = if (tracked.seen_once)
            0
        else switch (read_from) {
            .head => 0,
            .tail => opened.size,
        };
        tracked.seen_once = true;
    }

    fn detectPathReplacement(self: *Watcher, tracked: *TrackedFile) !void {
        const current_identity = tracked.identity orelse return;
        const opened = try self.openPathWithIdentity(tracked.path) orelse {
            // Path may not exist momentarily during rotation.
            return;
        };

        if (opened.identity.sameFile(current_identity) and !opened.identity.eql(current_identity)) {
            // Same inode but changed fingerprint: keep identity fresh, but only
            // reset when size shrank (truncate signal). Appends can change the
            // fingerprint for small files and must not force replay.
            tracked.identity = opened.identity;
            if (opened.size < tracked.offset) {
                tracked.offset = 0;
            }
            opened.file.close();
            self.clearPending(tracked);
            return;
        }

        if (opened.identity.eql(current_identity)) {
            opened.file.close();
            self.clearPending(tracked);
            return;
        }

        if (tracked.pending) |pending| {
            if (pending.identity.eql(opened.identity)) {
                // Already tracking this candidate identity.
                opened.file.close();
                return;
            }
            // Candidate changed again; replace pending handle.
            self.clearPending(tracked);
        }

        tracked.pending = .{
            .file = opened.file,
            .identity = opened.identity,
            .detected_ns = std.time.nanoTimestamp(),
        };
    }

    fn maybeSwitchToPending(self: *Watcher, tracked: *TrackedFile, current_size: u64) void {
        if (tracked.pending == null) return;
        const pending = tracked.pending.?;

        const elapsed_ns = std.time.nanoTimestamp() - pending.detected_ns;
        const drained = tracked.offset >= current_size;
        if (!drained or elapsed_ns < self.rotate_wait_ns) return;

        if (tracked.file) |file| {
            file.close();
        }

        tracked.file = pending.file;
        tracked.identity = pending.identity;
        tracked.pending = null;
        tracked.offset = 0;
    }

    fn clearPending(self: *Watcher, tracked: *TrackedFile) void {
        _ = self;
        if (tracked.pending) |pending| {
            pending.file.close();
            tracked.pending = null;
        }
    }

    const OpenedPath = struct {
        file: std.fs.File,
        identity: FileIdentity,
        size: u64,
    };

    fn openPathWithIdentity(self: *Watcher, path: []const u8) !?OpenedPath {
        _ = self;

        const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        errdefer file.close();

        const stat = try std.posix.fstat(file.handle);
        const size: u64 = @bitCast(stat.size);
        const identity = FileIdentity{
            .dev = @intCast(stat.dev),
            .inode = @intCast(stat.ino),
            .fingerprint = try computeFingerprint(file),
        };

        return .{
            .file = file,
            .identity = identity,
            .size = size,
        };
    }

    fn computeFingerprint(file: std.fs.File) !u32 {
        var buf: [1024]u8 = undefined;
        const n = try std.posix.pread(file.handle, &buf, 0);
        return std.hash.Crc32.hash(buf[0..n]);
    }
};

const testing = std.testing;

fn appendToFile(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.openFile(name, .{ .mode = .read_write });
    defer file.close();
    const end = try file.getEndPos();
    try file.seekTo(end);
    try file.writeAll(bytes);
}

fn truncateAndWrite(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    const file = try dir.createFile(name, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
}

fn eventBytes(allocator: std.mem.Allocator, watcher: *Watcher, event: FileEvent) ![]u8 {
    const len = event.end_offset - event.start_offset;
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    const file = watcher.fileForEvent(event);
    const n = try std.posix.pread(file.handle, buf, @intCast(event.start_offset));
    try testing.expectEqual(len, n);
    return buf;
}

test "Watcher public API: poll and fileForEvent read appended bytes" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try truncateAndWrite(tmp_dir.dir, "tail.log", "seed\n");
    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "tail.log");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, &.{path}, .tail, 0);
    defer watcher.deinit();

    // Tail mode should start at EOF and not emit existing bytes.
    try testing.expectEqual(@as(usize, 0), (try watcher.poll(.tail)).len);

    try appendToFile(tmp_dir.dir, "tail.log", "next\n");
    const events = try watcher.poll(.tail);
    try testing.expectEqual(@as(usize, 1), events.len);

    const bytes = try eventBytes(testing.allocator, &watcher, events[0]);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("next\n", bytes);
}

test "Watcher public API: rename+create rotation drains old then switches to new" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try truncateAndWrite(tmp_dir.dir, "tail.log", "before\n");
    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "tail.log");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, &.{path}, .head, 0);
    defer watcher.deinit();

    // Consume initial content from head mode.
    _ = try watcher.poll(.head);

    try tmp_dir.dir.rename("tail.log", "tail.log.1");
    try truncateAndWrite(tmp_dir.dir, "tail.log", "new-1\n");
    try appendToFile(tmp_dir.dir, "tail.log.1", "old-drain\n");

    const old_events = try watcher.poll(.head);
    try testing.expectEqual(@as(usize, 1), old_events.len);
    const old_bytes = try eventBytes(testing.allocator, &watcher, old_events[0]);
    defer testing.allocator.free(old_bytes);
    try testing.expectEqualStrings("old-drain\n", old_bytes);

    // First follow-up poll performs the switch to pending replacement.
    _ = try watcher.poll(.head);
    // Next poll observes bytes from the new file.
    const new_events = try watcher.poll(.head);
    try testing.expectEqual(@as(usize, 1), new_events.len);
    const new_bytes = try eventBytes(testing.allocator, &watcher, new_events[0]);
    defer testing.allocator.free(new_bytes);
    try testing.expectEqualStrings("new-1\n", new_bytes);
}

test "Watcher public API: copytruncate style reset resumes from zero" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try truncateAndWrite(tmp_dir.dir, "tail.log", "");
    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "tail.log");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, &.{path}, .head, 0);
    defer watcher.deinit();

    _ = try watcher.poll(.head); // initial empty poll

    try appendToFile(tmp_dir.dir, "tail.log", "first\n");
    const first_events = try watcher.poll(.head);
    try testing.expectEqual(@as(usize, 1), first_events.len);
    const first_bytes = try eventBytes(testing.allocator, &watcher, first_events[0]);
    defer testing.allocator.free(first_bytes);
    try testing.expectEqualStrings("first\n", first_bytes);

    // Simulate copytruncate in two phases so poll can observe truncation.
    try truncateAndWrite(tmp_dir.dir, "tail.log", "");
    _ = try watcher.poll(.head); // observes size<offset and resets to 0
    try appendToFile(tmp_dir.dir, "tail.log", "second\n");
    const second_events = try watcher.poll(.head);
    try testing.expectEqual(@as(usize, 1), second_events.len);
    const second_bytes = try eventBytes(testing.allocator, &watcher, second_events[0]);
    defer testing.allocator.free(second_bytes);
    try testing.expectEqualStrings("second\n", second_bytes);
}

test "Watcher public API: addPath is idempotent for duplicate discoveries" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try truncateAndWrite(tmp_dir.dir, "tail.log", "");
    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "tail.log");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, &.{}, .head, 0);
    defer watcher.deinit();

    try watcher.addPath(path, .head);
    try watcher.addPath(path, .head);
    try watcher.addPath(path, .head);

    _ = try watcher.poll(.head);
    try appendToFile(tmp_dir.dir, "tail.log", "once\n");

    const events = try watcher.poll(.head);
    try testing.expectEqual(@as(usize, 1), events.len);
    const bytes = try eventBytes(testing.allocator, &watcher, events[0]);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("once\n", bytes);

    try testing.expectEqual(@as(usize, 0), (try watcher.poll(.head)).len);
}

test "Watcher public API: reconcilePaths expires removed paths after grace" {
    var tmp_dir = testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try truncateAndWrite(tmp_dir.dir, "gone.log", "");
    const path = try tmp_dir.dir.realpathAlloc(testing.allocator, "gone.log");
    defer testing.allocator.free(path);

    var watcher = try Watcher.init(testing.allocator, &.{path}, .head, 0);
    defer watcher.deinit();

    try testing.expectEqual(@as(usize, 1), watcher.files.items.len);
    try watcher.reconcilePaths(&.{}, .head, 0);
    try testing.expectEqual(@as(usize, 0), watcher.files.items.len);
}
