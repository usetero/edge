const std = @import("std");
const builtin = @import("builtin");

const INOTIFY_MASK: u32 = 0x00000002 | 0x00000004 | 0x00000080 | 0x00000100 | 0x00000400 | 0x00000800;
const URING_UD_POLL: u64 = 0xED6E_1001;
const URING_UD_READ: u64 = 0xED6E_1002;

pub const State = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    file_wd_to_idx: std.AutoHashMap(i32, u32),
    dir_path_to_wd: std.StringHashMap(i32),
    dir_wd_to_path: std.AutoHashMap(i32, []const u8),
    ring: std.os.linux.IoUring,
    read_buf: [4096]u8,
    poll_armed: bool = false,
    read_armed: bool = false,
};

pub fn init(allocator: std.mem.Allocator) !State {
    if (builtin.os.tag != .linux) return error.UnsupportedWatcherBackend;
    const ino_flags: u32 = @bitCast(std.posix.O{ .NONBLOCK = true, .CLOEXEC = true });
    const fd = try std.posix.inotify_init1(ino_flags);
    errdefer std.posix.close(fd);
    var ring = try std.os.linux.IoUring.init(64, 0);
    errdefer ring.deinit();

    var s = State{
        .allocator = allocator,
        .fd = fd,
        .file_wd_to_idx = std.AutoHashMap(i32, u32).init(allocator),
        .dir_path_to_wd = std.StringHashMap(i32).init(allocator),
        .dir_wd_to_path = std.AutoHashMap(i32, []const u8).init(allocator),
        .ring = ring,
        .read_buf = undefined,
    };
    try armInitial(&s);
    return s;
}

pub fn deinit(s: *State) void {
    if (comptime builtin.os.tag == .linux) {
        var file_it = s.file_wd_to_idx.iterator();
        while (file_it.next()) |kv| std.posix.inotify_rm_watch(s.fd, kv.key_ptr.*);
    }
    s.file_wd_to_idx.deinit();

    if (comptime builtin.os.tag == .linux) {
        var dir_it = s.dir_wd_to_path.iterator();
        while (dir_it.next()) |kv| std.posix.inotify_rm_watch(s.fd, kv.key_ptr.*);
    }
    s.dir_wd_to_path.deinit();

    var path_it = s.dir_path_to_wd.iterator();
    while (path_it.next()) |kv| s.allocator.free(@constCast(kv.key_ptr.*));
    s.dir_path_to_wd.deinit();

    if (comptime builtin.os.tag == .linux) {
        s.ring.deinit();
        std.posix.close(s.fd);
    }
}

fn armInitial(u: anytype) !void {
    try queuePoll(u);
    if (u.ring.sq_ready() > 0) _ = try u.ring.submit();
}

pub fn collectDirty(self: anytype) !void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;

    var cqes: [16]std.os.linux.io_uring_cqe = undefined;
    while (true) {
        const count = u.ring.copy_cqes(&cqes, 0) catch break;
        if (count == 0) break;

        var i: usize = 0;
        while (i < count) : (i += 1) {
            const cqe = cqes[i];
            switch (cqe.user_data) {
                URING_UD_POLL => {
                    u.poll_armed = false;
                    if (cqe.res > 0) {
                        queueRead(u) catch {};
                    } else {
                        queuePoll(u) catch {};
                    }
                },
                URING_UD_READ => {
                    u.read_armed = false;
                    if (cqe.res > 0) {
                        const n: usize = @intCast(cqe.res);
                        parseInotifyEvents(self, u, u.read_buf[0..n]);
                        queueRead(u) catch {};
                    } else {
                        queuePoll(u) catch {};
                    }
                },
                else => {},
            }
        }
    }

    if (!u.poll_armed and !u.read_armed) {
        queuePoll(u) catch {};
    }
    if (u.ring.sq_ready() > 0) {
        _ = u.ring.submit() catch {};
    }
}

pub fn trackOpenFile(self: anytype, idx: u32, path: []const u8) !void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;
    try ensureDirectoryWatch(u, path);
    const wd = std.posix.inotify_add_watch(u.fd, path, INOTIFY_MASK) catch return;
    try u.file_wd_to_idx.put(wd, idx);
}

pub fn removeTracked(self: anytype, idx: u32) void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;
    var it = u.file_wd_to_idx.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* == idx) {
            std.posix.inotify_rm_watch(u.fd, kv.key_ptr.*);
            _ = u.file_wd_to_idx.remove(kv.key_ptr.*);
            break;
        }
    }
}

pub fn rebuildIndexes(self: anytype) void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;
    var old = u.file_wd_to_idx.iterator();
    while (old.next()) |kv| std.posix.inotify_rm_watch(u.fd, kv.key_ptr.*);
    u.file_wd_to_idx.clearRetainingCapacity();

    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        ensureDirectoryWatch(u, self.paths.items[i]) catch {};
        const file = self.files.items[i] orelse continue;
        _ = file;
        const wd = std.posix.inotify_add_watch(u.fd, self.paths.items[i], INOTIFY_MASK) catch continue;
        u.file_wd_to_idx.put(wd, @intCast(i)) catch {};
    }
}

fn queuePoll(u: anytype) !void {
    if (u.poll_armed) return;
    _ = try u.ring.poll_add(URING_UD_POLL, u.fd, std.os.linux.POLL.IN);
    u.poll_armed = true;
}

fn queueRead(u: anytype) !void {
    if (u.read_armed) return;
    _ = try u.ring.read(URING_UD_READ, u.fd, .{ .buffer = u.read_buf[0..] }, std.math.maxInt(u64));
    u.read_armed = true;
}

fn ensureDirectoryWatch(u: *State, path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    if (u.dir_path_to_wd.contains(dir_path)) return;

    const owned_dir_path = try u.allocator.dupe(u8, dir_path);
    errdefer u.allocator.free(owned_dir_path);

    const wd = std.posix.inotify_add_watch(u.fd, owned_dir_path, INOTIFY_MASK) catch return;
    errdefer std.posix.inotify_rm_watch(u.fd, wd);

    try u.dir_path_to_wd.put(owned_dir_path, wd);
    errdefer _ = u.dir_path_to_wd.remove(owned_dir_path);

    try u.dir_wd_to_path.put(wd, owned_dir_path);
}

fn parseInotifyEvents(self: anytype, u: *State, buf: []const u8) void {
    var off: usize = 0;
    while (off + @sizeOf(std.os.linux.inotify_event) <= buf.len) {
        const ev = std.mem.bytesAsValue(std.os.linux.inotify_event, buf[off .. off + @sizeOf(std.os.linux.inotify_event)]);
        if (u.file_wd_to_idx.get(ev.wd)) |idx| {
            self.markDirty(idx);
        } else if (u.dir_wd_to_path.get(ev.wd)) |dir_path| {
            markTrackedInDirDirty(self, dir_path);
        }
        off += @sizeOf(std.os.linux.inotify_event) + ev.len;
    }
}

fn markTrackedInDirDirty(self: anytype, dir_path: []const u8) void {
    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        const tracked_dir = std.fs.path.dirname(self.paths.items[i]) orelse ".";
        if (std.mem.eql(u8, tracked_dir, dir_path)) {
            self.markDirty(@intCast(i));
        }
    }
}
