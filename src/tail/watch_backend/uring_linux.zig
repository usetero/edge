const std = @import("std");
const builtin = @import("builtin");

const INOTIFY_MASK: u32 = 0x00000002 | 0x00000004 | 0x00000080 | 0x00000100 | 0x00000400 | 0x00000800;
const URING_UD_POLL: u64 = 0xED6E_1001;
const URING_UD_READ: u64 = 0xED6E_1002;

pub const State = struct {
    fd: std.posix.fd_t,
    wd_to_idx: std.AutoHashMap(i32, u32),
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
        .fd = fd,
        .wd_to_idx = std.AutoHashMap(i32, u32).init(allocator),
        .ring = ring,
        .read_buf = undefined,
    };
    try armInitial(&s);
    return s;
}

pub fn deinit(s: *State) void {
    s.wd_to_idx.deinit();
    s.ring.deinit();
    std.posix.close(s.fd);
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
                        self.parseInotifyEvents(&u.wd_to_idx, u.read_buf[0..n]);
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
    const wd = std.posix.inotify_add_watch(u.fd, path, INOTIFY_MASK) catch return;
    try u.wd_to_idx.put(wd, idx);
}

pub fn removeTracked(self: anytype, idx: u32) void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;
    var it = u.wd_to_idx.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* == idx) {
            std.posix.inotify_rm_watch(u.fd, kv.key_ptr.*);
            _ = u.wd_to_idx.remove(kv.key_ptr.*);
            break;
        }
    }
}

pub fn rebuildIndexes(self: anytype) void {
    if (builtin.os.tag != .linux) return;
    const u = &self.backend_state.uring;
    var old = u.wd_to_idx.iterator();
    while (old.next()) |kv| std.posix.inotify_rm_watch(u.fd, kv.key_ptr.*);
    u.wd_to_idx.clearRetainingCapacity();

    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        const file = self.files.items[i] orelse continue;
        _ = file;
        const wd = std.posix.inotify_add_watch(u.fd, self.paths.items[i], INOTIFY_MASK) catch continue;
        u.wd_to_idx.put(wd, @intCast(i)) catch {};
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
