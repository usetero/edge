const std = @import("std");
const builtin = @import("builtin");

const KQUEUE_FILTER_VNODE: i16 = -4;
const KQUEUE_EV_ADD: u16 = 0x0001;
const KQUEUE_EV_ENABLE: u16 = 0x0004;
const KQUEUE_EV_CLEAR: u16 = 0x0020;
const KQUEUE_VNODE_MASK: u32 = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000020 | 0x00000040;

pub const State = struct {
    fd: std.posix.fd_t,
    fd_to_idx: std.AutoHashMap(std.posix.fd_t, u32),
};

pub fn init(allocator: std.mem.Allocator) !State {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedWatcherBackend;
    const kq = try std.posix.kqueue();
    return .{
        .fd = kq,
        .fd_to_idx = std.AutoHashMap(std.posix.fd_t, u32).init(allocator),
    };
}

pub fn deinit(s: *State) void {
    s.fd_to_idx.deinit();
    std.posix.close(s.fd);
}

pub fn collectDirty(self: anytype) !void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;

    var out_events: [64]std.posix.Kevent = undefined;
    var timeout = std.posix.timespec{ .sec = 0, .nsec = 0 };
    const n = std.posix.kevent(kq.fd, &.{}, out_events[0..], &timeout) catch return;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ev = out_events[i];
        const fd: std.posix.fd_t = @intCast(ev.ident);
        if (kq.fd_to_idx.get(fd)) |idx| {
            self.markDirty(idx);
        }
    }
}

pub fn trackOpenFile(self: anytype, idx: u32, fd: std.posix.fd_t) !void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;
    var changes = [_]std.posix.Kevent{.{
        .ident = @intCast(fd),
        .filter = KQUEUE_FILTER_VNODE,
        .flags = KQUEUE_EV_ADD | KQUEUE_EV_CLEAR | KQUEUE_EV_ENABLE,
        .fflags = KQUEUE_VNODE_MASK,
        .data = 0,
        .udata = 0,
    }};
    _ = std.posix.kevent(kq.fd, changes[0..], &.{}, null) catch return;
    try kq.fd_to_idx.put(fd, idx);
}

pub fn removeTracked(self: anytype, idx: u32) void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;
    var it = kq.fd_to_idx.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* == idx) {
            _ = kq.fd_to_idx.remove(kv.key_ptr.*);
            break;
        }
    }
}

pub fn rebuildIndexes(self: anytype) void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;
    kq.fd_to_idx.clearRetainingCapacity();

    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        const file = self.files.items[i] orelse continue;
        var changes = [_]std.posix.Kevent{.{
            .ident = @intCast(file.handle),
            .filter = KQUEUE_FILTER_VNODE,
            .flags = KQUEUE_EV_ADD | KQUEUE_EV_CLEAR | KQUEUE_EV_ENABLE,
            .fflags = KQUEUE_VNODE_MASK,
            .data = 0,
            .udata = 0,
        }};
        _ = std.posix.kevent(kq.fd, changes[0..], &.{}, null) catch continue;
        kq.fd_to_idx.put(file.handle, @intCast(i)) catch {};
    }
}
