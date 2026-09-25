const std = @import("std");
const builtin = @import("builtin");

const log = std.log.scoped(.watch_kqueue);

const KQUEUE_FILTER_VNODE: i16 = -4;
const KQUEUE_EV_ADD: u16 = 0x0001;
const KQUEUE_EV_ENABLE: u16 = 0x0004;
const KQUEUE_EV_CLEAR: u16 = 0x0020;
const KQUEUE_VNODE_MASK: u32 = 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000020 | 0x00000040;

const Kevent = std.posix.Kevent;

fn closeFd(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

/// Submit `changes` and collect up to `out.len` events with an optional timeout.
fn kevent(kq: std.posix.fd_t, changes: []const Kevent, out: []Kevent, timeout: ?*const std.c.timespec) c_int {
    return std.c.kevent(
        kq,
        changes.ptr,
        @intCast(changes.len),
        out.ptr,
        @intCast(out.len),
        timeout,
    );
}

/// Register a VNODE watch for `fd` on `kq_fd`. Returns the kevent result.
fn addVnodeWatch(kq_fd: std.posix.fd_t, fd: std.posix.fd_t) c_int {
    const changes = [_]Kevent{.{
        .ident = @intCast(fd),
        .filter = KQUEUE_FILTER_VNODE,
        .flags = KQUEUE_EV_ADD | KQUEUE_EV_CLEAR | KQUEUE_EV_ENABLE,
        .fflags = KQUEUE_VNODE_MASK,
        .data = 0,
        .udata = 0,
    }};
    return kevent(kq_fd, &changes, &.{}, null);
}

pub const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    fd: std.posix.fd_t,
    fd_to_idx: std.AutoHashMap(std.posix.fd_t, u32),
    dir_watches: std.ArrayList(DirWatch),
};

const DirWatch = struct {
    path: []u8,
    fd: std.posix.fd_t,
};

pub fn init(allocator: std.mem.Allocator, io: std.Io) !State {
    if (comptime builtin.os.tag != .macos) return error.UnsupportedWatcherBackend;
    const kq = std.c.kqueue();
    if (kq < 0) return error.UnsupportedWatcherBackend;
    return .{
        .allocator = allocator,
        .io = io,
        .fd = kq,
        .fd_to_idx = std.AutoHashMap(std.posix.fd_t, u32).init(allocator),
        .dir_watches = .empty,
    };
}

pub fn deinit(s: *State) void {
    s.fd_to_idx.deinit();
    for (s.dir_watches.items) |dw| {
        closeFd(dw.fd);
        s.allocator.free(dw.path);
    }
    s.dir_watches.deinit(s.allocator);
    closeFd(s.fd);
    s.* = undefined;
}

pub fn collectDirty(self: anytype) !void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;
    try ensureDirectoryWatches(self);

    var out_events: [64]Kevent = undefined;
    var timeout: std.c.timespec = .{ .sec = 0, .nsec = 0 };
    const n = kevent(kq.fd, &.{}, out_events[0..], &timeout);
    if (n <= 0) return;
    var i: usize = 0;
    while (i < @as(usize, @intCast(n))) : (i += 1) {
        const ev = out_events[i];
        const fd: std.posix.fd_t = @intCast(ev.ident);
        if (kq.fd_to_idx.get(fd)) |idx| {
            self.markDirty(idx);
            continue;
        }
        if (directoryPathForFd(kq, fd)) |dir_path| {
            self.markDirDirty(dir_path);
        }
    }
}

pub fn trackOpenFile(self: anytype, idx: u32, path: []const u8, fd: std.posix.fd_t) !void {
    if (comptime builtin.os.tag != .macos) return;
    const kq = &self.backend_state.kqueue;
    try ensureDirectoryWatch(kq, path);
    _ = addVnodeWatch(kq.fd, fd);
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
        _ = addVnodeWatch(kq.fd, file.handle);
        kq.fd_to_idx.put(file.handle, @intCast(i)) catch |err| log.warn("rebuild fd_to_idx put failed: {}", .{err});
    }

    ensureDirectoryWatches(self) catch |err| log.warn("rebuild ensureDirectoryWatches failed: {}", .{err});
}

fn ensureDirectoryWatches(self: anytype) !void {
    const kq = &self.backend_state.kqueue;
    var i: usize = 0;
    while (i < self.paths.items.len) : (i += 1) {
        try ensureDirectoryWatch(kq, self.paths.items[i]);
    }
}

fn ensureDirectoryWatch(kq: *State, path: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse ".";
    if (hasDirectoryWatch(kq, dir_path)) return;

    const owned_dir_path = try kq.allocator.dupe(u8, dir_path);
    errdefer kq.allocator.free(owned_dir_path);

    const dir = std.Io.Dir.cwd().openDir(kq.io, owned_dir_path, .{}) catch |err| switch (err) {
        error.FileNotFound => {
            kq.allocator.free(owned_dir_path);
            return;
        },
        else => return err,
    };
    const dir_fd = dir.handle;
    errdefer closeFd(dir_fd);

    if (addVnodeWatch(kq.fd, dir_fd) < 0) {
        closeFd(dir_fd);
        kq.allocator.free(owned_dir_path);
        return;
    }
    try kq.dir_watches.append(kq.allocator, .{ .path = owned_dir_path, .fd = dir_fd });
}

fn hasDirectoryWatch(kq: *const State, dir_path: []const u8) bool {
    for (kq.dir_watches.items) |dw| {
        if (std.mem.eql(u8, dw.path, dir_path)) return true;
    }
    return false;
}

fn directoryPathForFd(kq: *const State, fd: std.posix.fd_t) ?[]const u8 {
    for (kq.dir_watches.items) |dw| {
        if (dw.fd == fd) return dw.path;
    }
    return null;
}

const testing = std.testing;

test "ensureDirectoryWatch does not leak when parent directory is missing" {
    if (comptime builtin.os.tag != .macos) return;
    var kq = try init(std.testing.allocator, std.Options.debug_io);
    defer deinit(&kq);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_abs = try tmp.dir.realPathFileAlloc(std.Options.debug_io, ".", testing.allocator);
    defer testing.allocator.free(root_abs);
    const target = try std.fmt.allocPrint(
        testing.allocator,
        "{s}/nonexistent_subdir_kqueue_leak/tail.log",
        .{root_abs},
    );
    defer testing.allocator.free(target);

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        try ensureDirectoryWatch(&kq, target);
    }
}
