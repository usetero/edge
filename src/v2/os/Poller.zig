//! Narrow native readiness boundary. These calls run on a dedicated reactor;
//! std.Io supplies its clock, while producers may only call wake concurrently.
const Self = @This();

const std = @import("std");
const builtin = @import("builtin");

fd: std.posix.fd_t,
wake_fd: std.posix.fd_t = -1,

const IS_MACOS = builtin.os.tag == .macos;
const linux = std.os.linux;
pub const RawEvent = if (IS_MACOS) std.c.Kevent else linux.epoll_event;
pub const Interest = struct { read: bool = false, write: bool = false };
pub const Event = struct {
    token: u64,
    readable: bool = false,
    writable: bool = false,
    read_closed: bool = false,
    write_closed: bool = false,
    failed: bool = false,
};

comptime {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) @compileError("v2 requires macOS or Linux");
    if (@bitSizeOf(usize) != 64) @compileError("v2 readiness requires a 64-bit target");
}

pub fn init() !Self {
    if (IS_MACOS) {
        const fd = std.c.kqueue();
        if (fd < 0) return error.PollerCreationFailed;
        errdefer closeFd(fd);
        try closeOnExec(fd);
        const self: Self = .{ .fd = fd };
        try self.change(&.{.{
            .ident = 0,
            .filter = std.c.EVFILT.USER,
            .flags = std.c.EV.ADD | std.c.EV.CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = 0,
        }});
        return self;
    }
    const fd = std.c.epoll_create1(linux.EPOLL.CLOEXEC);
    if (fd < 0) return error.PollerCreationFailed;
    errdefer closeFd(fd);
    const wake_fd = std.c.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    if (wake_fd < 0) return error.WakeCreationFailed;
    errdefer closeFd(wake_fd);
    var event: RawEvent = .{ .events = linux.EPOLL.IN, .data = .{ .u64 = 0 } };
    try control(fd, linux.EPOLL.CTL_ADD, wake_fd, &event);
    return .{ .fd = fd, .wake_fd = wake_fd };
}

/// All producers must have joined before closing the wake target.
pub fn deinit(self: *Self) void {
    if (self.wake_fd >= 0) closeFd(self.wake_fd);
    closeFd(self.fd);
    self.* = undefined;
}

/// The reactor must close a socket if this fails: kqueue changes can be partial.
pub fn set(self: *const Self, fd: std.posix.fd_t, token: u64, old: Interest, new: Interest) !void {
    if (IS_MACOS) {
        try self.change(&.{
            socketEvent(fd, token, std.c.EVFILT.READ, new.read),
            socketEvent(fd, token, std.c.EVFILT.WRITE, new.write),
        });
        return;
    }
    const was_active = old.read or old.write;
    const active = new.read or new.write;
    if (!active) {
        if (was_active) try control(self.fd, linux.EPOLL.CTL_DEL, fd, null);
        return;
    }
    var event: RawEvent = .{
        .events = (if (new.read) linux.EPOLL.IN | linux.EPOLL.RDHUP else @as(u32, 0)) |
            (if (new.write) linux.EPOLL.OUT else @as(u32, 0)),
        .data = .{ .u64 = token },
    };
    try control(self.fd, if (was_active) linux.EPOLL.CTL_MOD else linux.EPOLL.CTL_ADD, fd, &event);
}

/// Absolute awake-clock deadline, including time spent retrying interrupted waits.
/// Cancellation is explicit via wake and reactor shutdown state, not Io cancellation.
pub fn wait(self: *const Self, io: std.Io, out: []RawEvent, deadline: std.Io.Timestamp) !usize {
    std.debug.assert(out.len > 0);
    while (true) {
        const remaining = @max(0, deadline.nanoseconds - std.Io.Timestamp.now(io, .awake).nanoseconds);
        const result = if (IS_MACOS) blk: {
            const timeout: std.c.timespec = .{
                .sec = @intCast(@min(remaining / std.time.ns_per_s, std.math.maxInt(i32))),
                .nsec = @intCast(@mod(remaining, std.time.ns_per_s)),
            };
            break :blk std.c.kevent(self.fd, &.{}, 0, out.ptr, @intCast(out.len), &timeout);
        } else blk: {
            // Round up: a sub-millisecond remainder must not expire the deadline early.
            const ms = @min(@divFloor(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms), std.math.maxInt(i32));
            break :blk std.c.epoll_wait(self.fd, out.ptr, @intCast(out.len), @intCast(ms));
        };
        if (result >= 0) return @intCast(result);
        if (std.posix.errno(result) != .INTR) return error.PollerWaitFailed;
    }
}

/// A wake is a hint. Publish the queue entry first and always inspect the queue
/// before sleeping. Saturated eventfd already has a pending wake, so EAGAIN succeeds.
pub fn wake(self: *const Self) !void {
    if (IS_MACOS) return self.change(&.{.{
        .ident = 0,
        .filter = std.c.EVFILT.USER,
        .flags = 0,
        .fflags = std.c.NOTE.TRIGGER,
        .data = 0,
        .udata = 0,
    }});
    const one: u64 = 1;
    while (true) {
        const result = std.c.write(self.wake_fd, std.mem.asBytes(&one), @sizeOf(u64));
        if (result == @sizeOf(u64)) return;
        switch (std.posix.errno(result)) {
            .INTR => continue,
            .AGAIN => return,
            else => return error.WakeFailed,
        }
    }
}

/// Consume one coalesced counter, never loop against continuously arriving wakes.
pub fn decode(self: *const Self, raw: RawEvent) !Event {
    if (IS_MACOS) return .{
        .token = raw.udata,
        .readable = raw.filter == std.c.EVFILT.READ,
        .writable = raw.filter == std.c.EVFILT.WRITE,
        .read_closed = raw.filter == std.c.EVFILT.READ and raw.flags & std.c.EV.EOF != 0,
        .write_closed = raw.filter == std.c.EVFILT.WRITE and raw.flags & std.c.EV.EOF != 0,
        .failed = raw.flags & std.c.EV.ERROR != 0 or raw.fflags != 0 and raw.filter != std.c.EVFILT.USER,
    };
    if (raw.data.u64 == 0) {
        var counter: u64 = undefined;
        while (true) {
            const result = std.c.read(self.wake_fd, std.mem.asBytes(&counter), @sizeOf(u64));
            if (result == @sizeOf(u64)) break;
            switch (std.posix.errno(result)) {
                .INTR => continue,
                .AGAIN => break,
                else => return error.WakeReadFailed,
            }
        }
    }
    return .{
        .token = raw.data.u64,
        .readable = raw.events & linux.EPOLL.IN != 0,
        .writable = raw.events & linux.EPOLL.OUT != 0,
        .read_closed = raw.events & (linux.EPOLL.RDHUP | linux.EPOLL.HUP) != 0,
        .write_closed = raw.events & linux.EPOLL.HUP != 0,
        .failed = raw.events & linux.EPOLL.ERR != 0,
    };
}

/// Adoption requires nonblocking IO; preserve other flags already set by accept.
/// Prefer atomic accept4 flags at the accept site once the listener exists.
pub fn prepare(fd: std.posix.fd_t) !void {
    try closeOnExec(fd);
    const flags = try fcntl(fd, std.c.F.GETFL, 0);
    const nonblock: u32 = @bitCast(@as(std.c.O, .{ .NONBLOCK = true }));
    _ = try fcntl(fd, std.c.F.SETFL, flags | @as(c_int, @intCast(nonblock)));
}

/// Never retry close after EINTR: the descriptor may already have been reused.
/// Registered descriptors must not be duplicated or closed by any other owner.
pub fn closeFd(fd: std.posix.fd_t) void {
    _ = std.c.close(fd);
}

/// A listener has no write filter. In particular, do not rely on kqueue accepting
/// a disabled EVFILT_WRITE for a listening socket.
pub fn addListener(self: *const Self, fd: std.posix.fd_t, token: u64) !void {
    if (IS_MACOS) return self.change(&.{socketEvent(fd, token, std.c.EVFILT.READ, true)});
    var event: RawEvent = .{ .events = linux.EPOLL.IN, .data = .{ .u64 = token } };
    try control(self.fd, linux.EPOLL.CTL_ADD, fd, &event);
}

/// Suspend a still-readable listener during resource backoff without losing the
/// wake registration. Re-enabling level readiness reports pending connections.
pub fn enableListener(self: *const Self, fd: std.posix.fd_t, token: u64, enabled: bool) !void {
    if (IS_MACOS) return self.change(&.{socketEvent(fd, token, std.c.EVFILT.READ, enabled)});
    var event: RawEvent = .{
        .events = if (enabled) linux.EPOLL.IN else 0,
        .data = .{ .u64 = token },
    };
    try control(self.fd, linux.EPOLL.CTL_MOD, fd, &event);
}

pub const AcceptResult = union(enum) { socket: std.posix.fd_t, empty, retry, failed: anyerror };

/// Exactly one accept syscall per attempt. The parent counts interruptions and
/// aborted connections against its turn budget, avoiding unbounded retry loops.
pub fn acceptOne(listener: std.posix.fd_t) AcceptResult {
    const fd = if (IS_MACOS)
        std.c.accept(listener, null, null)
    else
        std.c.accept4(listener, null, null, std.c.SOCK.CLOEXEC | std.c.SOCK.NONBLOCK);
    if (fd < 0) return classifyAcceptError(std.posix.errno(fd));
    if (IS_MACOS) prepare(fd) catch |err| {
        closeFd(fd);
        return .{ .failed = err };
    };
    return .{ .socket = fd };
}

fn closeOnExec(fd: std.posix.fd_t) !void {
    const flags = try fcntl(fd, std.c.F.GETFD, 0);
    _ = try fcntl(fd, std.c.F.SETFD, flags | @as(c_int, std.c.FD_CLOEXEC));
}

fn fcntl(fd: std.posix.fd_t, command: c_int, arg: c_int) !c_int {
    while (true) {
        const result = std.c.fcntl(fd, command, arg);
        if (result >= 0) return result;
        if (std.posix.errno(result) != .INTR) return error.DescriptorFlagsFailed;
    }
}

fn socketEvent(fd: std.posix.fd_t, token: u64, filter: i16, enabled: bool) RawEvent {
    return .{
        .ident = @intCast(fd),
        .filter = filter,
        .flags = std.c.EV.ADD | (if (enabled) std.c.EV.ENABLE else @as(u16, std.c.EV.DISABLE)),
        .fflags = 0,
        .data = 0,
        .udata = @intCast(token),
    };
}

fn change(self: *const Self, events: []const RawEvent) !void {
    while (true) {
        var out: [0]RawEvent = .{};
        const result = std.c.kevent(self.fd, events.ptr, @intCast(events.len), &out, 0, null);
        if (result == 0) return;
        if (std.posix.errno(result) != .INTR) return error.RegistrationFailed;
    }
}

fn control(fd: std.posix.fd_t, operation: u32, socket: std.posix.fd_t, event: ?*RawEvent) !void {
    while (true) {
        const result = std.c.epoll_ctl(fd, operation, socket, event);
        if (result == 0) return;
        if (std.posix.errno(result) != .INTR) return error.RegistrationFailed;
    }
}

fn classifyAcceptError(err: std.posix.E) AcceptResult {
    if (comptime !IS_MACOS) switch (err) {
        .HOSTDOWN, .NONET, .OPNOTSUPP => return .retry,
        else => {},
    };
    return switch (err) {
        .AGAIN => .empty,
        .INTR, .CONNABORTED => .retry,
        .MFILE => .{ .failed = error.ProcessFdQuotaExceeded },
        .NFILE => .{ .failed = error.SystemFdQuotaExceeded },
        .NOBUFS, .NOMEM => .{ .failed = error.SystemResources },
        // Pending network errors can be attached to the next Linux accept.
        .NETDOWN, .PROTO, .NOPROTOOPT, .HOSTUNREACH, .NETUNREACH => .retry,
        .BADF, .INVAL, .NOTSOCK => .{ .failed = error.InvalidListener },
        else => .{ .failed = error.AcceptFailed },
    };
}

test "v2 native accept distinguishes transient work from resource backoff" {
    const testing = std.testing;
    try testing.expect(classifyAcceptError(.INTR) == .retry);
    try testing.expect(classifyAcceptError(.CONNABORTED) == .retry);
    try testing.expect(classifyAcceptError(.AGAIN) == .empty);
    try testing.expectEqual(error.ProcessFdQuotaExceeded, classifyAcceptError(.MFILE).failed);
    try testing.expectEqual(error.SystemFdQuotaExceeded, classifyAcceptError(.NFILE).failed);
    try testing.expectEqual(error.SystemResources, classifyAcceptError(.NOBUFS).failed);
    try testing.expectEqual(error.InvalidListener, classifyAcceptError(.BADF).failed);
}
