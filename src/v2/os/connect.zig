//! Bounded native connect until std.Io.Threaded implements connect timeouts.
const std = @import("std");
const Poller = @import("Poller.zig");

/// Sole ownership transfers on success. Polling also bounds shutdown during connect.
pub fn connect(
    io: std.Io,
    address: std.Io.net.IpAddress,
    deadline: std.Io.Timestamp,
    stopped: *const std.atomic.Value(bool),
) !std.Io.net.Stream {
    if (stopped.load(.acquire)) return error.ShuttingDown;
    if (std.Io.Timestamp.now(io, .awake).nanoseconds >= deadline.nanoseconds) return error.Timeout;
    const family: u32 = if (address == .ip4) std.posix.AF.INET else std.posix.AF.INET6;
    const fd = std.c.socket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (fd < 0) return error.SocketFailed;
    errdefer Poller.closeFd(fd);
    try Poller.prepare(fd);
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const length = std.Io.Threaded.addressToPosix(&address, &storage);
    const result = std.c.connect(fd, &storage.any, length);
    if (result != 0) switch (std.posix.errno(result)) {
        .INPROGRESS, .INTR => try wait(io, fd, deadline, stopped),
        else => return error.ConnectFailed,
    };
    if (stopped.load(.acquire)) return error.ShuttingDown;
    const flags = std.c.fcntl(fd, std.c.F.GETFL);
    if (flags < 0) return error.SocketFlagsFailed;
    const nonblock: u32 = @bitCast(@as(std.c.O, .{ .NONBLOCK = true }));
    if (std.c.fcntl(fd, std.c.F.SETFL, flags & ~@as(c_int, @intCast(nonblock))) < 0) {
        return error.SocketFlagsFailed;
    }
    var local_len: std.posix.socklen_t = @sizeOf(@TypeOf(storage));
    if (std.c.getsockname(fd, &storage.any, &local_len) != 0) return error.SocketAddressFailed;
    return .{ .socket = .{ .handle = fd, .address = std.Io.Threaded.addressFromPosix(&storage) } };
}

test "v2 connect refuses canceled and expired work before opening a socket" {
    var stopped: std.atomic.Value(bool) = .init(true);
    const address = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:1");
    const deadline: std.Io.Timestamp = .{ .nanoseconds = 0 };
    try std.testing.expectError(error.ShuttingDown, connect(std.testing.io, address, deadline, &stopped));
    stopped.store(false, .release);
    try std.testing.expectError(error.Timeout, connect(std.testing.io, address, deadline, &stopped));
}

fn wait(io: std.Io, fd: std.posix.fd_t, deadline: std.Io.Timestamp, stopped: *const std.atomic.Value(bool)) !void {
    while (!stopped.load(.acquire)) {
        const remaining = deadline.nanoseconds - std.Io.Timestamp.now(io, .awake).nanoseconds;
        if (remaining <= 0) return error.Timeout;
        var descriptor = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
        const ms: i32 = @intCast(@min(10, @divTrunc(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
        const count = std.c.poll(&descriptor, 1, ms);
        if (count < 0) {
            if (std.posix.errno(count) == .INTR) continue;
            return error.ConnectFailed;
        }
        if (count == 0) continue;
        var socket_error: c_int = 0;
        var length: std.posix.socklen_t = @sizeOf(c_int);
        if (std.c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, &socket_error, &length) != 0 or
            socket_error != 0) return error.ConnectFailed;
        return;
    }
    return error.ShuttingDown;
}
