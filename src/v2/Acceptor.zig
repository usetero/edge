//! Dedicated acceptor with bounded turns, round-robin handoff and resource backoff.
const Self = @This();

const std = @import("std");
const AcceptChannel = @import("AcceptChannel.zig");
const Readiness = @import("Readiness.zig");
const Native = @import("os/Poller.zig");

server: std.Io.net.Server,
native: Native,
options: Options,
next_target: usize = 0,
retry_at: ?std.Io.Timestamp = null,
stopped: bool = false,

// Bounds per-connection target scanning even if deployment config is invalid.
pub const MAX_TARGETS = 64;
const LISTENER_TOKEN = 1;
pub const Options = struct { backlog: u31 = 128, resource_backoff_ms: u16 = 50 };
pub const Target = struct { channel: *AcceptChannel, wake: *const Readiness };
pub const Stop = enum { drained, budget, backoff, stopped };
pub const Report = struct {
    attempts: u32 = 0,
    accepted: u32 = 0,
    rejected: u32 = 0,
    retries: u32 = 0,
    wake_failures: u32 = 0,
    failure: ?anyerror = null,
    control_error: ?anyerror = null,
    stop: Stop = .budget,
};

/// No application heap state: the composition root owns this value and target
/// array. The configured std.Io backend creates/listens/closes the server socket.
pub fn init(io: std.Io, address: std.Io.net.IpAddress, options: Options) !Self {
    if (options.backlog == 0 or options.resource_backoff_ms == 0) return error.InvalidOptions;
    var server = try address.listen(io, .{ .kernel_backlog = options.backlog });
    errdefer server.deinit(io);
    try Native.prepare(server.socket.handle);
    var native: Native = try .init();
    errdefer native.deinit();
    try native.addListener(server.socket.handle, LISTENER_TOKEN);
    return .{ .server = server, .native = native, .options = options };
}

/// Stop/join the acceptor and all external wake callers first. Target queues own
/// previously published descriptors independently and must still drain/close them.
pub fn deinit(self: *Self, io: std.Io) void {
    self.stop(io);
    self.native.deinit();
    self.* = undefined;
}

/// Acceptor-thread only. At most budget accept syscalls and MAX_TARGETS probes
/// per accepted fd. Overload closes a socket only if no queue takes ownership.
pub fn turn(self: *Self, io: std.Io, targets: []const Target, budget: u16) !Report {
    return self.runTurn(io, targets, budget, Native.acceptOne);
}

/// Wake is the only operation another thread may call. Shutdown state belongs
/// to the composition root; it wakes the acceptor, which calls stop on its thread.
pub fn wake(self: *const Self) !void {
    try self.native.wake();
}

/// Finite caller deadline also protects against failed wake publication. Resource
/// backoff disables listener readiness, and this wait ends by the retry deadline.
pub fn wait(self: *const Self, io: std.Io, deadline: std.Io.Timestamp) !void {
    if (self.stopped) return error.Stopped;
    var effective = deadline;
    if (self.retry_at) |retry_at| {
        if (retry_at.nanoseconds < effective.nanoseconds) effective = retry_at;
    }
    var events: [2]Native.RawEvent = undefined;
    const count = try self.native.wait(io, &events, effective);
    for (events[0..count]) |event| _ = try self.native.decode(event);
}

/// Acceptor-thread only; queued fds are unaffected. Stopping is idempotent.
pub fn stop(self: *Self, io: std.Io) void {
    if (self.stopped) return;
    self.stopped = true;
    self.retry_at = null;
    self.server.deinit(io);
}

fn runTurn(self: *Self, io: std.Io, targets: []const Target, budget: u16, comptime accept: anytype) !Report {
    if (targets.len == 0 or targets.len > MAX_TARGETS or budget == 0) return error.InvalidTurnLimits;
    var report: Report = .{};
    if (self.stopped) return .{ .stop = .stopped };
    if (self.retry_at) |retry_at| {
        if (std.Io.Timestamp.now(io, .awake).nanoseconds < retry_at.nanoseconds) return .{ .stop = .backoff };
        self.native.enableListener(self.server.socket.handle, LISTENER_TOKEN, true) catch |err| {
            self.stop(io);
            return .{ .stop = .stopped, .control_error = err };
        };
        self.retry_at = null;
    }
    for (0..budget) |_| {
        report.attempts += 1;
        switch (accept(self.server.socket.handle)) {
            .empty => {
                report.stop = .drained;
                return report;
            },
            .retry => report.retries += 1,
            .failed => |err| {
                report.failure = err;
                self.pause(io, &report);
                return report;
            },
            .socket => |fd| self.handoff(io, targets, fd, &report),
        }
    }
    return report;
}

fn handoff(self: *Self, io: std.Io, targets: []const Target, fd: std.posix.fd_t, report: *Report) void {
    const start = self.next_target % targets.len;
    for (0..targets.len) |offset| {
        const index = (start + offset) % targets.len;
        const target = targets[index];
        if (target.channel.offer(io, fd) != .accepted) continue;
        self.next_target = (index + 1) % targets.len;
        report.accepted += 1;
        target.wake.wake() catch {
            // The queue already owns fd. Never close/re-offer it on wake error.
            report.wake_failures += 1;
        };
        return;
    }
    self.next_target = (start + 1) % targets.len;
    Native.closeFd(fd);
    report.rejected += 1;
}

fn pause(self: *Self, io: std.Io, report: *Report) void {
    self.native.enableListener(self.server.socket.handle, LISTENER_TOKEN, false) catch |err| {
        report.control_error = err;
        report.stop = .stopped;
        self.stop(io);
        return;
    };
    self.retry_at = std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(self.options.resource_backoff_ms));
    report.stop = .backoff;
}

const testing = std.testing;

test "v2 acceptor bounds a real TCP backlog and distributes descriptors round robin" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const a = try fixture.connect();
    defer a.close(testing.io);
    const b = try fixture.connect();
    defer b.close(testing.io);
    const c = try fixture.connect();
    defer c.close(testing.io);
    const targets = fixture.targets();
    const first = try fixture.acceptor.turn(testing.io, &targets, 2);
    try testing.expectEqual(@as(u32, 2), first.accepted);
    try testing.expectEqual(Stop.budget, first.stop);
    const second = try fixture.acceptor.turn(testing.io, &targets, 2);
    try testing.expectEqual(@as(u32, 1), second.accepted);
    try testing.expectEqual(Stop.drained, second.stop);
    const fd_a = fixture.channels[0].receive(testing.io).?;
    defer Native.closeFd(fd_a);
    const fd_b = fixture.channels[1].receive(testing.io).?;
    defer Native.closeFd(fd_b);
    const fd_c = fixture.channels[0].receive(testing.io).?;
    defer Native.closeFd(fd_c);
    try testing.expect(fixture.channels[1].receive(testing.io) == null);
    try expectFlags(fd_a);
    try expectFlags(fd_b);
    try expectFlags(fd_c);
    for (&fixture.wakes) |*poller| {
        const events = try poller.wait(testing.io, deadlineIn(1000));
        try testing.expectEqual(@as(usize, 1), events.len);
        try testing.expectEqual(@as(u64, 0), events[0].token);
    }
}

const Fixture = struct {
    acceptor: Self,
    channels: [2]AcceptChannel,
    wakes: [2]Readiness,

    fn init() !Fixture {
        var acceptor: Self = try .init(testing.io, try std.Io.net.IpAddress.parse("127.0.0.1", 0), .{});
        errdefer acceptor.deinit(testing.io);
        var channels: [2]AcceptChannel = undefined;
        var wakes: [2]Readiness = undefined;
        var count: usize = 0;
        errdefer for (0..count) |i| {
            wakes[i].deinit(testing.allocator);
            channels[i].deinit(testing.allocator, testing.io);
        };
        for (0..2) |i| {
            channels[i] = try .init(testing.allocator, .{ .capacity = 2 });
            errdefer channels[i].deinit(testing.allocator, testing.io);
            wakes[i] = try .init(testing.allocator, .{ .sockets = 1, .events = 2 });
            count += 1;
        }
        return .{ .acceptor = acceptor, .channels = channels, .wakes = wakes };
    }

    fn deinit(self: *Fixture) void {
        self.acceptor.deinit(testing.io);
        for (&self.channels, &self.wakes) |*channel, *poller| {
            channel.deinit(testing.allocator, testing.io);
            poller.deinit(testing.allocator);
        }
        self.* = undefined;
    }

    fn connect(self: *Fixture) !std.Io.net.Stream {
        return self.acceptor.server.socket.address.connect(testing.io, .{ .mode = .stream });
    }

    fn targets(self: *Fixture) [2]Target {
        return .{
            .{ .channel = &self.channels[0], .wake = &self.wakes[0] },
            .{ .channel = &self.channels[1], .wake = &self.wakes[1] },
        };
    }
};

fn deadlineIn(ms: u16) std.Io.Timestamp {
    return std.Io.Timestamp.now(testing.io, .awake).addDuration(.fromMilliseconds(ms));
}

fn expectFlags(fd: std.posix.fd_t) !void {
    try testing.expect(std.c.fcntl(fd, std.c.F.GETFD) & std.c.FD_CLOEXEC != 0);
    const nonblock: u32 = @bitCast(@as(std.c.O, .{ .NONBLOCK = true }));
    try testing.expect(@as(u32, @intCast(std.c.fcntl(fd, std.c.F.GETFL))) & nonblock != 0);
}

test "v2 acceptor skips closed targets and sheds overload at its turn budget" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.channels[0].close(testing.io);
    const a = try fixture.connect();
    defer a.close(testing.io);
    const b = try fixture.connect();
    defer b.close(testing.io);
    const c = try fixture.connect();
    defer c.close(testing.io);
    const targets = fixture.targets();
    const report = try fixture.acceptor.turn(testing.io, &targets, 3);
    try testing.expectEqual(@as(u32, 2), report.accepted);
    try testing.expectEqual(@as(u32, 1), report.rejected);
    try testing.expectEqual(@as(u32, 3), report.attempts);
    try testing.expectEqual(Stop.budget, report.stop);
    try testing.expect(fixture.channels[0].receive(testing.io) == null);
    // A rejected TCP connection has no acknowledged request and is closed.
    var bytes: [1]u8 = undefined;
    try testing.expectEqual(@as(isize, 0), std.c.read(c.socket.handle, &bytes, bytes.len));
}

test "v2 acceptor wake failure cannot revoke a queued descriptor" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const a = try fixture.connect();
    defer a.close(testing.io);
    const targets = fixture.targets();
    const native_fd = fixture.wakes[0].native.fd;
    const wake_fd = fixture.wakes[0].native.wake_fd;
    defer fixture.wakes[0].native.fd = native_fd;
    defer fixture.wakes[0].native.wake_fd = wake_fd;
    fixture.wakes[0].native.fd = -1;
    fixture.wakes[0].native.wake_fd = -1;
    const report = try fixture.acceptor.turn(testing.io, &targets, 1);
    try testing.expectEqual(@as(u32, 1), report.accepted);
    try testing.expectEqual(@as(u32, 1), report.wake_failures);
    const fd = fixture.channels[0].receive(testing.io).?;
    defer Native.closeFd(fd);
    try expectFlags(fd);
    try testing.expect(fixture.channels[1].receive(testing.io) == null);
}

fn interruptedAccept(_: std.posix.fd_t) Native.AcceptResult {
    return .retry;
}

fn exhaustedAccept(_: std.posix.fd_t) Native.AcceptResult {
    return .{ .failed = error.ProcessFdQuotaExceeded };
}

test "v2 acceptor counts transient failures toward the accept budget" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const targets = fixture.targets();
    const report = try fixture.acceptor.runTurn(testing.io, &targets, 7, interruptedAccept);
    try testing.expectEqual(@as(u32, 7), report.attempts);
    try testing.expectEqual(@as(u32, 7), report.retries);
    try testing.expectEqual(Stop.budget, report.stop);
    try testing.expectError(error.InvalidTurnLimits, fixture.acceptor.turn(testing.io, &targets, 0));
    try testing.expectError(error.InvalidTurnLimits, fixture.acceptor.turn(testing.io, &.{}, 1));
}

test "v2 acceptor resource backoff suspends a readable listener and then resumes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.acceptor.options.resource_backoff_ms = 60000;
    const pending = try fixture.connect();
    defer pending.close(testing.io);
    const targets = fixture.targets();
    const report = try fixture.acceptor.runTurn(testing.io, &targets, 8, exhaustedAccept);
    try testing.expectEqual(Stop.backoff, report.stop);
    try testing.expectEqual(error.ProcessFdQuotaExceeded, report.failure.?);
    try testing.expectEqual(@as(u32, 1), report.attempts);
    const early = try fixture.acceptor.turn(testing.io, &targets, 8);
    try testing.expectEqual(Stop.backoff, early.stop);
    try testing.expectEqual(@as(u32, 0), early.attempts);
    // The control wake remains usable while the listener is suspended.
    try fixture.acceptor.wake();
    try fixture.acceptor.wait(testing.io, deadlineIn(0));
    const started: std.Io.Timestamp = .now(testing.io, .awake);
    try fixture.acceptor.wait(testing.io, deadlineIn(20));
    try testing.expect(started.durationTo(.now(testing.io, .awake)).toMilliseconds() >= 20);
    // Force expiry after proving that pending connections did not busy-wake us.
    fixture.acceptor.retry_at = .now(testing.io, .awake);
    const resumed = try fixture.acceptor.turn(testing.io, &targets, 8);
    try testing.expectEqual(@as(u32, 1), resumed.accepted);
    try testing.expectEqual(Stop.drained, resumed.stop);
}

test "v2 acceptor stop preserves pending handoff and refuses more accepts" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const peer = try fixture.connect();
    defer peer.close(testing.io);
    const targets = fixture.targets();
    _ = try fixture.acceptor.turn(testing.io, &targets, 1);
    fixture.acceptor.stop(testing.io);
    fixture.acceptor.stop(testing.io);
    try testing.expectEqual(Stop.stopped, (try fixture.acceptor.turn(testing.io, &targets, 1)).stop);
    try testing.expectError(error.Stopped, fixture.acceptor.wait(testing.io, deadlineIn(0)));
    const fd = fixture.channels[0].receive(testing.io).?;
    defer Native.closeFd(fd);
    try expectFlags(fd);
}

const Receiver = struct {
    channel: *AcceptChannel,
    poller: *Readiness,

    fn run(self: *Receiver, io: std.Io) !void {
        const deadline = std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(2000));
        _ = try self.poller.wait(io, deadline);
        const fd = self.channel.receive(io) orelse return error.MissingHandoff;
        defer Native.closeFd(fd);
        try expectFlags(fd);
        try testing.expectEqual(@as(isize, 1), std.c.write(fd, "x", 1));
    }
};

test "v2 accepted descriptor crosses a real reactor wake and remains usable" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var receiver: Receiver = .{ .channel = &fixture.channels[0], .poller = &fixture.wakes[0] };
    var task = try testing.io.concurrent(Receiver.run, .{ &receiver, testing.io });
    defer task.cancel(testing.io) catch {};
    const peer = try fixture.connect();
    defer peer.close(testing.io);
    const targets = fixture.targets();
    const report = try fixture.acceptor.turn(testing.io, &targets, 1);
    try testing.expectEqual(@as(u32, 1), report.accepted);
    try task.await(testing.io);
    var buffer: [1]u8 = undefined;
    try testing.expectEqual(@as(isize, 1), std.c.read(peer.socket.handle, &buffer, 1));
    try testing.expectEqual(@as(u8, 'x'), buffer[0]);
}

test "v2 acceptor stops safely if listener backoff registration fails" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const targets = fixture.targets();
    const native_fd = fixture.acceptor.native.fd;
    defer fixture.acceptor.native.fd = native_fd;
    fixture.acceptor.native.fd = -1;
    const report = try fixture.acceptor.runTurn(testing.io, &targets, 4, exhaustedAccept);
    try testing.expectEqual(Stop.stopped, report.stop);
    try testing.expectEqual(error.ProcessFdQuotaExceeded, report.failure.?);
    try testing.expectEqual(error.RegistrationFailed, report.control_error.?);
    try testing.expect(fixture.acceptor.stopped);
    try testing.expectError(error.Stopped, fixture.acceptor.wait(testing.io, deadlineIn(0)));
}
