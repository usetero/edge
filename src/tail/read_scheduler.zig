const std = @import("std");
const builtin = @import("builtin");
const framer_mod = @import("framer.zig");
const types = @import("types.zig");
const watch_mod = @import("watch.zig");

const poll_mod = @import("read_scheduler/poll.zig");
const uring_mod = if (builtin.os.tag == .linux)
    @import("read_scheduler/uring_linux.zig")
else
    struct {
        pub const Scheduler = void;
    };

const SchedulerEngine = enum { poll, uring };

/// Enum-backed scheduler interface with architecture-specific implementations
/// in separate files:
/// - `read_scheduler/poll.zig`
/// - `read_scheduler/uring_linux.zig`
pub const EngineScheduler = union(SchedulerEngine) {
    poll: poll_mod.Scheduler,
    uring: uring_mod.Scheduler,

    pub fn init(allocator: std.mem.Allocator, io_engine: types.IoEngine) !EngineScheduler {
        return switch (types.normalizeIoEngine(io_engine)) {
            .uring => if (builtin.os.tag == .linux)
                .{ .uring = try uring_mod.Scheduler.init(allocator) }
            else
                .{ .poll = try poll_mod.Scheduler.init(allocator) },
            .kqueue, .poll => .{ .poll = try poll_mod.Scheduler.init(allocator) },
            .auto, .inotify, .epoll => unreachable,
        };
    }

    pub fn deinit(self: *EngineScheduler) void {
        switch (self.*) {
            .poll => |*s| s.deinit(),
            .uring => if (builtin.os.tag == .linux) self.uring.deinit(),
        }
    }

    pub fn processBatch(
        self: *EngineScheduler,
        framer: *framer_mod.LineFramer,
        writer: *std.Io.Writer,
        events: []const watch_mod.Event,
        filter_ctx: *anyopaque,
        filter_fn: *const framer_mod.LineFramer.LineFilterFn,
    ) !usize {
        return switch (self.*) {
            .poll => |*s| try s.processBatch(framer, writer, events, filter_ctx, filter_fn),
            .uring => if (builtin.os.tag == .linux)
                try self.uring.processBatch(framer, writer, events, filter_ctx, filter_fn)
            else
                try self.poll.processBatch(framer, writer, events, filter_ctx, filter_fn),
        };
    }
};

const testing = std.testing;

fn keepAll(_: *anyopaque, _: []const u8, _: @import("types.zig").LineMeta) !bool {
    return true;
}

test "read scheduler public API: processes event batch" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const f = try tmp.dir.createFile("s.log", .{});
        defer f.close();
        try f.writeAll("a\n");
    }
    const abs = try tmp.dir.realpathAlloc(testing.allocator, "s.log");
    defer testing.allocator.free(abs);
    const file = try std.fs.openFileAbsolute(abs, .{ .mode = .read_only });
    defer file.close();

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var scheduler = try EngineScheduler.init(testing.allocator, .auto);
    defer scheduler.deinit();

    const n = try scheduler.processBatch(&framer, &out.writer, &.{
        .{ .file = &file, .start_offset = 0, .end_offset = 2, .identity = null },
    }, &framer, keepAll);
    try framer.finish(&out.writer, &framer, keepAll);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("a\n", out.written());
}
