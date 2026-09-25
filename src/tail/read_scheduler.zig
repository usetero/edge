const std = @import("std");
const builtin = @import("builtin");
const framer_mod = @import("framer.zig");
const types = @import("types.zig");
const watch_mod = @import("watch.zig");

const poll_mod = @import("read_scheduler/poll.zig");
const uring_linux_mod = @import("read_scheduler/uring_linux.zig");
const uring_mod = if (builtin.os.tag == .linux)
    uring_linux_mod
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

    pub fn init(allocator: std.mem.Allocator, io: std.Io, io_engine: types.IoEngine) !EngineScheduler {
        return switch (types.normalizeIoEngine(io_engine)) {
            .uring => if (builtin.os.tag == .linux)
                .{ .uring = try uring_mod.Scheduler.init(allocator, io) }
            else
                .{ .poll = try poll_mod.Scheduler.init(allocator, io) },
            .kqueue, .poll => .{ .poll = try poll_mod.Scheduler.init(allocator, io) },
            .auto, .inotify, .epoll => unreachable,
        };
    }

    pub fn deinit(self: *EngineScheduler) void {
        switch (self.*) {
            .poll => |*s| s.deinit(),
            .uring => if (builtin.os.tag == .linux) self.uring.deinit(),
        }
        self.* = undefined;
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

fn keepAll(_: *anyopaque, _: []const u8) !bool {
    return true;
}

test "read scheduler public API: processes event batch" {
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "s.log", .data = "a\n" });
    const abs = try tmp.dir.realPathFileAlloc(io, "s.log", testing.allocator);
    defer testing.allocator.free(abs);
    const file = try std.Io.Dir.cwd().openFile(io, abs, .{ .mode = .read_only });
    defer file.close(io);

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var scheduler = try EngineScheduler.init(testing.allocator, io, .auto);
    defer scheduler.deinit();

    const n = try scheduler.processBatch(&framer, &out.writer, &.{
        .{ .file = &file, .start_offset = 0, .end_offset = 2, .identity = null },
    }, &framer, keepAll);
    try framer.finish(&out.writer, &framer, keepAll);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("a\n", out.written());
}

/// Test allocator that refuses resize and remap and keeps freed memory
/// mapped. Each grow moves the buffer. The non-fixed uring path must size
/// `scratch` once per batch, or a kernel read targets the old buffer.
const MovingAllocator = struct {
    backing: std.mem.Allocator,
    tracked: std.ArrayList(Allocation),

    const Allocation = struct {
        memory: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    };

    fn init(backing: std.mem.Allocator) MovingAllocator {
        return .{ .backing = backing, .tracked = .empty };
    }

    fn deinit(self: *MovingAllocator) void {
        for (self.tracked.items) |a| {
            self.backing.rawFree(a.memory, a.alignment, a.ret_addr);
        }
        self.tracked.deinit(self.backing);
        self.* = undefined;
    }

    fn allocator(self: *MovingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *MovingAllocator = @ptrCast(@alignCast(ctx));
        const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.tracked.append(self.backing, .{
            .memory = ptr[0..len],
            .alignment = alignment,
            .ret_addr = ret_addr,
        }) catch {
            self.backing.rawFree(ptr[0..len], alignment, ret_addr);
            return null;
        };
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        _ = .{ ctx, memory, alignment, new_len, ret_addr };
        return false;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        _ = .{ ctx, memory, alignment, new_len, ret_addr };
        return null;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        _ = .{ ctx, memory, alignment, ret_addr };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };
};

test "read scheduler uring non-fixed path: multi-event batch keeps read buffers stable" {
    if (builtin.os.tag == .linux) {
        const io = std.Options.debug_io;
        const event_count: usize = 16;
        const read_buf_size: usize = 4096;
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();

        var files: std.ArrayList(std.Io.File) = .empty;
        defer {
            for (files.items) |*f| f.close(io);
            files.deinit(testing.allocator);
        }
        var expected: std.ArrayList(u8) = .empty;
        defer expected.deinit(testing.allocator);
        const file_content = try testing.allocator.alloc(u8, read_buf_size);
        defer testing.allocator.free(file_content);

        var i: usize = 0;
        while (i < event_count) : (i += 1) {
            const name = try std.fmt.allocPrint(testing.allocator, "ev{d}.log", .{i});
            defer testing.allocator.free(name);
            {
                const f = try tmp.dir.createFile(io, name, .{});
                defer f.close(io);
                const ch: u8 = @intCast('A' + i);
                var k: usize = 0;
                while (k < read_buf_size) : (k += 2) {
                    file_content[k] = ch;
                    file_content[k + 1] = '\n';
                }
                try f.writeStreamingAll(io, file_content);
            }
            try expected.appendSlice(testing.allocator, file_content);
            const abs = try tmp.dir.realPathFileAlloc(io, name, testing.allocator);
            defer testing.allocator.free(abs);
            try files.append(
                testing.allocator,
                try std.Io.Dir.cwd().openFile(io, abs, .{ .mode = .read_only }),
            );
        }

        var moving = MovingAllocator.init(std.heap.c_allocator);
        defer moving.deinit();
        const moving_alloc = moving.allocator();

        var framer = try framer_mod.LineFramer.init(moving_alloc, read_buf_size, 1024);
        defer framer.deinit();
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        var scheduler = uring_mod.Scheduler.init(moving_alloc, io) catch |err| switch (err) {
            error.SystemOutdated, error.PermissionDenied => return error.SkipZigTest,
            else => return err,
        };
        defer scheduler.deinit();
        scheduler.fixed_enabled = false;

        const events = try testing.allocator.alloc(watch_mod.Event, event_count);
        defer testing.allocator.free(events);
        for (events, 0..) |*evt, idx| {
            evt.* = .{
                .file = &files.items[idx],
                .start_offset = 0,
                .end_offset = read_buf_size,
                .identity = null,
            };
        }

        const n = try scheduler.processBatch(&framer, &out.writer, events, &framer, keepAll);
        try framer.finish(&out.writer, &framer, keepAll);
        // `cqes` fills only after submit_and_wait. A lower count means the
        // scalar fallback ran.
        try testing.expect(scheduler.cqes.items.len == event_count);
        try testing.expectEqual(@as(usize, event_count), n);
        try testing.expectEqualStrings(expected.items, out.written());
    }
}

test "read scheduler public API: isolates partial lines across files in one batch" {
    // File A has no trailing newline. Its partial line must not join file
    // B's first line.
    const io = std.Options.debug_io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "a.log", .data = "line1\npartial" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.log", .data = "hello\nworld\n" });
    const abs_a = try tmp.dir.realPathFileAlloc(io, "a.log", testing.allocator);
    defer testing.allocator.free(abs_a);
    const abs_b = try tmp.dir.realPathFileAlloc(io, "b.log", testing.allocator);
    defer testing.allocator.free(abs_b);
    const file_a = try std.Io.Dir.cwd().openFile(io, abs_a, .{ .mode = .read_only });
    defer file_a.close(io);
    const file_b = try std.Io.Dir.cwd().openFile(io, abs_b, .{ .mode = .read_only });
    defer file_b.close(io);

    var framer = try framer_mod.LineFramer.init(testing.allocator, 16, 1024);
    defer framer.deinit();
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var scheduler = try EngineScheduler.init(testing.allocator, io, .auto);
    defer scheduler.deinit();

    const n = try scheduler.processBatch(&framer, &out.writer, &.{
        .{ .file = &file_a, .start_offset = 0, .end_offset = 13, .identity = null },
        .{ .file = &file_b, .start_offset = 0, .end_offset = 12, .identity = null },
    }, &framer, keepAll);

    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("line1\nhello\nworld\n", out.written());
    try testing.expect(std.mem.indexOf(u8, out.written(), "partialhello") == null);
}
