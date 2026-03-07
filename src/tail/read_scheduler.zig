const std = @import("std");
const framer_mod = @import("framer.zig");
const watch_mod = @import("watch.zig");

/// Simple batched read scheduler.
///
/// The runtime assembles a batch of read tasks and this module executes them
/// in one pass. Linux io_uring can later replace this implementation behind
/// the same API surface.
pub const ReadScheduler = struct {
    pub fn processBatch(
        framer: *framer_mod.LineFramer,
        writer: *std.Io.Writer,
        events: []const watch_mod.Event,
        filter_ctx: *anyopaque,
        filter_fn: *const framer_mod.LineFramer.LineFilterFn,
    ) !usize {
        var processed: usize = 0;
        for (events) |evt| {
            try framer.readRange(evt.file, evt.start_offset, evt.end_offset, writer, filter_ctx, filter_fn);
            processed += 1;
        }
        return processed;
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

    const n = try ReadScheduler.processBatch(&framer, &out.writer, &.{
        .{ .file = &file, .start_offset = 0, .end_offset = 2, .identity = null },
    }, &framer, keepAll);
    try framer.finish(&out.writer, &framer, keepAll);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("a\n", out.written());
}
