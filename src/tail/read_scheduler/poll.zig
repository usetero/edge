const std = @import("std");
const framer_mod = @import("../framer.zig");
const watch_mod = @import("../watch.zig");
const common = @import("common.zig");

pub const Scheduler = struct {
    pub fn init(_: std.mem.Allocator) !Scheduler {
        return .{};
    }

    pub fn deinit(_: *Scheduler) void {}

    pub fn processBatch(
        _: *Scheduler,
        framer: *framer_mod.LineFramer,
        writer: *std.Io.Writer,
        events: []const watch_mod.Event,
        filter_ctx: *anyopaque,
        filter_fn: *const framer_mod.LineFramer.LineFilterFn,
    ) !usize {
        return common.processBatchScalar(framer, writer, events, filter_ctx, filter_fn);
    }
};
