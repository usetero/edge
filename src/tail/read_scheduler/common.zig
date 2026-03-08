const std = @import("std");
const framer_mod = @import("../framer.zig");
const watch_mod = @import("../watch.zig");

pub fn processBatchScalar(
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

pub fn readTailScalar(
    framer: *framer_mod.LineFramer,
    file: *const std.fs.File,
    start_offset: u64,
    end_offset: u64,
    writer: *std.Io.Writer,
    filter_ctx: *anyopaque,
    filter_fn: *const framer_mod.LineFramer.LineFilterFn,
) !void {
    var off = start_offset;
    while (off < end_offset) {
        const remaining = end_offset - off;
        const to_read: usize = @intCast(@min(remaining, framer.read_buf.len));
        const n = try std.posix.pread(file.handle, framer.read_buf[0..to_read], @intCast(off));
        if (n == 0) break;
        try framer.ingestChunk(framer.read_buf[0..n], writer, filter_ctx, filter_fn);
        off += n;
    }
}
