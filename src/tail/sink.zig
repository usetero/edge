const std = @import("std");
const io_mod = @import("io.zig");

pub const Sink = struct {
    output: *io_mod.Output,
    buffered_lines: usize = 0,

    pub fn init(output: *io_mod.Output) Sink {
        return .{ .output = output };
    }

    pub fn writeLine(self: *Sink, line: []const u8) !void {
        try self.output.writer().writeAll(line);
        try self.output.writer().writeByte('\n');
        self.buffered_lines += 1;
    }

    pub fn flush(self: *Sink) !void {
        try self.output.flush();
        self.buffered_lines = 0;
    }
};

const testing = std.testing;

test "sink public API: writes and flushes lines" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    const abs = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(abs);

    const path = try std.fs.path.join(testing.allocator, &.{ abs, "sink.log" });
    defer testing.allocator.free(path);

    var out = try io_mod.Output.initFileAppend(testing.allocator, path, 1024);
    defer out.deinit();

    var sink = Sink.init(&out);
    try sink.writeLine("a");
    try sink.writeLine("b");
    try sink.flush();

    const got = try tmp.dir.readFileAlloc(testing.allocator, "sink.log", 1024);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("a\nb\n", got);
}
