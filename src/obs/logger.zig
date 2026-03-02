const std = @import("std");

pub const Logger = struct {
    writer: *std.Io.Writer,

    pub fn init(writer: *std.Io.Writer) Logger {
        return .{ .writer = writer };
    }

    pub fn write(self: *Logger, msg: []const u8) !void {
        try self.writer.writeAll(msg);
    }

    pub fn flush(self: *Logger) !void {
        try self.writer.flush();
    }
};
