const std = @import("std");

pub fn main() !void {
    var out_buf: [1024]u8 = undefined;
    var out_writer = std.fs.File.stdout().writer(&out_buf);
    const out = &out_writer.interface;
    try out.print("echo-server scaffold: not implemented yet\n", .{});
    try out.flush();
}
