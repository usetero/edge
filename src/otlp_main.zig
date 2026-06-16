const std = @import("std");
const app = @import("runtime/app.zig");
const mode = @import("runtime/mode.zig");

pub const std_options = app.std_options;

pub fn main(init: std.process.Init) !void {
    try app.run(init, mode.Distribution.otlp);
}
