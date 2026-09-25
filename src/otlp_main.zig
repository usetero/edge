const std = @import("std");
const app = @import("runtime/app.zig");

pub const std_options = app.std_options;
pub const debug = app.debug;

pub fn main(init: std.process.Init) !void {
    try app.run(init, .otlp);
}
