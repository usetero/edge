const app = @import("runtime/app.zig");
const mode = @import("runtime/mode.zig");

pub const std_options = app.std_options;

pub fn main() !void {
    try app.run(mode.Distribution.datadog);
}
