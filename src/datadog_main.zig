const app = @import("runtime/app.zig");
const mode = @import("runtime/mode.zig");

pub fn main() !void {
    try app.run(mode.Distribution.datadog);
}
