//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

pub fn bufferedPrint() !void {
    // Stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try stdout.flush(); // Don't forget to flush!
}

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try std.testing.expect(add(3, 7) == 10);
}

// Import modules to include their tests
test {
    _ = @import("config/types.zig");
    _ = @import("config/parser.zig");
    _ = @import("core/filter.zig");
    _ = @import("core/policy_source.zig");
    _ = @import("core/policy_registry.zig");
    _ = @import("core/policy_provider.zig");
    // Skip datadog_v2_logs tests - they write to stdout and hang in test runner
    // _ = @import("proxy/datadog_v2_logs.zig");
    _ = @import("proxy/compress.zig");
    _ = @import("json/pretty_print.zig");
}
