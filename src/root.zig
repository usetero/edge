//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

// =============================================================================
// Public module exports for distributions
// =============================================================================

// Policy package (centralized policy management)
pub const policy = @import("policy/root.zig");

// Config modules (non-policy configuration)
pub const config_types = @import("config/types.zig");
pub const config_parser = @import("config/parser.zig");

// Proxy modules
pub const server = @import("proxy/server.zig");

// Module implementations
pub const proxy_module = @import("modules/proxy_module.zig");
pub const passthrough_module = @import("modules/passthrough_module.zig");
pub const datadog_module = @import("modules/datadog_module.zig");

// Hyperscan/Vectorscan bindings
pub const hyperscan = @import("hyperscan/hyperscan.zig");
pub const matcher_index = @import("hyperscan/matcher_index.zig");

// Re-export filter_engine from policy package for backwards compatibility
pub const filter_engine = @import("policy/filter_engine.zig");

// =============================================================================
// Distribution entry points
// =============================================================================

/// Datadog distribution - focused edge proxy for Datadog log ingestion
pub const datadog_distribution = @import("datadog_main.zig");

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
// Note: jsonpath.zig is tested separately via jsonpath_tests in build.zig
// because it requires C++ linkage that would conflict with the exe build
test {
    _ = @import("config/types.zig");
    _ = @import("config/parser.zig");
    _ = @import("policy/root.zig");
    _ = @import("policy/filter_engine.zig");
    _ = @import("hyperscan/matcher_index.zig");
    _ = @import("modules/proxy_module.zig");
    _ = @import("proxy/compress.zig");
    _ = @import("proxy/router.zig");
    _ = @import("proxy/upstream_client.zig");
    // Note: proxy/server.zig requires httpz which is only available in exe build
    _ = @import("modules/passthrough_module.zig");
    _ = @import("modules/datadog_module.zig");
    _ = @import("modules/datadog_logs_v2.zig");
    _ = @import("hyperscan/hyperscan.zig");
}
