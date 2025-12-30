const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const intercepting_writer = @import("../proxy/intercepting_writer.zig");

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;
const ResponseInterceptFn = proxy_module.ResponseInterceptFn;

/// Context for line-by-line processing of Prometheus metrics
pub const PrometheusInterceptContext = struct {
    /// Buffer to accumulate partial lines
    line_buffer: std.ArrayListUnmanaged(u8) = .{},
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PrometheusInterceptContext {
        return .{
            .line_buffer = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PrometheusInterceptContext) void {
        self.line_buffer.deinit(self.allocator);
    }
};

/// Factory function to create intercept context for each request
pub fn createInterceptContext(allocator: std.mem.Allocator) ?*anyopaque {
    const ctx = allocator.create(PrometheusInterceptContext) catch return null;
    ctx.* = PrometheusInterceptContext.init(allocator);
    return @ptrCast(ctx);
}

/// Cleanup function for intercept context
pub fn destroyInterceptContext(context: ?*anyopaque) void {
    if (context) |ptr| {
        const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(ptr));
        const allocator = ctx.allocator;
        ctx.deinit();
        allocator.destroy(ctx);
    }
}

/// Intercept callback that prints Prometheus metrics line by line.
/// Returns the data unchanged (pass-through) after printing.
pub fn prometheusInterceptCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(context orelse return data));

    var start: usize = 0;
    for (data, 0..) |byte, i| {
        if (byte == '\n') {
            // Found a newline - print accumulated buffer + this segment
            const segment = data[start .. i + 1];
            if (ctx.line_buffer.items.len > 0) {
                // Have buffered data - append segment and print
                ctx.line_buffer.appendSlice(ctx.allocator, segment) catch return data;
                // Print without the trailing newline for cleaner output
                const line = ctx.line_buffer.items;
                const trimmed = if (line.len > 0 and line[line.len - 1] == '\n')
                    line[0 .. line.len - 1]
                else
                    line;
                std.log.debug("[prometheus] {s}\n", .{trimmed});
                ctx.line_buffer.clearRetainingCapacity();
            } else {
                // No buffered data - print segment directly
                const trimmed = if (segment.len > 0 and segment[segment.len - 1] == '\n')
                    segment[0 .. segment.len - 1]
                else
                    segment;
                std.log.debug("[prometheus] {s}\n", .{trimmed});
            }
            start = i + 1;
        }
    }

    // Buffer any remaining data after the last newline
    if (start < data.len) {
        ctx.line_buffer.appendSlice(ctx.allocator, data[start..]) catch return data;
    }

    // Pass through unchanged
    return data;
}

/// Prometheus module - handles Prometheus metrics scraping with response interception
/// STATELESS, THREAD-SAFE
pub const PrometheusModule = struct {
    pub fn asProxyModule(self: *PrometheusModule) ProxyModule {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = ProxyModule.VTable{
        .init = init,
        .processRequest = processRequest,
        .deinit = deinit,
    };

    fn init(
        _: *anyopaque,
        _: std.mem.Allocator,
        _: ModuleConfig,
    ) anyerror!void {
        // Nothing to initialize - stateless module
    }

    /// THREAD-SAFE: Stateless - just passes requests through unchanged
    fn processRequest(
        _: *anyopaque,
        _: *const ModuleRequest,
        _: std.mem.Allocator,
    ) anyerror!ModuleResult {
        // Pass through unchanged - the response interception handles the metrics
        return ModuleResult.unchanged();
    }

    fn deinit(_: *anyopaque) void {
        // Nothing to cleanup (stateless)
    }
};

/// Routes for Prometheus metrics endpoint
pub const routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

test "PrometheusModule passes through requests unchanged" {
    const allocator = std.testing.allocator;

    var module = PrometheusModule{};
    const pm = module.asProxyModule();

    try pm.init(allocator, .{
        .id = @enumFromInt(0),
        .routes = &routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = null,
    });

    const req = ModuleRequest{
        .method = .GET,
        .path = "/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, allocator);
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);

    pm.deinit();
}

test "PrometheusInterceptContext lifecycle" {
    const allocator = std.testing.allocator;

    const ctx_ptr = createInterceptContext(allocator);
    try std.testing.expect(ctx_ptr != null);

    destroyInterceptContext(ctx_ptr);
}

test "prometheusInterceptCallback passes through data" {
    const allocator = std.testing.allocator;

    var ctx = PrometheusInterceptContext.init(allocator);
    defer ctx.deinit();

    const data = "# HELP http_requests_total Total HTTP requests\n";
    const result = prometheusInterceptCallback(data, @ptrCast(&ctx));

    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(data, result.?);
}

test "prometheusInterceptCallback handles partial lines" {
    const allocator = std.testing.allocator;

    var ctx = PrometheusInterceptContext.init(allocator);
    defer ctx.deinit();

    // First chunk - partial line
    const chunk1 = "# HELP http_requ";
    const result1 = prometheusInterceptCallback(chunk1, @ptrCast(&ctx));
    try std.testing.expectEqualStrings(chunk1, result1.?);

    // Second chunk - completes the line
    const chunk2 = "ests_total Total\n";
    const result2 = prometheusInterceptCallback(chunk2, @ptrCast(&ctx));
    try std.testing.expectEqualStrings(chunk2, result2.?);

    // Buffer should be cleared after complete line
    try std.testing.expectEqual(@as(usize, 0), ctx.line_buffer.items.len);
}
