const std = @import("std");
const handler_types = @import("handlers/types.zig");

/// Pipeline that processes handlers in sequence
/// Optimized for data-oriented design:
/// - Handlers grouped by route patterns for cache locality
/// - Sequential processing with early exit
/// - Zero allocations during request processing
pub const Pipeline = struct {
    /// All handlers in execution order
    /// Grouped by similar route patterns for better cache utilization
    handlers: []handler_types.Handler,

    /// Pre-computed route match data in parallel array
    /// This allows checking routes without dereferencing handler configs
    /// Struct-of-Arrays pattern for better cache performance
    routes: []handler_types.RouteMatch,

    allocator: std.mem.Allocator, // Long-lived allocator for pipeline structure

    pub fn init(allocator: std.mem.Allocator, handlers: []const handler_types.Handler) !Pipeline {
        const handler_copy = try allocator.dupe(handler_types.Handler, handlers);
        errdefer allocator.free(handler_copy);

        // Extract routes into parallel array for faster matching
        const routes = try allocator.alloc(handler_types.RouteMatch, handlers.len);
        errdefer allocator.free(routes);

        for (handlers, 0..) |handler, i| {
            routes[i] = handler.getRoute();
        }

        return .{
            .handlers = handler_copy,
            .routes = routes,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Pipeline) void {
        for (self.handlers) |*handler| {
            handler.deinit();
        }
        self.allocator.free(self.handlers);
        self.allocator.free(self.routes);
    }

    /// Execute all matching handlers in sequence
    /// Uses ctx.allocator (request arena) for temporary allocations
    /// Hot path: optimized for sequential processing with early exit
    pub fn process(self: *Pipeline, ctx: handler_types.RequestContext) !handler_types.HandlerResult {
        var current_ctx = ctx;

        // Process handlers sequentially
        // Route check is cache-friendly (separate array)
        for (self.handlers, self.routes) |handler, route| {
            // Fast path: check route match without touching handler config
            if (!route.matches(current_ctx.path, current_ctx.content_type)) {
                continue;
            }

            // Route matches, execute handler
            const result = try handler.execute(current_ctx);

            switch (result.action) {
                .continue_pipeline => current_ctx = result.context,
                .forward, .reject => return result, // Early exit
            }
        }

        // All handlers processed, forward the request
        return .{
            .action = .forward,
            .context = current_ctx,
        };
    }

    /// Get count of handlers that would match this request
    /// Useful for metrics/debugging
    pub fn countMatches(self: *Pipeline, path: []const u8, content_type: ?[]const u8) usize {
        var count: usize = 0;
        for (self.routes) |route| {
            if (route.matches(path, content_type)) {
                count += 1;
            }
        }
        return count;
    }
};
