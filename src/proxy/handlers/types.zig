const std = @import("std");

/// Represents the request data that flows through the pipeline
/// Uses request-scoped allocator (arena) for temporary allocations
pub const RequestContext = struct {
    method: std.http.Method,
    path: []const u8,
    url: []const u8,
    content_type: ?[]const u8,
    headers: []std.http.Header,
    body: ?[]const u8,

    // Handler decisions
    should_forward: bool = true,
    modified: bool = false,

    // Request-scoped allocator (typically an arena)
    // Used for temporary allocations during request processing
    allocator: std.mem.Allocator,
};

/// Handler decision - what to do with the request
pub const HandlerAction = enum {
    continue_pipeline, // Continue to next handler
    forward, // Forward immediately (skip remaining handlers)
    reject, // Reject request (don't forward)
};

/// Result from a handler execution
pub const HandlerResult = struct {
    action: HandlerAction,
    context: RequestContext,
};

/// Route matching criteria
/// Using compact representation for cache efficiency
pub const RouteMatch = struct {
    /// Path pattern to match (null means match all paths)
    path_pattern: ?[]const u8,

    /// Content-Type pattern to match (null means match all content types)
    content_type_pattern: ?[]const u8,

    /// Check if this route matches the request
    pub fn matches(self: RouteMatch, path: []const u8, content_type: ?[]const u8) bool {
        // Check path match
        if (self.path_pattern) |pattern| {
            if (!pathMatches(pattern, path)) return false;
        }

        // Check content-type match
        if (self.content_type_pattern) |pattern| {
            const ct = content_type orelse return false;
            if (!contentTypeMatches(pattern, ct)) return false;
        }

        return true;
    }

    fn pathMatches(pattern: []const u8, path: []const u8) bool {
        // Support wildcards: /api/* matches /api/anything
        if (std.mem.endsWith(u8, pattern, "/*")) {
            const prefix = pattern[0 .. pattern.len - 2];
            return std.mem.startsWith(u8, path, prefix);
        }

        // Exact match
        return std.mem.eql(u8, pattern, path);
    }

    fn contentTypeMatches(pattern: []const u8, content_type: []const u8) bool {
        // Support prefix matching: application/* matches application/json
        if (std.mem.endsWith(u8, pattern, "/*")) {
            const prefix = pattern[0 .. pattern.len - 2];
            return std.mem.startsWith(u8, content_type, prefix);
        }

        // Exact match (case insensitive)
        return std.ascii.eqlIgnoreCase(pattern, content_type);
    }
};

/// Handler type enumeration
pub const HandlerType = enum {
    log_filter,
    passthrough,
};

/// Configuration for log filter handler
/// Allocated once at startup, lives for entire program lifetime
pub const LogFilterConfig = struct {
    /// Patterns to search for in logs
    filter_patterns: []const []const u8,

    /// Action to take when pattern is found
    action: enum { reject, continue_pipeline } = .reject,

    /// Route matching criteria
    route: RouteMatch,

    allocator: std.mem.Allocator, // Long-lived allocator for config data

    pub fn init(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        action: @TypeOf(@as(LogFilterConfig, undefined).action),
        route: RouteMatch,
    ) !LogFilterConfig {
        // Deep copy patterns so they persist
        const owned_patterns = try allocator.alloc([]const u8, patterns.len);
        errdefer allocator.free(owned_patterns);

        for (patterns, 0..) |pattern, i| {
            owned_patterns[i] = try allocator.dupe(u8, pattern);
        }

        // Deep copy route patterns
        const owned_route = RouteMatch{
            .path_pattern = if (route.path_pattern) |p| try allocator.dupe(u8, p) else null,
            .content_type_pattern = if (route.content_type_pattern) |ct| try allocator.dupe(u8, ct) else null,
        };

        return .{
            .filter_patterns = owned_patterns,
            .action = action,
            .route = owned_route,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *LogFilterConfig) void {
        for (self.filter_patterns) |pattern| {
            self.allocator.free(pattern);
        }
        self.allocator.free(self.filter_patterns);

        if (self.route.path_pattern) |p| self.allocator.free(p);
        if (self.route.content_type_pattern) |ct| self.allocator.free(ct);
    }
};

/// Tagged union of all handler implementations
/// Handler configs are long-lived, allocated once at startup
pub const Handler = union(HandlerType) {
    log_filter: LogFilterConfig,
    passthrough: void,

    /// Execute this handler on the request context
    /// Uses ctx.allocator (request arena) for temporary allocations
    /// Uses self config data (long-lived) for handler logic
    pub fn execute(self: Handler, ctx: RequestContext) !HandlerResult {
        return switch (self) {
            .log_filter => |config| @import("log_filter.zig").execute(config, ctx),
            .passthrough => .{ .action = .continue_pipeline, .context = ctx },
        };
    }

    pub fn deinit(self: *Handler) void {
        switch (self.*) {
            .log_filter => |*config| config.deinit(),
            .passthrough => {},
        }
    }

    /// Get the route match criteria for this handler
    pub fn getRoute(self: Handler) RouteMatch {
        return switch (self) {
            .log_filter => |config| config.route,
            .passthrough => .{ .path_pattern = null, .content_type_pattern = null },
        };
    }
};
