const std = @import("std");

/// Module ID - use instead of pointers for type safety
pub const ModuleId = enum(u32) { _ };

/// HTTP method enum - mirrors common HTTP methods
/// Used instead of httpz.Method to avoid dependency on httpz in core types
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    OTHER,
};

/// HTTP method bitmask for route matching
pub const MethodBitmask = packed struct(u8) {
    get: bool = false,
    post: bool = false,
    put: bool = false,
    delete: bool = false,
    patch: bool = false,
    head: bool = false,
    options: bool = false,
    _unused: u1 = 0,

    pub const all = MethodBitmask{
        .get = true,
        .post = true,
        .put = true,
        .delete = true,
        .patch = true,
        .head = true,
        .options = true,
    };

    pub fn matches(self: MethodBitmask, method: HttpMethod) bool {
        return switch (method) {
            .GET => self.get,
            .POST => self.post,
            .PUT => self.put,
            .DELETE => self.delete,
            .PATCH => self.patch,
            .HEAD => self.head,
            .OPTIONS => self.options,
            .OTHER => false,
        };
    }
};

/// Route match pattern pre-compiled at init
pub const RoutePattern = struct {
    /// Pattern type for O(1) dispatch
    pattern_type: PatternType,

    /// Pre-computed hash for exact matches (0 for other types)
    hash: u64,

    /// Pattern string (stored in module's memory)
    pattern: []const u8,

    /// HTTP methods this route accepts (bitmask)
    methods: MethodBitmask,

    pub const PatternType = enum {
        /// Exact string match: "/api/v2/logs"
        exact,
        /// Prefix match: "/api/v2/*"
        prefix,
        /// Suffix match: "*.json"
        suffix,
        /// Match all: "/*"
        any,
    };

    /// Create an exact match route pattern
    pub fn exact(path: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .exact,
            .hash = std.hash.Wyhash.hash(0, path),
            .pattern = path,
            .methods = methods,
        };
    }

    /// Create a prefix match route pattern
    pub fn prefix(path_prefix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .prefix,
            .hash = 0,
            .pattern = path_prefix,
            .methods = methods,
        };
    }

    /// Create a suffix match route pattern
    pub fn suffix(path_suffix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .suffix,
            .hash = 0,
            .pattern = path_suffix,
            .methods = methods,
        };
    }

    /// Create a wildcard match route pattern
    pub fn any(methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .any,
            .hash = 0,
            .pattern = "/*",
            .methods = methods,
        };
    }
};

/// Upstream configuration with pre-allocated resources
pub const UpstreamConfig = struct {
    /// Pre-parsed upstream URL components
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,

    /// Maximum request/response sizes
    max_request_body: u32,
    max_response_body: u32,
};

/// Module configuration - allocated once at startup
pub const ModuleConfig = struct {
    /// Module identifier
    id: ModuleId,

    /// Routes this module handles
    routes: []const RoutePattern,

    /// Upstream configuration
    upstream: UpstreamConfig,

    /// Module-specific configuration (opaque, read-only)
    module_data: ?*const anyopaque,
};

/// Module request context - passed to handlers
/// IMPORTANT: All fields are read-only. Modules MUST NOT modify the original request directly.
pub const ModuleRequest = struct {
    /// HTTP method of the request
    method: HttpMethod,

    /// Request path
    path: []const u8,

    /// Query string (empty if none)
    query: []const u8,

    /// Upstream config for this module (READ-ONLY)
    upstream: *const UpstreamConfig,

    /// Module-specific context (READ-ONLY)
    module_ctx: ?*const anyopaque,

    /// Decompressed body (if request had body, already decompressed by proxy)
    /// Empty slice if no body
    body: []const u8,

    /// Original request headers accessor (opaque - implementation specific)
    /// Use getHeader() to access headers
    headers_ctx: ?*const anyopaque,

    /// Function to get a header value by name
    get_header_fn: ?*const fn (ctx: ?*const anyopaque, name: []const u8) ?[]const u8,

    /// Get a header value by name
    pub fn getHeader(self: *const ModuleRequest, name: []const u8) ?[]const u8 {
        if (self.get_header_fn) |get_fn| {
            return get_fn(self.headers_ctx, name);
        }
        return null;
    }
};

/// Module processing result
pub const ModuleResult = struct {
    /// What action to take
    action: Action,

    /// Modified body (if action is .proxy_modified)
    /// Module allocates with provided allocator
    /// Proxy will handle compression/cleanup
    modified_body: []const u8 = &.{},

    /// Status code (if action is .respond_immediately)
    status: u16 = 200,

    /// Response body (if action is .respond_immediately)
    response_body: []const u8 = &.{},

    pub const Action = enum {
        /// Pass request to upstream unchanged
        proxy_unchanged,

        /// Pass modified body to upstream
        proxy_modified,

        /// Drop request, respond with status immediately
        respond_immediately,
    };

    /// Convenience constructor for unchanged passthrough
    pub fn unchanged() ModuleResult {
        return .{ .action = .proxy_unchanged };
    }

    /// Convenience constructor for modified body
    pub fn modified(body: []const u8) ModuleResult {
        return .{
            .action = .proxy_modified,
            .modified_body = body,
        };
    }

    /// Convenience constructor for immediate response
    pub fn respond(status: u16, body: []const u8) ModuleResult {
        return .{
            .action = .respond_immediately,
            .status = status,
            .response_body = body,
        };
    }
};

/// Response context - passed to processResponse handlers
pub const ModuleResponse = struct {
    /// HTTP status code from upstream
    status: u16,

    /// Response body from upstream (decompressed)
    body: []const u8,

    /// Original request context (for access to path, method, etc.)
    request: *const ModuleRequest,

    /// Opaque context for header access
    headers_ctx: ?*const anyopaque,

    /// Function to get header value
    get_header_fn: ?*const fn (ctx: ?*const anyopaque, name: []const u8) ?[]const u8,

    /// Get a response header value by name
    pub fn getHeader(self: *const ModuleResponse, name: []const u8) ?[]const u8 {
        if (self.get_header_fn) |get_fn| {
            return get_fn(self.headers_ctx, name);
        }
        return null;
    }
};

/// Module interface - vtable pattern for zero-cost abstraction
/// THREAD SAFETY: All methods MUST be thread-safe (stateless processing only)
pub const ProxyModule = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Initialize module resources (called once at startup)
        /// NOT thread-safe (called before server starts)
        init: *const fn (
            ptr: *anyopaque,
            allocator: std.mem.Allocator,
            config: ModuleConfig,
        ) anyerror!void,

        /// Process incoming request body
        /// MUST be thread-safe and stateless
        /// - Receives decompressed body (compression handled by proxy)
        /// - Can return modified body or signal to drop/respond immediately
        /// - Any error = fail-open (request passes unchanged)
        processRequest: *const fn (
            ptr: *anyopaque,
            req: *const ModuleRequest,
            allocator: std.mem.Allocator,
        ) anyerror!ModuleResult,

        /// Process response from upstream
        /// MUST be thread-safe and stateless
        /// - Receives decompressed response body
        /// - Can return modified body or signal to drop
        /// - Any error = fail-open (response passes unchanged)
        /// - If null, response passes through unchanged
        processResponse: ?*const fn (
            ptr: *anyopaque,
            resp: *const ModuleResponse,
            allocator: std.mem.Allocator,
        ) anyerror!ModuleResult = null,

        /// Cleanup module resources (called once at shutdown)
        /// NOT thread-safe (called after server stops)
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn init(self: ProxyModule, allocator: std.mem.Allocator, config: ModuleConfig) !void {
        return self.vtable.init(self.ptr, allocator, config);
    }

    pub fn processRequest(self: ProxyModule, req: *const ModuleRequest, allocator: std.mem.Allocator) !ModuleResult {
        return self.vtable.processRequest(self.ptr, req, allocator);
    }

    pub fn processResponse(self: ProxyModule, resp: *const ModuleResponse, allocator: std.mem.Allocator) !ModuleResult {
        if (self.vtable.processResponse) |process_fn| {
            return process_fn(self.ptr, resp, allocator);
        }
        return ModuleResult.unchanged();
    }

    pub fn deinit(self: ProxyModule) void {
        self.vtable.deinit(self.ptr);
    }
};

/// Module registration info - used when setting up the proxy server
pub const ModuleRegistration = struct {
    /// The module instance
    module: ProxyModule,

    /// Routes this module handles
    routes: []const RoutePattern,

    /// Upstream URL for this module
    upstream_url: []const u8,

    /// Maximum path length for URI construction
    max_path_length: u32 = 2048,

    /// Maximum request body size
    max_request_body: u32 = 10 * 1024 * 1024, // 10MB default

    /// Maximum response body size
    max_response_body: u32 = 10 * 1024 * 1024, // 10MB default

    /// Module-specific configuration data (opaque)
    module_data: ?*const anyopaque = null,
};

// =============================================================================
// Tests
// =============================================================================

test "MethodBitmask.matches" {
    const post_only = MethodBitmask{ .post = true };
    try std.testing.expect(post_only.matches(.POST));
    try std.testing.expect(!post_only.matches(.GET));
    try std.testing.expect(!post_only.matches(.PUT));

    const get_post = MethodBitmask{ .get = true, .post = true };
    try std.testing.expect(get_post.matches(.GET));
    try std.testing.expect(get_post.matches(.POST));
    try std.testing.expect(!get_post.matches(.DELETE));

    try std.testing.expect(MethodBitmask.all.matches(.GET));
    try std.testing.expect(MethodBitmask.all.matches(.POST));
    try std.testing.expect(MethodBitmask.all.matches(.DELETE));
}

test "RoutePattern.exact" {
    const route = RoutePattern.exact("/api/v2/logs", .{ .post = true });
    try std.testing.expectEqual(RoutePattern.PatternType.exact, route.pattern_type);
    try std.testing.expectEqualStrings("/api/v2/logs", route.pattern);
    try std.testing.expect(route.hash != 0);
    try std.testing.expect(route.methods.post);
    try std.testing.expect(!route.methods.get);
}

test "RoutePattern.prefix" {
    const route = RoutePattern.prefix("/api/v2/", MethodBitmask.all);
    try std.testing.expectEqual(RoutePattern.PatternType.prefix, route.pattern_type);
    try std.testing.expectEqualStrings("/api/v2/", route.pattern);
    try std.testing.expectEqual(@as(u64, 0), route.hash);
}

test "ModuleResult convenience constructors" {
    const unchanged_result = ModuleResult.unchanged();
    try std.testing.expectEqual(ModuleResult.Action.proxy_unchanged, unchanged_result.action);

    const modified_result = ModuleResult.modified("new body");
    try std.testing.expectEqual(ModuleResult.Action.proxy_modified, modified_result.action);
    try std.testing.expectEqualStrings("new body", modified_result.modified_body);

    const respond_result = ModuleResult.respond(204, "");
    try std.testing.expectEqual(ModuleResult.Action.respond_immediately, respond_result.action);
    try std.testing.expectEqual(@as(u16, 204), respond_result.status);
}

test "ModuleRequest.getHeader" {
    // Test with null header function
    const req_no_headers = ModuleRequest{
        .method = .GET,
        .path = "/test",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = &.{},
        .headers_ctx = null,
        .get_header_fn = null,
    };
    try std.testing.expect(req_no_headers.getHeader("content-type") == null);
}
