const std = @import("std");
const proxy_module = @import("../modules/proxy_module.zig");

const ModuleId = proxy_module.ModuleId;
const ModuleConfig = proxy_module.ModuleConfig;
const RoutePattern = proxy_module.RoutePattern;
const MethodBitmask = proxy_module.MethodBitmask;
const HttpMethod = proxy_module.HttpMethod;

/// Result of a route match
pub const MatchResult = struct {
    module_id: ModuleId,
    /// Remaining path after match (for prefix routes)
    remaining_path: []const u8,
};

/// Internal representation for prefix routes, sorted by length
const PrefixRoute = struct {
    prefix: []const u8,
    prefix_len: u32,
    module_id: ModuleId,
    methods: MethodBitmask,
};

/// Internal representation for suffix routes
const SuffixRoute = struct {
    suffix: []const u8,
    module_id: ModuleId,
    methods: MethodBitmask,
};

/// Hash key for exact matches (includes method)
const ExactMatchKey = struct {
    hash: u64,
    method: HttpMethod,
};

/// Fast routing table built at startup
/// O(1) for exact matches, O(n) for prefix/suffix matches
pub const Router = struct {
    /// Hash table for exact matches (most common case)
    /// Key is path hash, value is module ID
    exact_matches: std.AutoHashMapUnmanaged(u64, ExactMatchEntry),

    /// Prefix routes sorted by length (longest first)
    prefix_routes: []PrefixRoute,

    /// Suffix routes
    suffix_routes: []SuffixRoute,

    /// Fallback route (wildcard "/*")
    fallback: ?FallbackRoute,

    allocator: std.mem.Allocator,

    const ExactMatchEntry = struct {
        module_id: ModuleId,
        methods: MethodBitmask,
    };

    const FallbackRoute = struct {
        module_id: ModuleId,
        methods: MethodBitmask,
    };

    /// Initialize router from module configurations
    pub fn init(allocator: std.mem.Allocator, modules: []const ModuleConfig) !Router {
        var exact_matches = std.AutoHashMapUnmanaged(u64, ExactMatchEntry){};
        var prefix_list = std.ArrayListUnmanaged(PrefixRoute){};
        var suffix_list = std.ArrayListUnmanaged(SuffixRoute){};
        var fallback: ?FallbackRoute = null;

        // Process all routes from all modules
        for (modules) |mod_config| {
            for (mod_config.routes) |route_pattern| {
                switch (route_pattern.pattern_type) {
                    .exact => {
                        try exact_matches.put(allocator, route_pattern.hash, .{
                            .module_id = mod_config.id,
                            .methods = route_pattern.methods,
                        });
                    },
                    .prefix => {
                        try prefix_list.append(allocator, .{
                            .prefix = route_pattern.pattern,
                            .prefix_len = @intCast(route_pattern.pattern.len),
                            .module_id = mod_config.id,
                            .methods = route_pattern.methods,
                        });
                    },
                    .suffix => {
                        try suffix_list.append(allocator, .{
                            .suffix = route_pattern.pattern,
                            .module_id = mod_config.id,
                            .methods = route_pattern.methods,
                        });
                    },
                    .any => {
                        // Last one wins for wildcard
                        fallback = .{
                            .module_id = mod_config.id,
                            .methods = route_pattern.methods,
                        };
                    },
                }
            }
        }

        // Sort prefix routes by length (longest first) for correct matching
        const prefix_routes = try prefix_list.toOwnedSlice(allocator);
        std.mem.sort(PrefixRoute, prefix_routes, {}, struct {
            fn lessThan(_: void, a: PrefixRoute, b: PrefixRoute) bool {
                return a.prefix_len > b.prefix_len; // Longest first
            }
        }.lessThan);

        return .{
            .exact_matches = exact_matches,
            .prefix_routes = prefix_routes,
            .suffix_routes = try suffix_list.toOwnedSlice(allocator),
            .fallback = fallback,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Router) void {
        self.exact_matches.deinit(self.allocator);
        self.allocator.free(self.prefix_routes);
        self.allocator.free(self.suffix_routes);
    }

    /// Route a request to the appropriate module
    /// O(1) for exact matches, O(n) for prefix/suffix matches
    pub fn route(self: *const Router, path: []const u8, method: HttpMethod) ?MatchResult {
        // 1. Try exact hash match first (fastest path)
        const hash = std.hash.Wyhash.hash(0, path);
        if (self.exact_matches.get(hash)) |entry| {
            if (entry.methods.matches(method)) {
                return .{
                    .module_id = entry.module_id,
                    .remaining_path = "",
                };
            }
        }

        // 2. Try prefix matches (longest first)
        for (self.prefix_routes) |prefix_route| {
            if (std.mem.startsWith(u8, path, prefix_route.prefix)) {
                if (prefix_route.methods.matches(method)) {
                    return .{
                        .module_id = prefix_route.module_id,
                        .remaining_path = path[prefix_route.prefix_len..],
                    };
                }
            }
        }

        // 3. Try suffix matches
        for (self.suffix_routes) |suffix_route| {
            if (std.mem.endsWith(u8, path, suffix_route.suffix)) {
                if (suffix_route.methods.matches(method)) {
                    return .{
                        .module_id = suffix_route.module_id,
                        .remaining_path = path,
                    };
                }
            }
        }

        // 4. Fallback to wildcard
        if (self.fallback) |fb| {
            if (fb.methods.matches(method)) {
                return .{
                    .module_id = fb.module_id,
                    .remaining_path = path,
                };
            }
        }

        return null;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "Router exact match" {
    const allocator = std.testing.allocator;

    const routes = [_]RoutePattern{
        RoutePattern.exact("/api/v2/logs", .{ .post = true }),
    };

    const modules = [_]ModuleConfig{
        .{
            .id = @enumFromInt(0),
            .routes = &routes,
            .upstream = .{
                .scheme = "https",
                .host = "example.com",
                .port = 443,
                .base_path = "",
                .max_request_body = 1024,
                .max_response_body = 1024,
            },
            .module_data = null,
        },
    };

    var router = try Router.init(allocator, &modules);
    defer router.deinit();

    // Exact match with correct method
    const result = router.route("/api/v2/logs", .POST);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(result.?.module_id));
    try std.testing.expectEqualStrings("", result.?.remaining_path);

    // Exact match with wrong method
    const no_match = router.route("/api/v2/logs", .GET);
    try std.testing.expect(no_match == null);

    // No match for different path
    const no_path = router.route("/api/v1/logs", .POST);
    try std.testing.expect(no_path == null);
}

test "Router prefix match" {
    const allocator = std.testing.allocator;

    const routes = [_]RoutePattern{
        RoutePattern.prefix("/api/v2/", MethodBitmask.all),
    };

    const modules = [_]ModuleConfig{
        .{
            .id = @enumFromInt(0),
            .routes = &routes,
            .upstream = .{
                .scheme = "https",
                .host = "example.com",
                .port = 443,
                .base_path = "",
                .max_request_body = 1024,
                .max_response_body = 1024,
            },
            .module_data = null,
        },
    };

    var router = try Router.init(allocator, &modules);
    defer router.deinit();

    // Prefix match
    const result = router.route("/api/v2/logs", .POST);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("logs", result.?.remaining_path);

    // Another prefix match
    const result2 = router.route("/api/v2/metrics/cpu", .GET);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqualStrings("metrics/cpu", result2.?.remaining_path);

    // No match for different prefix
    const no_match = router.route("/api/v1/logs", .POST);
    try std.testing.expect(no_match == null);
}

test "Router fallback match" {
    const allocator = std.testing.allocator;

    const routes = [_]RoutePattern{
        RoutePattern.exact("/specific", .{ .get = true }),
        RoutePattern.any(MethodBitmask.all),
    };

    const modules = [_]ModuleConfig{
        .{
            .id = @enumFromInt(0),
            .routes = &routes,
            .upstream = .{
                .scheme = "https",
                .host = "example.com",
                .port = 443,
                .base_path = "",
                .max_request_body = 1024,
                .max_response_body = 1024,
            },
            .module_data = null,
        },
    };

    var router = try Router.init(allocator, &modules);
    defer router.deinit();

    // Exact match takes priority
    const exact = router.route("/specific", .GET);
    try std.testing.expect(exact != null);
    try std.testing.expectEqualStrings("", exact.?.remaining_path);

    // Fallback for unmatched paths
    const fallback = router.route("/anything/else", .POST);
    try std.testing.expect(fallback != null);
    try std.testing.expectEqualStrings("/anything/else", fallback.?.remaining_path);
}

test "Router prefix priority (longest first)" {
    const allocator = std.testing.allocator;

    // Module 0 has shorter prefix
    const routes0 = [_]RoutePattern{
        RoutePattern.prefix("/api/", MethodBitmask.all),
    };

    // Module 1 has longer prefix
    const routes1 = [_]RoutePattern{
        RoutePattern.prefix("/api/v2/", MethodBitmask.all),
    };

    const modules = [_]ModuleConfig{
        .{
            .id = @enumFromInt(0),
            .routes = &routes0,
            .upstream = .{
                .scheme = "https",
                .host = "example.com",
                .port = 443,
                .base_path = "",
                .max_request_body = 1024,
                .max_response_body = 1024,
            },
            .module_data = null,
        },
        .{
            .id = @enumFromInt(1),
            .routes = &routes1,
            .upstream = .{
                .scheme = "https",
                .host = "example2.com",
                .port = 443,
                .base_path = "",
                .max_request_body = 1024,
                .max_response_body = 1024,
            },
            .module_data = null,
        },
    };

    var router = try Router.init(allocator, &modules);
    defer router.deinit();

    // /api/v2/logs should match module 1 (longer prefix)
    const result = router.route("/api/v2/logs", .POST);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u32, 1), @intFromEnum(result.?.module_id));

    // /api/v1/logs should match module 0 (shorter prefix)
    const result2 = router.route("/api/v1/logs", .POST);
    try std.testing.expect(result2 != null);
    try std.testing.expectEqual(@as(u32, 0), @intFromEnum(result2.?.module_id));
}
