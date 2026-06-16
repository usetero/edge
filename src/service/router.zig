//! Routing table built once at startup. Ported from proxy/router.zig with
//! identical matching semantics: O(1) exact hash lookup (with path equality
//! check against collisions), then prefix routes longest-first, then suffix
//! routes, then the wildcard fallback. Matches resolve to a ServiceIndex
//! into the distro's service table instead of a ModuleId.
const std = @import("std");
const service_mod = @import("service.zig");

const ServiceIndex = service_mod.ServiceIndex;
const RoutePattern = service_mod.RoutePattern;
const MethodBitmask = service_mod.MethodBitmask;
const HttpMethod = service_mod.HttpMethod;

/// Result of a route match
pub const MatchResult = struct {
    service: ServiceIndex,
    /// Remaining path after match (for prefix routes)
    remaining_path: []const u8,
};

/// Internal representation for prefix routes, sorted by length
const PrefixRoute = struct {
    prefix: []const u8,
    prefix_len: u32,
    service: ServiceIndex,
    methods: MethodBitmask,
};

/// Internal representation for suffix routes
const SuffixRoute = struct {
    suffix: []const u8,
    service: ServiceIndex,
    methods: MethodBitmask,
};

/// One service's routes, in registration order (health first, passthrough
/// last — order only matters for the wildcard, where last wins).
pub const RouteSet = struct {
    service: ServiceIndex,
    routes: []const RoutePattern,
};

pub const Router = struct {
    /// Hash table for exact matches (most common case)
    exact_matches: std.AutoHashMapUnmanaged(u64, ExactMatchEntry),

    /// Prefix routes sorted by length (longest first)
    prefix_routes: []PrefixRoute,

    /// Suffix routes
    suffix_routes: []SuffixRoute,

    /// Fallback route (wildcard "/*")
    fallback: ?FallbackRoute,

    allocator: std.mem.Allocator,

    const ExactMatchEntry = struct {
        path: []const u8,
        service: ServiceIndex,
        methods: MethodBitmask,
    };

    const FallbackRoute = struct {
        service: ServiceIndex,
        methods: MethodBitmask,
    };

    pub fn init(allocator: std.mem.Allocator, route_sets: []const RouteSet) !Router {
        var exact_matches = std.AutoHashMapUnmanaged(u64, ExactMatchEntry).empty;
        errdefer exact_matches.deinit(allocator);
        var prefix_list = std.ArrayList(PrefixRoute).empty;
        errdefer prefix_list.deinit(allocator);
        var suffix_list = std.ArrayList(SuffixRoute).empty;
        errdefer suffix_list.deinit(allocator);
        var fallback: ?FallbackRoute = null;

        for (route_sets) |set| {
            for (set.routes) |route_pattern| {
                switch (route_pattern.pattern_type) {
                    .exact => {
                        try exact_matches.put(allocator, route_pattern.hash, .{
                            .path = route_pattern.pattern,
                            .service = set.service,
                            .methods = route_pattern.methods,
                        });
                    },
                    .prefix => {
                        try prefix_list.append(allocator, .{
                            .prefix = route_pattern.pattern,
                            .prefix_len = @intCast(route_pattern.pattern.len),
                            .service = set.service,
                            .methods = route_pattern.methods,
                        });
                    },
                    .suffix => {
                        try suffix_list.append(allocator, .{
                            .suffix = route_pattern.pattern,
                            .service = set.service,
                            .methods = route_pattern.methods,
                        });
                    },
                    .any => {
                        // Last one wins for wildcard
                        fallback = .{
                            .service = set.service,
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
        self.* = undefined;
    }

    /// O(1) for exact matches, O(n) for prefix/suffix matches.
    pub fn route(self: *const Router, path: []const u8, method: HttpMethod) ?MatchResult {
        // 1. Try exact hash match first (fastest path)
        const hash = std.hash.Wyhash.hash(0, path);
        if (self.exact_matches.get(hash)) |entry| {
            if (std.mem.eql(u8, entry.path, path) and entry.methods.matches(method)) {
                return .{
                    .service = entry.service,
                    .remaining_path = "",
                };
            }
        }

        // 2. Try prefix matches (longest first)
        for (self.prefix_routes) |prefix_route| {
            if (std.mem.startsWith(u8, path, prefix_route.prefix)) {
                if (prefix_route.methods.matches(method)) {
                    return .{
                        .service = prefix_route.service,
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
                        .service = suffix_route.service,
                        .remaining_path = path,
                    };
                }
            }
        }

        // 4. Fallback to wildcard
        if (self.fallback) |fb| {
            if (fb.methods.matches(method)) {
                return .{
                    .service = fb.service,
                    .remaining_path = path,
                };
            }
        }

        return null;
    }
};

// =============================================================================
// Tests — ported from proxy/router.zig; assertion logic unchanged, the
// construction surface is RouteSet instead of ModuleConfig.
// =============================================================================

const testing = std.testing;

fn idx(n: u16) ServiceIndex {
    return @enumFromInt(n);
}

test "Router exact match" {
    const allocator = testing.allocator;

    const routes = [_]RoutePattern{
        .exact("/api/v2/logs", .{ .post = true }),
    };
    const sets = [_]RouteSet{
        .{ .service = idx(0), .routes = &routes },
    };

    var router = try Router.init(allocator, &sets);
    defer router.deinit();

    // Exact match with correct method
    const result = router.route("/api/v2/logs", .POST);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u16, 0), @intFromEnum(result.?.service));
    try testing.expectEqualStrings("", result.?.remaining_path);

    // Exact match with wrong method
    const no_match = router.route("/api/v2/logs", .GET);
    try testing.expect(no_match == null);

    // No match for different path
    const no_path = router.route("/api/v1/logs", .POST);
    try testing.expect(no_path == null);
}

test "Router exact hash hit requires path equality" {
    const allocator = testing.allocator;

    var exact_matches: std.AutoHashMapUnmanaged(u64, Router.ExactMatchEntry) = .empty;
    defer exact_matches.deinit(allocator);

    const target_path = "/api/v2/logs";
    const hash = std.hash.Wyhash.hash(0, target_path);

    try exact_matches.put(allocator, hash, .{
        .path = "/different-path",
        .service = idx(0),
        .methods = .{ .post = true },
    });

    const empty_prefix = try allocator.alloc(PrefixRoute, 0);
    defer allocator.free(empty_prefix);
    const empty_suffix = try allocator.alloc(SuffixRoute, 0);
    defer allocator.free(empty_suffix);

    const router: Router = .{
        .exact_matches = exact_matches,
        .prefix_routes = empty_prefix,
        .suffix_routes = empty_suffix,
        .fallback = null,
        .allocator = allocator,
    };

    const result = router.route(target_path, .POST);
    try testing.expect(result == null);
}

test "Router prefix match" {
    const allocator = testing.allocator;

    const routes = [_]RoutePattern{
        .prefix("/api/v2/", .all),
    };
    const sets = [_]RouteSet{
        .{ .service = idx(0), .routes = &routes },
    };

    var router = try Router.init(allocator, &sets);
    defer router.deinit();

    const result = router.route("/api/v2/logs", .POST);
    try testing.expect(result != null);
    try testing.expectEqualStrings("logs", result.?.remaining_path);

    const deep = router.route("/api/v2/a/b/c", .GET);
    try testing.expect(deep != null);
    try testing.expectEqualStrings("a/b/c", deep.?.remaining_path);

    const no_match = router.route("/api/v1/logs", .POST);
    try testing.expect(no_match == null);
}

test "Router longest prefix wins" {
    const allocator = testing.allocator;

    const short_routes = [_]RoutePattern{
        .prefix("/api/", .all),
    };
    const long_routes = [_]RoutePattern{
        .prefix("/api/v2/", .all),
    };
    const sets = [_]RouteSet{
        .{ .service = idx(0), .routes = &short_routes },
        .{ .service = idx(1), .routes = &long_routes },
    };

    var router = try Router.init(allocator, &sets);
    defer router.deinit();

    const result = router.route("/api/v2/logs", .POST);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u16, 1), @intFromEnum(result.?.service));
}

test "Router suffix match" {
    const allocator = testing.allocator;

    const routes = [_]RoutePattern{
        .suffix("/v1/logs", .{ .post = true }),
    };
    const sets = [_]RouteSet{
        .{ .service = idx(0), .routes = &routes },
    };

    var router = try Router.init(allocator, &sets);
    defer router.deinit();

    const direct = router.route("/v1/logs", .POST);
    try testing.expect(direct != null);

    const nested = router.route("/anything/v1/logs", .POST);
    try testing.expect(nested != null);
    try testing.expectEqualStrings("/anything/v1/logs", nested.?.remaining_path);

    const no_match = router.route("/v1/metrics", .POST);
    try testing.expect(no_match == null);
}

test "Router wildcard fallback and registration order" {
    const allocator = testing.allocator;

    const exact_routes = [_]RoutePattern{
        .exact("/_health", .{ .get = true }),
    };
    const wildcard = [_]RoutePattern{
        .any(.all),
    };
    const sets = [_]RouteSet{
        .{ .service = idx(0), .routes = &exact_routes },
        .{ .service = idx(1), .routes = &wildcard },
    };

    var router = try Router.init(allocator, &sets);
    defer router.deinit();

    // Exact beats wildcard
    const health = router.route("/_health", .GET);
    try testing.expectEqual(@as(u16, 0), @intFromEnum(health.?.service));

    // Everything else falls through
    const other = router.route("/random/path", .DELETE);
    try testing.expectEqual(@as(u16, 1), @intFromEnum(other.?.service));
}
