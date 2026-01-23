const std = @import("std");
const proxy_module = @import("../modules/proxy_module.zig");
const tripwire = @import("../testing/tripwire.zig");

const ModuleId = proxy_module.ModuleId;
const UpstreamConfig = proxy_module.UpstreamConfig;

/// Minimum buffer size required for TLS operations
const tls_min_buffer = std.crypto.tls.max_ciphertext_record_len;

/// Internal storage for upstream data
const UpstreamData = struct {
    /// Pre-parsed URL components
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,

    /// Pre-allocated URI buffer for this upstream
    uri_buffer: []u8,

    /// Maximum request/response sizes
    max_request_body: u32,
    max_response_body: u32,
};

/// Manages upstream configurations and a shared HTTP client pool.
///
/// The HTTP client is thread-safe for connection pooling:
/// - Connection pool operations (acquire, release, find) are mutex-protected
/// - Individual Request objects must be used by a single thread
/// - The allocator passed here MUST be thread-safe (e.g., GeneralPurposeAllocator)
///
/// This enables connection reuse across requests, avoiding TCP/TLS handshake
/// overhead for each request.
pub const UpstreamClientManager = struct {
    /// SoA for all upstream configs
    upstreams: std.MultiArrayList(UpstreamData),

    /// Shared HTTP client with connection pooling.
    /// Thread-safe for creating requests; individual requests are not thread-safe.
    http_client: std.http.Client,

    /// Thread-safe allocator for HTTP client operations
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) UpstreamClientManager {
        return .{
            .upstreams = .{},
            .http_client = .{
                .allocator = allocator,
                // TLS requires buffers of at least max_ciphertext_record_len for read/write
                .tls_buffer_size = tls_min_buffer,
                .read_buffer_size = tls_min_buffer,
                .write_buffer_size = tls_min_buffer,
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UpstreamClientManager) void {
        // Deinit HTTP client first (closes all pooled connections)
        self.http_client.deinit();

        const slice = self.upstreams.slice();

        // Free all allocated strings and buffers
        for (0..self.upstreams.len) |i| {
            self.allocator.free(slice.items(.scheme)[i]);
            self.allocator.free(slice.items(.host)[i]);
            self.allocator.free(slice.items(.base_path)[i]);
            self.allocator.free(slice.items(.uri_buffer)[i]);
        }

        self.upstreams.deinit(self.allocator);
    }

    /// Get the shared HTTP client for making upstream requests.
    /// The client is thread-safe for creating requests.
    /// Individual Request objects returned by client.request() must be used
    /// by a single thread only.
    pub fn getHttpClient(self: *UpstreamClientManager) *std.http.Client {
        return &self.http_client;
    }

    /// Tripwire for testing error paths in createUpstream
    pub const create_upstream_tw = tripwire.module(enum {
        dupe_scheme,
        dupe_host,
        dupe_base_path,
        alloc_uri_buffer,
        append_upstream,
    }, error{OutOfMemory});

    /// Create an upstream configuration from a URL
    /// Returns the ModuleId that can be used to reference this upstream
    pub fn createUpstream(
        self: *UpstreamClientManager,
        upstream_url: []const u8,
        max_path_length: u32,
        max_request_body: u32,
        max_response_body: u32,
    ) !ModuleId {
        const uri = try std.Uri.parse(upstream_url);

        try create_upstream_tw.check(.dupe_scheme);
        const scheme = try self.allocator.dupe(u8, uri.scheme);
        errdefer self.allocator.free(scheme);

        // Uri.host is a Component which can be percent_encoded or raw
        const host_str = if (uri.host) |h| h.percent_encoded else return error.MissingHost;
        try create_upstream_tw.check(.dupe_host);
        const host = try self.allocator.dupe(u8, host_str);
        errdefer self.allocator.free(host);

        try create_upstream_tw.check(.dupe_base_path);
        const base_path = if (uri.path.percent_encoded.len > 0)
            try self.allocator.dupe(u8, uri.path.percent_encoded)
        else
            try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(base_path);

        // URI buffer needs to fit: scheme + "://" + host + ":" + port + base_path + path + "?" + query
        // Max port is 5 digits, scheme is ~8, separators ~10, so add ~530 for overhead
        try create_upstream_tw.check(.alloc_uri_buffer);
        const uri_buffer = try self.allocator.alloc(u8, max_path_length + 530);
        errdefer self.allocator.free(uri_buffer);

        const port = uri.port orelse if (std.mem.eql(u8, scheme, "https")) @as(u16, 443) else @as(u16, 80);

        const upstream_data = UpstreamData{
            .scheme = scheme,
            .host = host,
            .port = port,
            .base_path = base_path,
            .uri_buffer = uri_buffer,
            .max_request_body = max_request_body,
            .max_response_body = max_response_body,
        };

        try create_upstream_tw.check(.append_upstream);
        try self.upstreams.append(self.allocator, upstream_data);
        return @enumFromInt(@as(u32, @intCast(self.upstreams.len - 1)));
    }

    /// Get the upstream config for a module
    pub fn getUpstreamConfig(self: *const UpstreamClientManager, module_id: ModuleId) UpstreamConfig {
        const idx = @intFromEnum(module_id);
        const slice = self.upstreams.slice();

        return .{
            .scheme = slice.items(.scheme)[idx],
            .host = slice.items(.host)[idx],
            .port = slice.items(.port)[idx],
            .base_path = slice.items(.base_path)[idx],
            .max_request_body = slice.items(.max_request_body)[idx],
            .max_response_body = slice.items(.max_response_body)[idx],
        };
    }

    /// Get max response body size for a module
    pub fn getMaxResponseBody(self: *const UpstreamClientManager, module_id: ModuleId) u32 {
        const idx = @intFromEnum(module_id);
        return self.upstreams.slice().items(.max_response_body)[idx];
    }

    /// Build upstream URI from pre-allocated components (zero allocation)
    /// Returns a slice into the pre-allocated buffer
    pub fn buildUpstreamUri(
        self: *UpstreamClientManager,
        module_id: ModuleId,
        request_path: []const u8,
        query_string: []const u8,
    ) ![]const u8 {
        const idx = @intFromEnum(module_id);
        const slice = self.upstreams.slice();

        const scheme = slice.items(.scheme)[idx];
        const host = slice.items(.host)[idx];
        const port = slice.items(.port)[idx];
        const base_path = slice.items(.base_path)[idx];
        const uri_buffer = slice.items(.uri_buffer)[idx];

        var fbs = std.io.fixedBufferStream(uri_buffer);
        const writer = fbs.writer();

        try writer.writeAll(scheme);
        try writer.writeAll("://");
        try writer.writeAll(host);

        // Only include port if non-standard
        const is_standard_port = (std.mem.eql(u8, scheme, "https") and port == 443) or
            (std.mem.eql(u8, scheme, "http") and port == 80);
        if (!is_standard_port) {
            try writer.print(":{d}", .{port});
        }

        // Add base path if present and not just "/"
        if (base_path.len > 0 and !std.mem.eql(u8, base_path, "/")) {
            try writer.writeAll(base_path);
        }

        // Add separator if needed between base_path and request_path
        if (request_path.len > 0) {
            const needs_separator = (base_path.len == 0 or base_path[base_path.len - 1] != '/') and
                request_path[0] != '/';
            if (needs_separator) {
                try writer.writeAll("/");
            }
            try writer.writeAll(request_path);
        }

        // Add query string if present
        if (query_string.len > 0) {
            try writer.writeAll("?");
            try writer.writeAll(query_string);
        }

        return fbs.getWritten();
    }
};

// =============================================================================
// Tests
// =============================================================================

test "UpstreamClientManager createUpstream parses URL correctly" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    const module_id = try manager.createUpstream(
        "https://intake.logs.datadoghq.com/api/v2",
        2048,
        10 * 1024 * 1024,
        10 * 1024 * 1024,
    );

    const config = manager.getUpstreamConfig(module_id);
    try std.testing.expectEqualStrings("https", config.scheme);
    try std.testing.expectEqualStrings("intake.logs.datadoghq.com", config.host);
    try std.testing.expectEqual(@as(u16, 443), config.port);
    try std.testing.expectEqualStrings("/api/v2", config.base_path);
}

test "UpstreamClientManager createUpstream with explicit port" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    const module_id = try manager.createUpstream(
        "http://localhost:8080/proxy",
        2048,
        1024,
        1024,
    );

    const config = manager.getUpstreamConfig(module_id);
    try std.testing.expectEqualStrings("http", config.scheme);
    try std.testing.expectEqualStrings("localhost", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
    try std.testing.expectEqualStrings("/proxy", config.base_path);
}

test "UpstreamClientManager buildUpstreamUri" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    const module_id = try manager.createUpstream(
        "https://api.example.com/v2",
        2048,
        1024,
        1024,
    );

    // Test basic path
    const uri1 = try manager.buildUpstreamUri(module_id, "/logs", "");
    try std.testing.expectEqualStrings("https://api.example.com/v2/logs", uri1);

    // Test with query string
    const uri2 = try manager.buildUpstreamUri(module_id, "/logs", "api_key=xxx&source=test");
    try std.testing.expectEqualStrings("https://api.example.com/v2/logs?api_key=xxx&source=test", uri2);

    // Test empty path
    const uri3 = try manager.buildUpstreamUri(module_id, "", "");
    try std.testing.expectEqualStrings("https://api.example.com/v2", uri3);
}

test "UpstreamClientManager buildUpstreamUri with non-standard port" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    const module_id = try manager.createUpstream(
        "http://localhost:9999",
        2048,
        1024,
        1024,
    );

    const uri = try manager.buildUpstreamUri(module_id, "/test", "");
    try std.testing.expectEqualStrings("http://localhost:9999/test", uri);
}

test "UpstreamClientManager multiple upstreams" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    const id0 = try manager.createUpstream("https://api1.example.com", 2048, 1024, 1024);
    const id1 = try manager.createUpstream("https://api2.example.com", 2048, 1024, 1024);

    const config0 = manager.getUpstreamConfig(id0);
    const config1 = manager.getUpstreamConfig(id1);

    try std.testing.expectEqualStrings("api1.example.com", config0.host);
    try std.testing.expectEqualStrings("api2.example.com", config1.host);
}

// -----------------------------------------------------------------------------
// Tripwire Tests for createUpstream
// -----------------------------------------------------------------------------

test "UpstreamClientManager.createUpstream: tripwire dupe_scheme fails" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    UpstreamClientManager.create_upstream_tw.errorAlways(.dupe_scheme, error.OutOfMemory);
    defer UpstreamClientManager.create_upstream_tw.reset();

    const result = manager.createUpstream("https://example.com", 2048, 1024, 1024);
    try std.testing.expectError(error.OutOfMemory, result);
    try UpstreamClientManager.create_upstream_tw.end(.retain);
}

test "UpstreamClientManager.createUpstream: tripwire dupe_host fails" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    UpstreamClientManager.create_upstream_tw.errorAlways(.dupe_host, error.OutOfMemory);
    defer UpstreamClientManager.create_upstream_tw.reset();

    const result = manager.createUpstream("https://example.com", 2048, 1024, 1024);
    try std.testing.expectError(error.OutOfMemory, result);
    try UpstreamClientManager.create_upstream_tw.end(.retain);
}

test "UpstreamClientManager.createUpstream: tripwire dupe_base_path fails" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    UpstreamClientManager.create_upstream_tw.errorAlways(.dupe_base_path, error.OutOfMemory);
    defer UpstreamClientManager.create_upstream_tw.reset();

    const result = manager.createUpstream("https://example.com/api/v2", 2048, 1024, 1024);
    try std.testing.expectError(error.OutOfMemory, result);
    try UpstreamClientManager.create_upstream_tw.end(.retain);
}

test "UpstreamClientManager.createUpstream: tripwire alloc_uri_buffer fails" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    UpstreamClientManager.create_upstream_tw.errorAlways(.alloc_uri_buffer, error.OutOfMemory);
    defer UpstreamClientManager.create_upstream_tw.reset();

    const result = manager.createUpstream("https://example.com", 2048, 1024, 1024);
    try std.testing.expectError(error.OutOfMemory, result);
    try UpstreamClientManager.create_upstream_tw.end(.retain);
}

test "UpstreamClientManager.createUpstream: tripwire append_upstream fails" {
    const allocator = std.testing.allocator;

    var manager = UpstreamClientManager.init(allocator);
    defer manager.deinit();

    UpstreamClientManager.create_upstream_tw.errorAlways(.append_upstream, error.OutOfMemory);
    defer UpstreamClientManager.create_upstream_tw.reset();

    const result = manager.createUpstream("https://example.com", 2048, 1024, 1024);
    try std.testing.expectError(error.OutOfMemory, result);
    try UpstreamClientManager.create_upstream_tw.end(.retain);
}
