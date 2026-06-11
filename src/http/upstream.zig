//! Upstream HTTP client manager: pre-parsed upstream URL components in a
//! MultiArrayList (SoA) plus one shared std.http.Client whose connection
//! pool is mutex-protected and rides entirely on std.Io. Ported from
//! proxy/upstream_client.zig; ModuleId became UpstreamId (index into this
//! manager, resolved from service UpstreamChoice at startup).
const std = @import("std");

/// Index of one configured upstream in this manager.
pub const UpstreamId = enum(u32) { _ };

/// Pre-parsed upstream components handed to outcome execution.
pub const UpstreamConfig = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,
    max_request_body: u32,
    max_response_body: u32,
};

/// Minimum buffer size required for TLS operations
const tls_min_buffer = std.crypto.tls.max_ciphertext_record_len;

/// Internal storage for upstream data
const UpstreamData = struct {
    /// Pre-parsed URL components
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,

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
pub const UpstreamManager = struct {
    /// SoA for all upstream configs
    upstreams: std.MultiArrayList(UpstreamData),

    /// Shared HTTP client with connection pooling.
    /// Thread-safe for creating requests; individual requests are not thread-safe.
    http_client: std.http.Client,

    /// Thread-safe allocator for HTTP client operations
    allocator: std.mem.Allocator,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, pool_size: usize) UpstreamManager {
        return .{
            .upstreams = .{},
            .http_client = .{
                .allocator = allocator,
                .io = io,
                // TLS requires buffers of at least max_ciphertext_record_len for read/write
                .tls_buffer_size = tls_min_buffer,
                .read_buffer_size = tls_min_buffer,
                .write_buffer_size = tls_min_buffer,
                // std's default keeps only 32 idle connections; with one
                // in-flight upstream request per downstream connection,
                // anything smaller than max_connections forces fresh dials
                // under load and exhausts ephemeral ports (AddressUnavailable).
                .connection_pool = .{ .free_size = pool_size },
            },
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *UpstreamManager) void {
        // Deinit HTTP client first (closes all pooled connections)
        self.http_client.deinit();

        const slice = self.upstreams.slice();

        // Free all allocated strings
        for (0..self.upstreams.len) |i| {
            self.allocator.free(slice.items(.scheme)[i]);
            self.allocator.free(slice.items(.host)[i]);
            self.allocator.free(slice.items(.base_path)[i]);
        }

        self.upstreams.deinit(self.allocator);
        self.* = undefined;
    }

    /// Get the shared HTTP client for making upstream requests.
    /// The client is thread-safe for creating requests.
    /// Individual Request objects returned by client.request() must be used
    /// by a single thread only.
    pub fn getHttpClient(self: *UpstreamManager) *std.http.Client {
        return &self.http_client;
    }

    /// Create an upstream configuration from a URL
    /// Returns the UpstreamId used to reference this upstream
    pub fn createUpstream(
        self: *UpstreamManager,
        upstream_url: []const u8,
        max_path_length: u32,
        max_request_body: u32,
        max_response_body: u32,
    ) !UpstreamId {
        _ = max_path_length;
        const uri = try std.Uri.parse(upstream_url);

        const scheme = try self.allocator.dupe(u8, uri.scheme);
        errdefer self.allocator.free(scheme);

        // Uri.host is a Component which can be percent_encoded or raw
        const host_str = if (uri.host) |h| h.percent_encoded else return error.MissingHost;
        const host = try self.allocator.dupe(u8, host_str);
        errdefer self.allocator.free(host);

        const base_path = if (uri.path.percent_encoded.len > 0)
            try self.allocator.dupe(u8, uri.path.percent_encoded)
        else
            try self.allocator.dupe(u8, "");
        errdefer self.allocator.free(base_path);

        const port = uri.port orelse if (std.mem.eql(u8, scheme, "https")) @as(u16, 443) else @as(u16, 80);

        const upstream_data: UpstreamData = .{
            .scheme = scheme,
            .host = host,
            .port = port,
            .base_path = base_path,
            .max_request_body = max_request_body,
            .max_response_body = max_response_body,
        };

        try self.upstreams.append(self.allocator, upstream_data);
        return @enumFromInt(@as(u32, @intCast(self.upstreams.len - 1)));
    }

    pub fn getUpstreamConfig(self: *const UpstreamManager, upstream_id: UpstreamId) UpstreamConfig {
        const idx = @intFromEnum(upstream_id);
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

    pub fn getMaxResponseBody(self: *const UpstreamManager, upstream_id: UpstreamId) u32 {
        const idx = @intFromEnum(upstream_id);
        return self.upstreams.slice().items(.max_response_body)[idx];
    }

    /// Build upstream URI from stored components.
    /// Caller owns returned memory.
    pub fn buildUpstreamUri(
        self: *UpstreamManager,
        allocator: std.mem.Allocator,
        upstream_id: UpstreamId,
        request_path: []const u8,
        query_string: []const u8,
    ) ![]const u8 {
        const idx = @intFromEnum(upstream_id);
        const slice = self.upstreams.slice();

        const scheme = slice.items(.scheme)[idx];
        const host = slice.items(.host)[idx];
        const port = slice.items(.port)[idx];
        const base_path = slice.items(.base_path)[idx];
        var out: std.Io.Writer.Allocating = .init(allocator);
        errdefer out.deinit();
        const writer = &out.writer;

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

        return out.toOwnedSlice();
    }
};

// =============================================================================
// Tests
// =============================================================================

test "UpstreamManager createUpstream parses URL correctly" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const upstream_id = try manager.createUpstream(
        "https://intake.logs.datadoghq.com/api/v2",
        2048,
        10 * 1024 * 1024,
        10 * 1024 * 1024,
    );

    const config = manager.getUpstreamConfig(upstream_id);
    try std.testing.expectEqualStrings("https", config.scheme);
    try std.testing.expectEqualStrings("intake.logs.datadoghq.com", config.host);
    try std.testing.expectEqual(@as(u16, 443), config.port);
    try std.testing.expectEqualStrings("/api/v2", config.base_path);
}

test "UpstreamManager createUpstream with explicit port" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const upstream_id = try manager.createUpstream(
        "http://localhost:8080/proxy",
        2048,
        1024,
        1024,
    );

    const config = manager.getUpstreamConfig(upstream_id);
    try std.testing.expectEqualStrings("http", config.scheme);
    try std.testing.expectEqualStrings("localhost", config.host);
    try std.testing.expectEqual(@as(u16, 8080), config.port);
    try std.testing.expectEqualStrings("/proxy", config.base_path);
}

test "UpstreamManager buildUpstreamUri" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const upstream_id = try manager.createUpstream(
        "https://api.example.com/v2",
        2048,
        1024,
        1024,
    );

    // Test basic path
    const uri1 = try manager.buildUpstreamUri(allocator, upstream_id, "/logs", "");
    defer allocator.free(uri1);
    try std.testing.expectEqualStrings("https://api.example.com/v2/logs", uri1);

    // Test with query string
    const uri2 = try manager.buildUpstreamUri(allocator, upstream_id, "/logs", "api_key=xxx&source=test");
    defer allocator.free(uri2);
    try std.testing.expectEqualStrings("https://api.example.com/v2/logs?api_key=xxx&source=test", uri2);

    // Test empty path
    const uri3 = try manager.buildUpstreamUri(allocator, upstream_id, "", "");
    defer allocator.free(uri3);
    try std.testing.expectEqualStrings("https://api.example.com/v2", uri3);
}

test "UpstreamManager buildUpstreamUri with non-standard port" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const upstream_id = try manager.createUpstream(
        "http://localhost:9999",
        2048,
        1024,
        1024,
    );

    const uri = try manager.buildUpstreamUri(allocator, upstream_id, "/test", "");
    defer allocator.free(uri);
    try std.testing.expectEqualStrings("http://localhost:9999/test", uri);
}

test "UpstreamManager multiple upstreams" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const id0 = try manager.createUpstream("https://api1.example.com", 2048, 1024, 1024);
    const id1 = try manager.createUpstream("https://api2.example.com", 2048, 1024, 1024);

    const config0 = manager.getUpstreamConfig(id0);
    const config1 = manager.getUpstreamConfig(id1);

    try std.testing.expectEqualStrings("api1.example.com", config0.host);
    try std.testing.expectEqualStrings("api2.example.com", config1.host);
}

// =============================================================================
// Header filtering, ported from io/transport.zig
// =============================================================================

pub fn shouldSkipRequestHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

pub fn shouldSkipResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

test "header skip helpers" {
    try std.testing.expect(shouldSkipRequestHeader("Host"));
    try std.testing.expect(shouldSkipResponseHeader("Transfer-Encoding"));
    try std.testing.expect(!shouldSkipRequestHeader("Content-Type"));
    try std.testing.expect(!shouldSkipResponseHeader("X-Test"));
}

test "shouldSkipRequestHeader" {
    try std.testing.expect(shouldSkipRequestHeader("host"));
    try std.testing.expect(shouldSkipRequestHeader("Host"));
    try std.testing.expect(shouldSkipRequestHeader("HOST"));
    try std.testing.expect(shouldSkipRequestHeader("connection"));
    try std.testing.expect(shouldSkipRequestHeader("Connection"));
    try std.testing.expect(shouldSkipRequestHeader("content-length"));
    try std.testing.expect(shouldSkipRequestHeader("Content-Length"));
    try std.testing.expect(shouldSkipRequestHeader("transfer-encoding"));
    try std.testing.expect(shouldSkipRequestHeader("Transfer-Encoding"));
    try std.testing.expect(!shouldSkipRequestHeader("content-type"));
    try std.testing.expect(!shouldSkipRequestHeader("x-custom-header"));
}

test "shouldSkipResponseHeader" {
    try std.testing.expect(shouldSkipResponseHeader("content-length"));
    try std.testing.expect(shouldSkipResponseHeader("Content-Length"));
    try std.testing.expect(shouldSkipResponseHeader("transfer-encoding"));
    try std.testing.expect(shouldSkipResponseHeader("Transfer-Encoding"));
    try std.testing.expect(!shouldSkipResponseHeader("content-type"));
    try std.testing.expect(!shouldSkipResponseHeader("x-custom-header"));
}
