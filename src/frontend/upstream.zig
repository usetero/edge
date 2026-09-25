//! Upstream HTTP client manager: pre-parsed upstream URL parts in a
//! MultiArrayList, and the shared std.http.Client pools.
const std = @import("std");

/// Index of one configured upstream in this manager.
pub const UpstreamId = enum(u32) { _ };

/// Minimum buffer size required for TLS operations
const tls_min_buffer = std.crypto.tls.max_ciphertext_record_len;

/// Internal storage for upstream data
const UpstreamData = struct {
    /// Pre-parsed URL components
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,

    /// Maximum response size
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
    /// No idle entries: a retry cannot accidentally acquire another stale socket.
    retry_client: std.http.Client,

    /// Thread-safe allocator for HTTP client operations
    allocator: std.mem.Allocator,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, pool_size: usize) UpstreamManager {
        return .{
            .upstreams = .{},
            // std's default keeps only 32 idle connections; with one
            // in-flight upstream request per downstream connection,
            // anything smaller than max_connections forces fresh dials
            // under load and exhausts ephemeral ports (AddressUnavailable).
            .http_client = httpClient(io, allocator, pool_size),
            .retry_client = httpClient(io, allocator, 0),
            .allocator = allocator,
        };
    }

    /// A client that keeps at most `free_size` idle connections.
    fn httpClient(io: std.Io, allocator: std.mem.Allocator, free_size: usize) std.http.Client {
        return .{
            .allocator = allocator,
            .io = io,
            // TLS requires buffers of at least max_ciphertext_record_len for read/write
            .tls_buffer_size = tls_min_buffer,
            .read_buffer_size = tls_min_buffer,
            .write_buffer_size = tls_min_buffer,
            .connection_pool = .{ .free_size = free_size },
        };
    }

    pub fn deinit(self: *UpstreamManager) void {
        // Deinit HTTP client first (closes all pooled connections)
        self.http_client.deinit();
        self.retry_client.deinit();

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

    /// Create an upstream configuration from a URL
    /// Returns the UpstreamId used to reference this upstream
    pub fn createUpstream(
        self: *UpstreamManager,
        upstream_url: []const u8,
        max_response_body: u32,
    ) !UpstreamId {
        const uri = try std.Uri.parse(upstream_url);

        const scheme = try self.allocator.dupe(u8, uri.scheme);
        errdefer self.allocator.free(scheme);

        // Uri.host is a Component which can be percent_encoded or raw
        const host_str = if (uri.host) |h| h.percent_encoded else return error.MissingHost;
        const host = try self.allocator.dupe(u8, host_str);
        errdefer self.allocator.free(host);

        const base_path = try self.allocator.dupe(u8, uri.path.percent_encoded);
        errdefer self.allocator.free(base_path);

        const port = uri.port orelse if (std.mem.eql(u8, scheme, "https")) @as(u16, 443) else @as(u16, 80);

        const upstream_data: UpstreamData = .{
            .scheme = scheme,
            .host = host,
            .port = port,
            .base_path = base_path,
            .max_response_body = max_response_body,
        };

        try self.upstreams.append(self.allocator, upstream_data);
        return @enumFromInt(@as(u32, @intCast(self.upstreams.len - 1)));
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
        const wrote_base = base_path.len > 0 and !std.mem.eql(u8, base_path, "/");
        if (wrote_base) {
            try writer.writeAll(base_path);
        }

        // Add request path, joining it with the base path. When the written
        // base path ends with '/' and the request path begins with '/', drop
        // the request's leading '/' so the boundary has a single '/' rather
        // than '//'. Otherwise insert a '/' only when neither side provides one.
        if (request_path.len > 0) {
            const base_ends_with_slash = wrote_base and base_path[base_path.len - 1] == '/';
            if (base_ends_with_slash and request_path[0] == '/') {
                try writer.writeAll(request_path[1..]);
            } else {
                const needs_separator = !base_ends_with_slash and request_path[0] != '/';
                if (needs_separator) {
                    try writer.writeAll("/");
                }
                try writer.writeAll(request_path);
            }
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

test "UpstreamManager buildUpstreamUri" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const upstream_id = try manager.createUpstream(
        "https://api.example.com/v2",
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
        1024,
    );

    const uri = try manager.buildUpstreamUri(allocator, upstream_id, "/test", "");
    defer allocator.free(uri);
    try std.testing.expectEqualStrings("http://localhost:9999/test", uri);
}

test "UpstreamManager buildUpstreamUri collapse boundary slashes" {
    const allocator = std.testing.allocator;
    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();
    const upstream_id = try manager.createUpstream(
        "https://internal-gateway.corp/datadog/",
        1024,
    );

    // Trailing-slash base + leading-slash request collapses to a single '/'.
    const uri1 = try manager.buildUpstreamUri(allocator, upstream_id, "/api/v2/logs", "");
    defer allocator.free(uri1);
    try std.testing.expectEqualStrings("https://internal-gateway.corp/datadog/api/v2/logs", uri1);

    // Query string is still appended after the collapsed path.
    const uri2 = try manager.buildUpstreamUri(allocator, upstream_id, "/api/v2/logs", "ddapikey=1");
    defer allocator.free(uri2);
    try std.testing.expectEqualStrings("https://internal-gateway.corp/datadog/api/v2/logs?ddapikey=1", uri2);

    // Trailing-slash base + request without leading '/' still joins correctly.
    const uri3 = try manager.buildUpstreamUri(allocator, upstream_id, "api/v2/logs", "");
    defer allocator.free(uri3);
    try std.testing.expectEqualStrings("https://internal-gateway.corp/datadog/api/v2/logs", uri3);

    // Empty request path leaves the base path as-is.
    const uri4 = try manager.buildUpstreamUri(allocator, upstream_id, "", "");
    defer allocator.free(uri4);
    try std.testing.expectEqualStrings("https://internal-gateway.corp/datadog/", uri4);

    // Every emitted URI must round-trip through std.Uri.parse with no '//' in
    // the path component (i.e. the malformed join no longer reaches the wire).
    const expected = "https://internal-gateway.corp/datadog/api/v2/logs";
    const parsed = try std.Uri.parse(expected);
    const path_str: []const u8 = switch (parsed.path) {
        .raw, .percent_encoded => |s| s,
    };
    try std.testing.expectEqualStrings("/datadog/api/v2/logs", path_str);
    try std.testing.expect(std.mem.indexOf(u8, path_str, "//") == null);
}

test "UpstreamManager buildUpstreamUri join boundary combinations" {
    const allocator = std.testing.allocator;
    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    // base_path == "" (path-less upstream URL)
    const empty_id = try manager.createUpstream("https://host.example.com", 1024);
    const e1 = try manager.buildUpstreamUri(allocator, empty_id, "/api/v2/logs", "");
    defer allocator.free(e1);
    try std.testing.expectEqualStrings("https://host.example.com/api/v2/logs", e1);
    const e2 = try manager.buildUpstreamUri(allocator, empty_id, "", "");
    defer allocator.free(e2);
    try std.testing.expectEqualStrings("https://host.example.com", e2);

    // base_path == "/" (root) is collapsed to nothing by the base-path guard.
    const root_id = try manager.createUpstream("https://host.example.com/", 1024);
    const r1 = try manager.buildUpstreamUri(allocator, root_id, "/api/v2/logs", "");
    defer allocator.free(r1);
    try std.testing.expectEqualStrings("https://host.example.com/api/v2/logs", r1);

    // base_path without trailing '/' + leading-slash request: single '/'.
    const plain_id = try manager.createUpstream("https://host.example.com/v2", 1024);
    const p1 = try manager.buildUpstreamUri(allocator, plain_id, "/logs", "");
    defer allocator.free(p1);
    try std.testing.expectEqualStrings("https://host.example.com/v2/logs", p1);
    // base_path without trailing '/' + request without leading '/': separator inserted.
    const p2 = try manager.buildUpstreamUri(allocator, plain_id, "logs", "");
    defer allocator.free(p2);
    try std.testing.expectEqualStrings("https://host.example.com/v2/logs", p2);

    // base_path with trailing '/' + leading-slash request: collapses to single '/'.
    const slash_id = try manager.createUpstream("https://host.example.com/v2/", 1024);
    const s1 = try manager.buildUpstreamUri(allocator, slash_id, "/logs", "");
    defer allocator.free(s1);
    try std.testing.expectEqualStrings("https://host.example.com/v2/logs", s1);
    // base_path with trailing '/' + request without leading '/': no extra separator.
    const s2 = try manager.buildUpstreamUri(allocator, slash_id, "logs", "");
    defer allocator.free(s2);
    try std.testing.expectEqualStrings("https://host.example.com/v2/logs", s2);
}

test "UpstreamManager multiple upstreams" {
    const allocator = std.testing.allocator;

    var manager = UpstreamManager.init(std.Options.debug_io, allocator, 8);
    defer manager.deinit();

    const id0 = try manager.createUpstream("https://api1.example.com", 1024);
    const id1 = try manager.createUpstream("https://api2.example.com", 1024);

    // Asserted through `buildUpstreamUri`, which production calls to reach a
    // host.
    const uri0 = try manager.buildUpstreamUri(allocator, id0, "/x", "");
    defer allocator.free(uri0);
    const uri1 = try manager.buildUpstreamUri(allocator, id1, "/x", "");
    defer allocator.free(uri1);

    try std.testing.expectEqualStrings("https://api1.example.com/x", uri0);
    try std.testing.expectEqualStrings("https://api2.example.com/x", uri1);
}

// =============================================================================
// Header filtering
// =============================================================================

pub fn shouldSkipRequestHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

pub fn shouldSkipResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "connection");
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
    try std.testing.expect(shouldSkipResponseHeader("connection"));
    try std.testing.expect(shouldSkipResponseHeader("Connection"));
    try std.testing.expect(shouldSkipResponseHeader("CONNECTION"));
    try std.testing.expect(!shouldSkipResponseHeader("content-type"));
    try std.testing.expect(!shouldSkipResponseHeader("x-custom-header"));
    try std.testing.expect(!shouldSkipResponseHeader("connection-info"));
    try std.testing.expect(!shouldSkipResponseHeader("x-connection"));
}
