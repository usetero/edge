const std = @import("std");
const router = @import("../control/router.zig");
const streaming = @import("streaming_proxy.zig");

pub const ProxyOptions = struct {
    request: streaming.StreamOptions = .{},
    response: streaming.StreamOptions = .{},
    extra_headers: []const std.http.Header = &.{},
};

pub const ProxyResult = struct {
    status_code: u16,
    request: streaming.TransferStats,
    response: streaming.TransferStats,
};

pub const UpstreamTransport = struct {
    allocator: std.mem.Allocator,
    client: std.http.Client,

    pub fn init(allocator: std.mem.Allocator) UpstreamTransport {
        return .{
            .allocator = allocator,
            .client = .{
                .allocator = allocator,
                .tls_buffer_size = std.crypto.tls.max_ciphertext_record_len,
                .read_buffer_size = std.crypto.tls.max_ciphertext_record_len,
                .write_buffer_size = std.crypto.tls.max_ciphertext_record_len,
            },
        };
    }

    pub fn deinit(self: *UpstreamTransport) void {
        self.client.deinit();
    }

    pub fn proxy(
        self: *UpstreamTransport,
        route: router.RouteKind,
        upstream_base_url: []const u8,
        method: std.http.Method,
        path: []const u8,
        query: []const u8,
        request_reader: *const std.Io.Reader,
        request_body: ?[]const u8,
        client_writer: *std.Io.Writer,
        options: ProxyOptions,
    ) !ProxyResult {
        _ = route;

        const upstream_uri_text = try buildUpstreamUri(self.allocator, upstream_base_url, path, query);
        defer self.allocator.free(upstream_uri_text);

        const uri = try std.Uri.parse(upstream_uri_text);
        var upstream_req = try self.client.request(method, uri, .{
            .extra_headers = options.extra_headers,
            .headers = .{ .accept_encoding = .omit },
        });
        defer upstream_req.deinit();

        const has_body = method.requestHasBody();
        var req_stats = streaming.TransferStats{};
        if (has_body) {
            if (request_body) |body| {
                try upstream_req.sendBodyComplete(@constCast(body));
                req_stats = .{
                    .bytes_in = body.len,
                    .bytes_out = body.len,
                };
            } else {
                upstream_req.transfer_encoding = .chunked;
                var req_body_buf: [8192]u8 = undefined;
                var req_body_writer = try upstream_req.sendBodyUnflushed(&req_body_buf);
                req_stats = try streaming.streamRequestBody(
                    request_reader,
                    &req_body_writer.writer,
                    self.allocator,
                    options.request,
                );
                try req_body_writer.end();
            }
        } else {
            try upstream_req.sendBodiless();
        }

        var upstream_res = try upstream_req.receiveHead(&.{});
        var transfer_buffer: [8192]u8 = undefined;
        const upstream_body_reader = upstream_res.reader(&transfer_buffer);
        const res_stats = try streaming.streamResponseBody(
            upstream_body_reader,
            client_writer,
            self.allocator,
            options.response,
        );
        try client_writer.flush();

        return .{
            .status_code = @intFromEnum(upstream_res.head.status),
            .request = req_stats,
            .response = res_stats,
        };
    }
};

fn buildUpstreamUri(
    allocator: std.mem.Allocator,
    upstream_base_url: []const u8,
    path: []const u8,
    query: []const u8,
) ![]u8 {
    const uri = try std.Uri.parse(upstream_base_url);
    const base_path = uri.path.percent_encoded;

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    try out.writer.writeAll(uri.scheme);
    try out.writer.writeAll("://");

    var host_buf: [std.Uri.host_name_max]u8 = undefined;
    const host = try uri.getHost(&host_buf);
    try out.writer.writeAll(host);

    if (uri.port) |port| {
        const default_port = if (std.mem.eql(u8, uri.scheme, "https")) @as(u16, 443) else @as(u16, 80);
        if (port != default_port) {
            try out.writer.print(":{d}", .{port});
        }
    }

    if (base_path.len > 0 and !std.mem.eql(u8, base_path, "/")) {
        try out.writer.writeAll(base_path);
    }

    if (path.len > 0) {
        const written = out.written();
        const need_sep = (written.len == 0 or written[written.len - 1] != '/') and path[0] != '/';
        if (need_sep) try out.writer.writeByte('/');
        try out.writer.writeAll(path);
    }

    if (query.len > 0) {
        try out.writer.writeByte('?');
        try out.writer.writeAll(query);
    }

    return out.toOwnedSlice();
}

test "buildUpstreamUri preserves base path and query" {
    const allocator = std.testing.allocator;
    const uri = try buildUpstreamUri(allocator, "https://api.example.com/v2", "/logs", "a=1");
    defer allocator.free(uri);
    try std.testing.expectEqualStrings("https://api.example.com/v2/logs?a=1", uri);
}

test "buildUpstreamUri omits default port" {
    const allocator = std.testing.allocator;
    const uri = try buildUpstreamUri(allocator, "http://localhost:80", "/x", "");
    defer allocator.free(uri);
    try std.testing.expectEqualStrings("http://localhost/x", uri);
}
