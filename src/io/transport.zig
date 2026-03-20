const std = @import("std");
const httpz = @import("httpz");
const o11y = @import("o11y");
const proxy_module = @import("../modules/proxy_module.zig");
const upstream_client = @import("../proxy/upstream_client.zig");

const EventBus = o11y.EventBus;
const ModuleId = proxy_module.ModuleId;
const ProxyModule = proxy_module.ProxyModule;
const UpstreamClientManager = upstream_client.UpstreamClientManager;

const ModuleError = struct {
    err: []const u8,
};

const UpstreamRequest = struct {
    method: []const u8,
    url: []const u8,
};

const UpstreamStreamError = struct {
    err: []const u8,
    bytes_streamed: usize = 0,
};

const UpstreamConnectionError = struct {
    err: []const u8,
    phase: []const u8,
    underlying_err: ?[]const u8 = null,
};

const UpstreamRetry = struct {
    attempt: u8,
    max_retries: u8,
    err: []const u8,
};

pub const Context = struct {
    upstreams: *UpstreamClientManager,
    bus: *EventBus,
    max_upstream_retries: u8,
};

pub const UpstreamTransport = struct {
    ctx: Context,

    pub fn proxyPrepared(
        self: *const UpstreamTransport,
        req: *httpz.Request,
        res: *httpz.Response,
        method: std.http.Method,
        module_id: ModuleId,
        module: ProxyModule,
        prepared_body: []const u8,
        has_body: bool,
    ) !usize {
        const max_retries = self.ctx.max_upstream_retries;
        var attempt: u8 = 0;

        // https://codeberg.org/ziglang/zig/issues/30165
        // TODO: Remove this once the bug is fixed.
        // Retry is needed because pooled upstream connections can go stale between
        // requests and fail on first write/read despite being selected from pool.
        // We precompute a replayable outbound body so retries are deterministic.
        while (attempt < max_retries) : (attempt += 1) {
            const result = self.proxyOnce(
                req,
                res,
                method,
                module_id,
                module,
                prepared_body,
                has_body,
            );
            if (result) |bytes| {
                return bytes;
            } else |err| {
                const err_name = @errorName(err);
                if (!shouldRetryErrorName(err_name) or attempt + 1 >= max_retries) return err;

                self.ctx.bus.warn(UpstreamRetry{
                    .attempt = attempt + 1,
                    .max_retries = max_retries,
                    .err = err_name,
                });
            }
        }

        return error.NotEnoughData;
    }

    fn proxyOnce(
        self: *const UpstreamTransport,
        req: *httpz.Request,
        res: *httpz.Response,
        method: std.http.Method,
        module_id: ModuleId,
        module: ProxyModule,
        prepared_body: []const u8,
        has_body: bool,
    ) !usize {
        const upstream_uri_str = try self.ctx.upstreams.buildUpstreamUri(
            req.arena,
            module_id,
            req.url.path,
            req.url.query,
        );
        const uri = try std.Uri.parse(upstream_uri_str);

        self.ctx.bus.debug(UpstreamRequest{
            .method = @tagName(method),
            .url = upstream_uri_str,
        });

        const client = self.ctx.upstreams.getHttpClient();
        var headers_buf: [64]std.http.Header = undefined;
        const headers = try buildHeadersArray(req, &headers_buf);

        var upstream_req = client.request(method, uri, .{
            .extra_headers = headers,
            .headers = .{ .accept_encoding = .omit },
        }) catch |err| {
            self.ctx.bus.err(UpstreamConnectionError{
                .err = @errorName(err),
                .phase = "connect",
            });
            return err;
        };
        defer upstream_req.deinit();

        if (has_body and method.requestHasBody()) {
            upstream_req.transfer_encoding = .{ .content_length = prepared_body.len };
            var request_write_buffer: [8192]u8 = undefined;
            var request_body_writer = upstream_req.sendBodyUnflushed(&request_write_buffer) catch |err| {
                self.ctx.bus.err(UpstreamConnectionError{
                    .err = @errorName(err),
                    .phase = "send_body",
                    .underlying_err = getUnderlyingWriteError(&upstream_req),
                });
                if (upstream_req.connection) |conn| conn.closing = true;
                return err;
            };

            var prepared_reader = std.Io.Reader.fixed(prepared_body);
            const bytes_streamed = streamReaderToWriter(
                &prepared_reader,
                &request_body_writer.writer,
                prepared_body.len,
            ) catch |err| {
                self.ctx.bus.err(UpstreamStreamError{
                    .err = @errorName(err),
                    .bytes_streamed = prepared_reader.seek,
                });
                return err;
            };

            if (bytes_streamed != prepared_body.len) {
                if (upstream_req.connection) |conn| conn.closing = true;
                return error.UnexpectedEof;
            }

            try request_body_writer.end();
        } else {
            try upstream_req.sendBodiless();
        }

        var upstream_res = try upstream_req.receiveHead(&.{});
        res.status = @intFromEnum(upstream_res.head.status);

        var header_it = upstream_res.head.iterateHeaders();
        while (header_it.next()) |header| {
            if (shouldSkipResponseHeader(header.name)) continue;
            const header_name = try req.arena.dupe(u8, header.name);
            const header_value = try req.arena.dupe(u8, header.value);
            res.header(header_name, header_value);
        }

        const max_size = self.ctx.upstreams.getMaxResponseBody(module_id);
        var read_buffer: [8192]u8 = undefined;
        const upstream_body_reader = upstream_res.reader(&read_buffer);
        const response_writer = res.writer();

        var response_filter = module.createResponseFilter(response_writer, req.arena) catch |err| blk: {
            self.ctx.bus.warn(ModuleError{ .err = @errorName(err) });
            break :blk null;
        };
        defer if (response_filter) |*filter| filter.destroy();

        const target_writer = if (response_filter) |*filter| filter.writer() else response_writer;
        const total_bytes = try streamReaderToWriter(
            upstream_body_reader,
            target_writer,
            max_size,
        );

        var bytes_forwarded: usize = total_bytes;
        if (response_filter) |*filter| {
            bytes_forwarded = filter.finish() catch total_bytes;
        }
        try response_writer.flush();
        return bytes_forwarded;
    }
};

pub fn shouldRetryErrorName(err_name: []const u8) bool {
    return std.mem.eql(u8, err_name, "ConnectionResetByPeer") or
        std.mem.eql(u8, err_name, "BrokenPipe") or
        std.mem.eql(u8, err_name, "ConnectionTimedOut") or
        std.mem.eql(u8, err_name, "UnexpectedReadFailure") or
        std.mem.eql(u8, err_name, "HttpConnectionClosing") or
        std.mem.eql(u8, err_name, "UnexpectedWriteFailure");
}

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

pub fn buildHeadersArray(req: *httpz.Request, buffer: []std.http.Header) ![]std.http.Header {
    var count: usize = 0;
    var it = req.headers.iterator();

    while (it.next()) |header| {
        if (shouldSkipRequestHeader(header.key)) continue;
        if (count >= buffer.len) return error.TooManyHeaders;

        buffer[count] = .{
            .name = header.key,
            .value = header.value,
        };
        count += 1;
    }

    return buffer[0..count];
}

pub fn streamReaderToWriter(reader: *std.Io.Reader, writer: *std.Io.Writer, max_bytes: usize) std.Io.Reader.StreamError!usize {
    var total_bytes: usize = 0;
    while (total_bytes < max_bytes) {
        const bytes = reader.stream(
            writer,
            std.Io.Limit.limited(max_bytes - total_bytes),
        ) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (bytes == 0) break;
        total_bytes += bytes;
    }
    return total_bytes;
}

fn getUnderlyingWriteError(upstream_req: *std.http.Client.Request) ?[]const u8 {
    const connection = upstream_req.connection orelse return null;
    const write_err = connection.stream_writer.err orelse return null;
    return @errorName(write_err);
}

test "shouldRetryErrorName covers transient connection failures" {
    try std.testing.expect(shouldRetryErrorName("BrokenPipe"));
    try std.testing.expect(shouldRetryErrorName("ConnectionResetByPeer"));
    try std.testing.expect(!shouldRetryErrorName("AccessDenied"));
}

test "header skip helpers" {
    try std.testing.expect(shouldSkipRequestHeader("Host"));
    try std.testing.expect(shouldSkipResponseHeader("Transfer-Encoding"));
    try std.testing.expect(!shouldSkipRequestHeader("Content-Type"));
    try std.testing.expect(!shouldSkipResponseHeader("X-Test"));
}

test "streamReaderToWriter respects limit" {
    var in_reader = std.Io.Reader.fixed("abcdef");
    var out_buf: [16]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);

    const n = try streamReaderToWriter(&in_reader, &out_writer, 3);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqualStrings("abc", out_buf[0..n]);
}
