const std = @import("std");
const zzz = @import("zzz");
const http = zzz.HTTP;
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

    pub fn proxyPreparedStreaming(
        self: *const UpstreamTransport,
        zctx: *const http.Context,
        req: *const http.Request,
        path: []const u8,
        query: ?[]const u8,
        allocator: std.mem.Allocator,
        method: std.http.Method,
        module_id: ModuleId,
        module: ProxyModule,
        prepared_body: []const u8,
        has_body: bool,
    ) !usize {
        const max_retries = self.ctx.max_upstream_retries;
        var attempt: u8 = 0;
        var downstream_started = false;

        // https://codeberg.org/ziglang/zig/issues/30165
        // TODO: Remove this once the bug is fixed.
        // Retry is needed because pooled upstream connections can go stale between
        // requests and fail on first write/read despite being selected from pool.
        // We precompute a replayable outbound body so retries are deterministic.
        while (attempt < max_retries) : (attempt += 1) {
            const result = self.proxyOnceStreaming(
                zctx,
                req,
                path,
                query,
                allocator,
                method,
                module_id,
                module,
                prepared_body,
                has_body,
                &downstream_started,
            );
            if (result) |bytes| {
                return bytes;
            } else |err| {
                const err_name = @errorName(err);
                if (downstream_started) return err;
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

    fn proxyOnceStreaming(
        self: *const UpstreamTransport,
        zctx: *const http.Context,
        req: *const http.Request,
        path: []const u8,
        query: ?[]const u8,
        allocator: std.mem.Allocator,
        method: std.http.Method,
        module_id: ModuleId,
        module: ProxyModule,
        prepared_body: []const u8,
        has_body: bool,
        downstream_started: *bool,
    ) !usize {
        const upstream_uri_str = try self.ctx.upstreams.buildUpstreamUri(
            allocator,
            module_id,
            path,
            query orelse "",
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
        var chunk_buffer: [32 * 1024]u8 = undefined;
        var raw_writer: RawSocketWriter = .init(&zctx.socket, zctx.runtime, &chunk_buffer);
        var chunked_writer: ChunkedSocketWriter = .init(&zctx.socket, zctx.runtime, &chunk_buffer);

        var response_filter = module.createResponseFilter(&chunked_writer.interface, allocator) catch |err| blk: {
            self.ctx.bus.warn(ModuleError{ .err = @errorName(err) });
            break :blk null;
        };
        defer if (response_filter) |*filter| filter.destroy();

        const has_filter = response_filter != null;
        const use_chunked = has_filter or upstream_res.head.content_length == null;

        zctx.response.status = statusFromStd(upstream_res.head.status);
        zctx.response.mime = if (upstream_res.head.content_type) |content_type|
            http.Mime.from_content_type(content_type)
        else
            .BIN;

        downstream_started.* = true;
        try writeResponseHead(
            &zctx.socket,
            zctx.runtime,
            allocator,
            upstream_res.head,
            use_chunked,
        );

        const max_size = self.ctx.upstreams.getMaxResponseBody(module_id);
        var read_buffer: [32 * 1024]u8 = undefined;
        const upstream_body_reader = upstream_res.reader(&read_buffer);
        const inner_writer: *std.Io.Writer = if (use_chunked) &chunked_writer.interface else &raw_writer.interface;

        const target_writer = if (response_filter) |*filter| filter.writer() else inner_writer;
        const total_bytes = try streamReaderToWriter(
            upstream_body_reader,
            target_writer,
            max_size,
        );
        try target_writer.flush();

        var bytes_forwarded: usize = total_bytes;
        if (response_filter) |*filter| {
            bytes_forwarded = filter.finish() catch total_bytes;
        }
        try inner_writer.flush();
        if (use_chunked) try chunked_writer.finish();
        return bytes_forwarded;
    }
};

const RawSocketWriter = struct {
    socket: *const zzz.secsock.SecureSocket,
    runtime: *zzz.tardy.Runtime,
    interface: std.Io.Writer,
    err: ?anyerror = null,

    fn init(
        socket: *const zzz.secsock.SecureSocket,
        runtime: *zzz.tardy.Runtime,
        buffer: []u8,
    ) RawSocketWriter {
        return .{
            .socket = socket,
            .runtime = runtime,
            .interface = .{
                .vtable = &.{
                    .drain = drain,
                    .sendFile = sendFile,
                },
                .buffer = buffer,
            },
        };
    }

    fn writeBytes(self: *RawSocketWriter, payload: []const u8) !usize {
        if (payload.len == 0) return 0;
        const sent = try self.socket.send_all(self.runtime, payload);
        if (sent != payload.len) return error.Closed;
        return payload.len;
    }

    fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const w: *RawSocketWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();

        if (buffered.len != 0) {
            const n = w.writeBytes(buffered) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }

        for (data[0 .. data.len - 1]) |buf| {
            if (buf.len == 0) continue;
            const n = w.writeBytes(buf) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }

        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return 0;
        const n = w.writeBytes(pattern) catch |err| {
            w.err = err;
            return error.WriteFailed;
        };
        return io_w.consume(n);
    }

    fn sendFile(
        io_w: *std.Io.Writer,
        file_reader: *std.fs.File.Reader,
        limit: std.Io.Limit,
    ) std.Io.Writer.FileError!usize {
        _ = io_w;
        _ = file_reader;
        _ = limit;
        return error.Unimplemented;
    }
};

const ChunkedSocketWriter = struct {
    socket: *const zzz.secsock.SecureSocket,
    runtime: *zzz.tardy.Runtime,
    interface: std.Io.Writer,
    err: ?anyerror = null,
    closed: bool = false,

    fn init(
        socket: *const zzz.secsock.SecureSocket,
        runtime: *zzz.tardy.Runtime,
        buffer: []u8,
    ) ChunkedSocketWriter {
        return .{
            .socket = socket,
            .runtime = runtime,
            .interface = .{
                .vtable = &.{
                    .drain = drain,
                    .sendFile = sendFile,
                },
                .buffer = buffer,
            },
        };
    }

    fn finish(self: *ChunkedSocketWriter) !void {
        if (self.closed) return;
        const sent = try self.socket.send_all(self.runtime, "0\r\n\r\n");
        if (sent != "0\r\n\r\n".len) return error.Closed;
        self.closed = true;
    }

    fn writeChunk(self: *ChunkedSocketWriter, payload: []const u8) !usize {
        if (payload.len == 0) return 0;
        var len_buf: [32]u8 = undefined;
        const len_slice = try std.fmt.bufPrint(&len_buf, "{x}\r\n", .{payload.len});

        const h = try self.socket.send_all(self.runtime, len_slice);
        if (h != len_slice.len) return error.Closed;
        const b = try self.socket.send_all(self.runtime, payload);
        if (b != payload.len) return error.Closed;
        const t = try self.socket.send_all(self.runtime, "\r\n");
        if (t != 2) return error.Closed;
        return payload.len;
    }

    fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const w: *ChunkedSocketWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const buffered = io_w.buffered();

        if (buffered.len != 0) {
            const n = w.writeChunk(buffered) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }

        for (data[0 .. data.len - 1]) |buf| {
            if (buf.len == 0) continue;
            const n = w.writeChunk(buf) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }

        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return 0;
        const n = w.writeChunk(pattern) catch |err| {
            w.err = err;
            return error.WriteFailed;
        };
        return io_w.consume(n);
    }

    fn sendFile(
        io_w: *std.Io.Writer,
        file_reader: *std.fs.File.Reader,
        limit: std.Io.Limit,
    ) std.Io.Writer.FileError!usize {
        _ = io_w;
        _ = file_reader;
        _ = limit;
        return error.Unimplemented;
    }
};

fn statusFromStd(status: std.http.Status) http.Status {
    return std.meta.intToEnum(http.Status, @intFromEnum(status)) catch .@"Internal Server Error";
}

fn writeResponseHead(
    socket: *const zzz.secsock.SecureSocket,
    runtime: *zzz.tardy.Runtime,
    allocator: std.mem.Allocator,
    head: std.http.Client.Response.Head,
    chunked: bool,
) !void {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    const writer = &out.writer;

    const status = statusFromStd(head.status);
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{
        @intFromEnum(status),
        @tagName(status),
    });
    try writer.writeAll("Server: edge\r\n");
    try writer.writeAll("Connection: keep-alive\r\n");

    if (head.content_type) |content_type| {
        try writer.print("Content-Type: {s}\r\n", .{content_type});
    } else {
        try writer.writeAll("Content-Type: application/octet-stream\r\n");
    }

    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (shouldSkipResponseHeader(header.name)) continue;
        try writer.print("{s}: {s}\r\n", .{ header.name, header.value });
    }

    if (chunked) {
        try writer.writeAll("Transfer-Encoding: chunked\r\n");
    } else if (head.content_length) |len| {
        try writer.print("Content-Length: {d}\r\n", .{len});
    } else {
        try writer.writeAll("Transfer-Encoding: chunked\r\n");
    }
    try writer.writeAll("\r\n");

    const bytes = out.written();
    const sent = try socket.send_all(runtime, bytes);
    if (sent != bytes.len) return error.Closed;
}

pub fn shouldRetryErrorName(err_name: []const u8) bool {
    return std.mem.eql(u8, err_name, "ConnectionResetByPeer") or
        std.mem.eql(u8, err_name, "BrokenPipe") or
        std.mem.eql(u8, err_name, "ConnectionTimedOut") or
        std.mem.eql(u8, err_name, "UnexpectedConnectFailure") or
        std.mem.eql(u8, err_name, "ConnectionRefused") or
        std.mem.eql(u8, err_name, "NetworkUnreachable") or
        std.mem.eql(u8, err_name, "HostUnreachable") or
        std.mem.eql(u8, err_name, "TemporaryNameServerFailure") or
        std.mem.eql(u8, err_name, "TryAgain") or
        std.mem.eql(u8, err_name, "SystemResources") or
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
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "server");
}

pub fn buildHeadersArray(req: *const http.Request, buffer: []std.http.Header) ![]std.http.Header {
    var count: usize = 0;
    var it = req.headers.iterator();

    while (it.next()) |header| {
        if (shouldSkipRequestHeader(header.key_ptr.*)) continue;
        if (count >= buffer.len) return error.TooManyHeaders;

        buffer[count] = .{
            .name = header.key_ptr.*,
            .value = header.value_ptr.*,
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
    try std.testing.expect(shouldRetryErrorName("UnexpectedConnectFailure"));
    try std.testing.expect(!shouldRetryErrorName("AccessDenied"));
}

test "header skip helpers" {
    try std.testing.expect(shouldSkipRequestHeader("Host"));
    try std.testing.expect(shouldSkipResponseHeader("Transfer-Encoding"));
    try std.testing.expect(!shouldSkipRequestHeader("Content-Type"));
    try std.testing.expect(shouldSkipResponseHeader("Content-Type"));
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
