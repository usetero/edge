const std = @import("std");
const httpz = @import("httpz");
const config_types = @import("../config/types.zig");
const filter_mod = @import("../core/filter.zig");
const datadog_v2_logs = @import("datadog_v2_logs.zig");
const compress = @import("compress.zig");

/// Represents the compression encoding used in a request or response
const CompressionEncoding = enum {
    none,
    gzip,
    zstd,

    /// Detect compression encoding from Content-Encoding header
    fn fromHeader(header_value: ?[]const u8) CompressionEncoding {
        const encoding = header_value orelse return .none;

        if (std.mem.indexOf(u8, encoding, "gzip") != null) {
            return .gzip;
        } else if (std.mem.indexOf(u8, encoding, "zstd") != null) {
            return .zstd;
        }

        return .none;
    }

    /// Get the header value for this encoding
    fn toHeaderValue(self: CompressionEncoding) ?[]const u8 {
        return switch (self) {
            .none => null,
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }
};

/// Decompress request body if it's compressed
fn decompressRequestBody(allocator: std.mem.Allocator, req: *httpz.Request, body: []const u8) ![]const u8 {
    const encoding = CompressionEncoding.fromHeader(req.header("content-encoding"));

    return switch (encoding) {
        .none => {
            // Not compressed, return original
            const result = try allocator.alloc(u8, body.len);
            @memcpy(result, body);
            return result;
        },
        .gzip => {
            std.log.debug("Decompressing gzip request body ({} bytes)", .{body.len});
            return try compress.decompressGzip(allocator, body);
        },
        .zstd => {
            std.log.debug("Decompressing zstd request body ({} bytes)", .{body.len});
            return try compress.decompressZstd(allocator, body);
        },
    };
}

/// Compress response body if original request was compressed
fn compressResponseBody(allocator: std.mem.Allocator, req: *httpz.Request, body: []const u8) ![]const u8 {
    const encoding = CompressionEncoding.fromHeader(req.header("content-encoding"));

    return switch (encoding) {
        .none => {
            // No compression needed, return copy
            const result = try allocator.alloc(u8, body.len);
            @memcpy(result, body);
            return result;
        },
        .gzip => {
            std.log.debug("Compressing gzip response body ({} bytes)", .{body.len});
            return try compress.compressGzip(allocator, body);
        },
        .zstd => {
            std.log.debug("Compressing zstd response body ({} bytes)", .{body.len});
            return try compress.compressZstd(allocator, body);
        },
    };
}

/// Get the content type from request headers
fn getContentType(req: *httpz.Request) []const u8 {
    if (req.header("content-type")) |content_type| {
        return content_type;
    }
    return "text/plain";
}

/// Context passed to handler functions
const HandlerContext = struct {
    req: *httpz.Request,
    filter: *const filter_mod.FilterEvaluator,
};

/// Handler function signature that modifies request body in place
const HandlerFn = *const fn (ctx: HandlerContext, decompressed_body: []const u8) anyerror![]const u8;

/// Generic wrapper that handles compression/decompression for any handler
/// This wrapper:
/// 1. Decompresses the request body if needed
/// 2. Calls the handler with decompressed data
/// 3. Updates the request body buffer with the modified data
/// 4. Recompresses if the original request was compressed
fn withCompressionHandling(ctx: HandlerContext, handler: HandlerFn) !void {
    const req = ctx.req;
    const allocator = req.arena;

    const original_body = req.body() orelse {
        std.log.err("Missing body in request", .{});
        return error.MissingBody;
    };

    // Remember the original encoding
    const encoding = CompressionEncoding.fromHeader(req.header("content-encoding"));

    // Step 1: Decompress request body if needed
    const decompressed_body = decompressRequestBody(allocator, req, original_body) catch |err| {
        std.log.err("Failed to decompress request body: {}", .{err});
        return error.DecompressionFailed;
    };
    defer allocator.free(decompressed_body);

    // Step 2: Call the handler to process the data
    const processed_data = handler(ctx, decompressed_body) catch |err| {
        std.log.err("Handler failed: {}", .{err});
        return err;
    };
    defer allocator.free(processed_data);

    // Step 3: Recompress if original was compressed
    const final_body = compressResponseBody(allocator, req, processed_data) catch |err| {
        std.log.err("Failed to compress request body: {}", .{err});
        return error.CompressionFailed;
    };

    // Step 4: Update the request body buffer with the modified data
    if (req.body_buffer) |*body_buffer| {
        if (final_body.len <= body_buffer.data.len) {
            // Fits in existing buffer
            @memcpy(body_buffer.data[0..final_body.len], final_body);
            req.body_len = final_body.len;
        } else {
            // Need to allocate new buffer (use arena allocator)
            const new_data = try allocator.alloc(u8, final_body.len);
            @memcpy(new_data, final_body);
            body_buffer.data = new_data;
            req.body_len = final_body.len;
        }
    }

    std.log.info("Successfully processed with compression handling: {} bytes -> {} bytes (encoding: {s})", .{
        original_body.len,
        final_body.len,
        @tagName(encoding),
    });
}

/// Handle Datadog v2 logs requests
fn handleDatadogLogs(ctx: HandlerContext, decompressed_body: []const u8) ![]const u8 {
    return try datadog_v2_logs.processDatadogLogs(ctx.req, ctx.filter, decompressed_body);
}

const ProxyContext = struct {
    config: *const config_types.ProxyConfig,
    filter: *const filter_mod.FilterEvaluator,

    pub fn dispatch(self: *ProxyContext, action: httpz.Action(*ProxyContext), req: *httpz.Request, res: *httpz.Response) !void {
        // Our custom dispatch lets us add a log + timing for every request
        // httpz supports middlewares, but in many cases, having a dispatch is good
        // enough and is much more straightforward.

        std.log.info("{s} {s} -> ({} bytes)", .{
            @tagName(req.method),
            req.url.path,
            req.body_len,
        });
        var start = try std.time.Timer.start();
        defer {
            std.debug.print("ts={d} us={d} path={s}\n", .{ std.time.timestamp(), start.lap() / 1000, req.url.path });
        }

        if (req.body_len == 0 or req.body_buffer == null) {
            try action(self, req, res);
            return;
        }

        // Check if this is a Datadog v2 logs request
        if (std.mem.eql(u8, req.url.path, "/api/v2/logs")) {
            // Process with compression handling (modifies request body in place)
            const ctx = HandlerContext{
                .req = req,
                .filter = self.filter,
            };
            try withCompressionHandling(ctx, handleDatadogLogs);
        }

        try action(self, req, res);
        return;
    }

    pub fn uncaughtError(_: *ProxyContext, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
        std.log.err("Uncaught error for {s} {s}: {}", .{
            @tagName(req.method),
            req.url.path,
            err,
        });
        res.status = 500;
        res.body = "Internal Server Error";
    }
};

pub const HttpzProxyServer = struct {
    server: *httpz.Server(*ProxyContext),
    context: *ProxyContext,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const config_types.ProxyConfig,
        filter: *const filter_mod.FilterEvaluator,
    ) !HttpzProxyServer {
        const ctx = try allocator.create(ProxyContext);
        ctx.* = .{
            .config = config,
            .filter = filter,
        };

        const current_config = config;

        const server = try allocator.create(httpz.Server(*ProxyContext));
        server.* = try httpz.Server(*ProxyContext).init(allocator, .{
            .address = formatAddress(current_config.listen_address),
            .port = current_config.listen_port,
            // .request = .{
            //     .lazy_read_size = 4_096,
            // },
        }, ctx);

        var router = try server.router(.{});
        router.all("/*", proxyHandler, .{});

        return .{
            .server = server,
            .context = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *HttpzProxyServer) void {
        self.server.deinit();
        self.allocator.destroy(self.context);
        self.allocator.destroy(self.server);
    }

    pub fn listen(self: *HttpzProxyServer) !void {
        try self.server.listen();
    }

    fn formatAddress(addr: [4]u8) []const u8 {
        // Use static buffer for address formatting
        const static = struct {
            var buf: [15]u8 = undefined;
        };
        return std.fmt.bufPrint(&static.buf, "{d}.{d}.{d}.{d}", .{
            addr[0],
            addr[1],
            addr[2],
            addr[3],
        }) catch unreachable;
    }

    fn errorHandler(req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
        res.status = 500;
        res.body = "Internal Server Error";
        std.log.warn("httpz: unhandled exception for request: {s}\nErr: {}", .{ req.url.raw, err });
    }

    fn proxyHandler(ctx: *ProxyContext, req: *httpz.Request, res: *httpz.Response) !void {
        const current_config = ctx.config;

        // Log the incoming request
        std.log.info("{s} {s} -> {s}", .{
            @tagName(req.method),
            req.url.path,
            current_config.upstream_url,
        });

        // Create HTTP client for upstream request
        var client = std.http.Client{ .allocator = req.arena };
        defer client.deinit();

        // Build full upstream URL by combining base URL with request path and query string
        var url_buffer: [2048]u8 = undefined;
        const upstream_url = blk: {
            var fbs = std.io.fixedBufferStream(&url_buffer);
            const writer = fbs.writer();

            // Write base URL
            try writer.writeAll(current_config.upstream_url);

            // Add separator if needed
            if (!std.mem.endsWith(u8, current_config.upstream_url, "/") and req.url.path[0] != '/') {
                try writer.writeAll("/");
            }

            // Write path
            try writer.writeAll(req.url.path);

            // Forward query string if present
            if (req.url.query.len > 0) {
                try writer.writeAll("?");
                try writer.writeAll(req.url.query);
            }

            break :blk fbs.getWritten();
        };

        const uri = try std.Uri.parse(upstream_url);

        // Determine the HTTP method from the request
        const method: std.http.Method = switch (req.method) {
            .GET => .GET,
            .POST => .POST,
            .PUT => .PUT,
            .DELETE => .DELETE,
            .HEAD => .HEAD,
            .OPTIONS => .OPTIONS,
            .PATCH => .PATCH,
            else => .GET,
        };

        // Build headers array for upstream request
        // Count how many headers we need to forward
        var header_count: usize = 0;
        var count_it = req.headers.iterator();

        std.log.info("----------------", .{});
        while (count_it.next()) |header| {
            const name = header.key;
            std.log.info("Incoming header: {s}: {s}", .{ name, header.value });
            // Skip headers that the HTTP client sets automatically
            if (std.mem.eql(u8, name, "host")) continue;
            if (std.mem.eql(u8, name, "connection")) continue;
            if (std.mem.eql(u8, name, "content-length")) continue;
            if (std.mem.eql(u8, name, "transfer-encoding")) continue;
            header_count += 1;
        }
        std.log.info("----------------", .{});

        // Allocate array for headers
        const headers_to_forward = try req.arena.alloc(std.http.Header, header_count);
        defer req.arena.free(headers_to_forward);

        // Copy headers to array
        var idx: usize = 0;
        var copy_it = req.headers.iterator();
        while (copy_it.next()) |header| {
            const name = header.key;
            // Skip headers that the HTTP client sets automatically
            if (std.mem.eql(u8, name, "host")) continue;
            if (std.mem.eql(u8, name, "connection")) continue;
            if (std.mem.eql(u8, name, "content-length")) continue;
            if (std.mem.eql(u8, name, "transfer-encoding")) continue;

            headers_to_forward[idx] = .{
                .name = name,
                .value = header.value,
            };
            idx += 1;
        }
        std.log.info("----------------", .{});
        for (headers_to_forward) |header| {
            std.log.info("Outgoing header: {s}: {s}", .{ header.name, header.value });
        }
        std.log.info("----------------", .{});
        std.log.info("uri: {s}, method: {any}", .{ upstream_url, method });
        std.log.info("----------------", .{});
        // Create upstream request with forwarded headers
        var upstream_req = try client.request(method, uri, .{
            .extra_headers = headers_to_forward,
        });

        defer upstream_req.deinit();

        // Send request with body if present and method supports it
        if (req.body()) |body| {
            switch (method) {
                .POST, .PUT, .PATCH => {
                    std.log.debug("Sending {} bytes to upstream", .{body.len});
                    // Note: sendBodyComplete requires mutable slice but doesn't actually mutate
                    try upstream_req.sendBodyComplete(@constCast(body));
                },
                else => try upstream_req.sendBodiless(),
            }
        } else {
            try upstream_req.sendBodiless();
        }

        var upstream_res = try upstream_req.receiveHead(&.{});

        // IMPORTANT: Process headers BEFORE reading the body
        // After calling reader(), the header data becomes invalid
        res.status = @intFromEnum(upstream_res.head.status);

        // Forward response headers (must copy to arena memory)
        var header_it = upstream_res.head.iterateHeaders();
        while (header_it.next()) |header| {
            // Skip headers that httpz handles automatically
            if (std.mem.eql(u8, header.name, "transfer-encoding")) continue;
            if (std.mem.eql(u8, header.name, "content-length")) continue;

            // Copy header name and value to arena memory so they survive client.deinit()
            const header_name = try req.arena.dupe(u8, header.name);
            const header_value = try req.arena.dupe(u8, header.value);
            res.header(header_name, header_value);
            std.log.info("Received Header: {s}: {s}", .{ header_name, header_value });
        }
        std.log.info("-------------------------", .{});

        // Read response body
        var body_writer = std.Io.Writer.Allocating.init(req.arena);
        defer body_writer.deinit();

        const max_size = current_config.max_body_size;
        var read_buffer: [8192]u8 = undefined;
        var upstream_body_reader = upstream_res.reader(&read_buffer);

        // Stream the entire response body with size limit
        var total_bytes_read: usize = 0;
        while (total_bytes_read < max_size) {
            const bytes_read = upstream_body_reader.stream(&body_writer.writer, std.io.Limit.limited(max_size - total_bytes_read)) catch |err| switch (err) {
                error.EndOfStream => {
                    // Normal end of HTTP response body
                    std.log.debug("Reached end of response body", .{});
                    break;
                },
                else => {
                    std.log.err("Error reading upstream response: {} (error set: {s}, total_bytes_read: {})", .{
                        err,
                        @errorName(err),
                        total_bytes_read,
                    });
                    res.status = 502; // Bad Gateway
                    res.body = "Error reading upstream response";
                    client.deinit();
                    return err;
                },
            };

            if (bytes_read == 0) break;
            total_bytes_read += bytes_read;
        }

        if (total_bytes_read >= max_size) {
            std.log.warn("Response body reached max size limit of {} bytes", .{max_size});
        }

        // Copy the body to arena memory before deinit invalidates it
        const temp_body = body_writer.written();
        const body = try req.arena.dupe(u8, temp_body);
        std.log.info("Body ({} bytes): {s}", .{ body.len, body });
        res.body = body;

        std.log.info("{s} {s} <- {} ({} bytes)\nxxxxxxxxxxxxxxxxxxxxxxxx", .{
            @tagName(req.method),
            req.url.path,
            res.status,
            body.len,
        });
    }
};
