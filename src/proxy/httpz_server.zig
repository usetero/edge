const std = @import("std");
const httpz = @import("httpz");
const config_types = @import("../config/types.zig");
const handler_pipeline = @import("handler_pipeline.zig");
const handler_types = @import("handlers/types.zig");

const ProxyContext = struct {
    allocator: std.mem.Allocator,
    config: *const std.atomic.Value(*const config_types.ProxyConfig),
    pipeline: handler_pipeline.Pipeline,
};

pub const HttpzProxyServer = struct {
    server: *httpz.Server(*ProxyContext),
    context: *ProxyContext,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        config: *const std.atomic.Value(*const config_types.ProxyConfig),
    ) !HttpzProxyServer {
        const ctx = try allocator.create(ProxyContext);
        errdefer allocator.destroy(ctx);

        // Initialize handlers with long-lived allocator
        // TODO: Load from config instead of hardcoding
        const handlers = [_]handler_types.Handler{
            .{ .log_filter = try handler_types.LogFilterConfig.init(
                allocator,
                &[_][]const u8{
                    "DROP TABLE",
                    "DELETE FROM",
                    "<script>",
                },
                .reject,
                .{
                    .path_pattern = "/api/*",
                    .content_type_pattern = "application/json",
                },
            ) },
        };

        var pipeline = try handler_pipeline.Pipeline.init(allocator, &handlers);
        errdefer pipeline.deinit();

        ctx.* = .{
            .allocator = allocator,
            .config = config,
            .pipeline = pipeline,
        };

        const current_config = config.load(.acquire);

        const server = try allocator.create(httpz.Server(*ProxyContext));
        server.* = try httpz.Server(*ProxyContext).init(allocator, .{
            .address = formatAddress(current_config.listen_address),
            .port = current_config.listen_port,
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
        self.context.pipeline.deinit();
        self.server.deinit();
        self.allocator.destroy(self.context);
        self.allocator.destroy(self.server);
    }

    pub fn listen(self: *HttpzProxyServer) !void {
        try self.server.listen();
    }

    pub fn dispatch(self: *App, action: httpz.Action(*App), req: *httpz.Request, res: *httpz.Response) !void {
        var timer = try std.time.Timer.start();

        // your `dispatch` doesn't _have_ to call the action
        try action(self, req, res);

        const elapsed = timer.lap() / 1000; // ns -> us
        std.log.info("{} {s} {d}", .{ req.method, req.url.path, elapsed });
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

    fn proxyHandler(ctx: *ProxyContext, req: *httpz.Request, res: *httpz.Response) !void {
        const current_config = ctx.config.load(.acquire);

        // Log the incoming request
        std.log.info("{s} {s} -> {s}", .{
            @tagName(req.method),
            req.url.path,
            current_config.upstream_url,
        });

        // Create HTTP client for upstream request
        var client = std.http.Client{ .allocator = ctx.allocator };
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
        while (count_it.next()) |header| {
            const name = header.key;
            // Skip headers that the HTTP client sets automatically
            if (std.mem.eql(u8, name, "host")) continue;
            if (std.mem.eql(u8, name, "connection")) continue;
            if (std.mem.eql(u8, name, "content-length")) continue;
            if (std.mem.eql(u8, name, "transfer-encoding")) continue;
            header_count += 1;
        }

        // Allocate array for headers
        const headers_to_forward = try ctx.allocator.alloc(std.http.Header, header_count);
        defer ctx.allocator.free(headers_to_forward);

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

        // Extract content-type from headers for pipeline routing
        var content_type: ?[]const u8 = null;
        for (headers_to_forward) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "content-type")) {
                content_type = header.value;
                break;
            }
        }

        // Create request context for pipeline processing
        const initial_ctx = handler_types.RequestContext{
            .method = method,
            .path = req.url.path,
            .url = upstream_url,
            .content_type = content_type,
            .headers = headers_to_forward,
            .body = if (req.body_buffer) |b| b.data else null,
            .allocator = req.arena, // Request-scoped allocator
        };

        // Process through handler pipeline
        const result = try ctx.pipeline.process(initial_ctx);

        // Check if request was rejected by handlers
        switch (result.action) {
            .reject => {
                res.status = 403;
                res.body = "Request rejected by security handler";
                std.log.warn("{s} {s} - rejected by handler pipeline", .{
                    @tagName(req.method),
                    req.url.path,
                });
                return;
            },
            .forward, .continue_pipeline => {
                // Continue with forwarding (potentially modified request)
            },
        }

        // Create upstream request with forwarded headers
        // Use potentially modified URL from pipeline
        const final_uri = try std.Uri.parse(result.context.url);
        var upstream_req = try client.request(method, final_uri, .{
            .extra_headers = result.context.headers,
        });
        defer upstream_req.deinit();

        // Send request with body if present and method supports it
        // Use potentially modified body from pipeline
        if (result.context.body) |body| {
            switch (method) {
                .POST, .PUT, .PATCH => {
                    // sendBodyComplete requires mutable slice, so we need to copy
                    const mutable_body = try req.arena.dupe(u8, body);
                    try upstream_req.sendBodyComplete(mutable_body);
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
        }

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
                error.EndOfStream => break,
                else => {
                    std.log.err("Error reading upstream response: {}", .{err});
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
        res.body = body;

        std.log.info("{s} {s} <- {} ({} bytes)", .{
            @tagName(req.method),
            req.url.path,
            res.status,
            body.len,
        });
    }
};
