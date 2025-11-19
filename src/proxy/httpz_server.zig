const std = @import("std");
const httpz = @import("httpz");
const config_types = @import("../config/types.zig");

const ProxyContext = struct {
    allocator: std.mem.Allocator,
    config: *const std.atomic.Value(*const config_types.ProxyConfig),
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
        ctx.* = .{
            .allocator = allocator,
            .config = config,
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

    fn proxyHandler(ctx: *ProxyContext, req: *httpz.Request, res: *httpz.Response) !void {
        std.log.debug("[PROXY] Handler started for request", .{});

        const current_config = ctx.config.load(.acquire);
        std.log.debug("[PROXY] Config loaded", .{});

        // Log the incoming request
        std.log.info("[PROXY] Incoming request: {} {s} to upstream {}.{}.{}.{}:{}", .{
            req.method,
            req.url.path,
            current_config.upstream_address[0],
            current_config.upstream_address[1],
            current_config.upstream_address[2],
            current_config.upstream_address[3],
            current_config.upstream_port,
        });

        // Create HTTP client for upstream request
        std.log.debug("[PROXY] Creating HTTP client", .{});
        var client = std.http.Client{ .allocator = ctx.allocator };
        std.log.debug("[PROXY] HTTP client created", .{});

        // Build upstream URL
        var url_buffer: [512]u8 = undefined;
        const upstream_url = try std.fmt.bufPrint(&url_buffer, "http://{d}.{d}.{d}.{d}:{d}{s}", .{
            current_config.upstream_address[0],
            current_config.upstream_address[1],
            current_config.upstream_address[2],
            current_config.upstream_address[3],
            current_config.upstream_port,
            req.url.path,
        });
        std.log.debug("[PROXY] Upstream URL: {s}", .{upstream_url});

        const uri = try std.Uri.parse(upstream_url);
        std.log.debug("[PROXY] URI parsed", .{});

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
        std.log.debug("[PROXY] HTTP method: {}", .{method});

        // Create upstream request
        std.log.debug("[PROXY] Creating upstream request", .{});
        var upstream_req = try client.request(method, uri, .{});
        std.log.debug("[PROXY] Upstream request created", .{});

        std.log.debug("[PROXY] Sending bodiless request to upstream", .{});
        try upstream_req.sendBodiless();
        std.log.debug("[PROXY] Request sent, waiting for response head", .{});

        var upstream_res = try upstream_req.receiveHead(&.{});
        std.log.info("[PROXY] Received response head from upstream: status={}", .{@intFromEnum(upstream_res.head.status)});

        // IMPORTANT: Process headers BEFORE reading the body
        // After calling reader(), the header data becomes invalid
        std.log.debug("[PROXY] Setting response status", .{});
        res.status = @intFromEnum(upstream_res.head.status);

        // Forward response headers
        // CRITICAL: Must copy header strings to arena memory because they become invalid
        // when we deinit the upstream client
        std.log.debug("[PROXY] Forwarding response headers", .{});
        var header_count: usize = 0;
        var header_it = upstream_res.head.iterateHeaders();
        while (header_it.next()) |header| {
            // Skip headers that httpz handles automatically
            // httpz will set content-length based on res.body length
            if (std.mem.eql(u8, header.name, "transfer-encoding")) {
                std.log.debug("[PROXY] Skipping transfer-encoding header", .{});
                continue;
            }
            if (std.mem.eql(u8, header.name, "content-length")) {
                std.log.debug("[PROXY] Skipping content-length header (httpz will set it)", .{});
                continue;
            }

            // Copy header name and value to arena memory so they survive client.deinit()
            const header_name = try req.arena.dupe(u8, header.name);
            const header_value = try req.arena.dupe(u8, header.value);

            std.log.debug("[PROXY] Forwarding header: {s}: {s}", .{ header_name, header_value });
            res.header(header_name, header_value);
            header_count += 1;
        }
        std.log.debug("[PROXY] Forwarded {} headers (content-length will be set by httpz)", .{header_count});

        // Read response body using stream() method
        // MUST be done AFTER processing headers
        // Use req.arena allocator so the memory survives until httpz finishes writing the response
        std.log.debug("[PROXY] Creating body writer with req.arena allocator", .{});
        var body_writer = std.Io.Writer.Allocating.init(req.arena);
        defer body_writer.deinit();

        const max_size = current_config.max_body_size;

        // Get body reader with a proper buffer
        std.log.debug("[PROXY] Getting body reader from upstream response", .{});
        var read_buffer: [8192]u8 = undefined;
        var upstream_body_reader = upstream_res.reader(&read_buffer);

        // Stream the entire response body with size limit
        // Use a loop to keep reading until we get all the data or hit the limit
        std.log.debug("[PROXY] Starting to stream response body (max_size={})", .{max_size});
        var total_bytes_read: usize = 0;
        while (total_bytes_read < max_size) {
            const bytes_read = upstream_body_reader.stream(&body_writer.writer, std.io.Limit.limited(max_size - total_bytes_read)) catch |err| switch (err) {
                error.EndOfStream => {
                    std.log.debug("[PROXY] Reached end of stream after {} bytes", .{total_bytes_read});
                    break;
                },
                else => {
                    std.log.err("[PROXY] Error reading upstream response: {}", .{err});
                    res.status = 502; // Bad Gateway
                    res.body = "Error reading upstream response";
                    client.deinit();
                    return err;
                },
            };

            if (bytes_read == 0) {
                std.log.debug("[PROXY] No more data available, stream complete", .{});
                break;
            }

            total_bytes_read += bytes_read;
            std.log.debug("[PROXY] Read {} bytes (total: {})", .{ bytes_read, total_bytes_read });
        }
        std.log.info("[PROXY] Streamed {} bytes from upstream response", .{total_bytes_read});

        if (total_bytes_read >= max_size) {
            std.log.warn("[PROXY] Response body reached max size limit of {} bytes", .{max_size});
        }

        // Copy the body to arena memory before deinit invalidates it
        const temp_body = body_writer.written();
        std.log.debug("[PROXY] Copying {} bytes to stable arena memory", .{temp_body.len});
        const body = try req.arena.dupe(u8, temp_body);
        std.log.debug("[PROXY] Body copied, setting response body ({} bytes)", .{body.len});
        res.body = body;

        std.log.info("[PROXY] Handler completed successfully - status={} body_size={} headers={}", .{
            res.status,
            body.len,
            header_count,
        });

        // Explicitly close the upstream connection before returning
        std.log.debug("[PROXY] Explicitly deinitializing upstream request before httpz sends response", .{});
        upstream_req.deinit();
        std.log.debug("[PROXY] Upstream request deinitialized", .{});

        std.log.debug("[PROXY] Explicitly deinitializing HTTP client", .{});
        client.deinit();
        std.log.debug("[PROXY] HTTP client deinitialized, handler returning", .{});
    }
};
