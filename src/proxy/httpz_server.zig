const std = @import("std");
const httpz = @import("httpz");
const config_types = @import("../config/types.zig");
const json = @import("../json/pretty_print.zig");

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
        const current_config = ctx.config.load(.acquire);

        // Log the incoming request
        std.log.info("{s} {s} -> {s}", .{
            @tagName(req.method),
            req.url.path,
            current_config.upstream_url,
        });

        // Create HTTP client for upstream request
        var client = std.http.Client{ .allocator = ctx.allocator };

        // Build full upstream URL by combining base URL with request path
        var url_buffer: [1024]u8 = undefined;
        const upstream_url = try std.fmt.bufPrint(&url_buffer, "{s}{s}{s}", .{
            current_config.upstream_url,
            if (std.mem.endsWith(u8, current_config.upstream_url, "/")) "" else if (req.url.path[0] == '/') "" else "/",
            req.url.path,
        });

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

        // Create and send upstream request
        var upstream_req = try client.request(method, uri, .{});
        if (req.body_buffer) |body| {
            switch (method) {
                .POST, .PUT, .PATCH => try upstream_req.sendBodyComplete(body.data),
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

        // Explicitly close the upstream connection before returning
        upstream_req.deinit();
        client.deinit();
    }
};
