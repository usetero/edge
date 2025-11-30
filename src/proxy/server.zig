const std = @import("std");
const httpz = @import("httpz");
const compress = @import("compress.zig");
const proxy_module = @import("../core/proxy_module.zig");
const router_mod = @import("router.zig");
const upstream_client = @import("upstream_client.zig");

const ModuleId = proxy_module.ModuleId;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const ModuleRegistration = proxy_module.ModuleRegistration;
const ProxyModule = proxy_module.ProxyModule;
const HttpMethod = proxy_module.HttpMethod;
const Router = router_mod.Router;
const UpstreamClientManager = upstream_client.UpstreamClientManager;

/// Represents the compression encoding used in a request or response
pub const CompressionEncoding = enum {
    none,
    gzip,
    zstd,

    /// Detect compression encoding from Content-Encoding header
    pub fn fromHeader(header_value: ?[]const u8) CompressionEncoding {
        const encoding = header_value orelse return .none;

        if (std.mem.indexOf(u8, encoding, "gzip") != null) {
            return .gzip;
        } else if (std.mem.indexOf(u8, encoding, "zstd") != null) {
            return .zstd;
        }

        return .none;
    }

    /// Get the header value for this encoding
    pub fn toHeaderValue(self: CompressionEncoding) ?[]const u8 {
        return switch (self) {
            .none => null,
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }
};

/// Module entry in the registry
const ModuleEntry = struct {
    id: ModuleId,
    instance: ProxyModule,
    config: ModuleConfig,
};

/// Module registry - stores all registered modules
const ModuleRegistry = struct {
    modules: std.MultiArrayList(ModuleEntry),

    pub fn get(self: *const ModuleRegistry, id: ModuleId) ?ModuleEntry {
        const idx = @intFromEnum(id);
        if (idx >= self.modules.len) return null;
        return self.modules.get(idx);
    }

    pub fn deinit(self: *ModuleRegistry, allocator: std.mem.Allocator) void {
        // Call deinit on all modules
        for (0..self.modules.len) |i| {
            const instance = self.modules.slice().items(.instance)[i];
            instance.deinit();
        }
        self.modules.deinit(allocator);
    }
};

/// Server context - passed to all httpz handlers
const ServerContext = struct {
    /// Pre-computed router
    router: Router,

    /// Registered modules
    modules: ModuleRegistry,

    /// Upstream client manager
    upstreams: UpstreamClientManager,

    /// Listen address (formatted)
    listen_address: []const u8,

    /// Listen port
    listen_port: u16,

    allocator: std.mem.Allocator,

    /// Handle all requests directly - we do our own routing
    pub fn handle(self: *ServerContext, req: *httpz.Request, res: *httpz.Response) void {
        // Log incoming request
        std.log.info("{s} {s} -> ({} bytes)", .{
            @tagName(req.method),
            req.url.path,
            req.body_len,
        });

        var start = std.time.Timer.start() catch {
            proxyHandler(self, req, res) catch |err| {
                self.uncaughtError(req, res, err);
            };
            return;
        };

        // Call handler with timing
        proxyHandler(self, req, res) catch |err| {
            self.uncaughtError(req, res, err);
        };

        const elapsed = start.lap() / 1000;
        std.log.debug("ts={d} us={d} path={s}", .{
            std.time.timestamp(),
            elapsed,
            req.url.path,
        });
    }

    fn uncaughtError(
        _: *ServerContext,
        req: *httpz.Request,
        res: *httpz.Response,
        err: anyerror,
    ) void {
        std.log.err("Uncaught error for {s} {s}: {}", .{
            @tagName(req.method),
            req.url.path,
            err,
        });
        res.status = 500;
        res.body = "Internal Server Error";
    }
};

/// Generic modular proxy server
pub const ProxyServer = struct {
    /// httpz HTTP server
    server: *httpz.Server(*ServerContext),

    /// Server context with all modules
    context: *ServerContext,

    allocator: std.mem.Allocator,

    /// Initialize the proxy server with registered modules
    pub fn init(
        allocator: std.mem.Allocator,
        listen_address: [4]u8,
        listen_port: u16,
        module_registrations: []const ModuleRegistration,
    ) !ProxyServer {
        var ctx = try allocator.create(ServerContext);
        errdefer allocator.destroy(ctx);

        ctx.allocator = allocator;
        ctx.upstreams = UpstreamClientManager.init(allocator);
        ctx.modules = .{ .modules = .{} };

        // Build module configs for router
        var module_configs = std.ArrayListUnmanaged(ModuleConfig){};
        defer module_configs.deinit(allocator);

        // Initialize modules
        for (module_registrations, 0..) |reg, i| {
            const module_id: ModuleId = @enumFromInt(@as(u32, @intCast(i)));

            // Create upstream for this module
            _ = try ctx.upstreams.createUpstream(
                reg.upstream_url,
                reg.max_path_length,
                reg.max_request_body,
                reg.max_response_body,
            );

            const upstream_config = ctx.upstreams.getUpstreamConfig(module_id);

            const module_config = ModuleConfig{
                .id = module_id,
                .routes = reg.routes,
                .upstream = upstream_config,
                .module_data = reg.module_data,
            };

            // Initialize the module
            try reg.module.init(allocator, module_config);

            // Store in registry
            try ctx.modules.modules.append(allocator, .{
                .id = module_id,
                .instance = reg.module,
                .config = module_config,
            });

            // Add to configs for router
            try module_configs.append(allocator, module_config);
        }

        // Build router from module configs
        ctx.router = try Router.init(allocator, module_configs.items);

        // Format listen address
        ctx.listen_address = try formatAddress(allocator, listen_address);
        ctx.listen_port = listen_port;

        // Create httpz server - using handle() for direct request handling
        const server = try allocator.create(httpz.Server(*ServerContext));
        server.* = try httpz.Server(*ServerContext).init(allocator, .{
            .address = ctx.listen_address,
            .port = listen_port,
        }, ctx);

        return .{
            .server = server,
            .context = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProxyServer) void {
        self.context.modules.deinit(self.allocator);
        self.context.upstreams.deinit();
        self.context.router.deinit();
        self.allocator.free(self.context.listen_address);
        self.server.deinit();
        self.allocator.destroy(self.context);
        self.allocator.destroy(self.server);
    }

    pub fn listen(self: *ProxyServer) !void {
        std.log.info("Proxy server listening on {s}:{d}", .{
            self.context.listen_address,
            self.context.listen_port,
        });
        try self.server.listen();
    }

    fn formatAddress(allocator: std.mem.Allocator, addr: [4]u8) ![]const u8 {
        return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            addr[0],
            addr[1],
            addr[2],
            addr[3],
        });
    }
};

/// Convert httpz.Method to our HttpMethod
fn toHttpMethod(method: httpz.Method) HttpMethod {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        else => .OTHER,
    };
}

/// Convert our HttpMethod to std.http.Method
fn toStdHttpMethod(method: HttpMethod) std.http.Method {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PUT => .PUT,
        .DELETE => .DELETE,
        .PATCH => .PATCH,
        .HEAD => .HEAD,
        .OPTIONS => .OPTIONS,
        .OTHER => .GET,
    };
}

/// Header getter function for ModuleRequest
fn getHeaderFromHttpz(ctx: ?*const anyopaque, name: []const u8) ?[]const u8 {
    const req: *const httpz.Request = @ptrCast(@alignCast(ctx));
    return req.header(name);
}

/// Decompress body if encoding is present
fn decompressIfNeeded(
    allocator: std.mem.Allocator,
    body: []const u8,
    encoding: CompressionEncoding,
) ![]const u8 {
    return switch (encoding) {
        .none => body, // Return original, no allocation
        .gzip => try compress.decompressGzip(allocator, body),
        .zstd => try compress.decompressZstd(allocator, body),
    };
}

/// Compress body if encoding is required
fn compressIfNeeded(
    allocator: std.mem.Allocator,
    body: []const u8,
    encoding: CompressionEncoding,
) ![]const u8 {
    return switch (encoding) {
        .none => body, // Return original, no allocation
        .gzip => try compress.compressGzip(allocator, body),
        .zstd => try compress.compressZstd(allocator, body),
    };
}

/// Check if header should be skipped when forwarding request
fn shouldSkipRequestHeader(name: []const u8) bool {
    return std.mem.eql(u8, name, "host") or
        std.mem.eql(u8, name, "connection") or
        std.mem.eql(u8, name, "content-length") or
        std.mem.eql(u8, name, "transfer-encoding");
}

/// Check if header should be skipped when forwarding response
fn shouldSkipResponseHeader(name: []const u8) bool {
    return std.mem.eql(u8, name, "content-length") or
        std.mem.eql(u8, name, "transfer-encoding");
}

/// Build headers array in single pass
fn buildHeadersArray(
    req: *httpz.Request,
    buffer: []std.http.Header,
) ![]std.http.Header {
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

/// Main proxy handler - catchall for all requests
fn proxyHandler(ctx: *ServerContext, req: *httpz.Request, res: *httpz.Response) !void {
    const http_method = toHttpMethod(req.method);

    // Route request to appropriate module
    const match = ctx.router.route(req.url.path, http_method) orelse {
        // No module matched - return 404
        res.status = 404;
        res.body = "Not Found";
        return;
    };

    const module_entry = ctx.modules.get(match.module_id) orelse {
        res.status = 500;
        res.body = "Internal Server Error: Module not found";
        return;
    };

    const upstream_config = ctx.upstreams.getUpstreamConfig(match.module_id);

    // Get original body
    const original_body = req.body() orelse &[_]u8{};

    // Detect compression encoding
    const encoding = CompressionEncoding.fromHeader(req.header("content-encoding"));

    // Decompress request body if needed (FAIL OPEN on error)
    var decompressed_body: []const u8 = original_body;
    var decompressed_allocated = false;

    if (original_body.len > 0 and encoding != .none) {
        decompressed_body = decompressIfNeeded(req.arena, original_body, encoding) catch |err| blk: {
            std.log.warn("Failed to decompress request (failing open): {}", .{err});
            break :blk original_body; // Fall back to original
        };
        decompressed_allocated = (decompressed_body.ptr != original_body.ptr);
    }
    defer if (decompressed_allocated) req.arena.free(decompressed_body);

    // Build module request
    const module_req = ModuleRequest{
        .method = http_method,
        .path = req.url.path,
        .query = req.url.query,
        .upstream = &upstream_config,
        .module_ctx = module_entry.config.module_data,
        .body = decompressed_body,
        .headers_ctx = req,
        .get_header_fn = getHeaderFromHttpz,
    };

    // Call module's processRequest (FAIL OPEN on error)
    const module_result = module_entry.instance.processRequest(&module_req, req.arena) catch |err| blk: {
        std.log.warn("Module error (failing open): {}", .{err});
        break :blk ModuleResult.unchanged();
    };

    // Handle module result
    switch (module_result.action) {
        .respond_immediately => {
            res.status = module_result.status;
            res.body = module_result.response_body;
            return;
        },

        .proxy_unchanged => {
            // Proxy original (potentially compressed) body to upstream
            try proxyToUpstream(ctx, req, res, match.module_id, original_body);
        },

        .proxy_modified => {
            // Module returned modified body (decompressed)
            // Need to recompress if original was compressed
            var body_to_send = module_result.modified_body;
            var compressed_allocated = false;

            if (encoding != .none) {
                body_to_send = compressIfNeeded(req.arena, module_result.modified_body, encoding) catch |err| blk: {
                    std.log.warn("Failed to compress modified body (failing open): {}", .{err});
                    break :blk module_result.modified_body; // Fall back to uncompressed
                };
                compressed_allocated = (body_to_send.ptr != module_result.modified_body.ptr);
            }
            defer if (compressed_allocated) req.arena.free(body_to_send);

            try proxyToUpstream(ctx, req, res, match.module_id, body_to_send);
        },
    }
}

/// Forward request to upstream and stream response back
fn proxyToUpstream(
    ctx: *ServerContext,
    req: *httpz.Request,
    res: *httpz.Response,
    module_id: ModuleId,
    body_to_send: []const u8,
) !void {
    // Build upstream URI using pre-allocated buffer
    const upstream_uri_str = try ctx.upstreams.buildUpstreamUri(
        module_id,
        req.url.path,
        req.url.query,
    );

    const uri = try std.Uri.parse(upstream_uri_str);
    const method = toStdHttpMethod(toHttpMethod(req.method));

    std.log.debug("Proxying to: {s} {s}", .{ @tagName(method), upstream_uri_str });

    // Create HTTP client for this request
    var client = std.http.Client{ .allocator = req.arena };
    defer client.deinit();

    // Build headers array (single pass)
    var headers_buf: [64]std.http.Header = undefined;
    const headers = try buildHeadersArray(req, &headers_buf);

    // Create upstream request
    var upstream_req = try client.request(method, uri, .{
        .extra_headers = headers,
    });
    defer upstream_req.deinit();

    // Send body if present
    if (body_to_send.len > 0) {
        switch (method) {
            .POST, .PUT, .PATCH => {
                std.log.debug("Sending {} bytes to upstream", .{body_to_send.len});
                try upstream_req.sendBodyComplete(@constCast(body_to_send));
            },
            else => try upstream_req.sendBodiless(),
        }
    } else {
        try upstream_req.sendBodiless();
    }

    // Receive response head
    var upstream_res = try upstream_req.receiveHead(&.{});

    // Set response status
    res.status = @intFromEnum(upstream_res.head.status);

    // Forward response headers (copy to arena memory)
    var header_it = upstream_res.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (shouldSkipResponseHeader(header.name)) continue;

        const header_name = try req.arena.dupe(u8, header.name);
        const header_value = try req.arena.dupe(u8, header.value);
        res.header(header_name, header_value);
    }

    // Stream response body
    const max_size = ctx.upstreams.getMaxResponseBody(module_id);
    var read_buffer: [8192]u8 = undefined;
    var upstream_body_reader = upstream_res.reader(&read_buffer);
    const response_writer = res.writer();

    var total_bytes: usize = 0;
    while (total_bytes < max_size) {
        const bytes = upstream_body_reader.stream(
            response_writer,
            std.Io.Limit.limited(max_size - total_bytes),
        ) catch |err| switch (err) {
            error.EndOfStream => break,
            else => {
                std.log.err("Error streaming upstream response: {}", .{err});
                return err;
            },
        };
        if (bytes == 0) break;
        total_bytes += bytes;
    }

    if (total_bytes >= max_size) {
        std.log.warn("Response body reached max size limit of {} bytes", .{max_size});
    }

    std.log.info("{s} {s} <- {} ({} bytes)", .{
        @tagName(req.method),
        req.url.path,
        res.status,
        total_bytes,
    });
}

// =============================================================================
// Tests
// =============================================================================

test "CompressionEncoding.fromHeader" {
    try std.testing.expectEqual(CompressionEncoding.none, CompressionEncoding.fromHeader(null));
    try std.testing.expectEqual(CompressionEncoding.gzip, CompressionEncoding.fromHeader("gzip"));
    try std.testing.expectEqual(CompressionEncoding.zstd, CompressionEncoding.fromHeader("zstd"));
    try std.testing.expectEqual(CompressionEncoding.none, CompressionEncoding.fromHeader("identity"));
}

test "toHttpMethod" {
    try std.testing.expectEqual(HttpMethod.GET, toHttpMethod(.GET));
    try std.testing.expectEqual(HttpMethod.POST, toHttpMethod(.POST));
    try std.testing.expectEqual(HttpMethod.DELETE, toHttpMethod(.DELETE));
}

test "shouldSkipRequestHeader" {
    try std.testing.expect(shouldSkipRequestHeader("host"));
    try std.testing.expect(shouldSkipRequestHeader("connection"));
    try std.testing.expect(shouldSkipRequestHeader("content-length"));
    try std.testing.expect(!shouldSkipRequestHeader("content-type"));
    try std.testing.expect(!shouldSkipRequestHeader("x-custom-header"));
}

test "shouldSkipResponseHeader" {
    try std.testing.expect(shouldSkipResponseHeader("content-length"));
    try std.testing.expect(shouldSkipResponseHeader("transfer-encoding"));
    try std.testing.expect(!shouldSkipResponseHeader("content-type"));
    try std.testing.expect(!shouldSkipResponseHeader("x-custom-header"));
}
