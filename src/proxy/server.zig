const std = @import("std");
const httpz = @import("httpz");
const compress = @import("compress.zig");
const intercepting_writer = @import("intercepting_writer.zig");
const proxy_module = @import("../modules/proxy_module.zig");
const router_mod = @import("router.zig");
const upstream_client = @import("upstream_client.zig");
const o11y = @import("../observability/root.zig");
const EventBus = o11y.EventBus;

const InterceptingWriter = intercepting_writer.InterceptingWriter;
const InterceptFn = intercepting_writer.InterceptFn;
const LinePrinterContext = intercepting_writer.LinePrinterContext;
const linePrinterCallback = intercepting_writer.linePrinterCallback;

const ModuleId = proxy_module.ModuleId;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const ModuleRegistration = proxy_module.ModuleRegistration;
const ProxyModule = proxy_module.ProxyModule;
const HttpMethod = proxy_module.HttpMethod;
const Router = router_mod.Router;
const UpstreamClientManager = upstream_client.UpstreamClientManager;

// =============================================================================
// Observability Events
// =============================================================================

const RequestStarted = struct {
    method: []const u8,
    path: []const u8,
    body_len: usize,
};

const RequestCompleted = struct {
    status: u16,
    response_bytes: usize,
};

const RequestError = struct {
    method: []const u8,
    path: []const u8,
    err: []const u8,
    stack_trace: ?[]const u8 = null,
};

const DecompressError = struct {
    err: []const u8,
};

const ModuleError = struct {
    err: []const u8,
};

const CompressError = struct {
    err: []const u8,
};

const UpstreamRequest = struct {
    method: []const u8,
    url: []const u8,
};

const UpstreamResponse = struct {
    status: u16,
    bytes: usize,
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

const ResponseFlushError = struct {
    err: []const u8,
    bytes_written: usize,
};

const ResponseTruncated = struct {
    max_size: usize,
};

const UpstreamRetry = struct {
    attempt: u8,
    max_retries: u8,
    err: []const u8,
};

const ServerListening = struct {
    address: []const u8,
    port: u16,
};

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

    /// Maximum retries for failed upstream requests
    max_upstream_retries: u8,

    /// Event bus for observability
    bus: *EventBus,

    allocator: std.mem.Allocator,

    /// Handle all requests directly - we do our own routing
    pub fn handle(self: *ServerContext, req: *httpz.Request, res: *httpz.Response) void {
        // Start request span
        var span = self.bus.started(.debug, RequestStarted{
            .method = @tagName(req.method),
            .path = req.url.path,
            .body_len = req.body_len,
        });

        // Call handler
        var response_bytes: usize = 0;
        proxyHandler(self, req, res, &response_bytes) catch |err| {
            self.uncaughtError(req, res, err);
        };

        // Complete span with response info
        span.completed(RequestCompleted{
            .status = res.status,
            .response_bytes = response_bytes,
        });
    }

    fn uncaughtError(
        self: *ServerContext,
        req: *httpz.Request,
        res: *httpz.Response,
        err: anyerror,
    ) void {
        // Format stack trace addresses if available
        var stack_buf: [2048]u8 = undefined;
        var stack_trace_str: ?[]const u8 = null;

        if (@errorReturnTrace()) |trace| {
            var fbs = std.io.fixedBufferStream(&stack_buf);
            const writer = fbs.writer().any();
            const frames = trace.instruction_addresses[0..@min(trace.index, trace.instruction_addresses.len)];
            for (frames) |addr| {
                writer.print("0x{x} ", .{addr}) catch break;
            }
            stack_trace_str = fbs.getWritten();
        }

        self.bus.err(RequestError{
            .method = @tagName(req.method),
            .path = req.url.path,
            .err = @errorName(err),
            .stack_trace = stack_trace_str,
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
        bus: *EventBus,
        listen_address: [4]u8,
        listen_port: u16,
        max_upstream_retries: u8,
        max_body_size: u32,
        module_registrations: []const ModuleRegistration,
    ) !ProxyServer {
        var ctx = try allocator.create(ServerContext);
        errdefer allocator.destroy(ctx);

        ctx.allocator = allocator;
        ctx.bus = bus;
        ctx.max_upstream_retries = max_upstream_retries;
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
            .request = .{
                .max_body_size = max_body_size,
            },
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
        self.context.bus.info(ServerListening{
            .address = self.context.listen_address,
            .port = self.context.listen_port,
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
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

/// Check if header should be skipped when forwarding response
fn shouldSkipResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
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
fn proxyHandler(ctx: *ServerContext, req: *httpz.Request, res: *httpz.Response, response_bytes: *usize) !void {
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
            ctx.bus.warn(DecompressError{ .err = @errorName(err) });
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
        ctx.bus.warn(ModuleError{ .err = @errorName(err) });
        break :blk ModuleResult.unchanged();
    };

    // Handle module result
    switch (module_result.action) {
        .respond_immediately => {
            res.status = module_result.status;
            res.body = module_result.response_body;
            response_bytes.* = if (module_result.response_body.len > 0) module_result.response_body.len else 0;
            return;
        },

        .proxy_unchanged => {
            // Proxy original (potentially compressed) body to upstream
            response_bytes.* = try proxyToUpstream(ctx, req, res, match.module_id, original_body);
        },

        .proxy_modified => {
            // Module returned modified body (decompressed)
            // Need to recompress if original was compressed
            var body_to_send = module_result.modified_body;
            var compressed_allocated = false;

            if (encoding != .none) {
                body_to_send = compressIfNeeded(req.arena, module_result.modified_body, encoding) catch |err| blk: {
                    ctx.bus.warn(CompressError{ .err = @errorName(err) });
                    break :blk module_result.modified_body; // Fall back to uncompressed
                };
                compressed_allocated = (body_to_send.ptr != module_result.modified_body.ptr);
            }
            defer if (compressed_allocated) req.arena.free(body_to_send);

            response_bytes.* = try proxyToUpstream(ctx, req, res, match.module_id, body_to_send);
        },
    }
}

/// Extract underlying write error from HTTP client request
/// The WriteFailed error is a wrapper - actual error is stored in the connection's stream_writer
fn getUnderlyingWriteError(upstream_req: *std.http.Client.Request) ?[]const u8 {
    const connection = upstream_req.connection orelse return null;
    const write_err = connection.stream_writer.err orelse return null;
    return @errorName(write_err);
}

/// Forward request to upstream and stream response back
/// Returns the number of bytes in the response body
fn proxyToUpstream(
    ctx: *ServerContext,
    req: *httpz.Request,
    res: *httpz.Response,
    module_id: ModuleId,
    body_to_send: []const u8,
) !usize {
    const max_retries = ctx.max_upstream_retries;
    var attempt: u8 = 0;

    // https://codeberg.org/ziglang/zig/issues/30165
    // TODO: Once the above is fixed, we should re-evaluate this logic.
    while (attempt < max_retries) : (attempt += 1) {
        const result = proxyToUpstreamOnce(ctx, req, res, module_id, body_to_send);
        if (result) |bytes| {
            return bytes;
        } else |err| {
            // Only retry on connection-related errors (stale connections from pool)
            const err_name = @errorName(err);
            const is_retryable = std.mem.eql(u8, err_name, "ConnectionResetByPeer") or
                std.mem.eql(u8, err_name, "BrokenPipe") or
                std.mem.eql(u8, err_name, "ConnectionTimedOut") or
                std.mem.eql(u8, err_name, "UnexpectedReadFailure") or
                std.mem.eql(u8, err_name, "HttpConnectionClosing") or
                std.mem.eql(u8, err_name, "UnexpectedWriteFailure");

            if (!is_retryable or attempt + 1 >= max_retries) {
                return err;
            }

            ctx.bus.warn(UpstreamRetry{
                .attempt = attempt + 1,
                .max_retries = max_retries,
                .err = err_name,
            });
        }
    }

    return error.NotEnoughData;
}

/// Single attempt to forward request to upstream
fn proxyToUpstreamOnce(
    ctx: *ServerContext,
    req: *httpz.Request,
    res: *httpz.Response,
    module_id: ModuleId,
    body_to_send: []const u8,
) !usize {
    // Build upstream URI using pre-allocated buffer
    const upstream_uri_str = try ctx.upstreams.buildUpstreamUri(
        module_id,
        req.url.path,
        req.url.query,
    );

    const uri = try std.Uri.parse(upstream_uri_str);
    const method = toStdHttpMethod(toHttpMethod(req.method));

    ctx.bus.debug(UpstreamRequest{
        .method = @tagName(method),
        .url = upstream_uri_str,
    });

    // Get shared HTTP client from upstream manager (thread-safe connection pooling)
    const client = ctx.upstreams.getHttpClient();

    // Build headers array (single pass)
    var headers_buf: [64]std.http.Header = undefined;
    const headers = try buildHeadersArray(req, &headers_buf);

    // Determine if we have a body to send
    const has_body = body_to_send.len > 0 and switch (method) {
        .POST, .PUT, .PATCH => true,
        else => false,
    };

    // Create upstream request
    // Note: We omit accept_encoding so we only forward the client's Accept-Encoding header
    // (if present in extra_headers), preventing std.http.Client from adding its default
    // "Accept-Encoding: gzip, deflate" which would cause upstream to compress when client
    // didn't request it.
    var upstream_req = client.request(method, uri, .{
        .extra_headers = headers,
        .headers = .{ .accept_encoding = .omit },
    }) catch |err| {
        ctx.bus.err(UpstreamConnectionError{
            .err = @errorName(err),
            .phase = "connect",
        });
        return err;
    };
    defer upstream_req.deinit();

    // Send body
    if (has_body) {
        upstream_req.sendBodyComplete(@constCast(body_to_send)) catch |err| {
            ctx.bus.err(UpstreamConnectionError{
                .err = @errorName(err),
                .phase = "send_body",
                .underlying_err = getUnderlyingWriteError(&upstream_req),
            });
            // https://codeberg.org/ziglang/zig/issues/30165
            // TODO: Remove this once the bug is fixed.
            if (upstream_req.connection) |conn| conn.closing = true;
            return err;
        };
    } else {
        upstream_req.sendBodiless() catch |err| {
            ctx.bus.err(UpstreamConnectionError{
                .err = @errorName(err),
                .phase = "send_bodiless",
                .underlying_err = getUnderlyingWriteError(&upstream_req),
            });
            // https://codeberg.org/ziglang/zig/issues/30165
            // TODO: Remove this once the bug is fixed.
            if (upstream_req.connection) |conn| conn.closing = true;
            return err;
        };
    }

    // Receive response head
    var upstream_res = upstream_req.receiveHead(&.{}) catch |err| {
        ctx.bus.err(UpstreamConnectionError{
            .err = @errorName(err),
            .phase = "receive_head",
        });
        // https://codeberg.org/ziglang/zig/issues/30165
        // TODO: Remove this once the bug is fixed.
        if (upstream_req.connection) |conn| {
            conn.closing = true;
            conn.end() catch {};
        }
        return err;
    };

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

    // Stream response body with line-by-line interception
    const max_size = ctx.upstreams.getMaxResponseBody(module_id);
    var read_buffer: [8192]u8 = undefined;
    var upstream_body_reader = upstream_res.reader(&read_buffer);
    const response_writer = res.writer();

    // Set up line printer for intercepting response body
    var line_printer_ctx = LinePrinterContext.init(req.arena);
    defer line_printer_ctx.deinit();

    // Stream response body, intercepting each chunk
    // We read into a local buffer, intercept it, then write to response
    var total_bytes: usize = 0;
    var chunk_buffer: [8192]u8 = undefined;

    while (total_bytes < max_size) {
        // Read a chunk from upstream
        const chunk_size = @min(chunk_buffer.len, max_size - total_bytes);
        const bytes_read = upstream_body_reader.readSliceShort(chunk_buffer[0..chunk_size]) catch |err| {
            ctx.bus.err(UpstreamStreamError{
                .err = @errorName(err),
                .bytes_streamed = total_bytes,
            });
            return err;
        };
        if (bytes_read == 0) break; // End of stream
        const chunk = chunk_buffer[0..bytes_read];

        // Intercept the chunk (print line by line)
        linePrinterCallback(chunk, @ptrCast(&line_printer_ctx));

        // Write to response
        response_writer.writeAll(chunk) catch |err| {
            ctx.bus.err(UpstreamStreamError{
                .err = @errorName(err),
                .bytes_streamed = total_bytes,
            });
            return err;
        };

        total_bytes += chunk.len;
    }

    if (total_bytes >= max_size) {
        ctx.bus.warn(ResponseTruncated{ .max_size = max_size });
    }

    // Flush the writer to ensure all data is sent to client
    response_writer.flush() catch |err| {
        ctx.bus.err(ResponseFlushError{
            .err = @errorName(err),
            .bytes_written = total_bytes,
        });
        return err;
    };

    // Flush any remaining partial line from the line printer
    line_printer_ctx.flush();

    return total_bytes;
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
