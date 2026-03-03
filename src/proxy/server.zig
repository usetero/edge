const std = @import("std");
const httpz = @import("httpz");
const proxy_module = @import("../modules/proxy_module.zig");
const router_mod = @import("router.zig");
const upstream_client = @import("upstream_client.zig");
const o11y = @import("o11y");
const EventBus = o11y.EventBus;

const ModuleId = proxy_module.ModuleId;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleStreamResult = proxy_module.ModuleStreamResult;
const ModuleRegistration = proxy_module.ModuleRegistration;
const ProxyModule = proxy_module.ProxyModule;
const ResponseFilter = proxy_module.ResponseFilter;
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

const ModuleError = struct {
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
        errdefer ctx.upstreams.deinit();
        ctx.modules = .{ .modules = .{} };
        errdefer ctx.modules.deinit(allocator);

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
        errdefer ctx.router.deinit();

        // Format listen address
        ctx.listen_address = try formatAddress(allocator, listen_address);
        errdefer allocator.free(ctx.listen_address);
        ctx.listen_port = listen_port;

        // Create httpz server - using handle() for direct request handling
        const server = try allocator.create(httpz.Server(*ServerContext));
        errdefer allocator.destroy(server);
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

/// Stream bytes from reader to writer up to max_bytes.
/// Uses only std.Io.Reader/std.Io.Writer vtables to keep streaming paths testable.
fn streamReaderToWriter(
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    max_bytes: usize,
) std.Io.Reader.StreamError!usize {
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
    const module_req = ModuleRequest{
        .method = http_method,
        .path = req.url.path,
        .query = req.url.query,
        .upstream = &upstream_config,
        .module_ctx = module_entry.config.module_data,
        .headers_ctx = req,
        .get_header_fn = getHeaderFromHttpz,
    };

    response_bytes.* = try proxyToUpstreamStreaming(ctx, req, res, match.module_id, module_entry.instance, module_req);
}

/// Extract underlying write error from HTTP client request
/// The WriteFailed error is a wrapper - actual error is stored in the connection's stream_writer
fn getUnderlyingWriteError(upstream_req: *std.http.Client.Request) ?[]const u8 {
    const connection = upstream_req.connection orelse return null;
    const write_err = connection.stream_writer.err orelse return null;
    return @errorName(write_err);
}

fn proxyToUpstreamStreaming(
    ctx: *ServerContext,
    req: *httpz.Request,
    res: *httpz.Response,
    module_id: ModuleId,
    module: ProxyModule,
    module_req: ModuleRequest,
) !usize {
    const prepared = try prepareOutboundBody(ctx, req, module, module_req);
    switch (prepared.action) {
        .respond_immediately => {
            res.status = prepared.status;
            res.body = prepared.response_body;
            return prepared.response_body.len;
        },
        .forwarded => {},
    }

    const max_retries = ctx.max_upstream_retries;
    var attempt: u8 = 0;

    // https://codeberg.org/ziglang/zig/issues/30165
    // TODO: Remove this once the bug is fixed.
    // Retry is needed because pooled upstream connections can go stale between
    // requests and fail on first write/read despite being selected from pool.
    // We precompute a replayable outbound body so retries are deterministic.
    while (attempt < max_retries) : (attempt += 1) {
        const result = proxyToUpstreamPreparedOnce(
            ctx,
            req,
            res,
            module_id,
            module,
            prepared.body,
            prepared.has_body,
        );
        if (result) |bytes| {
            return bytes;
        } else |err| {
            const err_name = @errorName(err);
            const is_retryable = std.mem.eql(u8, err_name, "ConnectionResetByPeer") or
                std.mem.eql(u8, err_name, "BrokenPipe") or
                std.mem.eql(u8, err_name, "ConnectionTimedOut") or
                std.mem.eql(u8, err_name, "UnexpectedReadFailure") or
                std.mem.eql(u8, err_name, "HttpConnectionClosing") or
                std.mem.eql(u8, err_name, "UnexpectedWriteFailure");

            if (!is_retryable or attempt + 1 >= max_retries) return err;

            ctx.bus.warn(UpstreamRetry{
                .attempt = attempt + 1,
                .max_retries = max_retries,
                .err = err_name,
            });
        }
    }

    return error.NotEnoughData;
}

const PreparedOutbound = struct {
    action: ModuleStreamResult.Action,
    body: []const u8 = &.{},
    has_body: bool = false,
    status: u16 = 200,
    response_body: []const u8 = &.{},
};

fn prepareOutboundBody(
    ctx: *ServerContext,
    req: *httpz.Request,
    module: ProxyModule,
    module_req: ModuleRequest,
) !PreparedOutbound {
    const method = toStdHttpMethod(toHttpMethod(req.method));
    if (method.requestHasBody()) {
        var request_reader = try req.reader(30_000);
        var captured_writer: std.Io.Writer.Allocating = .init(req.arena);
        errdefer captured_writer.deinit();

        const stream_result = module.processRequestStream(
            &module_req,
            &request_reader.interface,
            &captured_writer.writer,
            req.arena,
        ) catch |err| blk: {
            // Fail open: forward original body bytes if module stream processing fails.
            ctx.bus.warn(ModuleError{ .err = @errorName(err) });
            _ = streamReaderToWriter(&request_reader.interface, &captured_writer.writer, std.math.maxInt(usize)) catch {};
            break :blk ModuleStreamResult.forwarded();
        };

        switch (stream_result.action) {
            .respond_immediately => {
                captured_writer.deinit();
                return .{
                    .action = .respond_immediately,
                    .status = stream_result.status,
                    .response_body = stream_result.response_body,
                };
            },
            .forwarded => {
                const body = try captured_writer.toOwnedSlice();
                return .{
                    .action = .forwarded,
                    .body = body,
                    .has_body = true,
                };
            },
        }
    }

    var empty_reader = std.Io.Reader.fixed(&.{});
    var discard_buffer: [64]u8 = undefined;
    var discarding: std.Io.Writer.Discarding = .init(&discard_buffer);
    const stream_result = module.processRequestStream(
        &module_req,
        &empty_reader,
        &discarding.writer,
        req.arena,
    ) catch |err| {
        ctx.bus.warn(ModuleError{ .err = @errorName(err) });
        return .{ .action = .forwarded, .has_body = false };
    };

    return switch (stream_result.action) {
        .forwarded => .{ .action = .forwarded, .has_body = false },
        .respond_immediately => .{
            .action = .respond_immediately,
            .status = stream_result.status,
            .response_body = stream_result.response_body,
        },
    };
}

fn proxyToUpstreamPreparedOnce(
    ctx: *ServerContext,
    req: *httpz.Request,
    res: *httpz.Response,
    module_id: ModuleId,
    module: ProxyModule,
    prepared_body: []const u8,
    has_body: bool,
) !usize {
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

    const client = ctx.upstreams.getHttpClient();
    var headers_buf: [64]std.http.Header = undefined;
    const headers = try buildHeadersArray(req, &headers_buf);

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

    if (has_body and method.requestHasBody()) {
        upstream_req.transfer_encoding = .{ .content_length = prepared_body.len };
        var request_write_buffer: [8192]u8 = undefined;
        var request_body_writer = upstream_req.sendBodyUnflushed(&request_write_buffer) catch |err| {
            ctx.bus.err(UpstreamConnectionError{
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
            ctx.bus.err(UpstreamStreamError{
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

    const max_size = ctx.upstreams.getMaxResponseBody(module_id);
    var read_buffer: [8192]u8 = undefined;
    const upstream_body_reader = upstream_res.reader(&read_buffer);
    const response_writer = res.writer();

    var response_filter = module.createResponseFilter(response_writer, req.arena) catch |err| blk: {
        ctx.bus.warn(ModuleError{ .err = @errorName(err) });
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

test "streamReaderToWriter streams full payload" {
    const input = "hello world";
    var input_reader = std.Io.Reader.fixed(input);

    var out_buf: [64]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&out_buf);

    const bytes = try streamReaderToWriter(
        &input_reader,
        &output_writer,
        input.len,
    );

    try std.testing.expectEqual(input.len, bytes);
    try std.testing.expectEqualStrings(input, out_buf[0..bytes]);
}

test "streamReaderToWriter respects max_bytes limit" {
    const input = "abcdef";
    var input_reader = std.Io.Reader.fixed(input);

    var out_buf: [64]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&out_buf);

    const bytes = try streamReaderToWriter(
        &input_reader,
        &output_writer,
        3,
    );

    try std.testing.expectEqual(@as(usize, 3), bytes);
    try std.testing.expectEqualStrings("abc", out_buf[0..bytes]);
}
