const std = @import("std");
const zzz = @import("zzz");
const http = zzz.HTTP;
const tardy = zzz.tardy;
const proxy_module = @import("../modules/proxy_module.zig");
const router_mod = @import("router.zig");
const upstream_client = @import("upstream_client.zig");
const runtime_pipeline = @import("../runtime/pipeline.zig");
const runtime_metrics = @import("../runtime/runtime_metrics.zig");
const transport_mod = @import("../io/transport.zig");
const o11y = @import("o11y");
const EventBus = o11y.EventBus;

const Tardy = tardy.Tardy(.auto);
const Runtime = tardy.Runtime;
const Socket = tardy.Socket;

const ModuleId = proxy_module.ModuleId;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleStreamResult = proxy_module.ModuleStreamResult;
const ModuleRegistration = proxy_module.ModuleRegistration;
const ProxyModule = proxy_module.ProxyModule;
const HttpMethod = proxy_module.HttpMethod;
const RouteKind = proxy_module.RouteKind;
const Router = router_mod.Router;
const UpstreamClientManager = upstream_client.UpstreamClientManager;
const PrefilterDecision = runtime_pipeline.PrefilterDecision;
const UpstreamTransport = transport_mod.UpstreamTransport;
const RuntimeMetrics = runtime_metrics.RuntimeMetrics;
const MethodLabel = runtime_metrics.MethodLabel;
const RouteKindLabel = runtime_metrics.RouteKindLabel;
const KnownPathLabel = runtime_metrics.KnownPathLabel;
const PrefilterDecisionLabel = runtime_metrics.PrefilterDecisionLabel;

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
    route_kind: RouteKind,
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

const RoutePlan = struct {
    module_id: ModuleId,
    module: ProxyModule,
    route_kind: RouteKind,
    module_data: ?*const anyopaque,
    upstream: proxy_module.UpstreamConfig,
    decision: PrefilterDecision,
};

const RequestMetricContext = struct {
    known_path: KnownPathLabel = .other,
    route_kind: RouteKindLabel = .passthrough,
    prefilter: PrefilterDecisionLabel = .none,
};

const RequestParts = struct {
    uri: []const u8,
    path: []const u8,
    query: ?[]const u8,
};

fn splitUri(uri: []const u8) RequestParts {
    if (std.mem.indexOfScalar(u8, uri, '?')) |idx| {
        return .{
            .uri = uri,
            .path = uri[0..idx],
            .query = if (idx + 1 < uri.len) uri[idx + 1 ..] else "",
        };
    }
    return .{
        .uri = uri,
        .path = uri,
        .query = null,
    };
}

fn classifyRoutePlan(
    ctx: *ServerContext,
    path: []const u8,
    method: HttpMethod,
    content_type: ?[]const u8,
) ?RoutePlan {
    const match = ctx.router.route(path, method) orelse return null;
    const module_entry = ctx.modules.get(match.module_id) orelse return null;
    const upstream = ctx.upstreams.getUpstreamConfig(match.module_id);
    const route_kind = runtime_pipeline.classifyRoute(path, method);

    return .{
        .module_id = match.module_id,
        .module = module_entry.instance,
        .route_kind = route_kind,
        .module_data = module_entry.config.module_data,
        .upstream = upstream,
        .decision = runtime_pipeline.prefilter(
            route_kind,
            method,
            content_type,
        ),
    };
}

/// Server context - passed to all handlers
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

    /// Maximum request body size
    max_body_size: u32,

    /// Event bus for observability
    bus: *EventBus,

    /// Runtime Prometheus metrics registry
    metrics: *RuntimeMetrics,

    allocator: std.mem.Allocator,

    /// Handle all requests directly - we do our own routing
    pub fn handle(self: *ServerContext, zctx: *const http.Context) !http.Respond {
        const req = zctx.request;
        const uri = req.uri orelse "/";
        const parts = splitUri(uri);
        const method = req.method orelse .GET;
        const http_method = toHttpMethod(method);

        const start_ns = std.time.nanoTimestamp();
        var metric_ctx = RequestMetricContext{
            .known_path = classifyKnownPath(parts.path, http_method),
            .route_kind = .passthrough,
            .prefilter = .none,
        };

        // Start request span
        var span = self.bus.started(.debug, RequestStarted{
            .method = @tagName(method),
            .path = parts.path,
            .body_len = if (req.body) |body| body.len else 0,
        });

        // Call handler
        var response_bytes: usize = 0;
        const respond = proxyHandler(self, zctx, parts, &response_bytes, &metric_ctx) catch |err| {
            self.uncaughtError(zctx, parts.path, method, err, &metric_ctx);
            return .standard;
        };

        const elapsed_ns = std.time.nanoTimestamp() - start_ns;
        const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        self.metrics.recordRequest(
            toMethodLabel(http_method),
            metric_ctx.known_path,
        );
        self.metrics.recordRequestDuration(metric_ctx.known_path, elapsed_s);
        self.metrics.recordResponse(
            metric_ctx.known_path,
            runtime_metrics.statusClass(@intFromEnum(zctx.response.status orelse .OK)),
        );

        // Complete span with response info
        span.completed(RequestCompleted{
            .status = @intFromEnum(zctx.response.status orelse .OK),
            .response_bytes = response_bytes,
        });

        return respond;
    }

    fn uncaughtError(
        self: *ServerContext,
        zctx: *const http.Context,
        path: []const u8,
        method: http.Method,
        err: anyerror,
        metric_ctx: *const RequestMetricContext,
    ) void {
        if (isClientDisconnectError(err)) {
            // Peer closed mid-response/request; not a server fault.
            self.bus.debug(RequestError{
                .method = @tagName(method),
                .path = path,
                .err = @errorName(err),
                .stack_trace = null,
            });
            return;
        }

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
            .method = @tagName(method),
            .path = path,
            .err = @errorName(err),
            .stack_trace = stack_trace_str,
        });
        self.metrics.recordRequestError(metric_ctx.known_path, .uncaught);
        zctx.response.status = .@"Internal Server Error";
        zctx.response.mime = .TEXT;
        zctx.response.body = "Internal Server Error";
    }
};

fn isClientDisconnectError(err: anyerror) bool {
    return err == error.WriteFailed or
        err == error.ReadFailed or
        err == error.Closed or
        err == error.BrokenPipe or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionTimedOut;
}

/// Generic modular proxy server
pub const ProxyServer = struct {
    context: *ServerContext,
    allocator: std.mem.Allocator,
    runtime_lock: std.Thread.Mutex = .{},
    runtimes: std.ArrayListUnmanaged(*Runtime) = .empty,
    socket_lock: std.Thread.Mutex = .{},
    listen_socket: ?Socket = null,

    /// Initialize the proxy server with registered modules
    pub fn init(
        allocator: std.mem.Allocator,
        bus: *EventBus,
        metrics: *RuntimeMetrics,
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
        ctx.metrics = metrics;
        ctx.max_upstream_retries = max_upstream_retries;
        ctx.max_body_size = max_body_size;
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
                .route_kind = reg.route_kind,
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

        return .{
            .context = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProxyServer) void {
        self.runtimes.deinit(self.allocator);
        self.context.modules.deinit(self.allocator);
        self.context.upstreams.deinit();
        self.context.router.deinit();
        self.allocator.free(self.context.listen_address);
        self.allocator.destroy(self.context);
    }

    pub fn listen(self: *ProxyServer) !void {
        self.context.bus.info(ServerListening{
            .address = self.context.listen_address,
            .port = self.context.listen_port,
        });

        var t: Tardy = try .init(self.allocator, .{
            .threading = .auto,
        });
        defer t.deinit();

        var http_router: http.Router = try .init(self.allocator, &.{
            http.Route.init("/").all(self.context, handleRoute).layer(),
            http.Route.init("/%r").all(self.context, handleRoute).layer(),
        }, .{});
        defer http_router.deinit(self.allocator);

        var socket: Socket = try .init(.{
            .tcp = .{
                .host = self.context.listen_address,
                .port = self.context.listen_port,
            },
        });
        defer {
            self.socket_lock.lock();
            defer self.socket_lock.unlock();
            if (self.listen_socket) |s| {
                var close_sock = s;
                close_sock.close_blocking();
                self.listen_socket = null;
            }
        }

        self.socket_lock.lock();
        self.listen_socket = socket;
        self.socket_lock.unlock();

        try socket.bind();
        try socket.listen(4096);

        const EntryParams = struct {
            proxy: *ProxyServer,
            router: *const http.Router,
            socket: Socket,
            max_body_size: u32,
        };

        try t.entry(
            EntryParams{
                .proxy = self,
                .router = &http_router,
                .socket = socket,
                .max_body_size = self.context.max_body_size,
            },
            struct {
                fn entry(rt: *Runtime, p: EntryParams) !void {
                    p.proxy.runtime_lock.lock();
                    errdefer p.proxy.runtime_lock.unlock();
                    try p.proxy.runtimes.append(p.proxy.allocator, rt);
                    p.proxy.runtime_lock.unlock();
                    defer {
                        p.proxy.runtime_lock.lock();
                        defer p.proxy.runtime_lock.unlock();
                        for (p.proxy.runtimes.items, 0..) |item, i| {
                            if (item == rt) {
                                _ = p.proxy.runtimes.swapRemove(i);
                                break;
                            }
                        }
                    }

                    var server: http.Server = .init(.{
                        .stack_size = 1024 * 1024 * 4,
                        .socket_buffer_bytes = 1024 * 2,
                        .request_bytes_max = p.max_body_size,
                    });
                    try server.serve(rt, p.router, .{ .normal = p.socket });
                }
            }.entry,
        );
    }

    pub fn listenInNewThread(self: *ProxyServer) !std.Thread {
        self.context.bus.info(ServerListening{
            .address = self.context.listen_address,
            .port = self.context.listen_port,
        });
        return std.Thread.spawn(.{}, listenThreadMain, .{self});
    }

    pub fn stop(self: *ProxyServer) void {
        self.runtime_lock.lock();
        for (self.runtimes.items) |rt| {
            rt.stop();
        }
        self.runtime_lock.unlock();

        self.socket_lock.lock();
        if (self.listen_socket) |sock| {
            var close_sock = sock;
            close_sock.close_blocking();
            self.listen_socket = null;
        }
        self.socket_lock.unlock();
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

fn listenThreadMain(proxy: *ProxyServer) void {
    proxy.listen() catch |err| {
        proxy.context.bus.err(ModuleError{ .err = @errorName(err) });
    };
}

fn handleRoute(zctx: *const http.Context, server_ctx: *ServerContext) !http.Respond {
    return server_ctx.handle(zctx);
}

/// Convert zzz Method to our HttpMethod
fn toHttpMethod(method: http.Method) HttpMethod {
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

fn toMethodLabel(method: HttpMethod) MethodLabel {
    return switch (method) {
        .GET => .get,
        .POST => .post,
        .PUT => .put,
        .DELETE => .delete,
        .PATCH => .patch,
        .HEAD => .head,
        .OPTIONS => .options,
        .OTHER => .other,
    };
}

fn toRouteKindLabel(kind: RouteKind) RouteKindLabel {
    return switch (kind) {
        .datadog_logs => .datadog_logs,
        .datadog_metrics => .datadog_metrics,
        .otlp_logs => .otlp_logs,
        .otlp_metrics => .otlp_metrics,
        .otlp_traces => .otlp_traces,
        .prometheus_metrics => .prometheus_metrics,
        .health => .health,
        .passthrough => .passthrough,
    };
}

fn toPrefilterDecisionLabel(decision: PrefilterDecision) PrefilterDecisionLabel {
    return switch (decision) {
        .policy_path => .policy_path,
        .fast_path => .fast_path,
    };
}

fn classifyKnownPath(path: []const u8, method: HttpMethod) KnownPathLabel {
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/logs")) return .api_v2_logs;
    if (method == .POST and std.mem.eql(u8, path, "/api/v2/series")) return .api_v2_series;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/logs")) return .v1_logs;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/metrics")) return .v1_metrics;
    if (method == .POST and std.mem.endsWith(u8, path, "/v1/traces")) return .v1_traces;
    if (method == .GET and (std.mem.eql(u8, path, "/metrics") or std.mem.startsWith(u8, path, "/metrics/"))) return .metrics;
    if (method == .GET and std.mem.eql(u8, path, "/_health")) return .health;
    if (method == .GET and std.mem.eql(u8, path, "/_edge/metrics")) return .edge_metrics;
    return .other;
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

fn statusFromCode(code: u16) http.Status {
    return std.meta.intToEnum(http.Status, code) catch .@"Internal Server Error";
}

/// Header getter function for ModuleRequest
fn getHeaderFromZzz(ctx: ?*const anyopaque, name: []const u8) ?[]const u8 {
    const req: *const http.Request = @ptrCast(@alignCast(ctx));
    return req.headers.get(name);
}

/// Main proxy handler - catchall for all requests
fn proxyHandler(
    ctx: *ServerContext,
    zctx: *const http.Context,
    parts: RequestParts,
    response_bytes: *usize,
    metric_ctx: *RequestMetricContext,
) !http.Respond {
    const req = zctx.request;
    const method = req.method orelse .GET;
    const http_method = toHttpMethod(method);

    if (method == .GET and std.mem.eql(u8, parts.path, "/_edge/metrics")) {
        var out: std.Io.Writer.Allocating = .init(zctx.allocator);
        try ctx.metrics.writePrometheus(&out.writer);
        zctx.response.status = .OK;
        zctx.response.mime = .TEXT;
        zctx.response.body = try out.toOwnedSlice();
        response_bytes.* = zctx.response.body.?.len;
        metric_ctx.known_path = .edge_metrics;
        metric_ctx.route_kind = .passthrough;
        metric_ctx.prefilter = .none;
        return .standard;
    }

    const plan = classifyRoutePlan(ctx, parts.path, http_method, req.headers.get("content-type")) orelse {
        // No module matched - return 404
        zctx.response.status = .@"Not Found";
        zctx.response.mime = .TEXT;
        zctx.response.body = "Not Found";
        metric_ctx.known_path = classifyKnownPath(parts.path, http_method);
        metric_ctx.route_kind = .passthrough;
        metric_ctx.prefilter = .none;
        return .standard;
    };

    metric_ctx.known_path = classifyKnownPath(parts.path, http_method);
    metric_ctx.route_kind = toRouteKindLabel(plan.route_kind);
    metric_ctx.prefilter = toPrefilterDecisionLabel(plan.decision);
    ctx.metrics.recordPrefilterDecision(metric_ctx.route_kind, metric_ctx.prefilter);

    const module_req = ModuleRequest{
        .method = http_method,
        .route_kind = plan.route_kind,
        .path = parts.path,
        .query = parts.query orelse "",
        .upstream = &plan.upstream,
        .module_ctx = plan.module_data,
        .headers_ctx = req,
        .get_header_fn = getHeaderFromZzz,
    };

    const outcome = try proxyToUpstreamStreaming(
        ctx,
        zctx,
        req,
        zctx.allocator,
        parts.path,
        parts.query,
        plan.module_id,
        plan.module,
        plan.decision,
        module_req,
        metric_ctx,
    );
    response_bytes.* = outcome.bytes;
    return if (outcome.streamed) .responded else .standard;
}

const ProxyOutcome = struct {
    bytes: usize,
    streamed: bool,
};

fn proxyToUpstreamStreaming(
    ctx: *ServerContext,
    zctx: *const http.Context,
    req: *const http.Request,
    allocator: std.mem.Allocator,
    path: []const u8,
    query: ?[]const u8,
    module_id: ModuleId,
    module: ProxyModule,
    decision: PrefilterDecision,
    module_req: ModuleRequest,
    metric_ctx: *const RequestMetricContext,
) !ProxyOutcome {
    const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
    const prepared = switch (decision) {
        .fast_path => try prepareOutboundFastPath(req),
        .policy_path => try prepareOutboundBody(ctx, req, module, module_req, metric_ctx),
    };
    switch (prepared.action) {
        .respond_immediately => {
            zctx.response.status = statusFromCode(prepared.status);
            zctx.response.mime = .TEXT;
            zctx.response.body = prepared.response_body;
            return .{
                .bytes = prepared.response_body.len,
                .streamed = false,
            };
        },
        .forwarded => {},
    }

    const transport = UpstreamTransport{ .ctx = .{
        .upstreams = &ctx.upstreams,
        .bus = ctx.bus,
        .max_upstream_retries = ctx.max_upstream_retries,
    } };
    const streamed_bytes = try transport.proxyPreparedStreaming(
        zctx,
        req,
        path,
        query,
        allocator,
        method,
        module_id,
        module,
        prepared.body,
        prepared.has_body,
    );
    return .{
        .bytes = streamed_bytes,
        .streamed = true,
    };
}

const PreparedOutbound = struct {
    action: ModuleStreamResult.Action,
    body: []const u8 = &.{},
    has_body: bool = false,
    status: u16 = 200,
    response_body: []const u8 = &.{},
};

fn prepareOutboundFastPath(req: *const http.Request) !PreparedOutbound {
    const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
    if (!method.requestHasBody()) return .{ .action = .forwarded, .has_body = false };
    const body = req.body orelse return .{ .action = .forwarded, .has_body = false };
    if (body.len == 0) return .{ .action = .forwarded, .has_body = false };

    return .{
        .action = .forwarded,
        .body = body,
        .has_body = true,
    };
}

fn prepareOutboundBody(
    ctx: *ServerContext,
    req: *const http.Request,
    module: ProxyModule,
    module_req: ModuleRequest,
    metric_ctx: *const RequestMetricContext,
) !PreparedOutbound {
    const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
    if (method.requestHasBody()) {
        if (req.body) |body| {
            if (body.len == 0) return .{ .action = .forwarded, .has_body = false };

            var request_reader = std.Io.Reader.fixed(body);
            var captured_writer: std.Io.Writer.Allocating = .init(req.allocator);
            errdefer captured_writer.deinit();

            const stream_result = module.processRequestStream(
                &module_req,
                &request_reader,
                &captured_writer.writer,
                req.allocator,
            ) catch |err| blk: {
                // Fail open: forward original body bytes if module stream processing fails.
                ctx.bus.warn(ModuleError{ .err = @errorName(err) });
                ctx.metrics.recordRequestError(metric_ctx.known_path, .module);
                var fallback_reader = std.Io.Reader.fixed(body);
                _ = transport_mod.streamReaderToWriter(&fallback_reader, &captured_writer.writer, std.math.maxInt(usize)) catch {};
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
                    const captured = try captured_writer.toOwnedSlice();
                    return .{
                        .action = .forwarded,
                        .body = captured,
                        .has_body = true,
                    };
                },
            }
        }
    }

    var empty_reader = std.Io.Reader.fixed(&.{});
    var discard_buffer: [64]u8 = undefined;
    var discarding: std.Io.Writer.Discarding = .init(&discard_buffer);
    const stream_result = module.processRequestStream(
        &module_req,
        &empty_reader,
        &discarding.writer,
        req.allocator,
    ) catch |err| {
        ctx.bus.warn(ModuleError{ .err = @errorName(err) });
        ctx.metrics.recordRequestError(metric_ctx.known_path, .module);
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
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("host"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("Host"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("HOST"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("connection"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("Connection"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("content-length"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("Content-Length"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("transfer-encoding"));
    try std.testing.expect(transport_mod.shouldSkipRequestHeader("Transfer-Encoding"));
    try std.testing.expect(!transport_mod.shouldSkipRequestHeader("content-type"));
    try std.testing.expect(!transport_mod.shouldSkipRequestHeader("x-custom-header"));
}

test "shouldSkipResponseHeader" {
    try std.testing.expect(transport_mod.shouldSkipResponseHeader("content-length"));
    try std.testing.expect(transport_mod.shouldSkipResponseHeader("Content-Length"));
    try std.testing.expect(transport_mod.shouldSkipResponseHeader("transfer-encoding"));
    try std.testing.expect(transport_mod.shouldSkipResponseHeader("Transfer-Encoding"));
    try std.testing.expect(transport_mod.shouldSkipResponseHeader("content-type"));
    try std.testing.expect(!transport_mod.shouldSkipResponseHeader("x-custom-header"));
}

test "streamReaderToWriter streams full payload" {
    const input = "hello world";
    var input_reader = std.Io.Reader.fixed(input);

    var out_buf: [64]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&out_buf);

    const bytes = try transport_mod.streamReaderToWriter(
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

    const bytes = try transport_mod.streamReaderToWriter(
        &input_reader,
        &output_writer,
        3,
    );

    try std.testing.expectEqual(@as(usize, 3), bytes);
    try std.testing.expectEqualStrings("abc", out_buf[0..bytes]);
}
