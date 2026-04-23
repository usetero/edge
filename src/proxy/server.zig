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
const ModuleRegistration = proxy_module.ModuleRegistration;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleStreamResult = proxy_module.ModuleStreamResult;
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
};

const ModuleError = struct {
    err: []const u8,
};

const ServerListening = struct {
    address: []const u8,
    port: u16,
};

pub const CompressionEncoding = enum {
    none,
    gzip,
    zstd,

    pub fn fromHeader(header_value: ?[]const u8) CompressionEncoding {
        const encoding = header_value orelse return .none;
        if (std.mem.indexOf(u8, encoding, "gzip") != null) return .gzip;
        if (std.mem.indexOf(u8, encoding, "zstd") != null) return .zstd;
        return .none;
    }

    pub fn toHeaderValue(self: CompressionEncoding) ?[]const u8 {
        return switch (self) {
            .none => null,
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }
};

const ModuleEntry = struct {
    id: ModuleId,
    module: ProxyModule,
    route_kind: RouteKind,
    config: ModuleConfig,
};

const ModuleRegistry = struct {
    items: std.MultiArrayList(ModuleEntry),

    fn get(self: *const ModuleRegistry, id: ModuleId) ?ModuleEntry {
        const idx = @intFromEnum(id);
        if (idx >= self.items.len) return null;
        return self.items.get(idx);
    }

    fn deinit(self: *ModuleRegistry, allocator: std.mem.Allocator) void {
        for (0..self.items.len) |i| {
            self.items.slice().items(.module)[i].deinit();
        }
        self.items.deinit(allocator);
    }
};

const RuntimeRegistry = struct {
    lock: std.Thread.Mutex = .{},
    runtimes: std.ArrayListUnmanaged(*Runtime) = .empty,

    fn register(self: *RuntimeRegistry, allocator: std.mem.Allocator, rt: *Runtime) !void {
        self.lock.lock();
        defer self.lock.unlock();
        try self.runtimes.append(allocator, rt);
    }

    fn unregister(self: *RuntimeRegistry, rt: *Runtime) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.runtimes.items, 0..) |item, i| {
            if (item == rt) {
                _ = self.runtimes.swapRemove(i);
                break;
            }
        }
    }

    fn stopAll(self: *RuntimeRegistry) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.runtimes.items) |rt| rt.stop();
    }

    fn deinit(self: *RuntimeRegistry, allocator: std.mem.Allocator) void {
        self.runtimes.deinit(allocator);
    }
};

const RequestParts = struct {
    path: []const u8,
    query: ?[]const u8,
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

const ProxyOutcome = struct {
    bytes: usize,
    streamed: bool,
};

const PreparedOutbound = struct {
    action: ModuleStreamResult.Action,
    body: []const u8 = &.{},
    has_body: bool = false,
    status: u16 = 200,
    response_body: []const u8 = &.{},
};

const ServerContext = struct {
    allocator: std.mem.Allocator,
    bus: *EventBus,
    metrics: *RuntimeMetrics,
    listen_address: []const u8,
    listen_port: u16,
    max_body_size: u32,
    max_upstream_retries: u8,
    router: Router,
    modules: ModuleRegistry,
    upstreams: UpstreamClientManager,

    fn handle(self: *ServerContext, zctx: *const http.Context) !http.Respond {
        const req = zctx.request;
        const uri = req.uri orelse "/";
        const parts = splitUri(uri);
        const method = req.method orelse .GET;
        const http_method = toHttpMethod(method);
        const start_ns = std.time.nanoTimestamp();

        var metric_ctx = RequestMetricContext{
            .known_path = classifyKnownPath(parts.path, http_method),
        };
        var span = self.bus.started(.debug, RequestStarted{
            .method = @tagName(method),
            .path = parts.path,
            .body_len = if (req.body) |b| b.len else 0,
        });

        var bytes_out: usize = 0;
        const respond = self.handleProxy(zctx, parts, &bytes_out, &metric_ctx) catch |err| {
            self.handleRequestError(zctx, method, parts.path, err, metric_ctx);
            return .standard;
        };

        const elapsed_ns = std.time.nanoTimestamp() - start_ns;
        const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        self.metrics.recordRequest(toMethodLabel(http_method), metric_ctx.known_path);
        self.metrics.recordRequestDuration(metric_ctx.known_path, elapsed_s);
        self.metrics.recordResponse(
            metric_ctx.known_path,
            runtime_metrics.statusClass(@intFromEnum(zctx.response.status orelse .OK)),
        );

        span.completed(RequestCompleted{
            .status = @intFromEnum(zctx.response.status orelse .OK),
            .response_bytes = bytes_out,
        });
        return respond;
    }

    fn handleProxy(
        self: *ServerContext,
        zctx: *const http.Context,
        parts: RequestParts,
        bytes_out: *usize,
        metric_ctx: *RequestMetricContext,
    ) !http.Respond {
        const req = zctx.request;
        const method = req.method orelse .GET;
        const http_method = toHttpMethod(method);

        if (method == .GET and std.mem.eql(u8, parts.path, "/_edge/metrics")) {
            var out: std.Io.Writer.Allocating = .init(zctx.allocator);
            try self.metrics.writePrometheus(&out.writer);
            zctx.response.status = .OK;
            zctx.response.mime = .TEXT;
            zctx.response.body = try out.toOwnedSlice();
            bytes_out.* = zctx.response.body.?.len;
            metric_ctx.known_path = .edge_metrics;
            return .standard;
        }

        const plan = self.classifyPlan(parts.path, http_method, req.headers.get("content-type")) orelse {
            zctx.response.status = .@"Not Found";
            zctx.response.mime = .TEXT;
            zctx.response.body = "Not Found";
            return .standard;
        };

        metric_ctx.known_path = classifyKnownPath(parts.path, http_method);
        metric_ctx.route_kind = toRouteKindLabel(plan.route_kind);
        metric_ctx.prefilter = toPrefilterDecisionLabel(plan.decision);
        self.metrics.recordPrefilterDecision(metric_ctx.route_kind, metric_ctx.prefilter);

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

        const outcome = try self.forwardToUpstream(
            zctx,
            parts,
            plan.module_id,
            plan.module,
            plan.decision,
            module_req,
            metric_ctx,
        );
        bytes_out.* = outcome.bytes;
        return if (outcome.streamed) .responded else .standard;
    }

    fn forwardToUpstream(
        self: *ServerContext,
        zctx: *const http.Context,
        parts: RequestParts,
        module_id: ModuleId,
        module: ProxyModule,
        decision: PrefilterDecision,
        module_req: ModuleRequest,
        metric_ctx: *const RequestMetricContext,
    ) !ProxyOutcome {
        const req = zctx.request;
        const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
        const prepared = switch (decision) {
            .fast_path => try prepareFastPathBody(req),
            .policy_path => try preparePolicyBody(self, req, module, module_req, metric_ctx),
        };

        if (prepared.action == .respond_immediately) {
            zctx.response.status = statusFromCode(prepared.status);
            zctx.response.mime = .TEXT;
            zctx.response.body = prepared.response_body;
            return .{ .bytes = prepared.response_body.len, .streamed = false };
        }

        const transport = UpstreamTransport{ .ctx = .{
            .upstreams = &self.upstreams,
            .bus = self.bus,
            .max_upstream_retries = self.max_upstream_retries,
        } };
        const bytes = try transport.proxyPreparedStreaming(
            zctx,
            req,
            parts.path,
            parts.query,
            zctx.allocator,
            method,
            module_id,
            module,
            prepared.body,
            prepared.has_body,
        );
        return .{ .bytes = bytes, .streamed = true };
    }

    fn classifyPlan(
        self: *ServerContext,
        path: []const u8,
        method: HttpMethod,
        content_type: ?[]const u8,
    ) ?RoutePlan {
        const match = self.router.route(path, method) orelse return null;
        const module_entry = self.modules.get(match.module_id) orelse return null;
        const upstream = self.upstreams.getUpstreamConfig(match.module_id);
        const route_kind = runtime_pipeline.classifyRoute(path, method);
        return .{
            .module_id = match.module_id,
            .module = module_entry.module,
            .route_kind = route_kind,
            .module_data = module_entry.config.module_data,
            .upstream = upstream,
            .decision = runtime_pipeline.prefilter(route_kind, method, content_type),
        };
    }

    fn handleRequestError(
        self: *ServerContext,
        zctx: *const http.Context,
        method: http.Method,
        path: []const u8,
        err: anyerror,
        metric_ctx: RequestMetricContext,
    ) void {
        if (isClientDisconnectError(err)) {
            self.bus.debug(RequestError{
                .method = @tagName(method),
                .path = path,
                .err = @errorName(err),
            });
            return;
        }

        self.bus.err(RequestError{
            .method = @tagName(method),
            .path = path,
            .err = @errorName(err),
        });
        self.metrics.recordRequestError(metric_ctx.known_path, .uncaught);
        zctx.response.status = .@"Internal Server Error";
        zctx.response.mime = .TEXT;
        zctx.response.body = "Internal Server Error";
    }
};

pub const ProxyServer = struct {
    context: *ServerContext,
    allocator: std.mem.Allocator,
    runtime_registry: RuntimeRegistry = .{},
    socket_lock: std.Thread.Mutex = .{},
    listen_socket: ?Socket = null,

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

        ctx.* = .{
            .allocator = allocator,
            .bus = bus,
            .metrics = metrics,
            .listen_address = undefined,
            .listen_port = listen_port,
            .max_body_size = max_body_size,
            .max_upstream_retries = max_upstream_retries,
            .router = undefined,
            .modules = .{ .items = .{} },
            .upstreams = UpstreamClientManager.init(allocator),
        };
        errdefer ctx.upstreams.deinit();
        errdefer ctx.modules.deinit(allocator);

        var module_configs = std.ArrayListUnmanaged(ModuleConfig){};
        defer module_configs.deinit(allocator);

        for (module_registrations, 0..) |reg, i| {
            const module_id: ModuleId = @enumFromInt(@as(u32, @intCast(i)));
            _ = try ctx.upstreams.createUpstream(
                reg.upstream_url,
                reg.max_path_length,
                reg.max_request_body,
                reg.max_response_body,
            );
            const upstream_cfg = ctx.upstreams.getUpstreamConfig(module_id);
            const module_cfg = ModuleConfig{
                .id = module_id,
                .routes = reg.routes,
                .upstream = upstream_cfg,
                .module_data = reg.module_data,
            };
            try reg.module.init(allocator, module_cfg);
            try ctx.modules.items.append(allocator, .{
                .id = module_id,
                .module = reg.module,
                .route_kind = reg.route_kind,
                .config = module_cfg,
            });
            try module_configs.append(allocator, module_cfg);
        }

        ctx.router = try Router.init(allocator, module_configs.items);
        errdefer ctx.router.deinit();

        ctx.listen_address = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
            listen_address[0],
            listen_address[1],
            listen_address[2],
            listen_address[3],
        });
        errdefer allocator.free(ctx.listen_address);

        return .{
            .context = ctx,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ProxyServer) void {
        self.runtime_registry.deinit(self.allocator);
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

        var t: Tardy = try .init(self.allocator, .{ .threading = .auto });
        defer t.deinit();

        var router: http.Router = try .init(self.allocator, &.{
            http.Route.init("/").all(self.context, handleRoute).layer(),
            http.Route.init("/%r").all(self.context, handleRoute).layer(),
        }, .{});
        defer router.deinit(self.allocator);

        var socket: Socket = try .init(.{
            .tcp = .{
                .host = self.context.listen_address,
                .port = self.context.listen_port,
            },
        });
        defer socket.close_blocking();
        try socket.bind();
        try socket.listen(4096);

        self.socket_lock.lock();
        self.listen_socket = socket;
        self.socket_lock.unlock();
        defer {
            self.socket_lock.lock();
            self.listen_socket = null;
            self.socket_lock.unlock();
        }

        const EntryParams = struct {
            proxy: *ProxyServer,
            router: *const http.Router,
            socket: Socket,
            request_max: u32,
        };

        try t.entry(
            EntryParams{
                .proxy = self,
                .router = &router,
                .socket = socket,
                .request_max = self.context.max_body_size,
            },
            struct {
                fn entry(rt: *Runtime, p: EntryParams) !void {
                    try p.proxy.runtime_registry.register(p.proxy.allocator, rt);
                    defer p.proxy.runtime_registry.unregister(rt);

                    var server: http.Server = .init(.{
                        .stack_size = 1024 * 1024 * 4,
                        .socket_buffer_bytes = 32 * 1024,
                        .request_bytes_max = p.request_max,
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
        self.runtime_registry.stopAll();
        self.socket_lock.lock();
        if (self.listen_socket) |sock| {
            var close_sock = sock;
            close_sock.close_blocking();
            self.listen_socket = null;
        }
        self.socket_lock.unlock();
    }
};

fn listenThreadMain(proxy: *ProxyServer) void {
    proxy.listen() catch |err| {
        proxy.context.bus.err(ModuleError{ .err = @errorName(err) });
    };
}

fn handleRoute(zctx: *const http.Context, ctx: *ServerContext) !http.Respond {
    return ctx.handle(zctx);
}

fn splitUri(uri: []const u8) RequestParts {
    if (std.mem.indexOfScalar(u8, uri, '?')) |idx| {
        return .{
            .path = uri[0..idx],
            .query = if (idx + 1 < uri.len) uri[idx + 1 ..] else "",
        };
    }
    return .{ .path = uri, .query = null };
}

fn statusFromCode(code: u16) http.Status {
    return std.meta.intToEnum(http.Status, code) catch .@"Internal Server Error";
}

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

fn getHeaderFromZzz(ctx: ?*const anyopaque, name: []const u8) ?[]const u8 {
    const req: *const http.Request = @ptrCast(@alignCast(ctx));
    return req.headers.get(name);
}

fn prepareFastPathBody(req: *const http.Request) !PreparedOutbound {
    const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
    if (!method.requestHasBody()) return .{ .action = .forwarded, .has_body = false };
    const body = req.body orelse return .{ .action = .forwarded, .has_body = false };
    if (body.len == 0) return .{ .action = .forwarded, .has_body = false };
    return .{ .action = .forwarded, .body = body, .has_body = true };
}

fn preparePolicyBody(
    ctx: *ServerContext,
    req: *const http.Request,
    module: ProxyModule,
    module_req: ModuleRequest,
    metric_ctx: *const RequestMetricContext,
) !PreparedOutbound {
    const method = toStdHttpMethod(toHttpMethod(req.method orelse .GET));
    if (method.requestHasBody()) {
        if (req.body) |body| {
            if (body.len > 0) {
                var input = std.Io.Reader.fixed(body);
                var out: std.Io.Writer.Allocating = .init(req.allocator);
                errdefer out.deinit();

                const stream_result = module.processRequestStream(
                    &module_req,
                    &input,
                    &out.writer,
                    req.allocator,
                ) catch |err| blk: {
                    ctx.bus.warn(ModuleError{ .err = @errorName(err) });
                    ctx.metrics.recordRequestError(metric_ctx.known_path, .module);
                    var fallback = std.Io.Reader.fixed(body);
                    _ = transport_mod.streamReaderToWriter(&fallback, &out.writer, std.math.maxInt(usize)) catch {};
                    break :blk ModuleStreamResult.forwarded();
                };

                return switch (stream_result.action) {
                    .forwarded => .{
                        .action = .forwarded,
                        .body = try out.toOwnedSlice(),
                        .has_body = true,
                    },
                    .respond_immediately => .{
                        .action = .respond_immediately,
                        .status = stream_result.status,
                        .response_body = stream_result.response_body,
                    },
                };
            }
        }
    }

    var empty = std.Io.Reader.fixed(&.{});
    var scratch: [64]u8 = undefined;
    var discard: std.Io.Writer.Discarding = .init(&scratch);
    const stream_result = module.processRequestStream(
        &module_req,
        &empty,
        &discard.writer,
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

fn isClientDisconnectError(err: anyerror) bool {
    return err == error.WriteFailed or
        err == error.ReadFailed or
        err == error.Closed or
        err == error.BrokenPipe or
        err == error.ConnectionResetByPeer or
        err == error.ConnectionTimedOut;
}
