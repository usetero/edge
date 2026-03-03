const std = @import("std");

pub const ModuleId = enum(u32) { _ };

pub const RouteKind = enum {
    health,
    datadog_logs,
    datadog_metrics,
    otlp_logs,
    otlp_metrics,
    otlp_traces,
    prometheus_metrics,
    passthrough,
};

pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
    OTHER,
};

pub const MethodBitmask = packed struct(u8) {
    get: bool = false,
    post: bool = false,
    put: bool = false,
    delete: bool = false,
    patch: bool = false,
    head: bool = false,
    options: bool = false,
    _unused: u1 = 0,

    pub const all = MethodBitmask{
        .get = true,
        .post = true,
        .put = true,
        .delete = true,
        .patch = true,
        .head = true,
        .options = true,
    };

    pub fn matches(self: MethodBitmask, method: HttpMethod) bool {
        return switch (method) {
            .GET => self.get,
            .POST => self.post,
            .PUT => self.put,
            .DELETE => self.delete,
            .PATCH => self.patch,
            .HEAD => self.head,
            .OPTIONS => self.options,
            .OTHER => false,
        };
    }
};

pub const RoutePattern = struct {
    pattern_type: PatternType,
    hash: u64,
    pattern: []const u8,
    methods: MethodBitmask,

    pub const PatternType = enum {
        exact,
        prefix,
        suffix,
        any,
    };

    pub fn exact(path: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .exact,
            .hash = std.hash.Wyhash.hash(0, path),
            .pattern = path,
            .methods = methods,
        };
    }

    pub fn prefix(path_prefix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .prefix,
            .hash = 0,
            .pattern = path_prefix,
            .methods = methods,
        };
    }

    pub fn suffix(path_suffix: []const u8, methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .suffix,
            .hash = 0,
            .pattern = path_suffix,
            .methods = methods,
        };
    }

    pub fn any(methods: MethodBitmask) RoutePattern {
        return .{
            .pattern_type = .any,
            .hash = 0,
            .pattern = "/*",
            .methods = methods,
        };
    }
};

pub const UpstreamConfig = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
    base_path: []const u8,
    max_request_body: u32,
    max_response_body: u32,
};

pub const ModuleConfig = struct {
    id: ModuleId,
    routes: []const RoutePattern,
    upstream: UpstreamConfig,
    module_data: ?*const anyopaque,
};

pub const ModuleRequest = struct {
    method: HttpMethod,
    path: []const u8,
    query: []const u8,
    upstream: *const UpstreamConfig,
    module_ctx: ?*const anyopaque,
    // Compatibility field for tests/helpers.
    body: []const u8 = &.{},
    headers_ctx: ?*const anyopaque,
    get_header_fn: ?*const fn (ctx: ?*const anyopaque, name: []const u8) ?[]const u8,

    pub fn getHeader(self: *const ModuleRequest, name: []const u8) ?[]const u8 {
        if (self.get_header_fn) |get_fn| {
            return get_fn(self.headers_ctx, name);
        }
        return null;
    }
};

pub const ModuleStreamResult = struct {
    action: Action,
    status: u16 = 200,
    response_body: []const u8 = &.{},

    pub const Action = enum {
        forwarded,
        respond_immediately,
    };

    pub fn forwarded() ModuleStreamResult {
        return .{ .action = .forwarded };
    }

    pub fn respond(status: u16, body: []const u8) ModuleStreamResult {
        return .{
            .action = .respond_immediately,
            .status = status,
            .response_body = body,
        };
    }
};

pub const ResponseFilter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        getWriter: *const fn (ptr: *anyopaque) *std.Io.Writer,
        finish: *const fn (ptr: *anyopaque) anyerror!usize,
        destroy: *const fn (ptr: *anyopaque) void,
    };

    pub fn writer(self: ResponseFilter) *std.Io.Writer {
        return self.vtable.getWriter(self.ptr);
    }

    pub fn finish(self: ResponseFilter) !usize {
        return self.vtable.finish(self.ptr);
    }

    pub fn destroy(self: ResponseFilter) void {
        self.vtable.destroy(self.ptr);
    }
};
