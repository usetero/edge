const std = @import("std");
const httpz = @import("httpz");

const mode = @import("mode.zig");
const cfg = @import("../config/root.zig");
const pipeline_mod = @import("pipeline.zig");
const router = @import("../control/router.zig");
const policy_loader = @import("../control/policy_loader.zig");
const log_policy = @import("../control/log_policy.zig");
const trace_policy = @import("../control/trace_policy.zig");
const policy = @import("policy_zig");
const io = @import("../io/root.zig");

const AppState = struct {
    allocator: std.mem.Allocator,
    distribution: mode.Distribution,
    config: cfg.types.AppConfig,
    pipeline: pipeline_mod.Pipeline,
    log_program: log_policy.Program,
    trace_program: trace_policy.Program,
    policy_bus: *policy.observability.NoopEventBus,
    policy_registry: *policy.Registry,
    policy_engine: policy.PolicyEngine,
    transport: io.transport.UpstreamTransport,

    fn handleProxy(self: *AppState, route: router.RouteKind, req: *httpz.Request, res: *httpz.Response) !void {
        const is_json_ingest = route == .otlp_logs or
            route == .otlp_metrics or
            route == .otlp_traces or
            route == .datadog_logs;
        if (is_json_ingest) {
            const ct = req.header("content-type") orelse "";
            if (std.mem.indexOf(u8, ct, "json") != null or ct.len == 0) {
                if (req.header("content-length")) |cl| {
                    const n = std.fmt.parseInt(usize, cl, 10) catch 0;
                    if (n <= 2) {
                        res.status = 202;
                        return;
                    }
                }
            }
        }

        const req_reader = try req.reader(5000);
        const res_writer = res.writer();
        var headers_buf: [64]std.http.Header = undefined;
        const headers = try buildForwardHeaders(req, &headers_buf);
        const method = toStdMethod(req.method);
        const upstream_url = self.config.upstreamFor(route);
        const content_type = req.header("content-type");

        const req_encoding = contentEncodingFromHeader(req.header("content-encoding"));
        const req_options = io.transport.ProxyOptions{
            .request = .{
                .content_encoding = req_encoding,
            },
            .response = .{},
            .extra_headers = headers,
        };

        var policy_version: u64 = self.pipeline.engine.currentVersion();
        var policy_action: []const u8 = "fast_path";
        const pre = blk: {
            if (is_json_ingest) {
                const ct = content_type orelse "";
                if (std.mem.indexOf(u8, ct, "json") != null or ct.len == 0) {
                    break :blk pipeline_mod.PrefilterDecision.policy_path;
                }
            }
            break :blk self.pipeline.prefilter(route, content_type);
        };

        const result = switch (pre) {
            .fast_path => try self.transport.proxy(
                route,
                upstream_url,
                method,
                req.url.path,
                req.url.query,
                &req_reader.interface,
                req.body(),
                res_writer,
                req_options,
            ),
            .policy_path => try self.proxyWithPolicy(
                route,
                upstream_url,
                method,
                req,
                res_writer,
                req_options,
                &policy_version,
                &policy_action,
            ),
        };

        res.status = result.status_code;
        try res.headerOpts("x-edge-policy-version", try std.fmt.allocPrint(res.arena, "{d}", .{policy_version}), .{});
        try res.headerOpts("x-edge-policy-action", policy_action, .{ .dupe_value = true });
    }

    fn proxyWithPolicy(
        self: *AppState,
        route: router.RouteKind,
        upstream_url: []const u8,
        method: std.http.Method,
        req: *httpz.Request,
        res_writer: *std.Io.Writer,
        req_options: io.transport.ProxyOptions,
        out_version: *u64,
        out_action: *[]const u8,
    ) !io.transport.ProxyResult {
        var owned_payload: ?[]u8 = null;
        defer if (owned_payload) |buf| self.allocator.free(buf);
        var payload = if (req.body()) |b|
            b
        else blk: {
            var req_reader = try req.reader(5000);
            const mat = try materializeReader(
                self.allocator,
                &req_reader.interface,
                self.config.max_body_size,
            );
            owned_payload = mat;
            break :blk mat;
        };

        if (route == .otlp_logs or route == .datadog_logs) {
            if (isEmptyJsonPayload(payload)) {
                out_action.* = "empty_input";
                return .{
                    .status_code = 202,
                    .request = .{},
                    .response = .{},
                };
            }
            if (filterLogPayload(
                req.arena,
                route,
                payload,
                &self.log_program,
                out_version,
                out_action,
            )) |filtered| {
                payload = filtered;
            } else |_| {
                // Fall through to whole-payload evaluation on parse failures.
            }
        } else if (route == .otlp_traces) {
            if (isEmptyJsonPayload(payload)) {
                out_action.* = "empty_input";
                return .{
                    .status_code = 202,
                    .request = .{},
                    .response = .{},
                };
            }
            if (filterTracePayload(
                req.arena,
                payload,
                &self.policy_engine,
                out_version,
                out_action,
            )) |filtered| {
                payload = filtered;
            } else |_| {}
        }

        const decision = self.pipeline.evaluatePolicy(payload);
        out_version.* = decision.snapshot_version;
        out_action.* = @tagName(decision.action);

        if (decision.action == .drop) {
            return .{
                .status_code = 202,
                .request = .{},
                .response = .{},
            };
        }

        var payload_reader = std.Io.Reader.fixed(payload);
        return self.transport.proxy(
            route,
            upstream_url,
            method,
            req.url.path,
            req.url.query,
            &payload_reader,
            payload,
            res_writer,
            req_options,
        );
    }

    pub fn handle(self: *AppState, req: *httpz.Request, res: *httpz.Response) void {
        const path = req.url.path;
        const method = methodAsString(req);

        if (std.mem.eql(u8, method, "GET") and std.mem.eql(u8, path, "/healthz")) {
            res.status = 200;
            res.body = "ok";
            return;
        }

        const route = self.pipeline.classify(.{
            .method = method,
            .path = path,
        });
        if (!isRouteEnabled(self.distribution, route)) {
            res.status = 404;
            res.body = "not found";
            return;
        }

        self.handleProxy(route, req, res) catch |err| {
            res.status = 500;
            res.body = "proxy error";
            std.log.err("proxy error: {}", .{err});
            return;
        };
    }
};

pub fn run(distribution: mode.Distribution) !void {
    if (distribution == .lambda) {
        var stdout_buffer: [256]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const out = &stdout_writer.interface;
        try out.print("lambda distribution scaffold is not implemented yet\n", .{});
        try out.flush();
        return;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const conf = try cfg.types.AppConfig.fromArgs(allocator);

    var app = AppState{
        .allocator = allocator,
        .distribution = distribution,
        .config = conf,
        .pipeline = try pipeline_mod.Pipeline.init(allocator),
        .log_program = .{},
        .trace_program = .{},
        .policy_bus = try allocator.create(policy.observability.NoopEventBus),
        .policy_registry = try allocator.create(policy.Registry),
        .policy_engine = undefined,
        .transport = io.transport.UpstreamTransport.init(allocator),
    };
    app.policy_bus.init();
    app.policy_registry.* = policy.Registry.init(allocator, app.policy_bus.eventBus());
    app.policy_engine = policy.PolicyEngine.init(app.policy_bus.eventBus(), app.policy_registry);
    try policy_loader.loadFromProviders(allocator, &app.pipeline.engine, conf.policy_providers);
    {
        const count_files = blk: {
            var n: usize = 0;
            for (conf.policy_providers) |pp| {
                if (std.mem.eql(u8, pp.type, "file") and pp.path != null) n += 1;
            }
            break :blk n;
        };
        const files = try allocator.alloc([]const u8, count_files);
        defer allocator.free(files);
        var idx: usize = 0;
        for (conf.policy_providers) |pp| {
            if (std.mem.eql(u8, pp.type, "file")) if (pp.path) |p| {
                files[idx] = p;
                idx += 1;
            };
        }
        app.log_program = try log_policy.loadFromProviders(allocator, files);
        app.trace_program = try trace_policy.loadFromProviders(allocator, files);
        for (files) |path| {
            const parsed = try policy.parser.parsePoliciesFile(allocator, path);
            defer {
                for (parsed) |*p| p.deinit(allocator);
                allocator.free(parsed);
            }
            try app.policy_registry.updatePolicies(parsed, "file", .file);
        }
    }
    defer app.log_program.deinit(allocator);
    defer app.trace_program.deinit(allocator);
    defer {
        app.policy_registry.deinit();
        allocator.destroy(app.policy_registry);
        allocator.destroy(app.policy_bus);
    }
    defer app.pipeline.deinit();
    defer app.transport.deinit();

    var server = try httpz.Server(*AppState).init(allocator, .{
        .port = conf.listen_port,
        .address = conf.listen_address,
        .request = .{
            // Keeps large payloads streaming from socket instead of always buffering.
            .lazy_read_size = 32 * 1024,
            .max_body_size = conf.max_body_size,
        },
    }, &app);
    defer {
        server.stop();
        server.deinit();
    }

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const out = &stdout_writer.interface;
    try out.print(
        "starting {s} on {s}:{d}\n",
        .{ distribution.name(), conf.listen_address, conf.listen_port },
    );
    try out.flush();

    try server.listen();
}

fn contentEncodingFromHeader(header: ?[]const u8) io.streaming_proxy.ContentEncoding {
    const value = header orelse return .identity;
    if (std.ascii.eqlIgnoreCase(value, "gzip")) return .gzip;
    if (std.ascii.eqlIgnoreCase(value, "zstd")) return .zstd;
    return .identity;
}

fn methodAsString(req: *const httpz.Request) []const u8 {
    return switch (req.method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .PATCH => "PATCH",
        .DELETE => "DELETE",
        .OPTIONS => "OPTIONS",
        .CONNECT => "CONNECT",
        .OTHER => req.method_string,
    };
}

fn isRouteEnabled(distribution: mode.Distribution, route: router.RouteKind) bool {
    return switch (distribution) {
        .edge => route != .passthrough,
        .datadog => route == .datadog_logs,
        .otlp => route == .otlp_logs or route == .otlp_metrics or route == .otlp_traces,
        .prometheus => route == .prometheus_metrics,
        .lambda => false,
    };
}

fn toStdMethod(method: httpz.Method) std.http.Method {
    return switch (method) {
        .GET => .GET,
        .HEAD => .HEAD,
        .POST => .POST,
        .PUT => .PUT,
        .PATCH => .PATCH,
        .DELETE => .DELETE,
        .OPTIONS => .OPTIONS,
        .CONNECT => .CONNECT,
        .OTHER => .GET,
    };
}

fn buildForwardHeaders(req: *httpz.Request, buf: []std.http.Header) ![]std.http.Header {
    var count: usize = 0;
    const keys = req.headers.keys[0..req.headers.len];
    const vals = req.headers.values[0..req.headers.len];
    for (keys, vals) |name, value| {
        if (shouldSkipRequestHeader(name)) continue;
        if (count >= buf.len) return error.TooManyHeaders;
        buf[count] = .{ .name = name, .value = value };
        count += 1;
    }
    return buf[0..count];
}

fn shouldSkipRequestHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding");
}

fn materializeReader(
    allocator: std.mem.Allocator,
    reader: *const std.Io.Reader,
    max_bytes: usize,
) ![]u8 {
    var r = reader.*;
    var writer = std.Io.Writer.Allocating.init(allocator);
    errdefer writer.deinit();

    while (true) {
        const n = r.stream(&writer.writer, .limited(4096)) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        if (writer.written().len > max_bytes) return error.BodyTooLarge;
    }

    return writer.toOwnedSlice();
}

fn isEmptyJsonPayload(payload: []const u8) bool {
    const trimmed = std.mem.trim(u8, payload, " \n\r\t");
    return trimmed.len == 0 or std.mem.eql(u8, trimmed, "{}") or std.mem.eql(u8, trimmed, "[]");
}

fn filterLogPayload(
    allocator: std.mem.Allocator,
    route: router.RouteKind,
    payload: []const u8,
    program: *const log_policy.Program,
    out_version: *u64,
    out_action: *[]const u8,
) ![]u8 {
    var root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, payload, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });

    const dropped = switch (route) {
        .datadog_logs => filterDatadogRecords(&root, program, out_version),
        .otlp_logs => filterOtlpRecords(allocator, &root, program, out_version),
        else => 0,
    };
    _ = dropped;
    out_action.* = "record_filter";

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(root, .{}, &out.writer);
    return out.toOwnedSlice();
}

fn filterTracePayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
    program: *const trace_policy.Program,
    out_version: *u64,
    out_action: *[]const u8,
) ![]u8 {
    _ = out_version;
    var root = try std.json.parseFromSliceLeaky(std.json.Value, allocator, payload, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    _ = filterTraceSpans(allocator, &root, program);
    out_action.* = "record_filter";

    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();
    try std.json.Stringify.value(root, .{}, &out.writer);
    return out.toOwnedSlice();
}

fn filterTraceSpans(
    allocator: std.mem.Allocator,
    root: *std.json.Value,
    program: *const trace_policy.Program,
) usize {
    if (root.* != .object) return 0;
    const resource_spans_ptr = root.object.getPtr("resourceSpans") orelse return 0;
    if (resource_spans_ptr.* != .array) return 0;
    var dropped: usize = 0;

    var resource_write_idx: usize = 0;
    for (resource_spans_ptr.array.items) |resource_span_item| {
        if (resource_span_item != .object) continue;
        var resource_span = resource_span_item;
        const scope_spans_ptr = resource_span.object.getPtr("scopeSpans") orelse continue;
        if (scope_spans_ptr.* != .array) continue;

        var resource_attrs: std.ArrayListUnmanaged(trace_policy.Attribute) = .empty;
        defer resource_attrs.deinit(allocator);
        const resource_attrs_json = blk: {
            const resource = resource_span.object.get("resource") orelse break :blk null;
            if (resource != .object) break :blk null;
            break :blk resource.object.get("attributes");
        };
        collectTraceAttributes(allocator, resource_attrs_json, &resource_attrs) catch {};

        var scope_write_idx: usize = 0;
        for (scope_spans_ptr.array.items) |scope_span_item| {
            if (scope_span_item != .object) continue;
            var scope_span = scope_span_item;
            const spans_ptr = scope_span.object.getPtr("spans") orelse continue;
            if (spans_ptr.* != .array) continue;

            var scope_attrs: std.ArrayListUnmanaged(trace_policy.Attribute) = .empty;
            defer scope_attrs.deinit(allocator);
            const scope_attrs_json = blk: {
                const scope = scope_span.object.get("scope") orelse break :blk null;
                if (scope != .object) break :blk null;
                break :blk scope.object.get("attributes");
            };
            collectTraceAttributes(allocator, scope_attrs_json, &scope_attrs) catch {};
            const scope_name = traceScopeField(scope_span.object, "name");
            const scope_version = traceScopeField(scope_span.object, "version");
            const scope_schema_url = jsonString(scope_span.object.get("schemaUrl"));

            const sample_budgets = allocator.alloc(usize, program.policies.len) catch return dropped;
            defer allocator.free(sample_budgets);
            const sample_taken = allocator.alloc(usize, program.policies.len) catch return dropped;
            defer allocator.free(sample_taken);
            @memset(sample_budgets, 0);
            @memset(sample_taken, 0);

            for (program.policies, 0..) |*policy, idx| {
                if (policy.keep_percentage <= 0.0 or policy.keep_percentage >= 100.0) {
                    sample_budgets[idx] = std.math.maxInt(usize);
                    continue;
                }
                var matched_count: usize = 0;
                for (spans_ptr.array.items) |span_item| {
                    if (span_item != .object) continue;
                    var span_attrs: std.ArrayListUnmanaged(trace_policy.Attribute) = .empty;
                    defer span_attrs.deinit(allocator);
                    collectTraceAttributes(allocator, span_item.object.get("attributes"), &span_attrs) catch {};
                    const ctx = buildTraceContext(span_item.object, scope_name, scope_version, scope_schema_url, resource_attrs.items, scope_attrs.items, span_attrs.items);
                    if (trace_policy.policyMatches(policy, ctx)) matched_count += 1;
                }
                sample_budgets[idx] = @intFromFloat(@ceil(@as(f64, @floatFromInt(matched_count)) * (policy.keep_percentage / 100.0)));
            }

            var write_idx: usize = 0;
            for (spans_ptr.array.items) |span_item| {
                if (span_item != .object) continue;
                var span = span_item;
                var span_attrs: std.ArrayListUnmanaged(trace_policy.Attribute) = .empty;
                defer span_attrs.deinit(allocator);
                collectTraceAttributes(allocator, span.object.get("attributes"), &span_attrs) catch {};
                const ctx = buildTraceContext(span.object, scope_name, scope_version, scope_schema_url, resource_attrs.items, scope_attrs.items, span_attrs.items);

                var keep = true;
                var trace_state_pct: ?f64 = null;
                policy_loop: for (program.policies, 0..) |*policy, idx| {
                    if (!trace_policy.policyMatches(policy, ctx)) continue;
                    if (policy.keep_percentage > 0.0 and trace_state_pct == null) trace_state_pct = policy.keep_percentage;
                    if (policy.keep_percentage <= 0.0) {
                        keep = false;
                        break :policy_loop;
                    }
                    if (policy.keep_percentage >= 100.0) continue;
                    if (sample_taken[idx] >= sample_budgets[idx]) {
                        keep = false;
                        break :policy_loop;
                    }
                    sample_taken[idx] += 1;
                }

                if (keep) {
                    if (trace_state_pct) |pct| setTraceStateThreshold(&span, pct);
                    spans_ptr.array.items[write_idx] = span;
                    write_idx += 1;
                } else {
                    dropped += 1;
                }
            }
            spans_ptr.array.items.len = write_idx;
            if (write_idx > 0) {
                scope_spans_ptr.array.items[scope_write_idx] = scope_span;
                scope_write_idx += 1;
            }
        }
        scope_spans_ptr.array.items.len = scope_write_idx;
        if (scope_write_idx > 0) {
            resource_spans_ptr.array.items[resource_write_idx] = resource_span;
            resource_write_idx += 1;
        }
    }
    resource_spans_ptr.array.items.len = resource_write_idx;
    if (resource_write_idx == 0) _ = root.object.orderedRemove("resourceSpans");
    return dropped;
}

fn buildTraceContext(
    span_obj: std.json.ObjectMap,
    scope_name: ?[]const u8,
    scope_version: ?[]const u8,
    scope_schema_url: ?[]const u8,
    resource_attrs: []const trace_policy.Attribute,
    scope_attrs: []const trace_policy.Attribute,
    span_attrs: []const trace_policy.Attribute,
) trace_policy.SpanContext {
    return .{
        .name = traceString(span_obj.get("name")) orelse "",
        .has_name = span_obj.get("name") != null,
        .parent_span_id = traceString(span_obj.get("parentSpanId")) orelse "",
        .has_parent_span_id = span_obj.get("parentSpanId") != null,
        .trace_state = traceString(span_obj.get("traceState")) orelse "",
        .has_trace_state = span_obj.get("traceState") != null,
        .scope_name = scope_name orelse "",
        .has_scope_name = scope_name != null,
        .scope_version = scope_version orelse "",
        .has_scope_version = scope_version != null,
        .scope_schema_url = scope_schema_url orelse "",
        .has_scope_schema_url = scope_schema_url != null,
        .span_kind = spanKindString(span_obj.get("kind")) orelse "",
        .has_span_kind = span_obj.get("kind") != null,
        .span_status = spanStatusString(span_obj.get("status")) orelse "",
        .has_span_status = span_obj.get("status") != null,
        .has_event_name = spanHasEvent(span_obj.get("events")),
        .resource_attributes = resource_attrs,
        .scope_attributes = scope_attrs,
        .span_attributes = span_attrs,
    };
}

fn collectTraceAttributes(
    allocator: std.mem.Allocator,
    maybe: ?std.json.Value,
    out: *std.ArrayListUnmanaged(trace_policy.Attribute),
) !void {
    if (maybe == null or maybe.? != .array) return;
    for (maybe.?.array.items) |a| {
        if (a != .object) continue;
        const k = a.object.get("key") orelse continue;
        const v = a.object.get("value") orelse continue;
        if (k != .string) continue;
        try collectTraceAttributeValue(allocator, k.string, v, out);
    }
}

fn collectTraceAttributeValue(
    allocator: std.mem.Allocator,
    key: []const u8,
    value: std.json.Value,
    out: *std.ArrayListUnmanaged(trace_policy.Attribute),
) !void {
    if (value != .object) return;
    if (value.object.get("stringValue")) |sv| {
        if (sv == .string) try out.append(allocator, .{ .key = key, .value = sv.string });
        return;
    }
    if (value.object.get("boolValue")) |bv| {
        if (bv == .bool) try out.append(allocator, .{ .key = key, .value = if (bv.bool) "true" else "false" });
    }
}

fn traceScopeField(scope_span: std.json.ObjectMap, field: []const u8) ?[]const u8 {
    const scope = scope_span.get("scope") orelse return null;
    if (scope != .object) return null;
    return traceString(scope.object.get(field));
}

fn traceString(v: ?std.json.Value) ?[]const u8 {
    if (v == null or v.? != .string) return null;
    return v.?.string;
}

fn spanKindString(v: ?std.json.Value) ?[]const u8 {
    if (v == null) return null;
    if (v.? == .string) return v.?.string;
    if (v.? == .integer) {
        return switch (@as(i64, @intCast(v.?.integer))) {
            1 => "SPAN_KIND_INTERNAL",
            2 => "SPAN_KIND_SERVER",
            3 => "SPAN_KIND_CLIENT",
            4 => "SPAN_KIND_PRODUCER",
            5 => "SPAN_KIND_CONSUMER",
            else => "SPAN_KIND_UNSPECIFIED",
        };
    }
    return null;
}

fn spanStatusString(v: ?std.json.Value) ?[]const u8 {
    if (v == null or v.? != .object) return null;
    const code = v.?.object.get("code") orelse return null;
    if (code == .string) return switch (std.mem.eql(u8, code.string, "STATUS_CODE_ERROR")) {
        true => "SPAN_STATUS_CODE_ERROR",
        false => if (std.mem.eql(u8, code.string, "STATUS_CODE_OK")) "SPAN_STATUS_CODE_OK" else "SPAN_STATUS_CODE_UNSET",
    };
    if (code == .integer) return switch (code.integer) {
        1 => "SPAN_STATUS_CODE_OK",
        2 => "SPAN_STATUS_CODE_ERROR",
        else => "SPAN_STATUS_CODE_UNSET",
    };
    return null;
}

fn spanHasEvent(maybe_events: ?std.json.Value) bool {
    if (maybe_events == null or maybe_events.? != .array) return false;
    for (maybe_events.?.array.items) |e| {
        if (e != .object) continue;
        if (e.object.get("name")) |n| if (n == .string and n.string.len > 0) return true;
    }
    return false;
}

fn setTraceStateThreshold(span: *std.json.Value, pct: f64) void {
    if (span.* != .object) return;
    const th = traceThresholdHex(pct);
    const new_ot = std.fmt.allocPrint(std.heap.page_allocator, "ot=th:{s}", .{th}) catch return;
    const existing = traceString(span.object.get("traceState"));
    if (existing == null or existing.?.len == 0) {
        span.object.put("traceState", .{ .string = new_ot }) catch {};
        return;
    }

    var out = std.ArrayListUnmanaged(u8).empty;
    defer out.deinit(std.heap.page_allocator);
    out.appendSlice(std.heap.page_allocator, new_ot) catch return;
    var it = std.mem.splitScalar(u8, existing.?, ',');
    while (it.next()) |entry| {
        const e = std.mem.trim(u8, entry, " ");
        if (e.len == 0) continue;
        if (std.mem.startsWith(u8, e, "ot=")) continue;
        out.append(std.heap.page_allocator, ',') catch return;
        out.appendSlice(std.heap.page_allocator, e) catch return;
    }
    const merged = out.toOwnedSlice(std.heap.page_allocator) catch return;
    span.object.put("traceState", .{ .string = merged }) catch {};
}

fn traceThresholdHex(pct: f64) []const u8 {
    const clamped = std.math.clamp(pct, 0.0, 100.0);
    const raw = (100.0 - clamped) / 100.0 * 65536.0;
    var th: u32 = @intFromFloat(@floor(raw));
    if (th > 0xFFFF) th = 0xFFFF;
    const s = std.fmt.allocPrint(std.heap.page_allocator, "{x}", .{th}) catch return "0";
    var end = s.len;
    while (end > 1 and s[end - 1] == '0') : (end -= 1) {}
    return s[0..end];
}

fn filterDatadogRecords(
    root: *std.json.Value,
    program: *const log_policy.Program,
    out_version: *u64,
) usize {
    _ = out_version;
    if (root.* != .array) return 0;
    var dropped: usize = 0;
    const items = root.array.items;
    var write_idx: usize = 0;
    for (items) |item| {
        var keep = true;
        if (item == .object) {
            const body = if (item.object.get("message")) |msg| if (msg == .string) msg.string else "" else "";
            const decision = log_policy.evaluate(program, .{
                .body = body,
                .has_body = item.object.get("message") != null,
            });
            keep = !decision.drop;
        }
        if (keep) {
            root.array.items[write_idx] = item;
            write_idx += 1;
        } else {
            dropped += 1;
        }
    }
    root.array.items.len = write_idx;
    return dropped;
}

fn filterOtlpRecords(
    allocator: std.mem.Allocator,
    root: *std.json.Value,
    program: *const log_policy.Program,
    out_version: *u64,
) usize {
    _ = out_version;
    if (root.* != .object) return 0;
    const resource_logs_ptr = root.object.getPtr("resourceLogs") orelse return 0;
    if (resource_logs_ptr.* != .array) return 0;
    const policy_counters = allocator.alloc(usize, program.policies.len) catch return 0;
    defer allocator.free(policy_counters);
    @memset(policy_counters, 0);

    var dropped: usize = 0;
    var resource_write_idx: usize = 0;
    for (resource_logs_ptr.array.items) |resource_log| {
        if (resource_log != .object) continue;
        var kept_resource = resource_log;
        const resource_schema = jsonString(kept_resource.object.get("schemaUrl"));
        const scope_logs_ptr = kept_resource.object.getPtr("scopeLogs") orelse continue;
        if (scope_logs_ptr.* != .array) continue;

        var resource_attrs: std.ArrayListUnmanaged(log_policy.Attribute) = .empty;
        defer resource_attrs.deinit(allocator);
        const maybe_resource_attrs = blk: {
            const resource = kept_resource.object.get("resource") orelse break :blk null;
            if (resource != .object) break :blk null;
            break :blk resource.object.get("attributes");
        };
        collectAttributes(allocator, maybe_resource_attrs, &resource_attrs) catch {};

        var scope_write_idx: usize = 0;
        for (scope_logs_ptr.array.items) |scope_log| {
            if (scope_log != .object) continue;
            var kept_scope = scope_log;
            const scope_schema = jsonString(kept_scope.object.get("schemaUrl"));
            const records_ptr = kept_scope.object.getPtr("logRecords") orelse continue;
            if (records_ptr.* != .array) continue;

            var scope_attrs: std.ArrayListUnmanaged(log_policy.Attribute) = .empty;
            defer scope_attrs.deinit(allocator);
            const maybe_scope_attrs = blk: {
                const scope = kept_scope.object.get("scope") orelse break :blk null;
                if (scope != .object) break :blk null;
                break :blk scope.object.get("attributes");
            };
            collectAttributes(allocator, maybe_scope_attrs, &scope_attrs) catch {};

            const sample_budgets = allocator.alloc(usize, program.policies.len) catch return dropped;
            defer allocator.free(sample_budgets);
            const sample_taken = allocator.alloc(usize, program.policies.len) catch return dropped;
            defer allocator.free(sample_taken);
            @memset(sample_budgets, 0);
            @memset(sample_taken, 0);

            for (program.policies, 0..) |*policy, policy_idx| {
                switch (policy.keep) {
                    .sample_pct => |pct| {
                        if (pct == 0) {
                            sample_budgets[policy_idx] = 0;
                            continue;
                        }
                        if (pct >= 100) {
                            sample_budgets[policy_idx] = std.math.maxInt(usize);
                            continue;
                        }
                        var matched_count: usize = 0;
                        for (records_ptr.array.items) |rec_item| {
                            if (rec_item != .object) continue;
                            var attrs_for_match: std.ArrayListUnmanaged(log_policy.Attribute) = .empty;
                            defer attrs_for_match.deinit(allocator);
                            collectAttributes(allocator, rec_item.object.get("attributes"), &attrs_for_match) catch {};
                            const ctx_for_match = log_policy.RecordContext{
                                .body = otlpBodyString(rec_item.object) orelse "",
                                .has_body = rec_item.object.get("body") != null,
                                .severity_text = otlpSeverityText(rec_item.object) orelse "",
                                .has_severity_text = rec_item.object.get("severityText") != null,
                                .trace_id = otlpStringField(rec_item.object, "traceId") orelse "",
                                .has_trace_id = rec_item.object.get("traceId") != null,
                                .span_id = otlpStringField(rec_item.object, "spanId") orelse "",
                                .has_span_id = rec_item.object.get("spanId") != null,
                                .event_name = otlpStringField(rec_item.object, "eventName") orelse "",
                                .has_event_name = rec_item.object.get("eventName") != null,
                                .resource_schema_url = resource_schema orelse "",
                                .has_resource_schema_url = resource_schema != null,
                                .scope_schema_url = scope_schema orelse "",
                                .has_scope_schema_url = scope_schema != null,
                                .resource_attributes = resource_attrs.items,
                                .scope_attributes = scope_attrs.items,
                                .log_attributes = attrs_for_match.items,
                            };
                            if (log_policy.policyMatches(policy, ctx_for_match)) matched_count += 1;
                        }
                        sample_budgets[policy_idx] = (matched_count * pct + 99) / 100;
                    },
                    else => {},
                }
            }

            var write_idx: usize = 0;
            for (records_ptr.array.items) |record_item| {
                var record = record_item;
                var keep = true;
                if (record == .object) {
                    var attrs: std.ArrayListUnmanaged(log_policy.Attribute) = .empty;
                    defer attrs.deinit(allocator);
                    collectAttributes(allocator, record.object.get("attributes"), &attrs) catch {};

                    const ctx = log_policy.RecordContext{
                        .body = otlpBodyString(record.object) orelse "",
                        .has_body = record.object.get("body") != null,
                        .severity_text = otlpSeverityText(record.object) orelse "",
                        .has_severity_text = record.object.get("severityText") != null,
                        .trace_id = otlpStringField(record.object, "traceId") orelse "",
                        .has_trace_id = record.object.get("traceId") != null,
                        .span_id = otlpStringField(record.object, "spanId") orelse "",
                        .has_span_id = record.object.get("spanId") != null,
                        .event_name = otlpStringField(record.object, "eventName") orelse "",
                        .has_event_name = record.object.get("eventName") != null,
                        .resource_schema_url = resource_schema orelse "",
                        .has_resource_schema_url = resource_schema != null,
                        .scope_schema_url = scope_schema orelse "",
                        .has_scope_schema_url = scope_schema != null,
                        .resource_attributes = resource_attrs.items,
                        .scope_attributes = scope_attrs.items,
                        .log_attributes = attrs.items,
                    };
                    var drop_record = false;
                    policy_loop: for (program.policies, 0..) |*policy, policy_idx| {
                        if (!log_policy.policyMatches(policy, ctx)) continue;
                        switch (policy.keep) {
                            .none => {
                                drop_record = true;
                                break :policy_loop;
                            },
                            .all => {},
                            .rate => |r| {
                                if (policy_counters[policy_idx] >= r.limit) {
                                    drop_record = true;
                                    break :policy_loop;
                                }
                                policy_counters[policy_idx] += 1;
                            },
                            .sample_pct => |pct| {
                                _ = pct;
                                if (sample_taken[policy_idx] >= sample_budgets[policy_idx]) {
                                    drop_record = true;
                                    break :policy_loop;
                                }
                                sample_taken[policy_idx] += 1;
                            },
                        }
                        applyPolicyTransforms(policy, &record, &kept_resource, &kept_scope);
                        if (policy.add_body) |add_body| {
                            setOtlpBodyString(&record, add_body.value, add_body.upsert);
                        }
                    }
                    keep = !drop_record;
                }
                if (keep) {
                    records_ptr.array.items[write_idx] = record;
                    write_idx += 1;
                } else {
                    dropped += 1;
                }
            }
            records_ptr.array.items.len = write_idx;
            if (write_idx > 0) {
                scope_logs_ptr.array.items[scope_write_idx] = kept_scope;
                scope_write_idx += 1;
            }
        }
        scope_logs_ptr.array.items.len = scope_write_idx;
        if (scope_write_idx > 0) {
            resource_logs_ptr.array.items[resource_write_idx] = kept_resource;
            resource_write_idx += 1;
        }
    }
    resource_logs_ptr.array.items.len = resource_write_idx;
    if (resource_write_idx == 0) {
        _ = root.object.orderedRemove("resourceLogs");
    }
    return dropped;
}

fn otlpBodyString(obj: std.json.ObjectMap) ?[]const u8 {
    const body = obj.get("body") orelse return null;
    if (body != .object) return null;
    const str = body.object.get("stringValue") orelse return null;
    if (str != .string) return null;
    return str.string;
}

fn otlpSeverityText(obj: std.json.ObjectMap) ?[]const u8 {
    const sev = obj.get("severityText") orelse return null;
    if (sev != .string) return null;
    return sev.string;
}

fn otlpStringField(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    if (v != .string) return null;
    return v.string;
}

fn jsonString(v: ?std.json.Value) ?[]const u8 {
    if (v == null) return null;
    if (v.? != .string) return null;
    return v.?.string;
}

fn collectAttributes(
    allocator: std.mem.Allocator,
    maybe: ?std.json.Value,
    out: *std.ArrayListUnmanaged(log_policy.Attribute),
) !void {
    if (maybe == null) return;
    if (maybe.? != .array) return;
    for (maybe.?.array.items) |a| {
        if (a != .object) continue;
        const k = a.object.get("key") orelse continue;
        const v = a.object.get("value") orelse continue;
        if (k != .string) continue;
        try collectAttributeValue(allocator, k.string, v, out);
    }
}

fn collectAttributeValue(
    allocator: std.mem.Allocator,
    key: []const u8,
    value: std.json.Value,
    out: *std.ArrayListUnmanaged(log_policy.Attribute),
) !void {
    if (value != .object) return;
    if (value.object.get("stringValue")) |sv| {
        if (sv == .string) try out.append(allocator, .{ .key = key, .value = sv.string });
        return;
    }
    if (value.object.get("boolValue")) |bv| {
        if (bv == .bool) try out.append(allocator, .{
            .key = key,
            .value = if (bv.bool) "true" else "false",
        });
        return;
    }
    if (value.object.get("kvlistValue")) |kv| {
        if (kv != .object) return;
        const entries = kv.object.get("values") orelse return;
        if (entries != .array) return;
        for (entries.array.items) |entry| {
            if (entry != .object) continue;
            const child_key = entry.object.get("key") orelse continue;
            const child_value = entry.object.get("value") orelse continue;
            if (child_key != .string) continue;
            const full = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ key, child_key.string });
            try collectAttributeValue(allocator, full, child_value, out);
        }
    }
}

fn setOtlpBodyString(record: *std.json.Value, value: []const u8, upsert: bool) void {
    if (record.* != .object) return;
    var body = record.object.getPtr("body") orelse {
        record.object.put("body", .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) }) catch return;
        return setOtlpBodyString(record, value, upsert);
    };
    if (!upsert and body.* == .object and body.object.get("stringValue") != null) return;
    if (body.* != .object) body.* = .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) };
    body.object.put("stringValue", .{ .string = value }) catch {};
}

fn applyPolicyTransforms(
    policy: *const log_policy.Policy,
    record: *std.json.Value,
    resource_log: *std.json.Value,
    scope_log: *std.json.Value,
) void {
    const transform = policy.transform_raw orelse return;
    if (transform != .object) return;

    if (transform.object.get("remove")) |ops| applyRemoveTransforms(ops, record, resource_log, scope_log);
    if (transform.object.get("redact")) |ops| applyRedactTransforms(ops, record, resource_log, scope_log);
    if (transform.object.get("rename")) |ops| applyRenameTransforms(ops, record, resource_log, scope_log);
    if (transform.object.get("add")) |ops| applyAddTransforms(ops, record, resource_log, scope_log);
}

fn applyRemoveTransforms(ops: std.json.Value, record: *std.json.Value, resource_log: *std.json.Value, scope_log: *std.json.Value) void {
    if (ops != .array) return;
    for (ops.array.items) |op| {
        if (op != .object) continue;
        if (op.object.get("log_field")) |lf| {
            if (lf == .string and std.mem.eql(u8, lf.string, "body")) removeBody(record);
            continue;
        }
        if (op.object.get("log_attribute")) |k| {
            if (k == .string) removeAttribute(record, "attributes", k.string);
            continue;
        }
        if (op.object.get("resource_attribute")) |k| {
            if (k == .string) removeNestedAttribute(resource_log, "resource", "attributes", k.string);
            continue;
        }
        if (op.object.get("scope_attribute")) |k| {
            if (k == .string) removeNestedAttribute(scope_log, "scope", "attributes", k.string);
            continue;
        }
    }
}

fn applyRedactTransforms(ops: std.json.Value, record: *std.json.Value, resource_log: *std.json.Value, scope_log: *std.json.Value) void {
    if (ops != .array) return;
    for (ops.array.items) |op| {
        if (op != .object) continue;
        const replacement = op.object.get("replacement") orelse continue;
        if (replacement != .string) continue;
        if (op.object.get("log_field")) |lf| {
            if (lf == .string and std.mem.eql(u8, lf.string, "body")) {
                setOtlpBodyString(record, replacement.string, true);
            }
            continue;
        }
        if (op.object.get("log_attribute")) |k| {
            if (k == .string) redactAttribute(record, "attributes", k.string, replacement.string);
            continue;
        }
        if (op.object.get("resource_attribute")) |k| {
            if (k == .string) redactNestedAttribute(resource_log, "resource", "attributes", k.string, replacement.string);
            continue;
        }
        if (op.object.get("scope_attribute")) |k| {
            if (k == .string) redactNestedAttribute(scope_log, "scope", "attributes", k.string, replacement.string);
            continue;
        }
    }
}

fn applyRenameTransforms(ops: std.json.Value, record: *std.json.Value, resource_log: *std.json.Value, scope_log: *std.json.Value) void {
    if (ops != .array) return;
    for (ops.array.items) |op| {
        if (op != .object) continue;
        const to = op.object.get("to") orelse continue;
        if (to != .string) continue;
        const upsert = if (op.object.get("upsert")) |u| (u == .bool and u.bool) else false;
        if (op.object.get("from_log_attribute")) |from| {
            if (from == .string) renameAttribute(record, "attributes", from.string, to.string, upsert);
            continue;
        }
        if (op.object.get("from_resource_attribute")) |from| {
            if (from == .string) renameNestedAttribute(resource_log, "resource", "attributes", from.string, to.string, upsert);
            continue;
        }
        if (op.object.get("from_scope_attribute")) |from| {
            if (from == .string) renameNestedAttribute(scope_log, "scope", "attributes", from.string, to.string, upsert);
            continue;
        }
    }
}

fn applyAddTransforms(ops: std.json.Value, record: *std.json.Value, resource_log: *std.json.Value, scope_log: *std.json.Value) void {
    if (ops != .array) return;
    for (ops.array.items) |op| {
        if (op != .object) continue;
        const value = op.object.get("value") orelse continue;
        if (value != .string) continue;
        const upsert = if (op.object.get("upsert")) |u| (u == .bool and u.bool) else false;
        if (op.object.get("log_field")) |lf| {
            if (lf == .string and std.mem.eql(u8, lf.string, "body")) setOtlpBodyString(record, value.string, upsert);
            continue;
        }
        if (op.object.get("log_attribute")) |k| {
            if (k == .string) addAttribute(record, "attributes", k.string, value.string, upsert);
            continue;
        }
        if (op.object.get("resource_attribute")) |k| {
            if (k == .string) addNestedAttribute(resource_log, "resource", "attributes", k.string, value.string, upsert);
            continue;
        }
        if (op.object.get("scope_attribute")) |k| {
            if (k == .string) addNestedAttribute(scope_log, "scope", "attributes", k.string, value.string, upsert);
            continue;
        }
    }
}

fn removeBody(record: *std.json.Value) void {
    if (record.* != .object) return;
    _ = record.object.orderedRemove("body");
}

fn removeAttribute(parent: *std.json.Value, attrs_key: []const u8, key: []const u8) void {
    const attrs = parent.object.getPtr(attrs_key) orelse return;
    if (attrs.* != .array) return;
    compactRemoveAttr(attrs, key);
}

fn removeNestedAttribute(parent: *std.json.Value, child_key: []const u8, attrs_key: []const u8, key: []const u8) void {
    if (parent.* != .object) return;
    const child = parent.object.getPtr(child_key) orelse return;
    if (child.* != .object) return;
    removeAttribute(child, attrs_key, key);
}

fn redactAttribute(parent: *std.json.Value, attrs_key: []const u8, key: []const u8, replacement: []const u8) void {
    const idx = findAttrIndex(parent, attrs_key, key) orelse return;
    setAttrStringValue(parent, attrs_key, idx, replacement);
}

fn redactNestedAttribute(parent: *std.json.Value, child_key: []const u8, attrs_key: []const u8, key: []const u8, replacement: []const u8) void {
    if (parent.* != .object) return;
    const child = parent.object.getPtr(child_key) orelse return;
    if (child.* != .object) return;
    redactAttribute(child, attrs_key, key, replacement);
}

fn renameAttribute(parent: *std.json.Value, attrs_key: []const u8, from: []const u8, to: []const u8, upsert: bool) void {
    const src_idx = findAttrIndex(parent, attrs_key, from) orelse return;
    const dst_idx = findAttrIndex(parent, attrs_key, to);
    if (dst_idx != null and !upsert) return;

    if (dst_idx) |dst| {
        const src_val = getAttrStringValue(parent, attrs_key, src_idx) orelse return;
        setAttrStringValue(parent, attrs_key, dst, src_val);
        if (src_idx != dst) removeAttrAt(parent, attrs_key, src_idx);
        return;
    }
    setAttrKey(parent, attrs_key, src_idx, to);
}

fn renameNestedAttribute(parent: *std.json.Value, child_key: []const u8, attrs_key: []const u8, from: []const u8, to: []const u8, upsert: bool) void {
    if (parent.* != .object) return;
    const child = parent.object.getPtr(child_key) orelse return;
    if (child.* != .object) return;
    renameAttribute(child, attrs_key, from, to, upsert);
}

fn addAttribute(parent: *std.json.Value, attrs_key: []const u8, key: []const u8, value: []const u8, upsert: bool) void {
    const existing = findAttrIndex(parent, attrs_key, key);
    if (existing) |idx| {
        if (upsert) setAttrStringValue(parent, attrs_key, idx, value);
        return;
    }
    appendAttribute(parent, attrs_key, key, value);
}

fn addNestedAttribute(parent: *std.json.Value, child_key: []const u8, attrs_key: []const u8, key: []const u8, value: []const u8, upsert: bool) void {
    if (parent.* != .object) return;
    const child = parent.object.getPtr(child_key) orelse blk: {
        parent.object.put(child_key, .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) }) catch return;
        break :blk parent.object.getPtr(child_key) orelse return;
    };
    if (child.* != .object) child.* = .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) };
    addAttribute(child, attrs_key, key, value, upsert);
}

fn appendAttribute(parent: *std.json.Value, attrs_key: []const u8, key: []const u8, value: []const u8) void {
    const attrs = ensureAttrArray(parent, attrs_key) orelse return;
    attrs.array.append(.{
        .object = std.json.ObjectMap.init(std.heap.page_allocator),
    }) catch return;
    const idx = attrs.array.items.len - 1;
    var entry = &attrs.array.items[idx];
    entry.object.put("key", .{ .string = key }) catch return;
    entry.object.put("value", .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) }) catch return;
    const val_obj = entry.object.getPtr("value") orelse return;
    val_obj.object.put("stringValue", .{ .string = value }) catch return;
}

fn ensureAttrArray(parent: *std.json.Value, attrs_key: []const u8) ?*std.json.Value {
    if (parent.* != .object) return null;
    const attrs = parent.object.getPtr(attrs_key) orelse blk: {
        parent.object.put(attrs_key, .{ .array = std.json.Array.init(std.heap.page_allocator) }) catch return null;
        break :blk parent.object.getPtr(attrs_key) orelse return null;
    };
    if (attrs.* != .array) attrs.* = .{ .array = std.json.Array.init(std.heap.page_allocator) };
    return attrs;
}

fn findAttrIndex(parent: *std.json.Value, attrs_key: []const u8, key: []const u8) ?usize {
    if (parent.* != .object) return null;
    const attrs = parent.object.get(attrs_key) orelse return null;
    if (attrs != .array) return null;
    for (attrs.array.items, 0..) |entry, i| {
        if (entry != .object) continue;
        const k = entry.object.get("key") orelse continue;
        if (k == .string and std.mem.eql(u8, k.string, key)) return i;
    }
    return null;
}

fn getAttrStringValue(parent: *std.json.Value, attrs_key: []const u8, idx: usize) ?[]const u8 {
    const entry = getAttrEntry(parent, attrs_key, idx) orelse return null;
    const v = entry.object.get("value") orelse return null;
    if (v != .object) return null;
    const sv = v.object.get("stringValue") orelse return null;
    if (sv != .string) return null;
    return sv.string;
}

fn setAttrStringValue(parent: *std.json.Value, attrs_key: []const u8, idx: usize, value: []const u8) void {
    const entry = getAttrEntry(parent, attrs_key, idx) orelse return;
    const v = entry.object.getPtr("value") orelse blk: {
        entry.object.put("value", .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) }) catch return;
        break :blk entry.object.getPtr("value") orelse return;
    };
    if (v.* != .object) v.* = .{ .object = std.json.ObjectMap.init(std.heap.page_allocator) };
    v.object.put("stringValue", .{ .string = value }) catch return;
}

fn setAttrKey(parent: *std.json.Value, attrs_key: []const u8, idx: usize, key: []const u8) void {
    const entry = getAttrEntry(parent, attrs_key, idx) orelse return;
    entry.object.put("key", .{ .string = key }) catch return;
}

fn removeAttrAt(parent: *std.json.Value, attrs_key: []const u8, idx: usize) void {
    const attrs = parent.object.getPtr(attrs_key) orelse return;
    if (attrs.* != .array) return;
    if (idx >= attrs.array.items.len) return;
    var i = idx;
    while (i + 1 < attrs.array.items.len) : (i += 1) attrs.array.items[i] = attrs.array.items[i + 1];
    attrs.array.items.len -= 1;
}

fn compactRemoveAttr(attrs: *std.json.Value, key: []const u8) void {
    var write_idx: usize = 0;
    for (attrs.array.items) |entry| {
        var keep = true;
        if (entry == .object) {
            const k = entry.object.get("key");
            if (k != null and k.? == .string and std.mem.eql(u8, k.?.string, key)) keep = false;
        }
        if (keep) {
            attrs.array.items[write_idx] = entry;
            write_idx += 1;
        }
    }
    attrs.array.items.len = write_idx;
}

fn getAttrEntry(parent: *std.json.Value, attrs_key: []const u8, idx: usize) ?*std.json.Value {
    const attrs = parent.object.getPtr(attrs_key) orelse return null;
    if (attrs.* != .array) return null;
    if (idx >= attrs.array.items.len) return null;
    if (attrs.array.items[idx] != .object) return null;
    return &attrs.array.items[idx];
}

fn shouldSampleRecord(policy: *const log_policy.Policy, ctx: log_policy.RecordContext, pct: u8) bool {
    if (pct == 0) return false;
    if (pct >= 100) return true;
    const key = sampleKeyForPolicy(policy, ctx);
    const h = std.hash.Wyhash.hash(0, key);
    const bucket = h % 100;
    return bucket < pct;
}

fn sampleKeyForPolicy(policy: *const log_policy.Policy, ctx: log_policy.RecordContext) []const u8 {
    if (policy.sample_key) |sk| {
        return switch (sk.field) {
            .body => if (ctx.has_body) ctx.body else "",
            .severity_text => if (ctx.has_severity_text) ctx.severity_text else "",
            .trace_id => if (ctx.has_trace_id) ctx.trace_id else "",
            .span_id => if (ctx.has_span_id) ctx.span_id else "",
            .event_name => if (ctx.has_event_name) ctx.event_name else "",
            .resource_schema_url => if (ctx.has_resource_schema_url) ctx.resource_schema_url else "",
            .scope_schema_url => if (ctx.has_scope_schema_url) ctx.scope_schema_url else "",
            .resource_attribute => attrOrEmpty(ctx.resource_attributes, sk.key.?),
            .scope_attribute => attrOrEmpty(ctx.scope_attributes, sk.key.?),
            .log_attribute => attrOrEmpty(ctx.log_attributes, sk.key.?),
        };
    }
    if (ctx.has_trace_id and ctx.trace_id.len > 0) return ctx.trace_id;
    if (ctx.has_body) return ctx.body;
    return "";
}

fn attrOrEmpty(attrs: []const log_policy.Attribute, key: []const u8) []const u8 {
    for (attrs) |a| {
        if (std.mem.eql(u8, a.key, key)) return a.value;
    }
    return "";
}
