//! Prometheus Module
//!
//! Proxy module for Prometheus metrics scraping with policy-based filtering.
//! Filters metrics in streaming fashion based on configured policies.

const std = @import("std");
const module_types = @import("./module_types.zig");
const prometheus = @import("../prometheus/root.zig");
const policy = @import("policy_zig");
const runtime_metrics = @import("../runtime/runtime_metrics.zig");
const o11y = @import("o11y");

const ModuleConfig = module_types.ModuleConfig;
const ModuleRequest = module_types.ModuleRequest;
const ModuleStreamResult = module_types.ModuleStreamResult;
const RoutePattern = module_types.RoutePattern;
const ResponseFilter = module_types.ResponseFilter;

const PolicyStreamingFilter = prometheus.PolicyStreamingFilter;
const FilteringWriter = prometheus.FilteringWriter;

const PolicyRegistry = policy.Registry;
const EventBus = o11y.EventBus;
const RuntimeMetrics = runtime_metrics.RuntimeMetrics;

// =============================================================================
// Observability Events
// =============================================================================

const PrometheusFilterStats = struct {
    bytes_processed: usize,
    bytes_forwarded: usize,
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    scrape_truncated: bool,
};

// =============================================================================
// Configuration
// =============================================================================

pub const PrometheusConfig = struct {
    registry: *PolicyRegistry,
    bus: *EventBus,
    metrics: ?*RuntimeMetrics = null,
    max_input_bytes_per_scrape: usize = 10 * 1024 * 1024,
    max_output_bytes_per_scrape: usize = 10 * 1024 * 1024,
};

// =============================================================================
// PrometheusResponseFilter - Per-request filter state
// =============================================================================

/// Per-request filter state allocated on the arena.
/// Contains all buffers needed for streaming filter.
const PrometheusResponseFilter = struct {
    /// The policy streaming filter
    filter: PolicyStreamingFilter,

    /// The filtering writer that wraps the filter
    filtering_writer: FilteringWriter,

    /// Event bus for logging stats
    bus: *EventBus,
    metrics: ?*RuntimeMetrics,

    /// Allocator used for this filter (arena)
    allocator: std.mem.Allocator,

    // Buffers - allocated inline to avoid extra allocations
    line_buffer: [4096]u8,
    metadata_buffer: [2048]u8,
    writer_buffer: [8192]u8,

    const Self = @This();

    pub fn create(
        config: *const PrometheusConfig,
        inner_writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) !*Self {
        const self = try allocator.create(Self);

        self.bus = config.bus;
        self.metrics = config.metrics;
        self.allocator = allocator;

        // Initialize the policy streaming filter
        self.filter = PolicyStreamingFilter.init(.{
            .line_buffer = &self.line_buffer,
            .metadata_buffer = &self.metadata_buffer,
            .max_input_bytes = config.max_input_bytes_per_scrape,
            .max_output_bytes = config.max_output_bytes_per_scrape,
            .registry = config.registry,
            .bus = config.bus,
            .allocator = allocator,
        });

        // Initialize the filtering writer
        self.filtering_writer = FilteringWriter.init(.{
            .filter = &self.filter,
            .inner = inner_writer,
            .buffer = &self.writer_buffer,
        });

        return self;
    }

    pub fn writer(self: *Self) *std.Io.Writer {
        return self.filtering_writer.writer();
    }

    pub fn finish(self: *Self) !usize {
        const stats = try self.filtering_writer.finish();

        // Log filter stats
        self.bus.debug(PrometheusFilterStats{
            .bytes_processed = stats.bytes_processed,
            .bytes_forwarded = stats.bytes_forwarded,
            .lines_processed = stats.lines_processed,
            .lines_dropped = stats.lines_dropped,
            .lines_kept = stats.lines_kept,
            .scrape_truncated = stats.scrape_truncated,
        });
        if (self.metrics) |metrics| {
            metrics.recordPolicyBatch(.prometheus_metrics, stats.lines_processed, stats.lines_dropped);
        }

        return stats.bytes_forwarded;
    }

    pub fn destroy(self: *Self) void {
        self.allocator.destroy(self);
    }

    // ResponseFilter vtable implementation
    const vtable = ResponseFilter.VTable{
        .getWriter = getWriterVtable,
        .finish = finishVtable,
        .destroy = destroyVtable,
    };

    fn getWriterVtable(ptr: *anyopaque) *std.Io.Writer {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.writer();
    }

    fn finishVtable(ptr: *anyopaque) anyerror!usize {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.finish();
    }

    fn destroyVtable(ptr: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ptr));
        self.destroy();
    }

    pub fn asResponseFilter(self: *Self) ResponseFilter {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }
};

// =============================================================================
// Module
// =============================================================================

pub const PrometheusModule = struct {
    config: ?*const PrometheusConfig = null,

    pub fn init(self: *PrometheusModule, _: std.mem.Allocator, module_config: ModuleConfig) !void {
        self.config = @ptrCast(@alignCast(module_config.module_data));
    }

    pub fn processRequestStream(
        _: *PrometheusModule,
        _: *const ModuleRequest,
        body_reader: *std.Io.Reader,
        body_writer: *std.Io.Writer,
        _: std.mem.Allocator,
    ) !ModuleStreamResult {
        while (true) {
            const n = body_reader.stream(body_writer, .unlimited) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return err,
            };
            if (n == 0) break;
        }
        return ModuleStreamResult.forwarded();
    }

    pub fn createResponseFilter(
        self: *PrometheusModule,
        inner_writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) !?ResponseFilter {

        // If no config, don't filter
        const config = self.config orelse return null;

        // Create the per-request filter
        const filter = try PrometheusResponseFilter.create(config, inner_writer, allocator);
        return filter.asResponseFilter();
    }

    pub fn deinit(_: *PrometheusModule) void {}
};

pub const default_routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
    RoutePattern.prefix("/metrics/", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

test "PrometheusModule - processRequestStream forwards body" {
    var module = PrometheusModule{};

    try module.init(testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = null,
    });
    defer module.deinit();

    const req = ModuleRequest{
        .method = .GET,
        .path = "/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .headers_ctx = null,
        .get_header_fn = null,
    };

    var in_reader = std.Io.Reader.fixed("abc");
    var out_buf: [16]u8 = undefined;
    var out_writer = std.Io.Writer.fixed(&out_buf);
    const result = try module.processRequestStream(&req, &in_reader, &out_writer, testing.allocator);
    try testing.expectEqual(ModuleStreamResult.Action.forwarded, result.action);
    try testing.expectEqualStrings("abc", out_buf[0..out_writer.end]);
}

test "PrometheusModule - createResponseFilter returns null without config" {
    var module = PrometheusModule{};

    try module.init(testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = null, // No config
    });
    defer module.deinit();

    var output_buf: [1024]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&output_buf);

    const filter = try module.createResponseFilter(&output_writer, testing.allocator);
    try testing.expect(filter == null);
}

test "PrometheusModule - createResponseFilter with config" {
    const NoopEventBus = o11y.NoopEventBus;

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(testing.allocator, noop_bus.eventBus());
    defer registry.deinit();

    var config = PrometheusConfig{
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .max_input_bytes_per_scrape = 1024 * 1024,
        .max_output_bytes_per_scrape = 1024 * 1024,
    };

    var module = PrometheusModule{};

    try module.init(testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&config),
    });
    defer module.deinit();

    var output_buf: [4096]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&output_buf);

    const maybe_filter = try module.createResponseFilter(&output_writer, testing.allocator);
    try testing.expect(maybe_filter != null);

    var filter = maybe_filter.?;
    defer filter.destroy();

    // Write some prometheus data through the filter
    const input = "http_requests_total 100\nhttp_errors_total 5\n";
    try filter.writer().writeAll(input);

    const bytes_forwarded = try filter.finish();
    try testing.expect(bytes_forwarded > 0);

    // Check output
    const output = output_writer.buffered();
    try testing.expect(std.mem.indexOf(u8, output, "http_requests_total") != null);
}

test "PrometheusModule - response filter with DROP policy" {
    const NoopEventBus = o11y.NoopEventBus;
    const proto = @import("proto");

    var noop_bus: NoopEventBus = undefined;
    noop_bus.init();
    var registry = PolicyRegistry.init(testing.allocator, noop_bus.eventBus());
    defer registry.deinit();

    // Create DROP policy for debug metrics
    var drop_policy = proto.policy.Policy{
        .id = try testing.allocator.dupe(u8, "drop-debug"),
        .name = try testing.allocator.dupe(u8, "drop-debug"),
        .enabled = true,
        .target = .{
            .metric = .{
                .keep = false,
            },
        },
    };
    try drop_policy.target.?.metric.match.append(testing.allocator, .{
        .field = .{ .metric_field = .METRIC_FIELD_NAME },
        .match = .{ .regex = try testing.allocator.dupe(u8, "^debug_") },
    });
    defer drop_policy.deinit(testing.allocator);

    try registry.updatePolicies(&.{drop_policy}, "test-provider", .file);

    var config = PrometheusConfig{
        .registry = &registry,
        .bus = noop_bus.eventBus(),
        .max_input_bytes_per_scrape = 1024 * 1024,
        .max_output_bytes_per_scrape = 1024 * 1024,
    };

    var module = PrometheusModule{};

    try module.init(testing.allocator, .{
        .id = @enumFromInt(0),
        .routes = &default_routes,
        .upstream = .{
            .scheme = "http",
            .host = "localhost",
            .port = 9090,
            .base_path = "",
            .max_request_body = 1024,
            .max_response_body = 10 * 1024 * 1024,
        },
        .module_data = @ptrCast(&config),
    });
    defer module.deinit();

    var output_buf: [4096]u8 = undefined;
    var output_writer = std.Io.Writer.fixed(&output_buf);

    const maybe_filter = try module.createResponseFilter(&output_writer, testing.allocator);
    try testing.expect(maybe_filter != null);

    var filter = maybe_filter.?;
    defer filter.destroy();

    // Write prometheus data with debug metrics
    const input =
        \\http_requests_total 100
        \\debug_internal 999
        \\http_errors_total 5
        \\
    ;
    try filter.writer().writeAll(input);

    _ = try filter.finish();

    // Check output - debug_internal should be filtered out
    const output = output_writer.buffered();
    try testing.expect(std.mem.indexOf(u8, output, "http_requests_total") != null);
    try testing.expect(std.mem.indexOf(u8, output, "http_errors_total") != null);
    try testing.expect(std.mem.indexOf(u8, output, "debug_internal") == null);
}
