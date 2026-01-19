//! Prometheus Module
//!
//! Proxy module for Prometheus metrics scraping with policy-based filtering.
//!
//! Uses InterceptingWriter to filter response data line-by-line through
//! PolicyStreamingFilter, dropping metrics that don't pass policy evaluation.
//!
//! Memory Model:
//! - Global memory budget via BoundedAllocator (shared across all concurrent scrapes)
//! - Per-scrape data limit (max bytes to process per request)
//! - Returns 503 when global memory budget is exhausted
//!
//! Per-Scrape Memory Usage (~18KB):
//! - Line buffer: 8,192 bytes
//! - Metadata buffer: 1,024 bytes
//! - Output buffer: 8,192 bytes (matches typical chunk size)
//! - Context struct + PolicyEngine: ~500 bytes

const std = @import("std");
const proxy_module = @import("./proxy_module.zig");
const prometheus = @import("../prometheus/root.zig");
const policy = @import("../policy/root.zig");
const o11y = @import("../observability/root.zig");
const BoundedAllocator = @import("../bounded_allocator.zig").BoundedAllocator;

const ProxyModule = proxy_module.ProxyModule;
const ModuleConfig = proxy_module.ModuleConfig;
const ModuleRequest = proxy_module.ModuleRequest;
const ModuleResult = proxy_module.ModuleResult;
const RoutePattern = proxy_module.RoutePattern;

const PolicyEngine = policy.PolicyEngine;
const PolicyRegistry = policy.Registry;
const PolicyStreamingFilter = prometheus.PolicyStreamingFilter;
const EventBus = o11y.EventBus;

// =============================================================================
// Constants
// =============================================================================

/// Size of line buffer for parsing (max line length)
const LINE_BUFFER_SIZE: usize = 8192;

/// Size of metadata buffer for HELP/TYPE tracking
const METADATA_BUFFER_SIZE: usize = 1024;

/// Size of output buffer per request
const OUTPUT_BUFFER_SIZE: usize = 8192;

/// Approximate memory per scrape (for capacity planning)
pub const MEMORY_PER_SCRAPE: usize = LINE_BUFFER_SIZE + METADATA_BUFFER_SIZE + OUTPUT_BUFFER_SIZE + 512;

// =============================================================================
// Observability Events
// =============================================================================

const PrometheusMemoryExhausted = struct {
    budget: usize,
    bytes_allocated: usize,
    active_allocations: usize,
};

const PrometheusScrapeCompleted = struct {
    bytes_processed: usize,
    bytes_forwarded: usize,
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    scrape_truncated: bool,
};

const PrometheusScrapeError = struct {
    err: []const u8,
    phase: []const u8,
};

// =============================================================================
// Configuration
// =============================================================================

/// Configuration for Prometheus module filtering
pub const PrometheusConfig = struct {
    /// Policy registry for metric filtering
    registry: *const PolicyRegistry,

    /// Event bus for observability
    bus: *EventBus,

    /// Bounded allocator for memory management (global budget)
    /// If null, uses the request arena (unbounded)
    bounded_allocator: ?*BoundedAllocator = null,

    /// Maximum bytes to process per scrape (data throughput limit)
    /// Default: 10MB
    max_bytes_per_scrape: usize = 10 * 1024 * 1024,
};

// =============================================================================
// Intercept Context
// =============================================================================

/// Per-request context for filtering Prometheus metrics
pub const PrometheusInterceptContext = struct {
    /// The streaming filter
    filter: PolicyStreamingFilter,

    /// Output buffer for filtered data
    output_buffer: []u8,

    /// Current position in output buffer
    output_pos: usize,

    /// Allocator used for this context (for cleanup)
    allocator: std.mem.Allocator,

    /// Reference to config for stats emission
    config: *const PrometheusConfig,

    /// Line buffer (stored for cleanup)
    line_buffer: []u8,

    /// Metadata buffer (stored for cleanup)
    metadata_buffer: []u8,

    /// PolicyEngine (stored for cleanup)
    engine: *PolicyEngine,
};

/// Create intercept context for a request.
/// Called by the server for each request that needs response interception.
///
/// Uses BoundedAllocator if configured (returns null on memory exhaustion).
/// Falls back to request arena if no bounded allocator configured.
pub fn createInterceptContext(arena: std.mem.Allocator, module_data: ?*const anyopaque) ?*anyopaque {
    const config: *const PrometheusConfig = @ptrCast(@alignCast(module_data orelse return null));

    // Use bounded allocator if available, otherwise use arena
    const allocator = if (config.bounded_allocator) |ba|
        ba.allocator()
    else
        arena;

    // Allocate context struct
    const ctx = allocator.create(PrometheusInterceptContext) catch |err| {
        if (config.bounded_allocator) |ba| {
            const stats = ba.getStats();
            config.bus.warn(PrometheusMemoryExhausted{
                .budget = stats.budget,
                .bytes_allocated = stats.bytes_allocated,
                .active_allocations = stats.active_allocations,
            });
        }
        config.bus.warn(PrometheusScrapeError{
            .err = @errorName(err),
            .phase = "alloc_context",
        });
        return null;
    };

    // Allocate line buffer
    const line_buffer = allocator.alloc(u8, LINE_BUFFER_SIZE) catch |err| {
        allocator.destroy(ctx);
        config.bus.warn(PrometheusScrapeError{
            .err = @errorName(err),
            .phase = "alloc_line_buffer",
        });
        return null;
    };

    // Allocate metadata buffer
    const metadata_buffer = allocator.alloc(u8, METADATA_BUFFER_SIZE) catch |err| {
        allocator.free(line_buffer);
        allocator.destroy(ctx);
        config.bus.warn(PrometheusScrapeError{
            .err = @errorName(err),
            .phase = "alloc_metadata_buffer",
        });
        return null;
    };

    // Allocate output buffer
    const output_buffer = allocator.alloc(u8, OUTPUT_BUFFER_SIZE) catch |err| {
        allocator.free(metadata_buffer);
        allocator.free(line_buffer);
        allocator.destroy(ctx);
        config.bus.warn(PrometheusScrapeError{
            .err = @errorName(err),
            .phase = "alloc_output_buffer",
        });
        return null;
    };

    // Allocate policy engine
    const engine = allocator.create(PolicyEngine) catch |err| {
        allocator.free(output_buffer);
        allocator.free(metadata_buffer);
        allocator.free(line_buffer);
        allocator.destroy(ctx);
        config.bus.warn(PrometheusScrapeError{
            .err = @errorName(err),
            .phase = "alloc_engine",
        });
        return null;
    };
    engine.* = PolicyEngine.init(config.bus, @constCast(config.registry));

    // Initialize context
    ctx.* = .{
        .filter = PolicyStreamingFilter.init(.{
            .line_buffer = line_buffer,
            .metadata_buffer = metadata_buffer,
            .max_scrape_bytes = config.max_bytes_per_scrape,
            .engine = engine,
            .allocator = allocator,
        }),
        .output_buffer = output_buffer,
        .output_pos = 0,
        .allocator = allocator,
        .config = config,
        .line_buffer = line_buffer,
        .metadata_buffer = metadata_buffer,
        .engine = engine,
    };

    return @ptrCast(ctx);
}

/// Destroy intercept context and emit stats.
/// Called by the server after request completes.
pub fn destroyInterceptContext(context: ?*anyopaque) void {
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(context orelse return));

    // Emit scrape completion stats
    const stats = ctx.filter.getStats();
    if (stats.lines_processed > 0) {
        ctx.config.bus.info(PrometheusScrapeCompleted{
            .bytes_processed = stats.bytes_processed,
            .bytes_forwarded = stats.bytes_forwarded,
            .lines_processed = stats.lines_processed,
            .lines_dropped = stats.lines_dropped,
            .lines_kept = stats.lines_kept,
            .scrape_truncated = stats.scrape_truncated,
        });
    }

    // Free allocations
    const allocator = ctx.allocator;
    allocator.destroy(ctx.engine);
    allocator.free(ctx.output_buffer);
    allocator.free(ctx.metadata_buffer);
    allocator.free(ctx.line_buffer);
    allocator.destroy(ctx);
}

// =============================================================================
// Intercept Callback
// =============================================================================

/// Intercept callback that filters Prometheus metrics through policy engine.
/// Returns filtered data or null to drop the chunk entirely.
///
/// Behavior:
/// - Returns filtered output slice on success
/// - Returns null if all data in chunk was filtered out
/// - Returns original data on error (fail-open)
/// - Returns original data if output buffer is full (fail-open)
pub fn prometheusInterceptCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(context orelse return data));

    // Check if filter has stopped (data limit reached)
    if (ctx.filter.base.stopped) {
        return null; // Stop forwarding data
    }

    // Check if we have space in output buffer
    const remaining = ctx.output_buffer.len - ctx.output_pos;
    if (remaining == 0) {
        // Buffer full - reset and continue (streaming)
        ctx.output_pos = 0;
    }

    // Create writer for output space
    var output_writer = std.Io.Writer.fixed(ctx.output_buffer[ctx.output_pos..]);

    // Process through filter
    const result = ctx.filter.processChunk(data, &output_writer) catch {
        // On error, fail open
        return data;
    };

    // Check if we should stop
    if (result.should_stop) {
        // Data limit reached - return what we have and stop
        const written = output_writer.buffered();
        if (written.len == 0) {
            return null;
        }
        const start = ctx.output_pos;
        ctx.output_pos += written.len;
        return ctx.output_buffer[start..ctx.output_pos];
    }

    // Get what was written
    const written = output_writer.buffered();
    if (written.len == 0) {
        // Everything filtered out in this chunk
        return null;
    }

    // Return the filtered slice
    const start = ctx.output_pos;
    ctx.output_pos += written.len;
    return ctx.output_buffer[start..ctx.output_pos];
}

// =============================================================================
// Module
// =============================================================================

/// Prometheus module - stateless proxy with response filtering
pub const PrometheusModule = struct {
    pub fn asProxyModule(self: *PrometheusModule) ProxyModule {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = ProxyModule.VTable{
        .init = init,
        .processRequest = processRequest,
        .deinit = deinit,
    };

    fn init(_: *anyopaque, _: std.mem.Allocator, _: ModuleConfig) anyerror!void {}

    fn processRequest(_: *anyopaque, _: *const ModuleRequest, _: std.mem.Allocator) anyerror!ModuleResult {
        return ModuleResult.unchanged();
    }

    fn deinit(_: *anyopaque) void {}
};

/// Default routes for /metrics
pub const default_routes = [_]RoutePattern{
    RoutePattern.exact("/metrics", .{ .get = true }),
    RoutePattern.prefix("/metrics/", .{ .get = true }),
};

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

// Helper to create a test config with noop bus and empty registry
fn createTestConfig(allocator: std.mem.Allocator, bounded: ?*BoundedAllocator) !struct {
    config: PrometheusConfig,
    registry: *PolicyRegistry,
    bus: *o11y.NoopEventBus,
} {
    var bus = try allocator.create(o11y.NoopEventBus);
    bus.init();

    const registry = try allocator.create(PolicyRegistry);
    registry.* = PolicyRegistry.init(allocator, bus.eventBus());

    return .{
        .config = .{
            .registry = registry,
            .bus = bus.eventBus(),
            .bounded_allocator = bounded,
            .max_bytes_per_scrape = 10 * 1024 * 1024,
        },
        .registry = registry,
        .bus = bus,
    };
}

fn destroyTestConfig(allocator: std.mem.Allocator, registry: *PolicyRegistry, bus: *o11y.NoopEventBus) void {
    registry.deinit();
    allocator.destroy(registry);
    allocator.destroy(bus);
}

test "PrometheusModule - passthrough request" {
    var module = PrometheusModule{};
    const pm = module.asProxyModule();

    try pm.init(testing.allocator, .{
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
    defer pm.deinit();

    const req = ModuleRequest{
        .method = .GET,
        .path = "/metrics",
        .query = "",
        .upstream = undefined,
        .module_ctx = null,
        .body = "",
        .headers_ctx = null,
        .get_header_fn = null,
    };

    const result = try pm.processRequest(&req, testing.allocator);
    try testing.expectEqual(ModuleResult.Action.proxy_unchanged, result.action);
}

test "prometheusInterceptCallback - passthrough without context" {
    const data = "http_requests_total 100\n";
    const result = prometheusInterceptCallback(data, null);
    try testing.expect(result != null);
    try testing.expectEqualStrings(data, result.?);
}

test "createInterceptContext - returns null without module_data" {
    const ctx = createInterceptContext(testing.allocator, null);
    try testing.expect(ctx == null);
}

test "createInterceptContext - creates context with arena allocator" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);

    // Clean up
    destroyInterceptContext(ctx_ptr);
}

test "createInterceptContext - creates context with bounded allocator" {
    var bounded = try BoundedAllocator.init(1024 * 1024); // 1MB budget
    defer bounded.deinit();

    var test_cfg = try createTestConfig(testing.allocator, &bounded);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);

    // Verify memory was allocated from bounded allocator
    const stats = bounded.getStats();
    try testing.expect(stats.bytes_allocated > 0);
    try testing.expect(stats.active_allocations > 0);

    // Clean up
    destroyInterceptContext(ctx_ptr);

    // Verify memory was returned
    const stats_after = bounded.getStats();
    try testing.expectEqual(@as(usize, 0), stats_after.active_allocations);
}

test "createInterceptContext - returns null when bounded allocator exhausted" {
    // Create a tiny bounded allocator that can't fit our buffers
    var bounded = try BoundedAllocator.init(100); // Only 100 bytes
    defer bounded.deinit();

    var test_cfg = try createTestConfig(testing.allocator, &bounded);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr == null); // Should fail - not enough memory
}

test "prometheusInterceptCallback - processes simple metrics" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    const input = "http_requests_total 100\nhttp_errors_total 5\n";
    const result = prometheusInterceptCallback(input, ctx_ptr);

    try testing.expect(result != null);
    try testing.expectEqualStrings(input, result.?);
}

test "prometheusInterceptCallback - preserves HELP and TYPE lines" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    const input =
        \\# HELP http_requests_total Total HTTP requests
        \\# TYPE http_requests_total counter
        \\http_requests_total{method="get"} 100
        \\
    ;
    const result = prometheusInterceptCallback(input, ctx_ptr);

    try testing.expect(result != null);
    try testing.expectEqualStrings(input, result.?);
}

test "prometheusInterceptCallback - handles multiple chunks" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    // Process data in multiple chunks
    const chunk1 = "metric_a 1\n";
    const chunk2 = "metric_b 2\n";
    const chunk3 = "metric_c 3\n";

    const result1 = prometheusInterceptCallback(chunk1, ctx_ptr);
    try testing.expect(result1 != null);
    try testing.expectEqualStrings(chunk1, result1.?);

    const result2 = prometheusInterceptCallback(chunk2, ctx_ptr);
    try testing.expect(result2 != null);
    try testing.expectEqualStrings(chunk2, result2.?);

    const result3 = prometheusInterceptCallback(chunk3, ctx_ptr);
    try testing.expect(result3 != null);
    try testing.expectEqualStrings(chunk3, result3.?);
}

test "prometheusInterceptCallback - handles partial lines across chunks" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    // Split a line across chunks
    const chunk1 = "http_requests_total{method=\"get\"";
    const chunk2 = "} 100\nhttp_errors 5\n";

    const result1 = prometheusInterceptCallback(chunk1, ctx_ptr);
    // First chunk has no complete line, may return null or empty
    // The filter buffers partial lines

    const result2 = prometheusInterceptCallback(chunk2, ctx_ptr);
    try testing.expect(result2 != null);
    // Should contain the complete first line + second line
    try testing.expect(std.mem.indexOf(u8, result2.?, "http_requests_total") != null);
    try testing.expect(std.mem.indexOf(u8, result2.?, "http_errors") != null);
    _ = result1;
}

test "prometheusInterceptCallback - handles empty input" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    const result = prometheusInterceptCallback("", ctx_ptr);
    // Empty input produces no output
    try testing.expect(result == null);
}

test "prometheusInterceptCallback - handles metrics with labels" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    const input =
        \\http_requests_total{method="get",status="200",path="/api"} 100
        \\http_requests_total{method="post",status="201",path="/api"} 50
        \\
    ;
    const result = prometheusInterceptCallback(input, ctx_ptr);

    try testing.expect(result != null);
    try testing.expectEqualStrings(input, result.?);
}

test "prometheusInterceptCallback - handles histogram metrics" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    const input =
        \\# HELP http_request_duration_seconds Request duration
        \\# TYPE http_request_duration_seconds histogram
        \\http_request_duration_seconds_bucket{le="0.1"} 100
        \\http_request_duration_seconds_bucket{le="0.5"} 150
        \\http_request_duration_seconds_bucket{le="1"} 180
        \\http_request_duration_seconds_bucket{le="+Inf"} 200
        \\http_request_duration_seconds_sum 45.5
        \\http_request_duration_seconds_count 200
        \\
    ;
    const result = prometheusInterceptCallback(input, ctx_ptr);

    try testing.expect(result != null);
    try testing.expectEqualStrings(input, result.?);
}

test "per-scrape data limit - truncates at max_bytes_per_scrape" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    // Set a very small limit
    test_cfg.config.max_bytes_per_scrape = 50;

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);
    defer destroyInterceptContext(ctx_ptr);

    // Input larger than limit
    const input = "metric_a 1\nmetric_b 2\nmetric_c 3\nmetric_d 4\nmetric_e 5\n";
    try testing.expect(input.len > 50);

    const result = prometheusInterceptCallback(input, ctx_ptr);

    // Should get partial output
    try testing.expect(result != null);
    try testing.expect(result.?.len < input.len);

    // Verify filter stats show truncation
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(ctx_ptr));
    const stats = ctx.filter.getStats();
    try testing.expect(stats.scrape_truncated);
    try testing.expectEqual(@as(usize, 50), stats.bytes_processed);
}

test "bounded allocator - concurrent scrapes share memory budget" {
    // 50KB budget - enough for ~2-3 contexts
    var bounded = try BoundedAllocator.init(50 * 1024);
    defer bounded.deinit();

    var test_cfg = try createTestConfig(testing.allocator, &bounded);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    // Create first context
    const ctx1 = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx1 != null);

    // Create second context
    const ctx2 = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx2 != null);

    // Memory should be allocated for both
    const stats = bounded.getStats();
    try testing.expect(stats.active_allocations >= 8); // 4 allocs per context

    // Try to create third - may fail depending on exact allocation sizes
    const ctx3 = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    // May or may not succeed depending on fragmentation

    // Clean up
    if (ctx3) |c| destroyInterceptContext(c);
    destroyInterceptContext(ctx2);
    destroyInterceptContext(ctx1);

    // All memory should be returned
    const stats_after = bounded.getStats();
    try testing.expectEqual(@as(usize, 0), stats_after.active_allocations);
}

test "MEMORY_PER_SCRAPE constant is accurate" {
    // Verify our constant matches actual allocation
    var bounded = try BoundedAllocator.init(1024 * 1024);
    defer bounded.deinit();

    var test_cfg = try createTestConfig(testing.allocator, &bounded);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);

    const stats = bounded.getStats();

    // Actual allocation should be close to our constant
    // Allow some overhead for alignment
    try testing.expect(stats.bytes_allocated <= MEMORY_PER_SCRAPE * 2);
    try testing.expect(stats.bytes_allocated >= MEMORY_PER_SCRAPE / 2);

    destroyInterceptContext(ctx_ptr);
}

test "destroyInterceptContext - handles null gracefully" {
    // Should not crash
    destroyInterceptContext(null);
}

test "filter stats are emitted on context destroy" {
    var test_cfg = try createTestConfig(testing.allocator, null);
    defer destroyTestConfig(testing.allocator, test_cfg.registry, test_cfg.bus);

    const ctx_ptr = createInterceptContext(testing.allocator, @ptrCast(&test_cfg.config));
    try testing.expect(ctx_ptr != null);

    // Process some data
    const input = "metric_a 1\nmetric_b 2\n";
    _ = prometheusInterceptCallback(input, ctx_ptr);

    // Get stats before destroy
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(ctx_ptr));
    const stats = ctx.filter.getStats();
    try testing.expectEqual(@as(usize, 2), stats.lines_processed);
    try testing.expectEqual(@as(usize, 2), stats.lines_kept);
    try testing.expectEqual(@as(usize, 0), stats.lines_dropped);

    // Destroy emits stats (no way to verify in test without mock bus)
    destroyInterceptContext(ctx_ptr);
}
