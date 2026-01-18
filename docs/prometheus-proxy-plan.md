# Prometheus Scrape Proxy Implementation Plan

## Overview

This document outlines the implementation plan for a Prometheus scrape proxy
that applies metric policies to responses from application metrics endpoints.
The edge acts as a transparent proxy between Prometheus scrapers and application
`/metrics` endpoints, filtering metrics based on configured policies while
respecting memory limits.

**Architecture Choice: Option 2 - Response Filtering Proxy**

The edge proxies requests from Prometheus to application metrics endpoints and
applies filtering on the response stream. This fits the existing edge
architecture where modules process data flowing through the proxy.

```
┌──────────────┐     ┌─────────────────────────────────┐     ┌─────────────────┐
│  Prometheus  │────►│         Tero Edge               │────►│  Application    │
│   Scraper    │◄────│  (Prometheus Policy Filter)     │◄────│  /metrics       │
└──────────────┘     └─────────────────────────────────┘     └─────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │ PolicyRegistry  │
                     │ (MetricPolicies)│
                     └─────────────────┘
```

## Design Goals

1. **Precise Memory Control**: Users can limit the edge's memory footprint for
   metric responses
2. **Policy-Based Filtering**: Apply existing metric policies to Prometheus
   exposition format
3. **Streaming Architecture**: Process metrics line-by-line without buffering
   entire response
4. **Predictable Memory Usage**: Memory usage is bounded and deterministic based
   on configuration
5. **Fail-Open Behavior**: On parsing errors, pass through data unchanged
   (consistent with other modules)

## Key Constraints

### Memory Limit Enforcement

Users want to limit memory usage precisely. The current streaming architecture
(`server.zig:694-731`) streams directly from upstream to client without
buffering. For Prometheus filtering, we need to:

1. Parse each metric line to evaluate policies
2. Decide whether to include the line in the response
3. Never exceed the configured memory limit for response processing

### Prometheus Format Considerations

The Prometheus text exposition format is line-oriented:

```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="get",status="200"} 1234 1678886400000
```

Key properties that enable streaming:

- Each sample is a complete line (terminated by `\n`)
- Lines can be processed independently (no cross-line dependencies for
  filtering)
- HELP/TYPE metadata lines should be preserved if any matching metrics are kept
- Metrics are grouped by name with metadata appearing first

## Implementation Components

### 1. Prometheus Line Parser (`src/prometheus/line_parser.zig`)

A zero-allocation line parser for Prometheus exposition format.

```zig
const ParsedLine = union(enum) {
    /// Empty line
    empty: void,
    /// Comment line (# without HELP/TYPE)
    comment: []const u8,
    /// HELP metadata: # HELP metric_name description
    help: struct {
        metric_name: []const u8,
        description: []const u8,
    },
    /// TYPE metadata: # TYPE metric_name type
    type_info: struct {
        metric_name: []const u8,
        metric_type: MetricType,
    },
    /// Metric sample: metric_name{labels} value [timestamp]
    sample: struct {
        metric_name: []const u8,
        labels: LabelIterator,
        value: []const u8,
        timestamp: ?[]const u8,
    },
    /// Parse error - line couldn't be parsed
    parse_error: void,
};

const MetricType = enum {
    counter,
    gauge,
    histogram,
    summary,
    untyped,
    unknown,
};

/// Iterator over labels in a metric line (zero allocation)
const LabelIterator = struct {
    raw: []const u8, // Points into original line buffer
    pos: usize,

    fn next(self: *LabelIterator) ?Label {
        // Parse next label_name="label_value" pair
    }
};

const Label = struct {
    name: []const u8,
    value: []const u8,
};

/// Parse a single line of Prometheus exposition format
/// Returns a ParsedLine union - all slices point into the input buffer
pub fn parseLine(line: []const u8) ParsedLine {
    // Zero-allocation parsing - all returned slices reference input
}
```

### 2. Prometheus Field Accessor (`src/prometheus/field_accessor.zig`)

Maps policy field references to Prometheus line data.

```zig
const PrometheusMetricContext = struct {
    parsed: *const ParsedLine.sample,
    // Buffer for looking up label values
    label_cache: [16]?[]const u8 = [_]?[]const u8{null} ** 16,
    label_keys: [16][]const u8 = undefined,
    cached_labels: usize = 0,
};

/// Field accessor for Prometheus metrics
/// Maps MetricFieldRef to parsed Prometheus line data
fn prometheusFieldAccessor(ctx: *const anyopaque, field: MetricFieldRef) ?[]const u8 {
    const prom_ctx: *const PrometheusMetricContext = @ptrCast(@alignCast(ctx));

    return switch (field) {
        .metric_field => |mf| switch (mf) {
            .METRIC_FIELD_NAME => prom_ctx.parsed.metric_name,
            // Other metric fields not available in Prometheus format
            else => null,
        },
        .datapoint_attribute => |key| prom_ctx.findLabel(key),
        // Resource/scope attributes not available in Prometheus format
        .resource_attribute, .scope_attribute => null,
        .metric_type => null, // Would need to track TYPE metadata
        .aggregation_temporality => null,
    };
}
```

**Design Note**: Prometheus labels map to `datapoint_attribute` in our policy
model. This allows policies like:

```yaml
match:
  - field:
      datapoint_attribute: "method"
    regex: "GET|POST"
```

### 3. Streaming Response Filter (`src/prometheus/streaming_filter.zig`)

A streaming writer that filters Prometheus metrics line-by-line.

```zig
pub const StreamingPrometheusFilter = struct {
    // Configuration
    registry: *const PolicyRegistry,
    bus: *EventBus,
    max_output_bytes: usize,

    // Line parsing state
    line_buffer: []u8,          // Fixed buffer for current line
    line_len: usize,

    // Output tracking
    output_writer: *std.Io.Writer,
    bytes_written: usize,

    // Metric group state (for preserving HELP/TYPE when any sample matches)
    current_metric_name: [256]u8,
    current_metric_name_len: usize,
    pending_help: ?struct { start: usize, len: usize },
    pending_type: ?struct { start: usize, len: usize },
    current_metric_has_match: bool,

    // Statistics
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    truncated: bool,

    pub fn init(
        line_buffer: []u8,
        output_writer: *std.Io.Writer,
        max_output_bytes: usize,
        registry: *const PolicyRegistry,
        bus: *EventBus,
    ) StreamingPrometheusFilter {
        return .{
            .line_buffer = line_buffer,
            .line_len = 0,
            .output_writer = output_writer,
            .bytes_written = 0,
            .max_output_bytes = max_output_bytes,
            .registry = registry,
            .bus = bus,
            .current_metric_name = undefined,
            .current_metric_name_len = 0,
            .pending_help = null,
            .pending_type = null,
            .current_metric_has_match = false,
            .lines_processed = 0,
            .lines_dropped = 0,
            .lines_kept = 0,
            .truncated = false,
        };
    }

    /// Process bytes from upstream, filtering and writing to output
    /// Returns number of bytes consumed from input
    pub fn process(self: *StreamingPrometheusFilter, input: []const u8) !usize {
        var consumed: usize = 0;

        for (input) |byte| {
            consumed += 1;

            if (byte == '\n') {
                try self.processLine();
                self.line_len = 0;
            } else if (self.line_len < self.line_buffer.len) {
                self.line_buffer[self.line_len] = byte;
                self.line_len += 1;
            }
            // If line exceeds buffer, we'll process what we have at newline
        }

        return consumed;
    }

    fn processLine(self: *StreamingPrometheusFilter) !void {
        const line = self.line_buffer[0..self.line_len];
        self.lines_processed += 1;

        const parsed = line_parser.parseLine(line);

        switch (parsed) {
            .empty => try self.writeLine(line), // Pass through empty lines
            .comment => try self.writeLine(line), // Pass through comments
            .help => |h| self.handleHelp(h, line),
            .type_info => |t| self.handleType(t, line),
            .sample => |s| try self.handleSample(s, line),
            .parse_error => try self.writeLine(line), // Fail-open
        }
    }

    fn handleSample(self: *StreamingPrometheusFilter, sample: ParsedLine.sample, line: []const u8) !void {
        // Check if this is a new metric group
        if (!std.mem.eql(u8, sample.metric_name, self.currentMetricName())) {
            // Flush pending metadata if previous metric had matches
            try self.flushPendingMetadata();
            // Start new metric group
            self.startNewMetricGroup(sample.metric_name);
        }

        // Evaluate policy
        var ctx = PrometheusMetricContext{ .parsed = &sample };
        var policy_id_buf: [MAX_MATCHES_PER_SCAN][]const u8 = undefined;

        const engine = PolicyEngine.init(self.bus, @constCast(self.registry));
        const result = engine.evaluate(.metric, &ctx, prometheusFieldAccessor, noopMutator, &policy_id_buf);

        if (result.decision.shouldContinue()) {
            // Mark that this metric group has at least one kept sample
            self.current_metric_has_match = true;
            try self.writeLine(line);
            self.lines_kept += 1;
        } else {
            self.lines_dropped += 1;
        }
    }

    fn writeLine(self: *StreamingPrometheusFilter, line: []const u8) !void {
        const line_with_newline_len = line.len + 1;

        // Check memory limit
        if (self.bytes_written + line_with_newline_len > self.max_output_bytes) {
            self.truncated = true;
            return; // Don't write - would exceed limit
        }

        try self.output_writer.writeAll(line);
        try self.output_writer.writeAll("\n");
        self.bytes_written += line_with_newline_len;
    }

    pub fn finish(self: *StreamingPrometheusFilter) !FilterStats {
        // Flush any pending metadata for the last metric group
        try self.flushPendingMetadata();

        // Flush the underlying writer
        try self.output_writer.flush();

        return .{
            .lines_processed = self.lines_processed,
            .lines_dropped = self.lines_dropped,
            .lines_kept = self.lines_kept,
            .bytes_written = self.bytes_written,
            .truncated = self.truncated,
        };
    }
};

const FilterStats = struct {
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    bytes_written: usize,
    truncated: bool,
};
```

### 4. Prometheus Module (`src/modules/prometheus_module.zig`)

A new module that handles Prometheus scrape endpoints.

```zig
pub const PrometheusModule = struct {
    registry: *const PolicyRegistry,
    bus: *EventBus,
    bounded_allocator: *BoundedAllocator,
    max_bytes_per_scrape: usize,

    pub fn init(self: *PrometheusModule, allocator: Allocator, config: ModuleConfig) !void {
        const prom_config: *PrometheusConfig = @ptrCast(config.module_data);
        self.registry = prom_config.registry;
        self.bus = prom_config.bus;
        self.max_bytes_per_scrape = prom_config.max_bytes_per_scrape;

        // Initialize the pre-allocated bounded allocator
        self.bounded_allocator = try allocator.create(BoundedAllocator);
        self.bounded_allocator.* = try BoundedAllocator.init(prom_config.global_memory_budget);
    }

    pub fn deinit(self: *PrometheusModule, allocator: Allocator) void {
        self.bounded_allocator.deinit();
        allocator.destroy(self.bounded_allocator);
    }

    pub fn processRequest(self: *PrometheusModule, req: *ModuleRequest, allocator: Allocator) !ModuleResult {
        // Prometheus scraping is GET-only, verify this is a scrape request
        if (req.method != .GET) {
            return ModuleResult.respond(405, "Method Not Allowed");
        }

        // For Prometheus, we don't process the request body (there isn't one)
        // The filtering happens in the response streaming phase
        return ModuleResult.unchanged();
    }

    /// Get the response processor configuration for this module
    pub fn getResponseProcessor(self: *const PrometheusModule) ResponseProcessor {
        return .{ .prometheus = .{
            .registry = self.registry,
            .bus = self.bus,
            .bounded_allocator = self.bounded_allocator,
            .max_bytes_per_scrape = self.max_bytes_per_scrape,
        }};
    }
};

pub const PrometheusConfig = struct {
    registry: *const PolicyRegistry,
    bus: *EventBus,
    /// Global memory budget for the Prometheus module.
    /// Pre-allocated at startup and shared across all concurrent scrapes.
    /// Default: 50MB
    global_memory_budget: usize = 50 * 1024 * 1024,
    /// Maximum data to process per scrape (data volume limit, not memory).
    /// Default: 1GB
    max_bytes_per_scrape: usize = 1 * 1024 * 1024 * 1024,
};
```

### 5. Server Integration (`src/proxy/server.zig`)

Modify the response streaming code to support module-specific response
processing.

**Current code at line 694-731:**

```zig
// Stream response body
const max_size = ctx.upstreams.getMaxResponseBody(module_id);
var read_buffer: [8192]u8 = undefined;
var upstream_body_reader = upstream_res.reader(&read_buffer);
const response_writer = res.writer();
// ... direct streaming ...
```

**New approach - add response processor hook:**

```zig
// In ModuleConfig or UpstreamConfig
pub const ResponseProcessor = union(enum) {
    /// Direct streaming (current behavior)
    passthrough: void,
    /// Prometheus filtering with memory limits
    prometheus: struct {
        registry: *const PolicyRegistry,
        bus: *EventBus,
        bounded_allocator: *BoundedAllocator,  // Global memory budget (std.mem.Allocator interface)
        max_bytes_per_scrape: usize,            // Per-scrape data limit
    },
};

// In server.zig proxyToUpstream, around line 694
fn streamResponseBody(
    ctx: *ServerContext,
    module_id: ModuleId,
    upstream_res: anytype,
    res: anytype,
) !void {
    const processor = ctx.modules.getResponseProcessor(module_id);

    switch (processor) {
        .passthrough => {
            // Current direct streaming code
            const max_size = ctx.upstreams.getMaxResponseBody(module_id);
            var read_buffer: [8192]u8 = undefined;
            var upstream_body_reader = upstream_res.reader(&read_buffer);
            const response_writer = res.writer();
            // ... existing streaming logic ...
        },
        .prometheus => |config| {
            // 1. Get allocator from bounded allocator (implements std.mem.Allocator)
            const alloc = config.bounded_allocator.allocator();

            // 2. Allocate per-scrape buffers from bounded pool
            //    Returns error.OutOfMemory if budget exhausted
            var read_buffer = alloc.alloc(u8, 8192) catch {
                // Global memory budget exhausted
                const stats = config.bounded_allocator.getStats();
                config.bus.warn(PrometheusMemoryExhausted{
                    .budget = stats.budget,
                    .bytes_allocated = stats.bytes_allocated,
                    .active_allocations = stats.active_allocations,
                });
                return error.ServiceUnavailable;  // Return 503
            };
            defer alloc.free(read_buffer);

            var line_buffer = alloc.alloc(u8, 8192) catch {
                return error.ServiceUnavailable;
            };
            defer alloc.free(line_buffer);

            var metadata_buffer = alloc.alloc(u8, 1024) catch {
                return error.ServiceUnavailable;
            };
            defer alloc.free(metadata_buffer);

            var upstream_body_reader = upstream_res.reader(read_buffer);
            const response_writer = res.writer();

            // 3. Create filter with per-scrape DATA limit (not memory limit)
            var filter = StreamingPrometheusFilter.init(.{
                .line_buffer = line_buffer,
                .metadata_buffer = metadata_buffer,
                .max_scrape_bytes = config.max_bytes_per_scrape,  // Data volume cap
                .registry = config.registry,
                .bus = config.bus,
            });

            // 4. Stream and filter - memory stays constant, data flows through
            while (!filter.shouldStop()) {
                const chunk = upstream_body_reader.peek();
                if (chunk.len == 0) {
                    if (upstream_body_reader.isEndOfStream()) break;
                    continue;
                }

                const result = try filter.processChunk(chunk, response_writer);
                upstream_body_reader.toss(result.consumed);
            }

            const stats = try filter.finish(response_writer);

            if (stats.scrape_truncated) {
                ctx.bus.warn(PrometheusScrapeDataTruncated{
                    .max_bytes_per_scrape = config.max_bytes_per_scrape,
                    .bytes_processed = stats.bytes_processed,
                });
            }

            ctx.bus.info(PrometheusScrapeCompleted{
                .bytes_processed = stats.bytes_processed,
                .bytes_forwarded = stats.bytes_forwarded,
                .lines_processed = stats.lines_processed,
                .lines_dropped = stats.lines_dropped,
                .lines_kept = stats.lines_kept,
                .scrape_truncated = stats.scrape_truncated,
                .duration_us = stats.duration_us,
            });

            // 5. Buffers freed via defers, memory returned to pool
        },
    }
}
```

## Memory Model

The Prometheus module has two distinct limits that work together:

1. **Global Memory Budget**: Total RAM the module can use across all concurrent
   scrapes
2. **Per-Scrape Data Limit**: Maximum bytes to process/forward for a single
   scrape

These are orthogonal concerns:

- Global budget controls **actual memory allocation** (buffers, parsing state)
- Per-scrape limit controls **data throughput** (how much we read/forward)

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Global Memory Budget (e.g., 50MB)                   │
│                     Pre-allocated via FixedBufferAllocator              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐       ┌───────────┐ │
│  │  Scrape 1   │  │  Scrape 2   │  │  Scrape 3   │  ...  │ Scrape N  │ │
│  │  ~20KB buf  │  │  ~20KB buf  │  │  ~20KB buf  │       │ ~20KB buf │ │
│  │             │  │             │  │             │       │           │ │
│  │ Processing  │  │ Processing  │  │ Processing  │       │ Waiting   │ │
│  │ up to 1GB   │  │ up to 1GB   │  │ up to 1GB   │       │ for mem   │ │
│  │ of data     │  │ of data     │  │ of data     │       │           │ │
│  └─────────────┘  └─────────────┘  └─────────────┘       └───────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Key insight: Because we **stream** the response, we only need ~20KB of buffers
per scrape, but each scrape can process gigabytes of data flowing through those
buffers.

### User Configuration

```zig
pub const PrometheusConfig = struct {
    registry: *const PolicyRegistry,
    bus: *EventBus,

    /// Global memory budget for the Prometheus module.
    /// This is pre-allocated at startup and shared across all concurrent scrapes.
    /// Controls actual RAM usage.
    /// Default: 50MB
    global_memory_budget: usize = 50 * 1024 * 1024,

    /// Maximum data to process per scrape.
    /// If upstream returns more than this, we truncate.
    /// This is a data volume limit, NOT a memory limit.
    /// Default: 1GB
    max_bytes_per_scrape: usize = 1 * 1024 * 1024 * 1024,
};
```

### Global Memory Budget: Bounded Allocator

The global budget is enforced via a generic `BoundedAllocator` that wraps a
pre-allocated memory region. This allocator implements the standard
`std.mem.Allocator` interface, so it can be passed anywhere allocators are
accepted. This makes it reusable across different modules (Prometheus, future
modules, etc.).

**Location**: `src/core/bounded_allocator.zig`

```zig
/// A memory-bounded allocator that pre-allocates a fixed budget at init.
/// Implements std.mem.Allocator interface for seamless integration.
///
/// Use cases:
/// - Prometheus scrape processing (bounded per-module memory)
/// - Request processing with memory limits
/// - Any subsystem requiring predictable memory bounds
///
pub const BoundedAllocator = struct {
    /// Pre-allocated memory block
    backing_memory: []u8,

    /// Underlying fixed buffer allocator
    fba: std.heap.FixedBufferAllocator,

    /// Track active allocation count for observability
    active_allocations: std.atomic.Value(u32),

    /// Track bytes currently allocated
    bytes_allocated: std.atomic.Value(usize),

    /// The memory budget (for reporting)
    budget: usize,

    pub fn init(budget: usize) !BoundedAllocator {
        // Pre-allocate the entire budget at startup
        const backing = try std.heap.page_allocator.alloc(u8, budget);

        return .{
            .backing_memory = backing,
            .fba = std.heap.FixedBufferAllocator.init(backing),
            .active_allocations = std.atomic.Value(u32).init(0),
            .bytes_allocated = std.atomic.Value(usize).init(0),
            .budget = budget,
        };
    }

    pub fn deinit(self: *BoundedAllocator) void {
        std.heap.page_allocator.free(self.backing_memory);
    }

    /// Returns a std.mem.Allocator interface.
    /// This allocator can be passed to any code expecting an Allocator.
    /// Returns error.OutOfMemory when budget is exhausted.
    pub fn allocator(self: *BoundedAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        const result = self.fba.allocator().rawAlloc(len, ptr_align, ret_addr);
        if (result != null) {
            _ = self.active_allocations.fetchAdd(1, .monotonic);
            _ = self.bytes_allocated.fetchAdd(len, .monotonic);
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        const old_len = buf.len;
        const success = self.fba.allocator().rawResize(buf, buf_align, new_len, ret_addr);
        if (success) {
            if (new_len > old_len) {
                _ = self.bytes_allocated.fetchAdd(new_len - old_len, .monotonic);
            } else {
                _ = self.bytes_allocated.fetchSub(old_len - new_len, .monotonic);
            }
        }
        return success;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
        const self: *BoundedAllocator = @ptrCast(@alignCast(ctx));
        self.fba.allocator().rawFree(buf, buf_align, ret_addr);
        _ = self.active_allocations.fetchSub(1, .monotonic);
        _ = self.bytes_allocated.fetchSub(buf.len, .monotonic);
    }

    /// Stats for observability
    pub fn getStats(self: *const BoundedAllocator) Stats {
        return .{
            .budget = self.budget,
            .bytes_allocated = self.bytes_allocated.load(.monotonic),
            .bytes_available = self.budget - self.bytes_allocated.load(.monotonic),
            .active_allocations = self.active_allocations.load(.monotonic),
        };
    }

    pub const Stats = struct {
        budget: usize,
        bytes_allocated: usize,
        bytes_available: usize,
        active_allocations: u32,
    };
};
```

**Usage**:

```zig
var bounded = try BoundedAllocator.init(50 * 1024 * 1024); // 50MB
defer bounded.deinit();

const alloc = bounded.allocator();

// Per-request: allocate from pool, free when done
fn handleRequest() !void {
    var buf = try alloc.alloc(u8, 8192);  // Returns OutOfMemory if budget exhausted
    defer alloc.free(buf);
    // Process request...
}

// Check stats
const stats = bounded.getStats();
log.info("Memory: {d}/{d} bytes used", .{ stats.bytes_allocated, stats.budget });
```

The only addition over `FixedBufferAllocator` is observability stats tracking
(`bytes_allocated`, `active_allocations`).

**Memory exhaustion behavior**: When the budget is exhausted, allocations return
`error.OutOfMemory`. Callers handle this by either:

- Queuing the request until memory is available (with timeout)
- Rejecting with 503 Service Unavailable

### Per-Scrape Buffers

Each active scrape needs a small, fixed amount of memory:

```
Per-Scrape Memory Usage:
├── Read buffer (upstream):     8,192 bytes
├── Line parse buffer:          8,192 bytes
├── Metadata buffer (HELP/TYPE): 1,024 bytes
├── Metric name buffer:           256 bytes
└── Misc state:                   ~500 bytes
────────────────────────────────────────────
Total per scrape:              ~18 KB
```

**Max concurrent scrapes** = `global_memory_budget / per_scrape_memory`

| Global Budget | Per-Scrape | Max Concurrent |
| ------------- | ---------- | -------------- |
| 50 MB         | ~20 KB     | ~2,500         |
| 10 MB         | ~20 KB     | ~500           |
| 1 MB          | ~20 KB     | ~50            |

### Per-Scrape Data Limit

The per-scrape limit controls how much data flows through the streaming
pipeline. This is **not** about memory - it's about capping the response size.

```zig
pub const StreamingPrometheusFilter = struct {
    // Data volume tracking (NOT memory)
    max_scrape_bytes: usize,       // User-configured limit (e.g., 1GB)
    bytes_processed: usize,        // Running total of upstream bytes read
    bytes_forwarded: usize,        // Running total of bytes sent to Prometheus

    // Truncation state
    scrape_truncated: bool,        // Hit the per-scrape data limit

    pub fn processChunk(self: *Self, chunk: []const u8) !ProcessResult {
        // Check per-scrape data limit
        const remaining = self.max_scrape_bytes - self.bytes_processed;
        if (remaining == 0) {
            self.scrape_truncated = true;
            return .{ .consumed = 0, .should_stop = true };
        }

        // Process up to remaining budget
        const to_process = @min(chunk.len, remaining);
        self.bytes_processed += to_process;

        // Parse lines and apply policies...
        // Data flows through fixed buffers, not accumulated in memory

        return .{ .consumed = to_process, .should_stop = false };
    }
};
```

### How Streaming Enables This

The key insight is that streaming decouples memory from data volume:

```
Upstream (5GB)                    Edge (20KB buffers)              Prometheus
     │                                   │                              │
     │  ──── 8KB chunk ────►             │                              │
     │                            [parse, filter]                       │
     │                                   │  ──── filtered ────►         │
     │  ──── 8KB chunk ────►             │                              │
     │                            [parse, filter]                       │
     │                                   │  ──── filtered ────►         │
     │          ...                      │          ...                 │
     │  ──── 8KB chunk ────►             │                              │
     │                            [parse, filter]                       │
     │                                   │  ──── filtered ────►         │
     ▼                                   ▼                              ▼
   5GB sent                      Only 20KB used                    3GB received
                                   at any time                    (2GB filtered)
```

We read a chunk, parse it, filter it, write the output, then **reuse the same
buffers** for the next chunk. Memory stays constant regardless of data volume.

### Scrape Lifecycle with Memory Pool

```zig
fn handleScrapeRequest(
    pool: *PrometheusMemoryPool,
    config: *const PrometheusConfig,
    upstream_res: anytype,
    client_res: anytype,
) !void {
    // 1. Acquire memory from pool
    const allocator = pool.getAllocator() orelse {
        // Pool exhausted - reject request
        return error.MemoryBudgetExhausted;
    };
    defer pool.releaseAllocator(allocator);

    _ = pool.active_scrapes.fetchAdd(1, .monotonic);
    defer _ = pool.active_scrapes.fetchSub(1, .monotonic);

    // 2. Allocate per-scrape buffers from pool
    var read_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(read_buffer);

    var line_buffer = try allocator.alloc(u8, 8192);
    defer allocator.free(line_buffer);

    var metadata_buffer = try allocator.alloc(u8, 1024);
    defer allocator.free(metadata_buffer);

    // 3. Create filter with per-scrape DATA limit
    var filter = StreamingPrometheusFilter.init(.{
        .read_buffer = read_buffer,
        .line_buffer = line_buffer,
        .metadata_buffer = metadata_buffer,
        .max_scrape_bytes = config.max_bytes_per_scrape,  // Data limit, not memory
        .registry = config.registry,
        .bus = config.bus,
    });

    // 4. Stream and filter (memory stays constant, data flows through)
    var upstream_reader = upstream_res.reader(read_buffer);
    const client_writer = client_res.writer();

    while (!filter.shouldStop()) {
        const chunk = upstream_reader.peek();
        if (chunk.len == 0) {
            if (upstream_reader.isEndOfStream()) break;
            continue;
        }

        const result = try filter.processChunk(chunk, client_writer);
        upstream_reader.toss(result.consumed);
    }

    try filter.finish(client_writer);

    // 5. Buffers freed, memory returned to pool via defers
}
```

### What Happens at Limits

| Limit Hit               | Behavior                            | Result                                  |
| ----------------------- | ----------------------------------- | --------------------------------------- |
| Global memory exhausted | New scrape rejected with 503        | Existing scrapes unaffected             |
| Per-scrape data limit   | Stop reading upstream, flush, close | Prometheus gets partial (valid) metrics |

### Configuration Examples

**High-throughput environment** (many small scrapes):

```zig
.global_memory_budget = 100 * 1024 * 1024,  // 100MB total
.max_bytes_per_scrape = 10 * 1024 * 1024,   // 10MB per scrape
// ~5,000 concurrent scrapes possible
```

**Large metrics environment** (few huge scrapes):

```zig
.global_memory_budget = 50 * 1024 * 1024,   // 50MB total
.max_bytes_per_scrape = 5 * 1024 * 1024 * 1024,  // 5GB per scrape
// ~2,500 concurrent scrapes, each can stream up to 5GB
```

**Memory-constrained edge** (embedded/sidecar):

```zig
.global_memory_budget = 5 * 1024 * 1024,    // 5MB total
.max_bytes_per_scrape = 100 * 1024 * 1024,  // 100MB per scrape
// ~250 concurrent scrapes
```

### Observability

```zig
const PrometheusPoolStats = struct {
    global_budget: usize,
    memory_used: usize,
    memory_available: usize,
    active_scrapes: u32,
    max_concurrent_scrapes: u32,
    scrapes_rejected_oom: u64,  // Counter of 503s due to memory
};

const PrometheusScrapeCompleted = struct {
    bytes_processed: usize,      // Total upstream bytes read
    bytes_forwarded: usize,      // Bytes sent to Prometheus (after filtering)
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    scrape_truncated: bool,      // Hit per-scrape data limit
    duration_us: u64,
};
```

## Configuration

### Module Registration

```zig
const prom_config = PrometheusConfig{
    .registry = &policy_registry,
    .bus = &event_bus,
    .global_memory_budget = 50 * 1024 * 1024,  // 50MB total for all concurrent scrapes
    .max_bytes_per_scrape = 1 * 1024 * 1024 * 1024,  // 1GB max data per scrape
};

const registration = ModuleRegistration{
    .module = prometheus_module,
    .routes = &.{
        RoutePattern.prefix("/metrics"),
    },
    .upstream_url = "http://localhost:9090/metrics",
    .module_data = &prom_config,
};
```

### Policy Configuration

Reuse existing metric policies:

```yaml
policies:
  - id: drop-debug-metrics
    name: Drop Debug Metrics
    enabled: true
    target:
      metric:
        match:
          - field:
              metric_field: METRIC_FIELD_NAME
            regex: "^debug_.*"
        keep: false

  - id: keep-only-http-metrics
    name: Keep Only HTTP Metrics
    enabled: true
    target:
      metric:
        match:
          - field:
              metric_field: METRIC_FIELD_NAME
            regex: "^http_.*"
        keep: true
```

## HELP/TYPE Metadata Handling

The Prometheus format groups metrics with metadata:

```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="get"} 100
http_requests_total{method="post"} 50
```

**Challenge**: We must decide whether to include HELP/TYPE before seeing if any
samples match.

**Solution**: Buffered metadata approach

1. When encountering HELP/TYPE, store reference to line (not copy)
2. On first matching sample for that metric, flush HELP/TYPE first
3. If no samples match, discard the pending metadata
4. This requires storing up to 2 line references (HELP + TYPE) per metric group

```zig
// In StreamingPrometheusFilter
pending_help: ?struct {
    line: []const u8,  // Slice into line_buffer copy area
},
pending_type: ?struct {
    line: []const u8,
},

// Need a small metadata buffer area for pending lines
metadata_buffer: [2][512]u8,  // Two 512-byte buffers for HELP/TYPE lines
```

**Memory impact**: Additional 1KB for metadata buffering.

## Implementation Phases

Build iteratively, testing each component in isolation before integration.

### Phase 1: Prometheus Line Parser

**Goal**: Parse Prometheus exposition format lines with zero allocation.

**Files**:

- `src/prometheus/line_parser.zig`

**Tasks**:

1. Implement `ParsedLine` union type (empty, comment, help, type_info, sample,
   parse_error)
2. Implement `LabelIterator` for zero-copy label iteration
3. Implement `parseLine()` function
4. Handle edge cases: escaped characters, quoted metric names, timestamps

**Tests** (exhaustive):

- Empty lines
- Comment lines (`# this is a comment`)
- HELP lines (`# HELP metric_name description with spaces`)
- TYPE lines (`# TYPE metric_name counter/gauge/histogram/summary/untyped`)
- Simple samples (`metric_name 123`)
- Samples with labels (`metric_name{label="value"} 123`)
- Samples with multiple labels (`metric_name{a="1",b="2"} 123`)
- Samples with timestamps (`metric_name 123 1678886400000`)
- Escaped label values (`metric_name{path="/foo\"bar"} 1`)
- Histogram buckets (`http_duration_bucket{le="0.1"} 100`)
- Summary quantiles (`rpc_duration{quantile="0.99"} 0.5`)
- Malformed lines (should return parse_error)
- Unicode in label values
- Very long lines (boundary testing)

---

### Phase 2: Streaming Filter (No Policy Evaluation)

**Goal**: Stream data through line-by-line, tracking bytes, without filtering.

**Files**:

- `src/prometheus/streaming_filter.zig`

**Tasks**:

1. Implement `StreamingPrometheusFilter` struct with buffer management
2. Implement `processChunk()` - accumulate bytes into line buffer, emit on
   newline
3. Implement `finish()` - flush any remaining partial line
4. Track `bytes_processed` and `bytes_forwarded`
5. Implement `max_scrape_bytes` enforcement (data truncation)
6. Handle lines longer than line buffer (truncate or pass through)

**Tests**:

- Pass-through mode: input equals output
- Chunked input: data arrives in arbitrary chunk sizes (1 byte, 7 bytes, 8KB,
  etc.)
- Line boundary handling: newline split across chunks
- Data limit enforcement: stops at `max_scrape_bytes`
- Partial line at end of stream
- Empty input
- Input exactly at buffer boundaries
- Very long lines (exceed line buffer)

---

### Phase 3: Field Accessor

**Goal**: Map `MetricFieldRef` to parsed Prometheus line data.

**Files**:

- `src/prometheus/field_accessor.zig`

**Tasks**:

1. Implement `PrometheusMetricContext` struct
2. Implement `prometheusFieldAccessor()` function
3. Map `METRIC_FIELD_NAME` → metric name from parsed line
4. Map `datapoint_attribute` → label lookup via `LabelIterator`
5. Return `null` for unsupported fields (resource_attribute, scope_attribute,
   etc.)

**Tests**:

- Access metric name
- Access existing label
- Access non-existent label (returns null)
- Access with multiple labels
- Access unsupported field types (returns null)
- Label with special characters

---

### Phase 4: Streaming Filter with Policy Evaluation

**Goal**: Integrate policy engine into streaming filter.

**Files**:

- Update `src/prometheus/streaming_filter.zig`

**Tasks**:

1. Add `PolicyRegistry` and `EventBus` to filter config
2. For each sample line, create `PrometheusMetricContext`
3. Call `PolicyEngine.evaluate(.metric, ...)`
4. Keep or drop line based on `FilterDecision`
5. Implement HELP/TYPE metadata buffering (defer until first matching sample)
6. Track `lines_dropped` and `lines_kept` stats

**Tests**:

- No policies: all lines pass through
- DROP policy by metric name: matching lines dropped
- DROP policy by label value: matching lines dropped
- KEEP policy: only matching lines kept
- Multiple policies: correct precedence (drop beats keep)
- HELP/TYPE preserved when samples match
- HELP/TYPE dropped when no samples match
- Mixed metric groups (some dropped, some kept)
- Sampling policies (percentage-based)

---

### Phase 5: Bounded Allocator

**Goal**: Generic pre-allocated allocator for bounded memory usage (reusable
across modules).

**Files**:

- `src/core/bounded_allocator.zig`

**Tasks**:

1. Implement `BoundedAllocator` struct
2. Pre-allocate backing memory at init
3. Implement `std.mem.Allocator` interface (alloc, resize, free vtable)
4. Track `active_allocations` and `bytes_allocated` atomically
5. Implement `getStats()` for observability
6. Thread-safe allocation/deallocation

**Tests**:

- Single allocation and release
- Multiple concurrent allocations
- Exhaustion behavior (returns error.OutOfMemory)
- Free returns memory to pool
- Concurrent access (thread safety)
- Stats tracking accuracy (bytes_allocated, active_allocations)
- Works with any code expecting std.mem.Allocator

---

### Phase 6: Prometheus Module (Passthrough Only)

**Goal**: Module that proxies `/metrics` without filtering, validating the
response processor hook.

**Files**:

- `src/modules/prometheus_module.zig`
- Modify `src/proxy/server.zig` (add `ResponseProcessor` union)

**Tasks**:

1. Implement `PrometheusModule` struct with init/deinit
2. Implement `processRequest()` - return unchanged (GET only)
3. Implement `getResponseProcessor()` - return prometheus config
4. Add `ResponseProcessor` union to server types
5. Modify `streamResponseBody()` to switch on processor type
6. For prometheus processor: allocate from pool, stream through, release

**Tests**:

- GET request passes through to upstream
- Non-GET returns 405
- Response streams correctly from upstream to client
- Memory allocated from pool and released
- Large response streams without memory growth

---

### Phase 7: Full Integration

**Goal**: Wire everything together with filtering enabled.

**Files**:

- Update `src/modules/prometheus_module.zig`
- Update `src/proxy/server.zig`

**Tasks**:

1. Pass `PolicyRegistry` to `StreamingPrometheusFilter`
2. Enable policy evaluation in response streaming
3. Add observability events (`PrometheusScrapeCompleted`, etc.)
4. Handle memory exhaustion (503 response)
5. Handle data truncation (partial valid response)

**Tests**:

- End-to-end: Prometheus scrape with DROP policy
- End-to-end: Prometheus scrape with KEEP policy
- Memory exhaustion: concurrent scrapes exceed budget → 503
- Data truncation: large response truncated at limit
- Observability events emitted correctly
- Error handling: upstream errors propagate correctly

---

### Phase 8: Configuration & Documentation

**Goal**: Production-ready configuration and docs.

**Tasks**:

1. Add Prometheus module to default distribution
2. Document configuration options
3. Add example policies for common use cases
4. Performance benchmarks
5. Memory usage validation under load

---

## Summary: Build Order

```
1. line_parser.zig         ← standalone, exhaustive tests
2. streaming_filter.zig    ← uses line_parser, passthrough only
3. field_accessor.zig      ← standalone, uses line_parser types
4. streaming_filter.zig    ← add policy evaluation
5. bounded_allocator.zig   ← standalone, std.mem.Allocator interface, reusable
6. prometheus_module.zig   ← passthrough integration
7. Full integration        ← filtering enabled
8. Polish                  ← config, docs, benchmarks
```

Each phase produces a working, tested component before moving to the next.

## Alternative Considered: Full Buffering

We considered buffering the entire response, parsing, filtering, then sending.
This was rejected because:

1. **Unpredictable memory**: Response size varies, hard to bound
2. **Latency**: Must wait for complete response before sending
3. **Existing pattern**: Contradicts current streaming architecture

The streaming approach matches the edge's design philosophy of predictable
memory usage.

## Error Handling

| Error                     | Behavior                                |
| ------------------------- | --------------------------------------- |
| Line parse error          | Pass through unchanged (fail-open)      |
| Line too long             | Truncate line, pass through what fits   |
| Output limit reached      | Stop writing, return truncated response |
| Upstream connection error | Return error to client                  |
| Policy evaluation error   | Pass through line unchanged             |

## Observability

Events emitted during processing:

```zig
const PrometheusFilterStarted = struct {
    upstream_url: []const u8,
    max_output_bytes: usize,
};

const PrometheusFilterCompleted = struct {
    lines_processed: usize,
    lines_dropped: usize,
    lines_kept: usize,
    bytes_written: usize,
    truncated: bool,
    duration_us: u64,
};

const PrometheusLineParseError = struct {
    line_number: usize,
    line_preview: []const u8, // First 100 chars
};

const PrometheusOutputTruncated = struct {
    max_bytes: usize,
    lines_remaining: usize, // Approximate
};
```

## Future Extensions

1. **Histogram/Summary Aggregation**: Intelligently handle histogram buckets and
   summary quantiles as groups
2. **Label Rewriting**: Support for renaming/removing labels (transforms)
3. **Metric Renaming**: Transform metric names based on policies
4. **Caching**: Cache filtered responses for identical scrape intervals
5. **OpenMetrics Support**: Extend parser for OpenMetrics format
