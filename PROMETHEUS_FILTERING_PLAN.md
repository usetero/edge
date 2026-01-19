# Prometheus Metrics Filtering Architecture

## Overview

This document describes the architecture for policy-based Prometheus metrics
filtering in Tero Edge. The design combines the `InterceptingWriter` pattern
(for clean server integration) with the `PolicyStreamingFilter` (for
line-by-line policy evaluation).

## Data Flow

```
┌─────────────┐     ┌──────────────┐     ┌─────────────────────┐     ┌────────────┐
│  Upstream   │────▶│ InterceptingWriter │────▶│ PolicyStreamingFilter │────▶│   Client   │
│  /metrics   │     │  (per chunk)       │     │  (line-by-line)       │     │            │
└─────────────┘     └──────────────┘     └─────────────────────┘     └────────────┘
```

1. **Upstream** returns Prometheus metrics in exposition format
2. **InterceptingWriter** receives each chunk via its `drain` callback
3. **InterceptingWriter callback** passes data to `PolicyStreamingFilter`
4. **PolicyStreamingFilter** parses lines, evaluates policies, outputs kept
   metrics
5. **Client** receives filtered metrics

## Components

### 1. InterceptingWriter (`src/proxy/intercepting_writer.zig`)

A writer wrapper that intercepts data before writing to the inner writer.
Provides:

- `ResponseInterceptFn` callback for each chunk of data
- Context pointer for stateful processing
- Passthrough when no callback configured

**Already implemented in `jacob/eng-85-prometheus-line-client` branch.**

### 2. PrometheusInterceptContext (`src/modules/prometheus_module.zig`)

Per-request context that holds:

- `PolicyStreamingFilter` instance
- `PolicyEngine` reference (from registry)
- Line buffer and metadata buffer
- Output accumulator (ArrayList or similar)
- Allocator for the request lifetime

```zig
pub const PrometheusInterceptContext = struct {
    filter: PolicyStreamingFilter,
    engine: PolicyEngine,
    output: std.ArrayList(u8),
    allocator: std.mem.Allocator,

    // Buffers owned by this context
    line_buffer: []u8,
    metadata_buffer: []u8,
};
```

### 3. PolicyStreamingFilter (`src/prometheus/streaming_filter.zig`)

Line-by-line filter that:

- Accumulates bytes until newline
- Parses each line (metric sample, HELP, TYPE, comment)
- Evaluates metric samples against PolicyEngine
- Tracks HELP/TYPE metadata, only outputs if metric is kept
- Writes kept lines to output writer

**Already implemented, needs minor adaptation.**

### 4. Intercept Callback Flow

```zig
fn prometheusInterceptCallback(data: []const u8, context: ?*anyopaque) ?[]const u8 {
    const ctx: *PrometheusInterceptContext = @ptrCast(@alignCast(context));

    // Clear output buffer for this chunk
    ctx.output.clearRetainingCapacity();

    // Create a writer over the output buffer
    var output_writer = // ... writer over ctx.output

    // Process chunk through filter (writes to output_writer)
    _ = ctx.filter.processChunk(data, &output_writer) catch {
        // Fail open - return original data
        return data;
    };

    // Return filtered output (or null if everything was dropped)
    if (ctx.output.items.len == 0) {
        return null; // All metrics in this chunk were filtered
    }
    return ctx.output.items;
}
```

### 5. Module Registration

```zig
// In prometheus_main.zig
const module_registrations = [_]ModuleRegistration{
    .{
        .module = prometheus_module.asProxyModule(),
        .routes = &prometheus_mod.routes,
        .upstream_url = metrics_upstream,
        .max_request_body = 1024,
        .max_response_body = config.max_body_size,
        .module_data = @ptrCast(&prometheus_config),
        // Response interception
        .response_intercept_fn = prometheus_mod.interceptCallback,
        .create_intercept_context_fn = prometheus_mod.createContext,
        .destroy_intercept_context_fn = prometheus_mod.destroyContext,
    },
};
```

## Implementation Steps

### Step 1: Merge InterceptingWriter from other branch

- Copy `src/proxy/intercepting_writer.zig`
- Update `src/proxy/server.zig` with interception support
- Update `src/modules/proxy_module.zig` with intercept function types

### Step 2: Create ArrayList-based Writer adapter

The `PolicyStreamingFilter` writes to `std.Io.Writer`. We need an adapter that
writes to an ArrayList:

```zig
pub const ArrayListWriter = struct {
    list: *std.ArrayList(u8),

    pub fn writer(self: *ArrayListWriter) std.Io.Writer {
        return .{
            .vtable = &vtable,
            .buffer = &.{}, // No internal buffer, write directly
        };
    }

    // Implement drain to append to ArrayList
};
```

### Step 3: Update PrometheusInterceptContext

- Hold PolicyStreamingFilter + PolicyEngine
- Manage buffers and output ArrayList
- Implement factory/destroy functions

### Step 4: Implement Intercept Callback

- Get context, clear output
- Process chunk through filter
- Return filtered data or null

### Step 5: Wire up in prometheus_main.zig

- Create PrometheusConfig with registry reference
- Register module with intercept functions

## Memory Model

```
Request Lifetime (arena allocator):
├── PrometheusInterceptContext
│   ├── line_buffer[8192]      - For accumulating partial lines
│   ├── metadata_buffer[1024]  - For HELP/TYPE lines
│   └── output: ArrayList      - Filtered output per chunk
│
├── PolicyEngine (stack, references registry)
│
└── PolicyStreamingFilter (embedded in context)
```

All allocations use the request arena, automatically freed when request
completes.

## Policy Evaluation

For each metric sample line:

1. Parse line with `line_parser.parseLine()`
2. Build `PrometheusFieldContext` with parsed sample
3. Call
   `engine.evaluate(.metric, &ctx, prometheusFieldAccessor, null, &policy_ids)`
4. If `result.decision.shouldContinue()` → keep the line
5. If dropped → increment `lines_dropped` stat

## HELP/TYPE Handling

Prometheus format convention:

```
# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="get"} 100
http_requests_total{method="post"} 50
```

The filter:

1. Stores HELP/TYPE in metadata buffer when seen
2. When first sample for that metric is kept → output stored HELP/TYPE first
3. Clears stored metadata when metric name changes

## Statistics & Observability

Track per-scrape:

- `bytes_processed` - Total bytes from upstream
- `bytes_forwarded` - Total bytes sent to client
- `lines_processed` - Number of lines parsed
- `lines_dropped` - Lines filtered by policy
- `lines_kept` - Lines forwarded
- `scrape_truncated` - Hit max_scrape_bytes limit

Log stats when `lines_dropped > 0` or `scrape_truncated`.

## Error Handling

**Fail Open**: Any error in filtering returns data unchanged.

- Parse errors → forward line as-is
- Policy evaluation errors → keep the metric
- Memory allocation errors → passthrough mode

## Configuration

```json
{
  "prometheus": {
    "max_bytes_per_scrape": 52428800
  }
}
```

Policies are configured via the standard policy provider system (file/HTTP).

## Testing Strategy

1. **Unit tests** for PolicyStreamingFilter with mock PolicyEngine
2. **Unit tests** for intercept callback with various inputs
3. **Integration tests** with real policy registry
4. **Benchmark** streaming performance with large metrics payloads
