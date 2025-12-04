# Tero Edge

Tero Edge is a lightweight, high-performance telemetry proxy that enables efficient telemetry processing via a set of policies. The repository is structured as modular packages that can be composed to enable multiple use cases and scenarios.

## Current Configurations

1. **Edge data proxy** - Receives data in a gateway or sidecar configuration, processes the data through its policy engine, and forwards it to the next destination.

## Repository Structure

```
src/
├── main.zig              # Default distribution entry point
├── datadog_main.zig      # Datadog-focused distribution entry point
├── root.zig              # Library root (public API exports)
│
├── policy/               # Policy management package
├── hyperscan/            # Pattern matching package (Vectorscan bindings)
├── modules/              # Protocol-specific processing modules
├── proxy/                # HTTP proxy infrastructure
├── observability/        # Logging and tracing infrastructure
├── config/               # Configuration parsing (non-policy)
└── proto/                # Protobuf definitions and generated code
```

## Package Overview

Each package is designed to be as independent as possible, with clear interfaces for integration.

### `policy/` - Policy Management

The policy package provides centralized policy lifecycle management including loading, hot-reloading, and evaluation.

**Key exports:**
- `Registry` - Thread-safe policy store with lock-free reads via atomic snapshot pointers
- `Provider` - Vtable interface for policy sources (file, HTTP, etc.)
- `FileProvider` - File-based policy loading with inotify/kqueue watching
- `HttpProvider` - HTTP-based policy loading with polling and sync state
- `FilterEngine` - Hyperscan-based policy evaluation engine
- `SourceType` - Policy source classification (file, http)

**Integration:**
```zig
const policy = @import("policy/root.zig");

// Create registry
var registry = policy.Registry.init(allocator, event_bus);
defer registry.deinit();

// Create and register a file provider
const file_provider = try policy.FileProvider.init(allocator, bus, "local", "/path/to/policies.json");
const provider = policy.Provider.init(file_provider);
try registry.registerProvider(&provider);

// Evaluate policies (lock-free read)
var engine = policy.FilterEngine.init(allocator, bus, &registry);

// Evaluate data where ctx is the data you want to evaluate 
// and field_accessor_fn is a function that informs the engine how to access fields in the data.
const result = engine.evaluate(ctx, field_accessor_fn);
```

**Dependencies:** `hyperscan/` (for FilterEngine), `observability/`, `proto/`

---

### `hyperscan/` - Pattern Matching

High-performance regex matching via Vectorscan (Hyperscan fork). Provides both low-level bindings and a higher-level matcher index for policy evaluation.

**Key exports:**
- `Database` - Compiled Hyperscan database
- `Scratch` - Per-thread scratch space for scanning
- `Pattern` - Pattern definition with flags
- `MatcherIndex` - Inverted index mapping (MatchCase, key) tuples to compiled databases
- `MatcherDatabase` - Single compiled database with pattern metadata

**Integration:**
```zig
const hyperscan = @import("hyperscan/hyperscan.zig");

// Compile patterns
const patterns = [_]hyperscan.Pattern{
    .{ .expression = "error", .id = 0, .flags = .{} },
    .{ .expression = "warning", .id = 1, .flags = .{} },
};
var db = try hyperscan.Database.compileMulti(allocator, &patterns, .{});
defer db.deinit();

// Create scratch and scan
var scratch = try hyperscan.Scratch.init(&db);
defer scratch.deinit();
_ = try db.scanWithCallback(&scratch, input_text, &ctx, callback_fn);
```

**Dependencies:** `observability/`, `proto/` (for MatcherIndex), links to libhs (Vectorscan)

---

### `modules/` - Protocol Modules

Protocol-specific request processing modules that plug into the proxy infrastructure.

**Key exports:**
- `ProxyModule` - Vtable interface for request processing
- `ModuleRegistration` - Module configuration (routes, upstream, etc.)
- `DatadogModule` - Datadog log ingestion with policy-based filtering
- `PassthroughModule` - No-op passthrough for unhandled routes

**Integration:**
```zig
const modules = @import("modules/proxy_module.zig");
const datadog = @import("modules/datadog_module.zig");

var datadog_module = datadog.DatadogModule{};
var passthrough = modules.PassthroughModule{};

const registrations = [_]modules.ModuleRegistration{
    .{
        .module = datadog_module.asProxyModule(),
        .routes = &datadog.routes,
        .upstream_url = "https://intake.logs.datadoghq.com",
        .max_request_body = 10 * 1024 * 1024,
        .max_response_body = 1024 * 1024,
        .module_data = @ptrCast(&config),
    },
    .{
        .module = passthrough.asProxyModule(),
        .routes = &passthrough.default_routes,
        .upstream_url = upstream_url,
        .max_request_body = max_body,
        .max_response_body = max_body,
        .module_data = null,
    },
};
```

**Dependencies:** `policy/` (for DatadogModule), `observability/`

---

### `proxy/` - HTTP Proxy Infrastructure

Core HTTP proxy server and routing infrastructure.

**Key exports:**
- `ProxyServer` - HTTP server with module-based request routing
- `Router` - Route matching (path patterns, method bitmasks)
- `UpstreamClient` - HTTP client for forwarding requests
- `compress` - gzip compression/decompression utilities

**Integration:**
```zig
const proxy = @import("proxy/server.zig");

var server = try proxy.ProxyServer.init(
    allocator,
    event_bus,
    listen_address,
    listen_port,
    &module_registrations,
);
defer server.deinit();

try server.listen(); // Blocks until server.stop() called
```

**Dependencies:** `modules/`, `observability/`, links to httpz

---

### `observability/` - Logging and Tracing

Structured event-based observability infrastructure. All logging goes through an EventBus that can route to different backends.

**Key exports:**
- `EventBus` - Vtable interface for event emission
- `StdioEventBus` - JSON-formatted output to stdout/stderr
- `NoopEventBus` - Silent bus for testing
- `Level` - Log levels (trace, debug, info, warn, err)
- `Span` - Duration tracking with start/complete events
- `StdLogAdapter` - Routes `std.log` through the EventBus

**Integration:**
```zig
const o11y = @import("observability/root.zig");

var stdio_bus: o11y.StdioEventBus = undefined;
stdio_bus.init();
const bus = stdio_bus.eventBus();

bus.setLevel(.info);
bus.info(MyEvent{ .field = value });

// Spans for timing
var span = bus.started(.info, StartEvent{});
// ... do work ...
span.completed(EndEvent{});
```

**Dependencies:** None (leaf package)

---

### `config/` - Configuration Parsing

Application configuration loading and parsing (non-policy configuration).

**Key exports:**
- `Config` - Main configuration struct
- `parseConfigFile` - JSON config file parsing

**Integration:**
```zig
const config = @import("config/parser.zig");

const cfg = try config.parseConfigFile(allocator, "config.json");
defer {
    allocator.free(cfg.upstream_url);
    // ... cleanup ...
    allocator.destroy(cfg);
}
```

**Dependencies:** `policy/` (for ProviderConfig types)

---

### `proto/` - Protocol Buffers

Generated Zig code from protobuf definitions. Provides policy and telemetry data structures.

**Key exports:**
- `policy.Policy` - Policy definition
- `policy.LogMatcher` - Log matching rules
- `policy.FilterAction` - DROP/KEEP actions

**Dependencies:** None (leaf package)

---

## Distributions

Distributions are pre-configured entry points that compose packages for specific use cases.

### Default (`main.zig`)
Generic proxy with Datadog and passthrough modules.

### Datadog (`datadog_main.zig`)
Focused distribution for Datadog log ingestion with:
- Policy-based log filtering (DROP/KEEP)
- Fail-open behavior (errors pass logs through)
- Lock-free policy updates
- Graceful shutdown with signal handling

Build: `zig build` (default) or `zig build datadog`

## Building

```bash
# Build all targets
zig build

# Run tests
zig build test

# Build specific distribution
zig build datadog
```

## Configuration

See `config.json` for example configuration. Key settings:
- `listen_address` / `listen_port` - Server bind address
- `upstream_url` - Default upstream destination
- `policy_providers` - List of policy sources (file/http)
- `max_body_size` - Request/response body limits

## Design Principles

1. **Data-Oriented Design** - Optimize for cache coherency and memory access patterns
2. **Lock-Free Reads** - Policy evaluation uses atomic snapshot pointers for zero-contention reads
3. **Fail-Open** - Errors in policy evaluation result in data passthrough, not drops
4. **Modular Composition** - Packages can be used independently or composed together
5. **Explicit Dependencies** - Each package declares its dependencies via imports
