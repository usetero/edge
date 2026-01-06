# Tero Edge

Tero Edge is a lightweight, high-performance telemetry proxy that enables
efficient telemetry processing via a set of policies. The repository is
structured as modular packages that can be composed to enable multiple use cases
and scenarios. The proxy demonstrates how to implement the policy spec described
in
[this OTEP](https://github.com/open-telemetry/opentelemetry-specification/pull/4738).
This project is not meant to replace the opentelemetry collector but rather work
in tandem with it, providing a lightweight alternative for solely applying
policies. It's expected that a follow up to this project will be a collector
processor Policy implementation.

## Current Configurations

1. **Edge data proxy** - Receives data in a gateway or sidecar configuration,
   processes the data through its policy engine, and forwards it to the next
   destination.

2. **OTLP (OpenTelemetry) proxy** - Receives OpenTelemetry logs via the
   `/v1/logs` endpoint, applies policy-based filtering (DROP/KEEP), and forwards
   to OTLP-compatible backends.

3. **Datadog proxy** - Receives OpenTelemetry logs via the `/api/v2/logs`
   endpoint, applies policy-based filtering (DROP/KEEP), and forwards to
   Datadog.

## Repository Structure

```
src/
├── main.zig              # Default distribution entry point
├── datadog_main.zig      # Datadog-focused distribution entry point
├── otlp_main.zig         # OTLP-focused distribution entry point
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

Each package is designed to be as independent as possible, with clear interfaces
for integration.

### `policy/` - Policy Management

The policy package provides centralized policy lifecycle management including
loading, hot-reloading, and evaluation.

**Key exports:**

- `Registry` - Thread-safe policy store with lock-free reads via atomic snapshot
  pointers
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

High-performance regex matching via Vectorscan (Hyperscan fork). Provides both
low-level bindings and a higher-level matcher index for policy evaluation.

**Key exports:**

- `Database` - Compiled Hyperscan database
- `Scratch` - Per-thread scratch space for scanning
- `Pattern` - Pattern definition with flags
- `MatcherIndex` - Inverted index mapping (MatchCase, key) tuples to compiled
  databases
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

**Dependencies:** `observability/`, `proto/` (for MatcherIndex), links to libhs
(Vectorscan)

---

### `modules/` - Protocol Modules

Protocol-specific request processing modules that plug into the proxy
infrastructure.

**Key exports:**

- `ProxyModule` - Vtable interface for request processing
- `ModuleRegistration` - Module configuration (routes, upstream, etc.)
- `DatadogModule` - Datadog log ingestion with policy-based filtering
- `OtlpModule` - OpenTelemetry log ingestion with policy-based filtering
- `PassthroughModule` - No-op passthrough for unhandled routes

**Integration:**

```zig
const modules = @import("modules/proxy_module.zig");
const datadog = @import("modules/datadog_module.zig");

var datadog_logs_module = datadog.DatadogModule{};
var datadog_metrics_module = datadog.DatadogModule{};
var passthrough = modules.PassthroughModule{};

const registrations = [_]modules.ModuleRegistration{
    .{
        .module = datadog_logs_module.asProxyModule(),
        .routes = &datadog.logs_routes,
        .upstream_url = "https://intake.logs.datadoghq.com",
        .max_request_body = 10 * 1024 * 1024,
        .max_response_body = 1024 * 1024,
        .module_data = @ptrCast(&config),
    },
    .{
        .module = datadog_metrics_module.asProxyModule(),
        .routes = &datadog.metrics_routes,
        .upstream_url = "https://api.datadoghq.com",
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

**Dependencies:** `policy/` (for DatadogModule, OtlpModule), `observability/`

#### OtlpModule

The OTLP module handles OpenTelemetry log ingestion with policy-based filtering.
It processes the standard OTLP JSON format (`ExportLogsServiceRequest`).

**Supported filter match cases:**

- `log_body` - Match against log message body
- `log_severity_text` - Match against severity text (INFO, DEBUG, ERROR, etc.)
- `log_severity_number` - Match against severity number (1-24)
- `log_attribute` - Match against log record attributes
- `resource_attribute` - Match against resource attributes (e.g.,
  `service.name`)
- `scope_name` - Match against instrumentation scope name
- `scope_version` - Match against instrumentation scope version
- `scope_attribute` - Match against scope attributes

**Routes:**

- `POST /v1/logs` - OTLP log ingestion endpoint

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

Structured event-based observability infrastructure. All logging goes through an
EventBus that can route to different backends.

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

Generated Zig code from protobuf definitions. Provides policy and telemetry data
structures.

**Key exports:**

- `policy.Policy` - Policy definition
- `policy.LogMatcher` - Log matching rules
- `policy.FilterAction` - DROP/KEEP actions

**Dependencies:** None (leaf package)

---

## Distributions

Distributions are pre-configured entry points that compose packages for specific
use cases.

### Full (`main.zig`)

Full distribution supporting both Datadog and OTLP ingestion with:

- Handles Datadog `/api/v2/logs` and `/api/v2/series` endpoints
- Handles OTLP `/v1/logs` and `/v1/metrics` endpoints
- Policy-based filtering (DROP/KEEP) for logs and metrics
- Separate upstream URLs for logs and metrics (optional)
- Async policy loading (server starts immediately while policies load in
  background)
- Fail-open behavior (errors pass data through unchanged)
- Lock-free policy updates via atomic snapshots
- Graceful shutdown with signal handling
- SIGSEGV handler for crash diagnostics with stack traces

Build: `zig build` (default) Run: `zig build run` or
`./zig-out/bin/edge [config-file]`

### Datadog (`datadog_main.zig`)

Focused distribution for Datadog log and metrics ingestion with:

- Handles `/api/v2/logs` and `/api/v2/series` endpoints
- Policy-based filtering (DROP/KEEP)
- Separate upstream URLs for logs and metrics (optional)
- Async policy loading (non-blocking startup)
- Fail-open behavior (errors pass data through)
- Lock-free policy updates via atomic snapshots
- Graceful shutdown with signal handling
- SIGSEGV handler for crash diagnostics

Build: `zig build datadog` Run: `zig build run-datadog` or
`./zig-out/bin/edge-datadog [config-file]`

### OTLP (`otlp_main.zig`)

Focused distribution for OpenTelemetry Protocol (OTLP) log ingestion with:

- Handles `/v1/logs` endpoint (OTLP JSON format)
- Policy-based log filtering (DROP/KEEP) on log body, severity, attributes
- Support for resource attributes, scope attributes, and log attributes
- Async policy loading (non-blocking startup)
- Fail-open behavior (errors pass logs through unchanged)
- Lock-free policy updates via atomic snapshots
- Graceful shutdown with signal handling
- SIGSEGV handler for crash diagnostics
- Compatible with any OTLP-receiving backend (Datadog, Jaeger, etc.)

Build: `zig build otlp` Run: `zig build run-otlp` or
`./zig-out/bin/edge-otlp [config-file]`

## Building

```bash
# Build all targets
zig build

# Run tests
zig build test

# Build specific distribution
zig build edge     # Full distribution (Datadog + OTLP)
zig build datadog  # Datadog-only distribution
zig build otlp     # OTLP-only distribution

# Run specific distribution
zig build run-edge
zig build run-datadog
zig build run-otlp
```

## Docker

Multi-stage Dockerfile for building minimal container images.

```bash
# Build the full distribution
docker build --build-arg DISTRIBUTION=edge -t edge .

# Build Datadog-only distribution
docker build --build-arg DISTRIBUTION=datadog -t edge-datadog .

# Build OTLP-only distribution
docker build --build-arg DISTRIBUTION=otlp -t edge-otlp .

# Run with a config file
docker run -v $(pwd)/config.json:/app/config.json -p 8080:8080 edge
```

Available distributions: `edge`, `datadog`, `otlp`

## Configuration

See `config.json` for the Datadog distribution or `config-otlp.json` for the
OTLP distribution.

### Key settings:

- `listen_address` / `listen_port` - Server bind address
- `upstream_url` - Default upstream destination (used when specific URLs not
  set)
- `logs_url` - (Optional) Upstream URL for log endpoints (falls back to
  `upstream_url`)
- `metrics_url` - (Optional) Upstream URL for metrics endpoints (falls back to
  `upstream_url`)
- `workspace_id` - Workspace identifier for policy sync
- `log_level` - Logging level (trace, debug, info, warn, err)
- `policy_providers` - List of policy sources (file/http)
- `max_body_size` - Request/response body limits

### Example OTLP Configuration (`config-otlp.json`):

```json
{
  "listen_address": "127.0.0.1",
  "listen_port": 8080,
  "upstream_url": "https://otlp.us5.datadoghq.com",
  "workspace_id": "your-workspace-id",
  "log_level": "info",
  "max_body_size": 1048576,
  "policy_providers": [
    {
      "id": "file",
      "type": "file",
      "path": "policies.json"
    },
    {
      "id": "http",
      "type": "http",
      "url": "http://localhost:9090/v1/policy/sync"
    }
  ]
}
```

### Environment Variables:

- `TERO_LOG_LEVEL` - Override log level (trace, debug, info, warn, err)

## Design Principles

1. **Data-Oriented Design** - Optimize for cache coherency and memory access
   patterns
2. **Lock-Free Reads** - Policy evaluation uses atomic snapshot pointers for
   zero-contention reads
3. **Fail-Open** - Errors in policy evaluation result in data passthrough, not
   drops
4. **Modular Composition** - Packages can be used independently or composed
   together
5. **Explicit Dependencies** - Each package declares its dependencies via
   imports
