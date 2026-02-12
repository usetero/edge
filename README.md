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

4. **Prometheus proxy** - Sits as a sidecar next to your application, proxies
   `/metrics` scrapes with streaming policy-based metric filtering, and forwards
   filtered metrics to Prometheus.

## Repository Structure

```
src/
├── main.zig              # Default distribution entry point
├── datadog_main.zig      # Datadog-focused distribution entry point
├── otlp_main.zig         # OTLP-focused distribution entry point
├── prometheus_main.zig   # Prometheus-focused distribution entry point
├── lambda_main.zig       # AWS Lambda extension entry point
├── root.zig              # Library root (public API exports)
│
├── modules/              # Protocol-specific processing modules
├── proxy/                # HTTP proxy infrastructure
├── prometheus/           # Prometheus metric parsing and filtering
├── config/               # Configuration parsing (non-policy)
├── lambda/               # AWS Lambda extension support
└── zonfig/               # Comptime configuration with env overrides
```

## External Dependencies

Edge consumes the following shared modules from
[policy-zig](https://github.com/usetero/policy-zig):

- **`policy_zig`** - Policy engine, registry, matchers, transforms, and
  Hyperscan/Vectorscan bindings
- **`proto`** - Protobuf types (policy, common, OTLP
  logs/metrics/trace/resource)
- **`o11y`** - Observability (EventBus, structured logging, spans)

## Package Overview

Each package is designed to be as independent as possible, with clear interfaces
for integration.

### `modules/` - Protocol Modules

Protocol-specific request processing modules that plug into the proxy
infrastructure.

**Key exports:**

- `ProxyModule` - Vtable interface for request processing
- `ModuleRegistration` - Module configuration (routes, upstream, etc.)
- `DatadogModule` - Datadog log ingestion with policy-based filtering
- `OtlpModule` - OpenTelemetry log ingestion with policy-based filtering
- `PrometheusModule` - Prometheus metrics scraping with streaming policy-based
  filtering
- `PassthroughModule` - No-op passthrough for unhandled routes

**Dependencies:** `policy_zig`, `proto`, `o11y`

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

**Dependencies:** `o11y`, links to httpz

---

### `prometheus/` - Prometheus Metrics

Streaming Prometheus exposition format parsing and policy-based filtering.

**Key exports:**

- `PolicyStreamingFilter` - Streaming filter that applies policies to metrics
- `FilteringWriter` - Writer that filters metrics line-by-line
- `FieldAccessor` - Maps policy field references to Prometheus metric fields
- `LineParser` - Prometheus exposition format parser

**Dependencies:** `policy_zig`, `proto`, `o11y`

---

### `config/` - Configuration Parsing

Application configuration loading and parsing (non-policy configuration).

**Key exports:**

- `ProxyConfig` - Main proxy configuration struct
- `ProviderConfig` - Policy provider configuration (re-exported from policy-zig)
- `ServiceMetadata` - Service metadata (re-exported from policy-zig)

**Dependencies:** `policy_zig`

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

### Prometheus (`prometheus_main.zig`)

Focused distribution for Prometheus metrics scraping with streaming filtering:

- Proxies `/metrics` endpoint with policy-based metric filtering
- Streaming response processing (bounded memory regardless of response size)
- Configurable per-scrape limits (`max_input_bytes_per_scrape`,
  `max_output_bytes_per_scrape`)
- Filters metrics by name, labels, type, and other fields
- Zero-copy forwarding for metrics that pass policy checks
- Fail-open behavior (errors pass metrics through unchanged)
- Designed for sidecar deployment next to your application
- Lock-free policy updates via atomic snapshots
- Graceful shutdown with signal handling

Build: `zig build prometheus` Run: `zig build run-prometheus` or
`./zig-out/bin/edge-prometheus [config-file]`

### Lambda (`lambda_main.zig`)

AWS Lambda extension distribution for Datadog telemetry processing.

Build: `zig build lambda` Run: Deployed as a Lambda layer

## Building

```bash
# Build all targets
zig build

# Run tests
zig build test

# Build specific distribution
zig build edge        # Full distribution (Datadog + OTLP + Prometheus)
zig build datadog     # Datadog-only distribution
zig build otlp        # OTLP-only distribution
zig build prometheus  # Prometheus-only distribution
zig build lambda      # Lambda extension distribution

# Run specific distribution
zig build run-edge
zig build run-datadog
zig build run-otlp
zig build run-prometheus
```

## Installation

### Pre-built Binaries

Download the latest release for your platform from the
[Releases](../../releases) page:

| Platform                    | Binary              |
| --------------------------- | ------------------- |
| Linux x86_64                | `edge-linux-amd64`  |
| Linux ARM64                 | `edge-linux-arm64`  |
| macOS ARM64 (Apple Silicon) | `edge-darwin-arm64` |

For Datadog-only or OTLP-only distributions, use `edge-datadog-*` or
`edge-otlp-*` binaries.

```bash
# Download and run (example for Linux x86_64)
curl -LO https://github.com/<org>/edge/releases/latest/download/edge-linux-amd64
chmod +x edge-linux-amd64
./edge-linux-amd64 config.json
```

### Docker

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

Pre-built images are available from GitHub Container Registry:

```bash
# Pull the full distribution
docker pull ghcr.io/<org>/edge:latest

# Pull Datadog-only distribution
docker pull ghcr.io/<org>/edge-datadog:latest

# Pull OTLP-only distribution
docker pull ghcr.io/<org>/edge-otlp:latest
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
