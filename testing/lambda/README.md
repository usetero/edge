# Lambda Extension Testing with AWS RIE

This directory contains test infrastructure for running the Tero Edge Lambda
extension locally using the AWS Lambda Runtime Interface Emulator (RIE).

## Prerequisites

- Docker with ARM64 support (Docker Desktop on Apple Silicon)
- curl (for testing)

## Quick Start

### 1. Build and Run

```bash
cd src/testing/lambda

# Build the Docker image (compiles Zig inside container)
docker compose build

# Start the Lambda environment
docker compose up
```

### 2. Invoke the Function

In another terminal:

```bash
# Invoke the Lambda function
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
  -d '{"test": "event"}'
```

### 3. What to Expect

You should see logs showing:

1. The Tero Edge extension starting and registering with the Extensions API
2. The extension proxy server starting on port 8080
3. The bootstrap handler receiving the invocation
4. The bootstrap sending test telemetry through the extension
5. The extension processing and forwarding the telemetry

## Testing with Mock Upstream

To test without sending data to real Datadog:

```bash
# Start with mock upstream
docker compose --profile mock up

# Update extension config to use mock
# Set TERO_UPSTREAM_URL=http://mock-upstream:80
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Docker Container                                 │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   AWS Lambda RIE                             │   │
│  │  - Emulates Lambda Runtime API                               │   │
│  │  - Emulates Lambda Extensions API                            │   │
│  │  - Manages lifecycle (INVOKE, SHUTDOWN)                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                           │                                         │
│         ┌─────────────────┼─────────────────┐                      │
│         ▼                 ▼                 ▼                      │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│  │  bootstrap  │   │ tero-edge   │   │  /opt/ext   │              │
│  │  (handler)  │   │ (extension) │   │  directory  │              │
│  │             │   │             │   │             │              │
│  │ - Gets      │   │ - Registers │   │ Extensions  │              │
│  │   events    │   │   with RIE  │   │ discovered  │              │
│  │ - Sends     │──▶│ - Runs      │   │ here        │              │
│  │   telemetry │   │   proxy on  │   │             │              │
│  │   to :8080  │   │   :8080     │   │             │              │
│  └─────────────┘   └─────────────┘   └─────────────┘              │
│                           │                                         │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
                            ▼
                    Datadog / Mock Upstream
```

## Environment Variables

| Variable            | Default | Description                                    |
| ------------------- | ------- | ---------------------------------------------- |
| `TERO_LISTEN_PORT`  | 8080    | Port for the proxy server                      |
| `TERO_UPSTREAM_URL` | -       | Default upstream URL                           |
| `TERO_LOGS_URL`     | -       | Logs-specific URL (falls back to UPSTREAM_URL) |
| `TERO_METRICS_URL`  | -       | Metrics-specific URL                           |
| `TERO_LOG_LEVEL`    | info    | Log level (debug/info/warn/err)                |
| `TERO_POLICY_URL`   | -       | HTTP policy provider URL                       |

## Troubleshooting

### Extension not starting

Check that:

- The binary is at `/opt/extensions/tero-edge`
- The binary has execute permissions
- Logs show "Registering extension" messages

### Connection refused to port 8080

The extension proxy may not have started yet. Check:

- Extension logs for errors
- That `TERO_LISTEN_PORT` matches what bootstrap is using

### Build failures

If the Docker build fails:

- Ensure you have enough memory allocated to Docker (vectorscan needs ~2GB)
- Check that all Zig dependencies are available
