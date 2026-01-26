# Lambda Extension Testing with AWS RIE

This directory contains test infrastructure for running the Tero Edge Lambda
extension locally using the AWS Lambda Runtime Interface Emulator (RIE).

## Prerequisites

- Docker with buildx support
- curl (for testing)

## Quick Start

### 1. Build the Layer

First, build and extract the Lambda layer files:

```bash
cd lambda

# Build and extract the layer (ARM64)
docker buildx build --platform linux/arm64 -f Dockerfile -o type=local,dest=.layers ..

# Or for x86_64
docker buildx build --platform linux/amd64 -f Dockerfile -o type=local,dest=.layers ..
```

This creates the layer structure in `.layers/`:

```
.layers/
  extensions/tero-edge    # Wrapper script (Lambda launches this)
  bin/tero-edge-bin       # Actual binary
  lib/                    # musl libraries
```

### 2. Run the Test Environment

```bash
# Start the Lambda test environment
docker compose up lambda-test
```

### 3. Invoke the Function

In another terminal:

```bash
# Invoke the Lambda function
curl -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
  -d '{"test": "event"}'
```

### 4. What to Expect

You should see logs showing:

1. The Tero Edge extension starting and registering with the Extensions API
2. The extension proxy server starting on port 3000
3. The test handler receiving the invocation
4. The handler sending test telemetry through the extension
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
│  │              AWS Lambda Python Runtime + RIE                 │   │
│  │  - Emulates Lambda Runtime API                               │   │
│  │  - Emulates Lambda Extensions API                            │   │
│  │  - Manages lifecycle (INVOKE, SHUTDOWN)                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                           │                                         │
│         ┌─────────────────┼─────────────────┐                      │
│         ▼                 ▼                 ▼                      │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐              │
│  │ test_handler│   │ tero-edge   │   │  /opt/ext   │              │
│  │   (Python)  │   │ (extension) │   │  directory  │              │
│  │             │   │             │   │             │              │
│  │ - Gets      │   │ - Registers │   │ Extensions  │              │
│  │   events    │   │   with RIE  │   │ discovered  │              │
│  │ - Sends     │──▶│ - Runs      │   │ here        │              │
│  │   telemetry │   │   proxy on  │   │             │              │
│  │   to :3000  │   │   :3000     │   │             │              │
│  └─────────────┘   └─────────────┘   └─────────────┘              │
│                           │                                         │
└───────────────────────────┼─────────────────────────────────────────┘
                            │
                            ▼
                    Datadog / Mock Upstream
```

## Environment Variables

| Variable             | Default | Description                                    |
| -------------------- | ------- | ---------------------------------------------- |
| `TERO_LISTEN_PORT`   | 3000    | Port for the proxy server                      |
| `TERO_UPSTREAM_URL`  | -       | Default upstream URL                           |
| `TERO_LOGS_URL`      | -       | Logs-specific URL (falls back to UPSTREAM_URL) |
| `TERO_METRICS_URL`   | -       | Metrics-specific URL                           |
| `TERO_LOG_LEVEL`     | info    | Log level (debug/info/warn/err)                |
| `TERO_POLICY_URL`    | -       | HTTP policy provider URL                       |
| `TERO_POLICY_STATIC` | -       | Static policy JSON string                      |

## Troubleshooting

### Extension not starting

Check that:

1. The layer was built and extracted: `ls -la .layers/extensions/`
2. The wrapper script exists: `cat .layers/extensions/tero-edge`
3. The binary exists: `ls -la .layers/bin/tero-edge-bin`

### Empty .layers directory

If `.layers/` exists but is empty, you need to rebuild:

```bash
rm -rf .layers
docker buildx build --platform linux/arm64 -f Dockerfile -o type=local,dest=.layers ..
```

### Connection refused to port 3000

The extension proxy may not have started yet. Check:

- Extension logs for errors
- That the layer files are properly mounted

### Build failures

If the Docker build fails:

- Ensure you have enough memory allocated to Docker (vectorscan needs ~2GB)
- Check that all Zig dependencies are available

## Files

| File                 | Description                                   |
| -------------------- | --------------------------------------------- |
| `Dockerfile`         | Builds the Lambda layer with the extension    |
| `docker-compose.yml` | Test environment configuration                |
| `test_handler.py`    | Simple Python handler for testing             |
| `template.yaml`      | CloudFormation template for Datadog Forwarder |
