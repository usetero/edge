# Policy Scaling Benchmark Report - otelcol

**Date:** 2026-01-03T04:29:06Z
**Requests per test:** 1000
**Concurrent connections:** 50
**Policy counts tested:** 0 10

## Results

| Binary | Telemetry | Policies | Payload | Req/s | p50 (ms) | p99 (ms) | Success % | CPU % | Mem MB | Echo Reqs |
|--------|-----------|----------|---------|-------|----------|----------|-----------|-------|--------|-----------|
| otelcol | OTLP Logs | 0 | 4081 | 43800 | 1.02 | 2.03 | 100 | 0 | 0 | 100 |
| otelcol | DD Logs | 0 | 2739 | 21771 | 1.63 | 3.55 | 100 | 0 | 0 | 100 |
| otelcol | OTLP Logs | 10 | 4081 | 42112 | 1.04 | 1.94 | 100 | 0 | 0 | 100 |
| otelcol | DD Logs | 10 | 2739 | 20594 | 1.8 | 3.68 | 100 | 0 | 0 | 100 |

## Verification

Echo server request counts should be close to 1000 for passthrough (0 policies).
With policies, counts may be lower due to drops/sampling.
