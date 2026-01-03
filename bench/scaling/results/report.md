# Policy Scaling Benchmark Report - Edge + otelcol

**Date:** 2026-01-03T04:14:20Z
**Requests per test:** 1000
**Concurrent connections:** 50
**Policy counts tested:** 0 10

## Results

| Binary | Telemetry | Policies | Payload | Req/s | p50 (ms) | p99 (ms) | Success % | CPU % | Mem MB | Echo Reqs |
|--------|-----------|----------|---------|-------|----------|----------|-----------|-------|--------|-----------|
| edge-otlp | OTLP Logs | 0 | 4081 | 31173 | 1.56 | 3.68 | 100 | 30.0 | 9.9 | 1000 |
| edge-otlp | OTLP Metrics | 0 | 3505 | 29472 | 1.51 | 4.2 | 100 | 30.0 | 8.7 | 1000 |
| edge-datadog | DD Logs | 0 | 2739 | 26350 | 1.67 | 4.46 | 100 | 70.0 | 9.9 | 1000 |
| edge-datadog | DD Metrics | 0 | 1863 | 28631 | 1.66 | 3.76 | 100 | 60.0 | 10.0 | 1000 |
| otelcol | OTLP Logs | 0 | 4081 | 42631 | 1.08 | 2.11 | 100 | 80.0 | 157.3 | 100 |
| otelcol | DD Logs | 0 | 2739 | 20444 | 1.75 | 3.94 | 100 | 80.0 | 154.6 | 100 |
| edge-otlp | OTLP Logs | 10 | 4081 | 30221 | 1.64 | 3.86 | 100 | 30.0 | 12.9 | 1000 |
| edge-otlp | OTLP Metrics | 10 | 3505 | 29763 | 1.57 | 3.54 | 100 | 30.0 | 11.9 | 1000 |
| edge-datadog | DD Logs | 10 | 2739 | 27580 | 1.64 | 3.88 | 100 | 70.0 | 13.2 | 1000 |
| edge-datadog | DD Metrics | 10 | 1863 | 26712 | 1.67 | 5.02 | 100 | 90.0 | 13.2 | 1000 |
| otelcol | OTLP Logs | 10 | 4081 | 43459 | 1.03 | 1.71 | 100 | 100.0 | 161.9 | 77 |
| otelcol | DD Logs | 10 | 2739 | 21484 | 1.81 | 3.49 | 100 | 110.0 | 155.4 | 77 |

## Verification

Echo server request counts should be close to 1000 for passthrough (0 policies).
With policies, counts may be lower due to drops/sampling.
