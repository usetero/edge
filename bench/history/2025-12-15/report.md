# Tero Edge Benchmark Report

**Date:** 2025-12-15T15:44:37Z
**Requests per test:** 10
**Concurrent connections:** 50

## Results

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success | CPU % | Peak Mem MB |
|----------|------|------|---------|-------|----------|----------|---------|-------|-------------|
| Datadog Small | datadog | passthrough | 228 bytes | 4071 | 1.03 | 1.44 | 100% | 0 | 6.4 |
| Datadog Small | datadog | with-rules | 228 bytes | 3677 | 1.35 | 1.75 | 100% | 0 | 8.9 |
| Datadog Large | datadog | passthrough | 1129 bytes | 3295 | 1.54 | 1.95 | 100% | 0 | 6.5 |
| Datadog Large | datadog | with-rules | 1129 bytes | 3855 | 1.09 | 1.63 | 100% | 0 | 8.9 |
| Datadog 1MB | datadog | passthrough | 1473789 bytes | 152 | 44.9 | 64.27 | 100% | 0 | 6.5 |
| Datadog 1MB | datadog | with-rules | 1473789 bytes | 121 | 48.52 | 81.26 | 100% | 0 | 8.9 |
| OTLP Small | otlp | passthrough | 559 bytes | 3759 | 1.26 | 1.4 | 100% | 0 | 6.5 |
| OTLP Small | otlp | with-rules | 559 bytes | 3551 | 1.36 | 1.6 | 100% | 0 | 9.0 |
| OTLP Large | otlp | passthrough | 3177 bytes | 3810 | 1.14 | 1.54 | 100% | 0 | 6.6 |
| OTLP Large | otlp | with-rules | 3177 bytes | 3545 | 1.32 | 1.49 | 100% | 0 | 9.0 |
| OTLP 1MB | otlp | passthrough | 1624770 bytes | 112 | 56.03 | 87.33 | 100% | 0 | 27.6 |
| OTLP 1MB | otlp | with-rules | 1624770 bytes | 150 | 47.31 | 65 | 100% | 0 | 8.9 |
| Datadog Small | otelcol-datadog | passthrough | 228 bytes | 2088 | 1.32 | 1.89 | 100% | 0 | 175.9 |
| Datadog Small | otelcol-datadog | with-rules | 228 bytes | 4314 | 1.17 | 1.49 | 100% | 0 | 176.5 |
| Datadog Large | otelcol-datadog | passthrough | 1129 bytes | 4371 | 1.16 | 1.42 | 100% | 0 | 176.2 |
| Datadog Large | otelcol-datadog | with-rules | 1129 bytes | 3753 | 1.42 | 1.75 | 100% | 0 | 178.3 |
| Datadog 1MB | otelcol-datadog | passthrough | 1473789 bytes | 83 | 79.2 | 116.54 | 100% | 0 | 268.9 |
| Datadog 1MB | otelcol-datadog | with-rules | 1473789 bytes | 22 | 387.51 | 439.18 | 100% | 210.0 | 244.4 |
| OTLP Small | otelcol-otlp | passthrough | 559 bytes | 4699 | 0.84 | 1.11 | 100% | 0 | 175.2 |
| OTLP Small | otelcol-otlp | with-rules | 559 bytes | 4197 | 1.04 | 1.33 | 100% | 0 | 177.1 |
| OTLP Large | otelcol-otlp | passthrough | 3177 bytes | 4484 | 0.93 | 1.18 | 100% | 0 | 174.7 |
| OTLP Large | otelcol-otlp | with-rules | 3177 bytes | 4059 | 1.11 | 1.38 | 100% | 0 | 178.8 |
| OTLP 1MB | otelcol-otlp | passthrough | 1624770 bytes | 188 | 44.13 | 51.8 | 100% | 0 | 173.5 |
| OTLP 1MB | otelcol-otlp | with-rules | 1624770 bytes | 33 | 279.53 | 294.63 | 100% | 310.0 | 235.8 |
| Datadog Small | vector-datadog | passthrough | 228 bytes | 3913 | 1.23 | 1.45 | 100% | 0 | 71.7 |
| Datadog Small | vector-datadog | with-rules | 228 bytes | 4121 | 1.14 | 1.32 | 100% | 0 | 75.8 |
| Datadog Large | vector-datadog | passthrough | 1129 bytes | 4376 | 1.09 | 1.29 | 100% | 0 | 71.6 |
| Datadog Large | vector-datadog | with-rules | 1129 bytes | 4358 | 0.97 | 1.3 | 100% | 0 | 75.6 |
| Datadog 1MB | vector-datadog | passthrough | 1473789 bytes | 137 | 65.18 | 71.35 | 100% | 0 | 71.8 |
| Datadog 1MB | vector-datadog | with-rules | 1473789 bytes | 116 | 80.13 | 84.29 | 100% | 0 | 170.4 |
| OTLP Small | vector-otlp | passthrough | 559 bytes | 3611 | 1.3 | 1.82 | 100% | 0 | 71.5 |
| OTLP Small | vector-otlp | with-rules | 559 bytes | 3414 | 1.61 | 1.79 | 100% | 0 | 75.4 |
| OTLP Large | vector-otlp | passthrough | 3177 bytes | 2873 | 2.04 | 2.23 | 100% | 0 | 71.3 |
| OTLP Large | vector-otlp | with-rules | 3177 bytes | 2804 | 2.12 | 2.41 | 100% | 0 | 75.4 |
| OTLP 1MB | vector-otlp | passthrough | 1624770 bytes | 913 | 9.4 | 9.67 | 100% | 0 | 71.5 |
| OTLP 1MB | vector-otlp | with-rules | 1624770 bytes | 525 | 16.02 | 17.74 | 100% | 0 | 75.6 |

## Analysis

### Passthrough vs Rules Overhead
- **Datadog Small (datadog):** 10.0% throughput overhead, +0.32ms p50 latency
- **Datadog Large (datadog):** -10.0% throughput overhead, +-0.45ms p50 latency
- **Datadog 1MB (datadog):** 30.0% throughput overhead, +3.62ms p50 latency
- **OTLP Small (otlp):** 10.0% throughput overhead, +0.10ms p50 latency
- **OTLP Large (otlp):** 10.0% throughput overhead, +0.18ms p50 latency
- **OTLP 1MB (otlp):** -30.0% throughput overhead, +-8.72ms p50 latency
- **Datadog Small (otelcol-datadog):** -100.0% throughput overhead, +-0.15ms p50 latency
- **Datadog Large (otelcol-datadog):** 20.0% throughput overhead, +0.26ms p50 latency
- **Datadog 1MB (otelcol-datadog):** 80.0% throughput overhead, +308.31ms p50 latency
- **OTLP Small (otelcol-otlp):** 20.0% throughput overhead, +0.20ms p50 latency
- **OTLP Large (otelcol-otlp):** 10.0% throughput overhead, +0.18ms p50 latency
- **OTLP 1MB (otelcol-otlp):** 90.0% throughput overhead, +235.40ms p50 latency
- **Datadog Small (vector-datadog):** 0% throughput overhead, +-0.09ms p50 latency
- **Datadog Large (vector-datadog):** 10.0% throughput overhead, +-0.12ms p50 latency
- **Datadog 1MB (vector-datadog):** 20.0% throughput overhead, +14.95ms p50 latency
- **OTLP Small (vector-otlp):** 10.0% throughput overhead, +0.31ms p50 latency
- **OTLP Large (vector-otlp):** 10.0% throughput overhead, +0.08ms p50 latency
- **OTLP 1MB (vector-otlp):** 50.0% throughput overhead, +6.62ms p50 latency
