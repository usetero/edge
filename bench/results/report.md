# Tero Edge Benchmark Report

**Date:** 2025-12-11T03:08:54Z
**Requests per test:** 10000
**Concurrent connections:** 150

## Results

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success |
|----------|------|------|---------|-------|----------|----------|---------|
| Datadog Small | datadog | passthrough | 153 bytes | 39541 | 2.32 | 20.64 | 100% |
| Datadog Small | datadog | with-rules | 153 bytes | 37445 | 2.7 | 17.67 | 100% |
| Datadog Large | datadog | passthrough | 1236 bytes | 33861 | 2.77 | 27.65 | 100% |
| Datadog Large | datadog | with-rules | 1236 bytes | 36751 | 2.65 | 18.28 | 100% |
| Datadog 1MB | datadog | passthrough | 1555891 bytes | 1486 | 74.53 | 347.01 | 100% |
| Datadog 1MB | datadog | with-rules | 1555891 bytes | 1042 | 74.21 | 585.75 | 100% |
| OTLP Small | otlp | passthrough | 250 bytes | 37421 | 2.3 | 21.34 | 100% |
| OTLP Small | otlp | with-rules | 250 bytes | 36642 | 2.82 | 17.61 | 100% |
| OTLP Large | otlp | passthrough | 1802 bytes | 31975 | 3.35 | 20.8 | 100% |
| OTLP Large | otlp | with-rules | 1802 bytes | 32985 | 3.2 | 25.64 | 100% |
| OTLP 1MB | otlp | passthrough | 1847231 bytes | 3201 | 41.34 | 73.89 | 100% |
| OTLP 1MB | otlp | with-rules | 1847231 bytes | 3097 | 42.72 | 83.88 | 100% |

## Analysis

### Passthrough vs Rules Overhead
- **Datadog Small (datadog):** 10.0% throughput overhead, +0.38ms p50 latency
- **Datadog Large (datadog):** 0% throughput overhead, +-0.12ms p50 latency
- **Datadog 1MB (datadog):** 30.0% throughput overhead, +-0.32ms p50 latency
- **OTLP Small (otlp):** 10.0% throughput overhead, +0.52ms p50 latency
- **OTLP Large (otlp):** 0% throughput overhead, +-0.15ms p50 latency
- **OTLP 1MB (otlp):** 10.0% throughput overhead, +1.38ms p50 latency
