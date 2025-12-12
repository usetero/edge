# Tero Edge Benchmark Report

**Date:** 2025-12-12T16:01:08Z
**Requests per test:** 10000
**Concurrent connections:** 50

## Results

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success | CPU % | Peak Mem MB |
|----------|------|------|---------|-------|----------|----------|---------|-------|-------------|
| Datadog Small | datadog | passthrough | 228 bytes | 76473 | 0.48 | 2.62 | 100% | 90.0 | 8.1 |
| Datadog Small | datadog | with-rules | 228 bytes | 77888 | 0.47 | 2.6 | 100% | 100.0 | 10.3 |
| Datadog Large | datadog | passthrough | 1129 bytes | 76640 | 0.47 | 2.25 | 100% | 110.0 | 8.3 |
| Datadog Large | datadog | with-rules | 1129 bytes | 74903 | 0.48 | 2.52 | 100% | 110.0 | 10.6 |
| Datadog 1MB | datadog | passthrough | 1473789 bytes | 1814 | 20.7 | 109.28 | 100% | 1160.0 | 214.4 |
| Datadog 1MB | datadog | with-rules | 1473789 bytes | 818 | 45.68 | 256.62 | 100% | 1310.0 | 286.7 |
| OTLP Small | otlp | passthrough | 559 bytes | 76751 | 0.48 | 2.42 | 100% | 100.0 | 8.3 |
| OTLP Small | otlp | with-rules | 559 bytes | 79059 | 0.46 | 2.59 | 100% | 130.0 | 10.5 |
| OTLP Large | otlp | passthrough | 3177 bytes | 77809 | 0.5 | 2.24 | 100% | 130.0 | 8.5 |
| OTLP Large | otlp | with-rules | 3177 bytes | 76236 | 0.47 | 2.28 | 100% | 120.0 | 10.7 |
| OTLP 1MB | otlp | passthrough | 1624770 bytes | 1660 | 22.51 | 121.94 | 100% | 1130.0 | 189.2 |
| OTLP 1MB | otlp | with-rules | 1624770 bytes | 891 | 41.64 | 247.65 | 100% | 1260.0 | 189.1 |
| Datadog Small | otelcol-datadog | passthrough | 228 bytes | 34234 | 1.3 | 4.27 | 100% | 170.0 | 195.0 |
| Datadog Small | otelcol-datadog | with-rules | 228 bytes | 32956 | 1.38 | 3.73 | 100% | 200.0 | 194.2 |
| Datadog Large | otelcol-datadog | passthrough | 1129 bytes | 33457 | 1.37 | 3.69 | 100% | 200.0 | 220.4 |
| Datadog Large | otelcol-datadog | with-rules | 1129 bytes | 31285 | 1.42 | 4.26 | 100% | 240.0 | 217.5 |
| Datadog 1MB | otelcol-datadog | passthrough | 1473789 bytes | 926 | 43.38 | 209.67 | 100% | 1300.0 | 22022.1 |
| Datadog 1MB | otelcol-datadog | with-rules | 1473789 bytes | 262 | 181.36 | 375.87 | 100% | 1360.0 | 22061.0 |
| OTLP Small | otelcol-otlp | passthrough | 559 bytes | 126196 | 0.3 | 1.31 | 100% | 220.0 | 190.0 |
| OTLP Small | otelcol-otlp | with-rules | 559 bytes | 127000 | 0.31 | 1.25 | 100% | 230.0 | 197.8 |
| OTLP Large | otelcol-otlp | passthrough | 3177 bytes | 111722 | 0.35 | 1.61 | 100% | 250.0 | 216.4 |
| OTLP Large | otelcol-otlp | with-rules | 3177 bytes | 107747 | 0.41 | 1.42 | 100% | 290.0 | 230.7 |
| OTLP 1MB | otelcol-otlp | passthrough | 1624770 bytes | 1325 | 31.81 | 123.78 | 100% | 1130.0 | 1281.9 |
| OTLP 1MB | otelcol-otlp | with-rules | 1624770 bytes | 367 | 95.76 | 507.19 | 100% | 1310.0 | 1251.4 |
| Datadog Small | vector-datadog | passthrough | 228 bytes | 124150 | 0.28 | 1.49 | 100% | 150.0 | 74.3 |
| Datadog Small | vector-datadog | with-rules | 228 bytes | 130396 | 0.31 | 0.83 | 100% | 160.0 | 77.2 |
| Datadog Large | vector-datadog | passthrough | 1129 bytes | 131322 | 0.29 | 1.28 | 100% | 170.0 | 88.8 |
| Datadog Large | vector-datadog | with-rules | 1129 bytes | 130419 | 0.29 | 1.42 | 100% | 200.0 | 93.0 |
| Datadog 1MB | vector-datadog | passthrough | 1473789 bytes | 443 | 110.95 | 148.57 | 100% | 1140.0 | 913.1 |
| Datadog 1MB | vector-datadog | with-rules | 1473789 bytes | 433 | 115.39 | 131.19 | 100% | 1270.0 | 878.5 |
| OTLP Small | vector-otlp | passthrough | 559 bytes | 88128 | 0.53 | 1.17 | 100% | 490.0 | 251.8 |
| OTLP Small | vector-otlp | with-rules | 559 bytes | 75952 | 0.61 | 1.52 | 100% | 460.0 | 283.2 |
| OTLP Large | vector-otlp | passthrough | 3177 bytes | 121 | 1.64 | 3.33 | 100% | 0 | 314.9 |
| OTLP Large | vector-otlp | with-rules | 3177 bytes | 690 | 1.95 | 3079.29 | 100% | 30.0 | 405.4 |
| OTLP 1MB | vector-otlp | passthrough | 1624770 bytes | 7059 | 6.9 | 13.06 | 100% | 340.0 | 16269.4 |
| OTLP 1MB | vector-otlp | with-rules | 1624770 bytes | 5660 | 6.73 | 32.37 | 100% | 710.0 | 15487.9 |

## Analysis

### Passthrough vs Rules Overhead
- **Datadog Small (datadog):** 0% throughput overhead, +-0.01ms p50 latency
- **Datadog Large (datadog):** 10.0% throughput overhead, +0.01ms p50 latency
- **Datadog 1MB (datadog):** 60.0% throughput overhead, +24.98ms p50 latency
- **OTLP Small (otlp):** 0% throughput overhead, +-0.02ms p50 latency
- **OTLP Large (otlp):** 10.0% throughput overhead, +-0.03ms p50 latency
- **OTLP 1MB (otlp):** 50.0% throughput overhead, +19.13ms p50 latency
- **Datadog Small (otelcol-datadog):** 10.0% throughput overhead, +0.08ms p50 latency
- **Datadog Large (otelcol-datadog):** 10.0% throughput overhead, +0.05ms p50 latency
- **Datadog 1MB (otelcol-datadog):** 80.0% throughput overhead, +137.98ms p50 latency
- **OTLP Small (otelcol-otlp):** 0% throughput overhead, +0.01ms p50 latency
- **OTLP Large (otelcol-otlp):** 10.0% throughput overhead, +0.06ms p50 latency
- **OTLP 1MB (otelcol-otlp):** 80.0% throughput overhead, +63.95ms p50 latency
- **Datadog Small (vector-datadog):** 0% throughput overhead, +0.03ms p50 latency
- **Datadog Large (vector-datadog):** 10.0% throughput overhead, +0.00ms p50 latency
- **Datadog 1MB (vector-datadog):** 10.0% throughput overhead, +4.44ms p50 latency
- **OTLP Small (vector-otlp):** 20.0% throughput overhead, +0.08ms p50 latency
- **OTLP Large (vector-otlp):** -470.0% throughput overhead, +0.31ms p50 latency
- **OTLP 1MB (vector-otlp):** 20.0% throughput overhead, +-0.17ms p50 latency
