# Tero Edge Benchmark Report

**Date:** 2026-01-02T21:53:38Z
**Requests per test:** 10000
**Concurrent connections:** 100

## Results

| Scenario | Type | Mode | Payload | Req/s | p50 (ms) | p99 (ms) | Success | CPU % | Peak Mem MB |
|----------|------|------|---------|-------|----------|----------|---------|-------|-------------|
| Datadog 1MB | datadog | with-rules | 1473789 bytes | 490 | 127.18 | 1136.9 | 100% | 1470.0 | 308.1 |
| OTLP 1MB | otlp | with-rules | 1624770 bytes | 616 | 112.26 | 725.51 | 100% | 1460.0 | 274.4 |

## Analysis

### Passthrough vs Rules Overhead
