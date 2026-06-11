# Bench: old (httpz) stack vs new (std.Io) stack

Scenario: the user's exact repro — `edge-otlp` + `bench/scaling/configs/generated/edge-otlp-1.json`
(max_body 4 MiB), `oha -c 150` POSTing `bench/scaling/payloads/otlp-metrics.pb`
(protobuf → streaming pipe_stream route, policy eval per ResourceMetrics record),
15s runs, ReleaseFast, macOS, upstream = the OLD (httpz) echo-server for both
sides so only the proxy differs. Old stack built from dba3aaf in a worktree.

| | old (httpz) | new (std.Io) |
|---|---|---|
| Requests/sec | 53,588 | **66,202 (+24%)** |
| p50 | 1.98 ms | 2.26 ms |
| p90 | 5.49 ms | **2.46 ms** |
| p99 | 12.48 ms | **2.70 ms (4.6x tighter)** |
| Success | 100% | 100% |
| RSS under load | 12.4 MiB | 121 MiB (touched slab decode regions; load-proportional, bounded by DataPlaneBudget) |

## Fixes found by this bench (the user's 8.61%-success run)
1. Upstream-open failures closed the client socket without a response →
   reconnect storm. Now answered with 502 (parity with the old stack).
2. Kernel listen backlog was std's default 128 on both edge and echo →
   "connection refused" avalanche under churn. Raised to 1024.
3. ROOT CAUSE of the 502s themselves: std.http.Client's connection pool
   keeps only 32 idle connections (free_size default). At c=150 every
   release beyond 32 destroyed the socket; each round redialed ~118
   connections until ephemeral ports ran out (error.AddressUnavailable).
   Pool now sized to limits.max_connections.

## Caveats
- The NEW echo-server (rewritten on std.Io thread-per-conn) tops out around
  ~27k rps as an upstream and was the bottleneck in early runs; use the old
  httpz echo binary for proxy benchmarks until it gets the same treatment.
- Numbers are single-machine loopback; relative deltas matter, absolutes don't.
