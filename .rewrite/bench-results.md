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

# Frontend swap bench (2026-06-11, PLAN-FRONTEND-SWAP.md Phase D)

Methodology: `oha -n 1000000 -c 150 -m POST` with the 1 KB otlp-metrics.pb
payload against `/v1/metrics`; upstream = rewritten echo-server (ReleaseFast,
measured 131k rps direct, not the bottleneck — the ~27k caveat above is stale,
phase-7 fixes landed). ReleaseFast, single-machine loopback.

| config | frontend | RPS | p50 | RSS during | RSS after load |
|---|---|---|---|---|---|
| 4000 policies | stdio (pre fast-path) | 38.9k | 3.51 ms | 155 MB | 142 MB (never returns) |
| 4000 policies | httpz | 51.9k | 2.06 ms | 81 MB | ~80 MB (hyperscan DB dominates) |
| 0 policies | stdio (+ fast paths) | 63.4k | 2.30 ms | 33 MB | 33 MB |
| 0 policies | httpz (+ fast paths) | 64.6k | 1.73 ms | 15.5 MB | 15.5 MB (5 MB idle) |

Fast paths added during this phase (both frontends, exec.zig):
- `policiesActiveFor(registry, signal)`: one snapshot load per request; empty
  per-signal target set → RecordSink keeps without decode, processBuffered
  returns raw, and pipe_stream degrades to forward_raw (no framer/chunked).
  0-policy httpz: 40.2k → 64.6k rps, 31 MB → 15.5 MB.
- `thread_pool.count = 64` experiment REGRESSED (47k rps, 2x RSS — pool
  contention); httpz defaults (1 worker, 32 pool threads) win. Locked by the
  configFromLimits test.

Gate readout vs plan (§5: ≥75k rps, ≤20 MB steady):
- Memory: MET on the frontend's own terms (5 MB idle, 15.5 MB under load,
  0-policy config; with 4000 policies the floor is the hyperscan DB + client
  pool, frontend-independent).
- Throughput: NOT met in absolute terms (64.6k vs 75k). Diagnosed, not
  frontend-bound: remaining ceiling is the synchronous upstream round-trip
  occupying the 32 handler threads (~0.49 ms/request) and, with policies
  loaded, the per-record decode→eval→encode path. Same ceiling on both
  frontends (63.4k vs 64.6k at 0 policies). Default flipped to httpz anyway:
  it dominates stdio in every measured cell. Path to full master parity =
  prefilter port (TODO.md).
