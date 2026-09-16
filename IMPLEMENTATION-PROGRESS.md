# Implementation progress

## Fault matrix suite for the stdio frontend (`bench/matrix/`)

Goal: bubble up what a customer would hit, by injecting faults on both sides of
the edge — sender to edge, and edge to intake — and running every case against
both frontends so httpz acts as the oracle.

### Environment

- [x] Install `python3` through hermit (3.12.3, `bin/python3`).
- [x] Use `uv` (already in `bin/`) for the `requests` dependency.
- [x] Keep `oha` for load cases; it stays a brew dependency, as `bench/perf/run.sh` already assumes.

### Echo server: intake faults (`src/bench/echo_server.zig`)

- [x] `Fault` enum: status, hang, close_early, reject_early, reset, garbage, truncate, slow, oversize, stale_keepalive.
- [x] Arm over HTTP: `POST /fault?mode=&arg=&count=`, so a test can fault the first N requests only.
- [x] Report `fault`, `fault_arg` and `fault_applied` from `/stats`, so a test can assert the fault fired.
- [x] Faults apply to the echo path only, so `/stats` and `/fault` stay reachable.
- [x] Build, format and lint clean.

### Harness (`bench/matrix/harness/`)

- [ ] `echo.py`: start the echo server, arm faults, read stats.
- [ ] `edge.py`: write a config, start the edge binary, wait for health, scrape metrics, read logs.
- [ ] `case.py`: the shared `MatrixCase` base, with per-class config, helpers and the invariants every case asserts.
- [ ] `raw.py`: raw socket client for malformed and stalled senders.
- [ ] `load.py`: `oha` wrapper that returns rps and percentiles.
- [ ] `run.py`: build both binaries, run the suite per frontend, print the disagreements.

### Cases: sender to edge (`bench/matrix/tests/`)

- [ ] a01 idle connection, never sends.
- [ ] a02 partial head, then stalls.
- [ ] a03 `Content-Length` larger than the body sent.
- [ ] a04 body drips one byte at a time.
- [ ] a05 no `Content-Length` and no chunking.
- [ ] a06 valid chunked body.
- [ ] a07 invalid chunk size.
- [ ] a08 body above `max_body_size`.
- [ ] a09 corrupt gzip body.
- [ ] a10 unsupported content encoding.
- [ ] a11 client disconnects mid-body.
- [ ] a12 pipelined requests.
- [ ] a13 keep-alive reuse.
- [ ] a14 more forward headers than the cap.
- [ ] a15 garbage bytes instead of a request.

### Cases: edge to intake

- [ ] b01 connection refused.
- [ ] b02 intake never answers.
- [ ] b03 intake answers slowly.
- [ ] b04 intake closes mid-request.
- [ ] b05 intake rejects on headers, before the body (the reported signature).
- [ ] b06 intake status relay (429, 500, 503).
- [ ] b07 response above the response cap.
- [ ] b08 intake answers with garbage.
- [ ] b09 stale pooled keep-alive.
- [ ] b10 intake resets the connection.
- [ ] b11 truncated response body.

### Cases: capacity

- [ ] c01 shed above `max_connections`.
- [ ] c02 health probe under a burst with a slow intake.
- [ ] c03 idle socket flood.

### Findings

Recorded as each case runs. A case that reveals a product defect keeps its
finding next to it here rather than being quietly marked green.
