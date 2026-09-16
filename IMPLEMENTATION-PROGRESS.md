# Implementation progress

## Fault matrix suite for both frontends (`bench/matrix/`)

Goal: bubble up what a customer would hit, by injecting faults on both sides of
the edge — sender to edge, and edge to intake.

**Neither frontend is the oracle.** An early draft treated httpz as correct and
marked every stdio difference as acceptable, which hid four httpz defects. Each
case now asserts what a customer needs, and both frontends are judged against
it.

### Environment

- [x] Install `python3` through hermit (3.12.3, `bin/python3`).
- [x] Use `uv` (already in `bin/`) for the `requests` and `zstandard` dependencies.
- [x] Keep `oha` for load cases; it stays a brew dependency, as `bench/perf/run.sh` already assumes.

### Echo server: intake faults (`src/bench/echo_server.zig`)

- [x] `Fault` enum: status, hang, close_early, reject_early, reset, garbage, truncate, slow, oversize, stale_keepalive.
- [x] Arm over HTTP: `POST /fault?mode=&arg=&count=`, so a case can fault the first N requests only.
- [x] Report `fault`, `fault_arg` and `fault_applied` from `/stats`.
- [x] Faults apply to the echo path only, so `/stats` and `/fault` stay reachable.
- [x] Build, format and lint clean.

### Harness (`bench/matrix/harness/`)

- [x] `procs.py`: the fault-injecting intake and the edge binary, with logs and metrics.
- [x] `raw.py`: raw socket sender for malformed, partial and dribbling senders.
- [x] `case.py`: the `MatrixCase` base, per-class config and policies, and the invariants every case asserts.
- [x] `load.py`: `oha` wrapper.
- [x] `run.py`: builds both binaries, runs the suite per frontend, prints the table and the findings.
- [x] Declared defects report as `xfail` with their note, and as `XPASS` once fixed.
- [x] `README.md`.

### Cases: sender to edge

- [x] a01 idle connection, never sends.
- [x] a02 partial head, then stalls.
- [x] a03 `Content-Length` larger than the body sent.
- [x] a04 body drips one byte at a time.
- [x] a05 no `Content-Length` and no chunking.
- [x] a06 valid chunked body.
- [x] a07 invalid chunk size.
- [x] a08 body above `max_body_size`.
- [x] a09 corrupt gzip, with and without policies loaded.
- [x] a10 unsupported content encoding.
- [x] a11 client disconnects mid-body.
- [x] a12 pipelined requests.
- [x] a13 keep-alive reuse.
- [x] a14 more forward headers than the cap.
- [x] a15 garbage bytes, complete and incomplete.
- [x] a16 zstd batch, which is what a current Datadog agent sends. Passes on both frontends.

### Cases: edge to intake

- [x] b01 connection refused.
- [x] b02 intake never answers.
- [x] b03 intake answers slowly.
- [x] b04 intake closes mid-request.
- [x] b05 intake rejects on headers, before the body.
- [x] b06 status relay (429, 500, 503).
- [x] b07 response above the response cap.
- [x] b08 intake answers with garbage.
- [x] b09 stale pooled keep-alive.
- [x] b10 intake resets the connection.
- [x] b11 truncated response body.

### Cases: capacity

- [x] c01 shed above `max_connections`.
- [x] c02 health probe under a synchronised burst with a slow intake.
- [x] c03 idle socket flood.

## Findings

### Fixed while building the suite

1. **stdio never retried any batch.** Every body with a `Content-Length` was
   streamed, and a stream cannot be replayed, so one stale pooled connection
   lost the batch. Log intake clients do not retry, so this was silent data
   loss. Bodies below the streaming threshold are now resident, which is where
   httpz already drew the line. Caught by b04, b09 and b10.
2. **A header flood answered 502.** Our cap, the sender's fault, so it now
   answers 431. A 5xx sent the agent into a retry loop it could never win.
   Caught by a14.
3. **A retried dial was uncounted.** `edge_upstream_retries_total` missed the
   second dial, so a dial storm was invisible in metrics. Caught by b01.

### Open, both frontends

4. **An undecodable body is dropped when policies are loaded.** With a policy
   active, a body the decoder rejects never reaches the intake, though
   `service/datadog` documents fail-open. The edge becomes the reason the data
   disappears. Caught by a09.
5. **A truncated intake response is reported as success.** The intake declares
   more body than it sends; the edge relays what arrived and answers 202. An
   agent that reads 202 deletes its copy. Caught by b11.
6. **An unsupported content encoding drops the batch.** Intent is forward-raw.
   httpz answers 502 and blames the intake; stdio answers 400. Caught by a10.

### Open, httpz only

7. **A batch of up to 16 requests goes to one pool thread.** A health probe that
   arrives with a burst waited 6.0 s against a 3 s intake. This is the reported
   ECS failure. Caught by c02.
8. **Pipelined requests are refused** with 400. Caught by a12.
9. **Headers above the cap are dropped in silence**, and the request still
   answers 202. Caught by a14.
10. **A stalled sender gets no status**: partial head, short body and dribbled
    body all close with nothing. Caught by a02, a03, a04.

### Open, stdio only

11. **A broken chunk waits for the request deadline** instead of being refused
    at once, so bad framing holds a connection slot for 30 s. Caught by a07.
