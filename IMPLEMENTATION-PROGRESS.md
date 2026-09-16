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
- [x] Declarative telemetry: `EXPECT_METRICS`, `EXPECT_METRICS_FOR`, `EXPECT_LOGS`,
      `EXPECT_LOGS_FOR`, `FORBID_LOGS`, asserted for every case by the base class.
- [x] Universal pairing rule: a counter that moved must be explainable from the
      log (`METRIC_NEEDS_LOG`), so a case that declares nothing still cannot
      pass with silent telemetry.
- [x] 24 of 31 case files declare telemetry; the rest are covered by the
      pairing rule alone. Verified by breaking one expectation on purpose.

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

## Harness defects found while adding the telemetry assertions

These were mine, not the product's, and each one had produced a false finding
before it was fixed:

- Both edge streams were captured into one file. The edge writes INFO and WARN
  to stdout and ERROR to stderr through independent buffers, so the single file
  interleaved and cut lines in half. `request.failed` appeared at byte 0, ahead
  of the startup lines. Fixed by capturing the streams separately.
- Case-scoped logs were sliced by byte offset, which assumes one append-ordered
  file. Now diffed by line.
- Log assertions read once, so a line that arrived just after the response read
  as missing. Now they poll, and the forbidden-line check settles first.
- The invariant "every 5xx must leave a log line" was wrong: a 5xx relayed from
  the intake is not our failure and owes no log. Replaced by the pairing rule,
  which only covers errors we produce ourselves.
- `FORBID_LOGS = ["upstream"]` matched the startup line `upstream.configured`,
  which the case-scoped diff now excludes.

## Findings

### Fixed

1. **stdio never retried any batch.** Every body with a `Content-Length` was
   streamed, and a stream cannot be replayed, so one stale pooled connection
   lost the batch. Log intake clients do not retry, so this was silent data
   loss. Bodies below the streaming threshold are resident now, which is where
   httpz already drew the line. Caught by b04, b09, b10.
2. **A header flood answered 502.** Our cap, the sender's fault, so it answers
   431. Caught by a14.
3. **A retried dial was uncounted**, so a dial storm was invisible in
   `edge_upstream_retries_total`. Caught by b01.
4. **The streamed policy path dropped a body it could not decode.** With a
   policy loaded, an undecodable batch never reached the intake, though
   `execPipeBuffered` already failed open for the same condition. It now
   forwards the raw batch, emits `policy.failed.open` with the stage, and
   counts a module error. Caught by a09.
5. **A truncated intake response was reported as 202.** The relay compares the
   bytes copied against the declared `content-length` and fails with
   `UpstreamResponseTruncated`, so the frontend closes without finishing the
   body and the sender retries instead of recording a success. Caught by b11.
6. **httpz dropped headers above its own cap in silence.** Its default
   `max_header_count` is 32, below our 64-header forward cap, so a request
   with more headers was forwarded incomplete and answered 202. The httpz
   config now sits above our cap, and `MAX_FORWARD_HEADERS` in limits.zig is
   the single source of truth. Caught by a14.

### Corrected findings

- **httpz does not mishandle an unsupported encoding.** The 502 came from our
  own `std.http.Server` based echo intake refusing brotli. Verified against a
  lenient intake: httpz forwards the batch and relays 200. The earlier entry
  blaming httpz was wrong.
- **httpz does cut off a dribbling sender.** Its request timeout runs from
  accept, not per read, so a small dribbled body is caught. The per-read
  restart only applies to a body above `lazy_read_size`. The declared defect
  was removed after the runner reported XPASS.

### Open: needs a change in a dependency

- **httpz hands a batch of up to 16 requests to one pool thread** (c02). A
  health probe that arrives with a burst waited 3.0 to 6.0 s against a 3 s
  intake. This is the reported ECS failure. Fix: one shared queue in
  `thread_pool.zig`, plus a `received_at` stamp for a queue-wait metric.
- **httpz refuses a pipelined pair** with 400 (a12). Fix: after
  `requestDone`, parse the bytes already buffered as the next request.
- **httpz closes a stalled sender with no status** (a02, a03). Fix: answer 408
  before closing, and add a whole-request deadline.
- **stdio cannot accept an unknown content encoding** (a10).
  `std.http.Server` maps `content-encoding` through `ContentEncoding.fromString`
  and fails the whole head with `HttpHeadersInvalid` for anything else, with no
  distinct error to match on. An agent using brotli gets 400 and retries
  forever. Fix: accept unknown encodings as opaque in std, or parse the head
  ourselves.
- **stdio waits for the request deadline on a broken chunk** (a07), so bad
  framing holds a connection slot for 30 s. httpz refuses it at once. Fix:
  std's chunked parser must error on an invalid size line.
