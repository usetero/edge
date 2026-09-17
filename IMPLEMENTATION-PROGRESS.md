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

## Backlog triage (BACKLOG.md)

Fourteen cases taken from the backlog, in three groups:

- **Verified first, then written:** a22 health methods, a30 the streaming
  threshold, b11b the truncation challenge. Two backlog claims did not
  reproduce as written and were corrected before the case was added.
- **Written as specified:** a19 framing conflicts, a35 decompression bomb,
  b12 dial blackhole, b23 duplicate delivery, b24 retry amplification,
  c04 hung-intake saturation, c05 health at capacity, c09 log back-pressure,
  d01 to d03 SIGTERM behaviour.
- **Skipped, with reasons in the review:** the framer and OTLP torture cases
  belong in the Zig unit tests, the idle-close race is nondeterministic, and
  the soak and tiny-profile modes are runner projects.

Three universal invariants came with them, and each one caught something the
per-case assertions missed: no phantom success, in-flight back to zero, and
descriptors back to baseline.

## The two challenges, settled with tests

1. **"Log intake clients do not retry" is wrong.** From the agent's own
   source, `comp/logs-library/client/http/destination.go`: 400, 401, 403 and
   413 increment `payloads_dropped` and are never resent; every other error
   status and every transport failure becomes a `RetryableError` with
   exponential backoff. Encoded in `bench/matrix/harness/agent.py` and asserted
   as an invariant: answering a drop-class status for a batch the intake never
   received is permanent data loss. This raises the severity of our 4xx
   choices and lowers it for our 5xx choices.
2. **The b11 note was half right.** Two cases now separate the halves. When the
   intake truncates *before* reading the body it received nothing, so our 502
   and the agent's retry repair it. When it reads the whole batch and *then*
   truncates, the batch is already in, and our 502 makes the agent deliver a
   second copy, measured at exactly two. The fix worth making is to relay the
   2xx when we know the body was fully sent, and count the truncation.

## Findings

### Fixed

1. **stdio never retried any batch.** Bodies below the streaming threshold are
   resident now. Caught by b04, b09, b10.
2. **A header flood answered 502**, now 431. Caught by a14. The agent retries
   both, so this is about diagnosis rather than agent behaviour.
3. **A retried dial was uncounted.** Caught by b01.
4. **The streamed policy path dropped a body it could not decode**, which the
   agent would have discarded for good on the 400. It fails open now, with
   `policy.failed.open`. Caught by a09.
5. **A truncated intake response was reported as 202.** Now
   `UpstreamResponseTruncated`. See the challenge above for the nuance.
6. **httpz dropped headers above its own cap in silence.** Caught by a14.

### From the backlog cases: fixed

7. **`/_health` was GET-only, so every other method reached Datadog.** An ALB
   or ECS check configured for HEAD tested the intake, not the edge, and
   failed whenever the intake was unreachable. The route claims every method
   now: 200 for GET and HEAD, 405 for the rest. `/_edge/*` had the same hole
   and got the same treatment. Both frontends. (a22)
8. **stdio took 30 s to shut down with idle keep-alive connections**, against
   httpz's 2 s, because cancellation does not reach a task parked in a poll,
   so each connection waited out its own idle deadline. The slab now records
   the socket per slot and `stopAccepting` interrupts them all, the same way
   the upstream watchdog already did. Exit is under 2 s. (d03)
9. **A body that expanded past the decoded cap answered 413**, which the agent
   discards for good. The two size limits are split now: the raw cap stays
   413, because the sender can act on it, and a decoded-size overrun fails
   open, because the sender cannot see our decode budget. (a35)
10. **Control paths were labelled by method, so a HEAD health probe counted as
    data traffic** in `edge_responses_total`. Found by the phantom-success
    invariant while checking the fix for 7. `/_health` and `/_edge/*` are
    labelled by path now.

### From the backlog cases: documented, not fixed

11. **A batch above the streaming threshold cannot be replayed**, so an intake
    blip mid-exchange ends it with a 502. Deliberate: the agent retries a 5xx
    with backoff, so the cost is a delay and a duplicate risk, not loss.
    Making every batch replayable costs one `max_body_size` buffer per
    concurrent request, which policy deployments already pay and passthrough
    deployments do not. Recorded at the decision in `stdio/conn.zig` and in
    the a30 case. Exposing the threshold as configuration is the follow-up.

### From the backlog cases: still open

12. **stdio forwards an absolute-form target upstream** as a path; httpz
    refuses it with 400. (a22)
13. **Health is shed at capacity** rather than reserved, which restarts the
    sidecar during the spike that filled it. (c05)

### Open: needs a change in a dependency

- httpz hands a batch of up to 16 requests to one pool thread (c02).
- httpz refuses a pipelined pair (a12).
- httpz closes a stalled sender with no status (a02, a03).
- stdio cannot accept an unknown content encoding, because `std.http.Server`
  fails the whole head (a10). The agent drops the batch for good on that 400.
- stdio waits for the request deadline on a broken chunk (a07).
