# Lab notebook

What the fault matrix found, what we changed because of it, and what is still
open. Kept next to the suite, because every entry here points at a case in
`tests/`. `README.md` lists the cases; this file records the reasoning.

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

## Scope: remaining matrix cases and stdio fixes

### Fixes we can make ourselves

| Item | What | Effort |
|---|---|---|
| a22 absolute-form | Accept `GET http://host/path` and route on the path, per RFC 9112 §3.2.2, instead of forwarding the whole URL upstream as a path. stdio only | S |
| c05 health at capacity | Reserve a small number of slab slots that are handed out only after a normal claim fails, and serve those connections without keep-alive. A probe then answers during the spike that filled the slab, instead of being shed and restarting the sidecar | M |

### Fixes that need a change outside our tree

| Item | Why it is blocked | What the fix looks like |
|---|---|---|
| b12 dial deadline (both frontends) | `std.http.Client.ConnectTcpOptions` **declares** `timeout` and never passes it to `host.connect`, and `Connection.Plain.create` is private, so we cannot build a connection with our own bounded dial | One line in std to forward the timeout, plus a `timeout` on `RequestOptions`. Worth an upstream patch; we carry a circuit breaker only if that stalls |
| a10 unknown content encoding (stdio) | `std.http.Server` maps `content-encoding` through `ContentEncoding.fromString` and fails the whole head with `HttpHeadersInvalid`, with no distinct error to match on | std should carry an unknown encoding as opaque. Byte-rewriting the header in our own buffer is not worth it for an encoding no agent sends |
| a07 broken chunk (stdio) | std's chunked reader waits for a valid size line rather than erroring, so only the request deadline bounds it | std should reject an invalid chunk size |
| a30 streaming threshold | Deliberate. Documented at the decision | Expose the threshold as configuration |
| httpz dispatch, pipelining, stalled-sender status | Inside httpz | The fork series already scoped |

### Cases still to write

Ingress: a17 oversize head, a18 chunked above the cap, a20 Expect 100-continue,
a23 resync after a local error, a25 half-close, a26 RST mid-body, a27 vanish
after forward, a34 encoding spellings (reduced), a36 gzip with two members,
a37 record above the scratch cap, a39 unframeable JSON, a41 policy drop-all.

Egress: b14 keep-alive off, b15 HTTP/1.0 read-until-close, b16 bodiless
statuses, b17 response header flood, b18 slow-drip response, b19 slow-reading
intake, b20 accept then silence, b21 early rejection of a streamed body,
b22 intake restart, b25 redirect, b26 base path and query fidelity, b28 slow
dial warning, b29 scrape path faults.

Capacity and lifecycle: c06 memory budget under saturation, c07 connection
churn, d04 startup with the intake down, d05 policy hot reload under load.

New echo modes they need: `keep_alive_off`, `slow_read`, `accept_silence`,
`slow_body`, `header_flood`, `redirect`, `bodiless`, `http10_no_length`, and
the last request target reported in `/stats` for b26.

Left out on purpose: anything that needs a particular platform or container
shape (the Linux run, the constrained-CPU profile, c10 descriptor exhaustion),
the framer and OTLP torture cases (unit tests), a29 (nondeterministic), a21
(h2 cannot work against an HTTP/1 edge), c08 and c13 (runner modes).

## This round: cases added and fixes made

### Cases added (28, taking the suite to 81)

Ingress: a17 oversize head, a20 Expect 100-continue, a23 resync after a local
error, a25 half-close, a26 RST mid-body, a27 vanish after forward, a34 encoding
spellings, a41 policy drop-all plus the rejected-pattern case.

Egress: b14 keep-alive off, b15 HTTP/1.0 read-until-close, b16 bodiless
statuses, b17 response header flood, b18 slow-drip response, b19 slow-reading
intake, b20 accept then silence, b21 early rejection of a streamed body,
b22 intake restart, b25 redirect, b26 target fidelity, b29 scrape path faults.

Capacity and lifecycle: c06 memory budget, c07 connection churn, d04 startup
with the intake down, d05 policy reload under load.

New intake fault modes: `keep_alive_off`, `bodiless`, `redirect`,
`header_flood`, `http10_no_length`, `slow_body`, `slow_read`,
`accept_silence`, `read_then_close`, `truncate_after_read`, plus the last
request target in `/stats`.

### Fixes made this round

- **`/_health` and `/_edge/*` claim every method.** A HEAD probe is answered,
  everything else gets 405, and neither reaches the intake. (a22)
- **Control paths are labelled by path, not by method**, so a HEAD probe is no
  longer counted as data traffic.
- **stdio accepts an absolute-form target** and routes on its path, per
  RFC 9112 §3.2.2, instead of forwarding the whole URL upstream. (a22)
- **stdio interrupts its inbound sockets on shutdown.** 30 s to under 2 s. (d03)
- **A decoded-size overrun fails open**; only the raw cap answers 413. (a35)
- **stdio keeps a control reserve.** Two slots are held back, and a connection
  taken from the reserve serves one control request and closes. A health probe
  now answers while the slab is full, instead of being shed and restarting the
  sidecar during the spike. (c05)
- **httpz relays response headers up to our own cap.** Its default of 16
  silently truncated an intake answer, so a `Retry-After` on a 429 vanished
  while the request still reported 202. (b17)

### Corrections to earlier claims

- **`.*` is not a policy bug.** Hyperscan refuses a pattern that can match an
  empty buffer, so `.*` never compiles and `.+` or `^.*$` is the correct way to
  say "everything". The real finding is narrower: the matcher builds nothing
  (`policy_count=0`), while the loader reports `loaded_count=1 failed_count=0`
  and `/_edge/policies` lists the policy as enabled. A rule that cannot compile
  looks live. (a41)
- **b16 is stdio only.** httpz keeps a 204 bodiless; stdio re-frames it as
  chunked.

## Latest round: the two defects that were ours

- **A rejected pattern is now named.** policy-zig already recorded the reason;
  the edge never read it. `/_edge/policies` leads with
  `# REJECTED id=<policy>: log: match[0]: invalid regex ".*"`, the gauge
  `edge_policies_rejected` counts them, and `policies.rejected` warns when the
  count changes. A rule that cannot compile no longer reads as live. (a41)
- **stdio keeps a bodiless status bodiless.** 204, 304 and 1xx answer directly
  instead of opening a streamed body, so the relay no longer frames a chunked
  body onto a status that must not have one. (b16)

Everything else on the ledger needs a change in `std`, in httpz, or a product
decision about the streaming threshold.

## A shed connection carries `Retry-After`

A connection refused because the edge has no connection slot keeps its
`503 Service Unavailable` and now carries `Retry-After: 1`. Both shed paths
send it: the slab is full, and the Io implementation is at its task limit.

503 is the honest status here, and 429 is not. Connection exhaustion is a
condition of the whole proxy, not an allowance we granted one sender. The OTLP
spec admits either status for an overloaded server and scopes `Retry-After` to
both, and the collector retries 429, 502, 503 and 504 alike, so the status
alone changes no client behaviour. What it does change is how a gateway reads
it: collectors in gateway mode use 429 for a non-retryable tenant limit, and
the edge is deployed as a gateway. The Datadog agent is equally indifferent to
the two, because it backs off on every error status except 400, 401, 403 and
413.

So the header is the whole improvement. A sender that honours `Retry-After`
waits the stated interval instead of retrying at once. `SHED_RETRY_AFTER_SECONDS`
sets both the header and the fixed shed response, so the two cannot disagree.

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
