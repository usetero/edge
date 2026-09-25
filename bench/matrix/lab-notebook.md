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

## The default frontend is stdio

`-Dfrontend` now defaults to `stdio`, so the release binaries and the container
image carry it. httpz stays buildable, and every case in this suite still runs
against both.

The reason is the incident this suite was written for. httpz hands a batch of
up to 16 requests to one pool thread, so one slow intake response parks the
rest of that batch, and a health probe behind them times out (c02, c05).
stdio runs a task per connection and answers the probe (c05 passes on stdio,
and reproduces as a declared defect on httpz).

A sweep on the Mac Studio, 12 s per row, both frontends, `bench/perf/sweep.py`:

| intake | httpz rps | stdio rps | httpz p99.9 | stdio p99.9 |
| ------ | --------- | --------- | ----------- | ----------- |
| immediate | 87,733 | 87,344 | 1.9 ms | 1.0 ms |
| slow, stage 1 | 741 | 2,089 | 469.6 ms | 50.6 ms |
| slow, stage 2 | 183 | 444 | 2083.1 ms | 203.4 ms |
| slow, stage 3 | 105 | 221 | 4600.7 ms | 351.8 ms |

Read the stages as "the intake gets slower", not as a number: the host
stretches short sleeps, so the axis label understates the real delay. Both
frontends met the same intake. Throughput with an immediate intake is equal,
stdio serves 2 to 2.8 times as many requests once the intake is slow, and its
p99.9 stays within 50 ms of its own p50 while httpz's runs to ten times its
p50. The `threads` and `maxconn` axes are flat for both.

### What the swap costs

Two things get worse. A third, the pair of encoding defects, is fixed below.

1. **An invalid chunk waits for the request deadline** instead of a fast 400
   (a07). The sender still gets an answer, just late.
2. **Memory grows with the connection count.** `Io.Threaded` gives each
   connection a task, so 256 concurrent senders cost 229 MB against httpz's
   129 MB. Below 64 connections stdio is the cheaper of the two (21 MB at 16
   connections, 65 MB at 64), and it does not grow with `thread_pool_count`,
   which httpz does: 20.7 MB at 8 threads against 119.9 MB at 128.

httpz keeps five declared defects of its own (a02, a03, a12, c02, c05), two of
them the incident.

## Repairing a head std refuses over one header

std's head parser maps `content-encoding` through an exact-match table of seven
spellings (std/http.zig:283) and fails the whole head for anything else
(std/http/Server.zig:164). Two real senders hit that, and both lost data,
because 400 is one of the four statuses the Datadog agent treats as permanent:

* `Content-Encoding: GZIP`. RFC 9110 §8.4.1 makes codings case-insensitive,
  and the table is keyed on lowercase bytes (a34).
* `Content-Encoding: br`, or any codec we do not decode. The router plans
  `forward_raw` for those, so the batch should reach the intake untouched
  (a10).

`src/frontend/stdio/head_repair.zig` rewrites the value in a copy of the head
and parses it again: a known coding gets the spelling std takes, and an unknown
one becomes `identity`, which leaves the body unread. The router decides on
what the sender sent, and the relay forwards it, so a coding we cannot decode
reaches the intake exactly as it arrived. Both cases now pass on both
frontends, and a10 asserts the header the intake received, not only the status.

Three details make it work:

1. **The bytes are still there.** `http.Reader.receiveHead` ends with `toss`,
   which only moves the read cursor, so the head sits in the receive buffer we
   own. The frontend records the cursor before the call and reads the head back
   after the failure.
2. **std reports the cause, one layer down.** `Head.parse` returns
   `HttpTransferEncodingUnsupported`; `receiveHead` flattens it to
   `HttpHeadersInvalid` on one line (std/http/Server.zig:53). Re-parsing the
   bytes recovers the distinction, which is what makes the repair safe: any
   other fault still answers 400.
3. **`Server.Request` is a public struct.** The repaired request is built from
   the rewritten head, and `reader.state` is already `received_head`, so the
   rest of the connection path runs unchanged.

There is no metric. A sender spells an encoding the same way on every request,
so the signal is one warn line per cause for the process (`head.repaired`), not
a counter that only ever says "this deployment has that sender".

The fake intake shares the repair, because a real intake accepts a coding it
cannot decode and ours is `std.http.Server` based too. Without that, a10 would
measure the test double.

## Two cases that tested less than they claimed

Both came out of the full run after the repair landed, and neither was a
product defect.

**d05 ran the machine out of ports.** The reload case sends from four threads
for six seconds with no keep-alive, which is a connection per request. That
exhausts the ephemeral range in seconds, and the sender then fails with
`EADDRNOTAVAIL`: its own local address, not anything the edge did. Each thread
now keeps one connection, which is also what an agent does. `post_logs` takes
a `session` for that.

**Four cases ran with no policy in force.** They asked for `"regex": ".*"`,
which the matcher refuses because the pattern can match an empty buffer, so
a09, a34, a35 and d05 claimed to exercise the decode path while nothing
decoded. They now say `.+`.

One invariant closes that class for good: a case that declares `EDGE_POLICIES`
must end with `edge_policies_rejected` at zero. a41 is the only case that opts
out, with `EXPECT_REJECTED_POLICIES`, because a41 is the case about the
refusal.

## A case that passed for the wrong reason

b12 points the edge at a blackhole and asserts the sender is not held for the
kernel's connect timeout. It started passing on both frontends, which would
have read as "the dial is bounded now". It is not. The blackhole was a loopback
listener with a filled accept queue, and loopback accepted the connection
anyway, so the case measured the request deadline instead of the dial.

It now dials `198.51.100.1`, reserved for documentation by RFC 5737, which
swallows the SYN. Both frontends hold the sender for the full 120 s client
timeout, so the defect is declared again and the case proves it. Where a host
refuses the route instead of dropping it, the case skips rather than claim a
bound it did not test.

## Observability review

An audit of every metric and every log site, for gaps on one side and noise on
the other.

### Logs added

Five places could lose or fail something with no line at all:

1. **A batch policy empties.** Both paths now report it: the record path
   forwards the empty batch, and the buffered path answers success and
   forwards nothing. `batch.dropped` carries `forwarded`, so the line says
   which happened. This is the first thing to read when an operator asks where
   their data went. a41 asserts it.
2. **An s3-dump flush that did not deliver.** `s3.dump.records.dropped` is
   data lost for good, from a full backlog or an encode failure.
   `s3.dump.upload.failed` is a failed upload that was requeued, which is the
   leading indicator of the first. The counters gave the rate; nothing gave
   the reason. Both the flush loop and the shutdown drain report through one
   helper.
3. **An `accept` that failed.** `accept.failed`. One inbound connection is
   gone before it carried a request.
4. **A watchdog that could not start.** `watchdog.spawn.failed`, on both
   frontends. The spawn error was dropped on the floor, and the process shut
   down with no reason given.
5. **A listener that stopped.** `listen.failed` on httpz. It explains a
   process that is up and deaf.

Three of those were `std.log` free text before. A named type gives the event a
stable telemetry name, so an alert can match it and this suite can assert it.

Two events are warn-once-per-process, then debug: `batch.dropped` and
`head.repaired`. The fact is what an operator needs, and it does not change
between requests; the rate belongs to the counter. A warn per request at 87k
rps is its own outage.

### Metrics removed and trimmed

- `edge_prefilter_decisions_total{route_kind,decision}` is gone. It answered
  whether the prefilter took the fast path, which is tuning work, not
  operation. That is 24 series, and no case or dashboard read it. The
  `RouteKindLabel` enum and `prefilterRouteLabel` went with it.
- `edge_request_duration_seconds` drops from 18 buckets to 11 boundaries, 100
  us to 30 s. At 18 it was half the whole series budget (18 x 9 paths), finer
  than any alert reads.

The series budget goes from about 380 to about 240, and the README now lists
every series with its labels.

### Cardinality

No unbounded label anywhere. Every label is a bounded enum, and the only
string labels are `version` and `commit` on `edge_build_info`, one series per
process. No path, status code, policy id or client value reaches a label, so
the series count cannot grow with traffic.

httpz keeps three events against stdio's twelve, and its connection metrics
are compiled out (`conn_metrics_enabled`). That is left as it is: stdio is the
default, and the comment that claimed httpz exports its own connection series
through `endpoints.zig` was wrong, because no such series exists.

## What the scaling benchmark taught us

A run of `bench/scaling/run.sh` on the Mac Studio reported 99% success while
the edge answered 49,889 of 49,927 requests with a 5xx. Four causes, none of
them the frontend swap: the same shape passes on both frontends locally, and
the same command on that host with clean ports and a raised descriptor limit
was 100% on every scenario.

1. **The benchmark asked for `log_level: err`,** so every warning was thrown
   away. The edge reset the bus level from the config right after loading it,
   which is why those logs held exactly two lines. It asks for `warn` now.
2. **The benchmark never read the counters.** `edge_requests_total`,
   `edge_responses_total`, `edge_connections_shed_total` and the rest answer
   "where did the missing requests go" directly, and a `kill -9` took them
   with it. The script now scrapes `/_edge/metrics` before it stops each edge,
   saves it under `debug/`, and prints one line naming what became of the
   requests the intake never saw.
3. **Two processes shared a port.** `reuse_address` sets SO_REUSEADDR *and*
   SO_REUSEPORT (std/Io/net.zig:229), so a second edge binds the same port
   happily, and macOS hands new connections to the newest listener. Proved
   with two processes on one port: the newest served 600 of 600, the older
   none. The script slept 0.3 s after SIGTERM and never checked the port, so a
   slow shutdown or a leftover process from an earlier run split the traffic:
   one scenario reported 70,757 requests for 50,000 sent, and a scrape
   labelled `v1_logs` for a traces run. It now clears the fixed ports, waits
   for the previous process to exit, and refuses to start a second listener.
4. **`ulimit -n`.** macOS defaults to 256 descriptors, which cannot hold 256
   inbound connections plus an upstream pool. The script raises it to 8192.

Two of our own problems surfaced with it:

* `arena_pool` warned once per release, 19,306 times in one run, that the
  connection arena had grown past its reserve. It now warns on a new
  high-water mark, so a repeat is silent and a worse leak still gets a line.
  Worth noting on its own: the Datadog metrics path does exceed the 16 KiB
  reserve.
* The echo server printed `/stats` strings raw, so one request with control
  bytes in its target made the whole document unparseable and hid every number
  in it. `std.http.Server` accepts such a target, and the edge forwards it.
  The strings are escaped now, and `src/bench` finally has a test artifact in
  `build.zig`: its tests never ran, because it is outside the `src` package.

The payload generator also needed `bench/scaling/proto_gen`, which is
gitignored, so a fresh checkout could not run the benchmark at all. It now
takes the published `opentelemetry-proto` package through uv, and hermit's zig
and python by path, so nothing depends on an activated shell.

## Undefined behaviour on sender input

A customer ran 1.32.0 in ECS, and the sidecar exited with SIGSEGV after 23
to 56 minutes. We reproduced it with one request: a gzip batch that the
sender abandons partway through. An audit then found more faults of the same
kind. This section records each fault, what fixed it, and what is still open.

### Status

| # | Fault | Cases | Status |
|---|---|---|---|
| 1 | A partial body passes as a whole batch (stdio) | a11, a44, a45, c10 | Fixed |
| 2 | std gzip decoder crashes on a stream that ends early (both frontends) | a44, a46, a47 | Fixed by a guard; upstream fix in Zig 0.17 |
| 3 | std zstd decoder crashes on some corrupt frames | a47 | Fixed: zstd decodes with libzstd |
| 4 | The gzip CRC and length are never checked | a47b | Fixed |
| 5 | A zero-byte `stream()` return ends the decode copy, so the buffered path answers 413 | a49 | Fixed |
| 6 | A bare LF in a header value reaches the upstream (stdio) | a50 | Fixed |
| 7 | A POST with no framing trips a std assert (stdio) | a05 | Fixed |
| 8 | Two gzip members: std flate stops after the first | a51 | Fixed: fails open |
| 9 | Chunk size `ffffffffffffffff` overflows in `std.http` | none | Open |

### 1. A partial body passes as a whole batch

std's Content-Length body reader returns `EndOfStream` when the peer closes
early, and `inboundBodyOf` took that as the normal end. With no policy the
edge forwarded the partial body and the intake answered 202. With a log
policy the partial gzip body went to the decoder, which is fault 2. Chunked
bodies were safe: std reports `HttpChunkTruncated`.

Fix: `inboundBodyOf` reads a resident body with `streamExact64`. A short body
fails as `InboundBodyTruncated` and gets a 408, which the agent retries.

### 2. The std gzip decoder on a stream that ends early

In Zig 0.16.0, `tossBitsShort` in `flate/Decompress.zig` adds `consumed_bits`
where it must subtract them. When the input ends before the stream, the bit
reader passes its own end, and the decoder reaches `unreachable` or overflows.
In ReleaseFast that is undefined behaviour: a segfault, or a thread that spins
forever. The published amd64 image spun 257 threads under chaos traffic.

Corrupt bytes reach the same fault. A corruption can make the deflate data ask
for more bits than the stream holds. All 55 gzip crash inputs from the audit
panic with std's reader and none with the guard, including the full-length
corrupt ones. So a body length check alone cannot prevent the crash.

Fix: `encoding.residentReader` makes the end of a resident gzip body read as
`ReadFailed`. A complete stream never reads past its 8-byte footer, so a valid
body never sees the end, and flate returns `ReadFailed` as a clean error.

**Upstream:** reported as https://codeberg.org/ziglang/zig/issues/35789 and
fixed on master by PR 35815 (June 2026), a one-character change. The fix is
not in 0.16.0 and not on the `0.16.x` branch. It should ship in Zig 0.17.
When the edge moves to that release, delete the gzip case in
`residentReader`. The matrix and the decode safety tests then prove std alone.

### 3. The std zstd decoder on corrupt frames

`zstd.Decompress` writes the literals after the sequences with
`writableSlice(len)`, and nothing checks that the block stays inside the one
block of space reserved for it. A valid frame never goes over, but a corrupt
one can, and the rebase is `unreachableRebase`. A larger buffer does not help:
std guarantees only one block of free space before each block. This bug is
not reported upstream, and master has the same code.

Fix: the edge decodes zstd from a sender with
`compress_buffered.decompressZstd` (libzstd), then runs the pipeline on the
decoded bytes as identity. `decompressZstd` was rewritten for untrusted input:
it decoded some valid frames with no declared size as failures, it refused
bodies below the cap, it set no window limit, and it logged every bad input
at error level. It now reads every frame, caps output exactly, and caps the
window at `zstd_window_len`. A frame that declares its size decodes into the
output with no window, so only frames with no declared size need the cap.

Cost: on the streamed logs path, a zstd body is decoded into memory once,
up to `max_decoded_bytes`, instead of streamed. The buffered path already
held the whole decoded body.

### 4. The gzip CRC and length

std flate reads the CRC32 and ISIZE from the footer and never compares them.
When a policy changed the batch, the edge wrote a new stream with a fresh CRC,
so damaged data reached the intake as sound. Fix: `Decoder.verifyEnd` compares
both against the decoded bytes, on the streamed and the buffered path. A
mismatch fails open, so the intake gets the body as sent and rejects it.

### 5. Zero-byte returns

`streamReaderToWriter` stopped when `stream()` returned 0. std decoders return
0 before they have output, and so does TLS. On the buffered path every valid
gzip or zstd body then failed the excess check and got 413, which the agent
discards for good. That path serves Datadog metrics JSON and OTLP JSON. Fix:
only `EndOfStream` ends the copy, as in std's `streamRemaining`.

### 6 to 8. Smaller faults

- **Bare LF (a50).** `x-a: b\nx-c: d` parses in std as one header with an LF
  in its value, and stdio forwarded it. A lenient upstream would read a second
  header that the name filter never saw. stdio now answers 400. httpz already
  refused it.
- **Unframed POST (a05).** A POST with no `Content-Length` and no chunking
  has no body (RFC 9112 §6.3). stdio skipped the body reader, and std's
  `discardBody` asserts that it exists. stdio now makes the reader, and the
  connection closes after the response.
- **Two gzip members (a51).** std flate stops after the first member, so a
  policy would have filtered part of the batch and dropped the rest.
  `verifyEnd` treats bytes after the member as an error, so the body fails
  open.

### 9. Open: chunk size overflow

std.http accepts a chunk size of `ffffffffffffffff`, then computes
`chunk_len + 2 - n` (`http.zig:586`, and the discard path at `:654`). In
ReleaseSafe one request panics the process. In ReleaseFast the value wraps and
the chunk framing goes out of sync. Upstream responses reach the same code.
Master has the same code. There is no matrix case yet.

### How it is tested

- **Matrix.** The runner builds ReleaseSafe by default (`--optimize`), so
  undefined behaviour panics and the "edge died" invariant fails. The runner
  reports the first failure of a case in time order. Cases: a05, a11, a44,
  a45, a45b, a46, a46b, a47, a47b, a49, a50, a51, c10. The corrupt-body
  fixtures from the audit are in `fixtures/`.
- **Decode safety tests** (`src/pipeline/decode_safety_test.zig`). Every test
  checks one property: a decode returns an error or the exact input, and never
  panics or returns other bytes. They cover zlib levels 0, 1, 6 and 9 and
  std's encoder for gzip, and three zstd levels with and without a checksum
  and with no declared size. They decode every prefix of short streams, the
  ends and a spread of long ones, random corruption, random bytes behind a
  valid header, the audit's crash inputs, footer faults, header fields, extra
  members and frames, the window cap, the exact decoded-size cap, and the
  streamed path through `pipeline.run`. Two `std.testing.fuzz` tests search
  for new inputs under `zig build test --fuzz`.
- **Deep run:** `zig build test -Doptimize=ReleaseSafe -Ddecode-test-scale=50`
  multiplies the random cases and the prefixes of long streams by 50.

### Other faults seen on the way

- httpz answers a 4xx for an abandoned streamed batch, and requests stay
  counted in flight. (a45b)
- The segfault handler in `runtime/app.zig` starts its trace at its own
  return address, so it prints the signal trampoline, not the faulting frame.
  std's handler, which ReleaseFast turns off, unwinds from the fault.
- The "conn arena grew" warning names cold paths. On stdio, bodies up to
  64 KiB go into that arena on purpose, so the warning is normal traffic and
  misleads the operator.
- `latest` moves on every chart release. release-please publishes a chart
  release after each app release, and `release.yaml` tags it `latest`.
- The metrics carry only the status class, so the drop invariant reads every
  4xx as a permanent drop. a03, a11, a44, a45, a45b, c01, c05 and c10 opt out
  and check their statuses themselves. A counter for retryable 4xx answers
  would let the invariant tell them apart.

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
