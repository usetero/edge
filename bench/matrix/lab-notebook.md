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

## Codec rewrite (`src/codec/`)

The first-principles plan from the review of the decode fixes: one small
module, one reference library per format in both directions (zlib for gzip,
libzstd for zstd), and library state reused between bodies. It is built
beside the old code first, then compared with zbench. Wiring it into the
request path, and one body intake rule for both frontends, is the next phase.

- [x] `codec/root.zig`: the API, `Codec`, `DecodeError`, `DecodeLimits`.
- [x] `Decoder`: pulls decoded bytes from a complete body. gzip and zstd,
      several members and frames, an exact output cap, a zstd window cap.
      A read with no progress is `Truncated` or `Corrupt`, never a loop.
- [x] `Encoder`: a `std.Io.Writer` that compresses straight into the free
      space of another writer.
- [x] Tests (`codec_test.zig`): every property from
      `decode_safety_test.zig`, std's decoders as an independent oracle,
      output chunk sizes from 1 byte to the whole body, one decoder across
      thousands of good, bad and abandoned bodies, several gzip members,
      header CRC fields, encoder round trips over four write patterns and
      four staging sizes, a full output writer, agreement with the old decode
      path, and fuzz tests.
- [x] Build: the tests run in `zig build test`, and
      `zig build codec-bench -Doptimize=ReleaseFast` runs the benchmark.
- [x] Benchmark with zbench, below.
- [x] Results recorded.

The caller owns the library state. A zstd compression context holds about
3.5 MiB at level 3, so one for each of 128 handler threads costs about
450 MiB. The wiring phase must pool encoders, as `CctxCache` does today.

### Benchmark: old against new

`zig build codec-bench -Doptimize=ReleaseFast`, Apple M-series, JSON log
batches shaped like agent output, decode read in 4 KiB chunks as the
pipeline reads them. Two runs agreed to within a few percent; run 1 is shown.

| Operation | Size | Old | New | New is |
|---|---|---|---|---|
| gzip decode | 16 KiB | 49.2 us | 7.0 us | 7.0x faster |
| gzip decode | 256 KiB | 728 us | 83 us | 8.8x faster |
| gzip decode | 2 MiB | 5.90 ms | 0.90 ms | 6.6x faster |
| zstd decode | 16 KiB | 5.9 us | 5.6 us | same |
| zstd decode | 256 KiB | 65 us | 69 us | same |
| zstd decode | 2 MiB | 543 us | 602 us (549 us, no size) | same |
| gzip encode | 16 KiB | 94.9 us | 43.1 us | 2.2x faster |
| gzip encode | 256 KiB | 1.66 ms | 1.28 ms | 1.3x faster |
| gzip encode | 2 MiB | 14.2 ms | 12.9 ms | 1.1x faster |
| zstd encode | 16 KiB | 16.8 us | 13.3 us | 1.3x faster |
| zstd encode | 256 KiB | 197 us | 194 us | same |
| zstd encode | 2 MiB | 2.14 ms | 2.12 ms | same |

- Old gzip decode is std flate with the checkpoint guards: `residentReader`,
  the CRC, `verifyEnd`. New is zlib.
- Old zstd decode is the checkpoint path: libzstd into a buffer that holds
  the whole decoded body, then read in chunks. The speed is the same, but new
  holds 4 KiB of output, not the whole body (2 MiB at the largest size).
- The streamed std zstd decoder, which the edge used before the checkpoint,
  took 75.7 us, 1.01 ms and 6.46 ms: 10 to 14 times slower than libzstd.
- zlib at level 6 writes gzip 3% to 6% smaller than std flate at level 6:
  2,141 against 2,207 bytes at 16 KiB, and 234,806 against 250,818 bytes at
  2 MiB. zstd sizes are the same, because both paths use libzstd.

### Verification

- `zig build test`: 659 of 661 pass, 2 skipped. The codec and decode safety
  tests add about 1 s at the default scale.
- Deep run on Linux (Alpine, musl, aarch64), ReleaseSafe,
  `-Ddecode-test-scale=50`: 660 of 661 pass, 1 skipped, in 5 minutes. Docker
  must run with `--security-opt seccomp=unconfined`, or the tail tests fail
  on io_uring with `PermissionDenied`.
- `zig build codec-bench` in ReleaseSafe: every path decodes and encodes
  with no safety check tripped.

### Facts found while testing

- A zstd frame keeps its checksum flag in the frame header, so a corruption
  can turn the check off, and libzstd then decodes changed data with no
  error. The format allows this. The tests check exact output only for
  changes after the header of a checksum frame.
- libzstd decodes a frame that declares its size straight into an output
  buffer large enough for it. It then needs no window and skips the window
  cap. The window cap matters only for frames with no declared size.
- A one-shot zstd compressor that knows the input size shrinks the window to
  fit, even when it does not write the size. Only a streaming compressor
  declares a large window for a small input.
- `zig build test --fuzz` does not build in Zig 0.16.0: the test runner
  fails to compile with `-ffuzz` (`test_runner.zig:566`, `*builtin.StackTrace`
  where `*const debug.StackTrace` is expected). The fuzz tests still run
  their corpus in a normal `zig build test`. The seeded random cases carry
  the deep search: `-Ddecode-test-scale=50`.

## Wire the codec in, and delete the old path

- [x] `codec.ContentEncoding` (identity, gzip, zstd) replaces
      `encoding.ContentEncoding` in the service plans.
- [x] `codec.EncoderPool`: a bounded pool, so idle zstd contexts cost at most
      the pool size times 3.5 MiB, as `CctxCache` did.
- [x] `pipeline.run` takes the complete body as a slice, decodes with a
      `codec.Decoder`, and encodes with a `codec.Encoder`.
- [x] One `codec.Decoder` per handler thread, in `ThreadBufs`. The decode and
      encode buffers go.
- [x] `execPipeStream` and `processBuffered` use the new pipeline. The zstd
      split goes.
- [x] Body intake: a decoder only ever sees a complete body, in both
      frontends. `pipeline.run` takes a slice, so it cannot start before the
      body exists. A short lazy body is `InboundBodyTruncated` in both
      frontends, and stdio checks std's `.ready` state after a chunked body.
      httpz hands over a resident body only once it holds all of it.
- [x] Delete `pipeline/encoding.zig`, `pipeline/compress_buffered.zig` and
      `pipeline/decode_safety_test.zig`. Test fixtures move to
      `codec/fixtures.zig`, and the crash corpus to `codec/testdata/`.
- [x] `codec-bench` keeps the new paths as a regression benchmark.
- [x] a51: two gzip members are now decoded and filtered, not failed open.
- [x] Unit tests, lint, the full matrix, and a chaos run pass. 625 of 627
      unit tests pass (2 skipped). The full matrix, slow cases included:
      103 cases, 0 failures, the same 11 declared defects. The 399-cut repro
      answers 408 at every cut on the Linux build, ReleaseFast and
      ReleaseSafe. Chaos traffic for 600 s: 505,831 requests (ReleaseFast)
      and 476,891 (ReleaseSafe), and the edge stayed up.
- [x] `latest`: tag it only for an app release, never for a chart release or
      a manual run. `release.yaml` now builds nothing for a chart release,
      and moves `latest` only when the release is the newest `v*` tag, so a
      patch to an older line cannot move it back. `actionlint` passes.

## Scaling sweep on the Mac Studio: codec branch against master

`bench/scaling/run.sh --edge-only`, 50,000 requests, 64 oha connections,
5 ms intake latency, policy counts 0 and 1000. Cells: handler threads 64 and
256, max connections 256, 1024 and 2048. Master is `df26f84`; the branch is
`b85aa33`. The two trees alternated inside each cell. Every run was 100%
successful.

| Scenario | Master | Branch | Change |
|---|---|---|---|
| DD Logs, 1000 policies (1 MiB gzip, 4 MiB decoded) | 444–449 req/s, p50 142–144 ms, p99 193–196 ms | 528–544 req/s, p50 118–121 ms, p99 167–175 ms | +18% to +22% req/s |
| DD Metrics and OTLP, 1000 policies | 77–82 MB | 49–51 MB | about 30 MB less memory |
| Every other scenario | about 2,100 req/s | about 2,100 req/s | within ±2% |

Two facts about the setup limit what the grid shows:

- On the stdio frontend, `thread_pool_count` does nothing, and with 64
  senders a connection cap of 256 or more never binds. So the six cells
  measured one configuration six times, and their spread (about ±2%) is the
  noise.
- Each request pays about six times the configured intake latency: the p50
  is 32 ms at 5 ms here, and 62.7 ms at 10 ms in the earlier master sweep.
  That caps the small scenarios near 2,100 req/s on both trees. The
  comparison is fair, but the absolute numbers understate the edge. The
  cause is in the harness, and it is not found yet.

## Crash reports

The old handler in `runtime/app.zig` started its trace at its own return
address, so a crash printed the signal trampoline and nothing else. It is
gone. Every entry point now sets `std_options.enable_segfault_handler`,
which ReleaseFast turns off by default, and exports `debug.handleSegfault`
from `runtime/crash.zig`. The hook names the build (version, distribution,
frontend, commit), then hands over to std, which covers SIGSEGV, SIGBUS,
SIGILL and SIGFPE and unwinds from the faulting instruction. A crash now
exits with SIGABRT (134), not SIGSEGV (139).

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

## Cases added for the combined fix branch (PR #348)

Seven additions, each aimed at a fix the branch carries end to end. Every one
runs on both frontends.

- **a06 `ChunkedBodyIdentity`, `ChunkedBodyUnderPolicies`.** A multi-chunk body
  larger than the pump buffer reaches the intake byte for byte, with and
  without a keep-all policy. Pins the socket-to-socket pump and the resident
  drain on the policy path.
- **a08 `ChunkedBodyTooLarge`.** A chunked body over `max_body_size` answers
  413 mid-stream and the intake records nothing. The streaming design may open
  the upstream before the cap trips, so this class does not forbid upstream
  log lines.
- **a16 `LargeZstdBatchWithPolicies`.** A frame that decodes to 3 MiB under a
  keep-all policy is accepted. Covers the decode window cap and the zero
  return from the decompressor in the bounded copy.
- **a52 `RedactionComposes`.** Two regex redacts on the same wrapped path both
  reach the intake. The check is on the forwarded bytes.
- **a53 `MalformedContainerFailsOpen`.** A record with `"x":[1,]` under a
  matching drop policy is forwarded as sent.
- **c06 `ChunkedBodiesCostNoMoreThanContentLength`.** Three Content-Length
  rounds as the control, then four chunked rounds. A chunked round must cost
  no more resident memory than a declared one, and the chunked rounds must
  not grow.
- **c11 `SlotChurnIntegrity`.** 64 senders, a fresh connection per batch, 1280
  distinct bodies checked at the intake. The only test that can reach the
  slot decommit race, because the unit test I/O is single-threaded.

### Two httpz defects the new cases found

- **httpz answers a chunked 413 itself.** httpz enforces its own body cap
  before the edge handler runs, so the response has no log line and no
  `edge_responses_total` count. An operator cannot see it. Declared in a08.
- **httpz grows with chunked bodies.** With 12 senders and 900 KiB bodies,
  RSS rises about 23 MB when the bodies switch from Content-Length to chunked,
  and about 12 MB per round after that. Content-Length rounds grow about
  6 MB per round on httpz too, which the original c06 bound of 32 MB hides.
  stdio is flat in both regimes. Declared in c06.

### What the descriptor invariant taught us here

`std.http.Client` pools up to 32 idle upstream connections. A case that
drives 32 raw senders at once leaves 32 pooled sockets, and the descriptor
budget allows 16 above the baseline. The original c06 passes only because
`requests` paces its threads. The chunked class uses 12 senders.

## Scaling sweep on the Mac Studio, PR #348 branch (2026-09-22)

`bench/scaling/run.sh`, edge only, 50k requests, 64 oha connections, policy
counts 0 and 1000. Twelve cells: upstream latency 0 and 10 ms, handler threads
64 and 256, max connections 256, 1024 and 2048. Every row is 100 percent
success with 50000 requests at the intake. Raw results:
`~/pr348-sweep/` on the Mac Studio and
`bench/scaling/results/pr348-mac-studio-2026-09-22/` locally.

| scenario | policies | req/s at 0 ms | req/s at 10 ms | p99 at 0 ms | p99 at 10 ms | RSS MB |
| --- | --- | --- | --- | --- | --- | --- |
| OTLP Logs | 0 | 85.3k to 86.6k | 1072 to 1100 | 2.1 to 2.2 | 92 | 33 |
| OTLP Logs | 1000 | 48.4k to 65.8k | 1067 to 1085 | 2.1 to 2.7 | 95 | 79 |
| OTLP Metrics | 0 | 84.9k to 86.8k | 1085 to 1097 | 2.1 | 92 | 33 |
| OTLP Metrics | 1000 | 75.1k to 78.0k | 1057 to 1087 | 2.1 to 2.2 | 94 | 77 |
| OTLP Traces | 0 | 85.6k to 86.5k | 1067 to 1102 | 2.1 | 92 | 33 |
| OTLP Traces | 1000 | 50.3k to 62.2k | 1057 to 1086 | 2.1 to 2.8 | 95 | 78 |
| DD Logs | 0 | 5212 to 5575 | 969 to 1021 | 12.9 to 14.4 | 112 to 116 | 63 |
| DD Logs | 1000 | 442 to 449 | 442 to 446 | 182 to 185 | 227 to 231 | 187 to 192 |
| DD Metrics | 0 | 83.4k to 86.2k | 1075 to 1099 | 2.1 | 92 | 34 |
| DD Metrics | 1000 | 78.3k to 79.7k | 1081 to 1095 | 2.1 | 94 | 80 |

The range in each cell is the spread across the six thread and max-connection
combinations at that latency.

- **The thread and max-connection axes are flat.** The stdio frontend gives
  each connection its own task and reads neither value. At 10 ms the mean
  req/s by threads is 1094 against 1087 for OTLP Logs, and by max connections
  1088, 1086 and 1098. The spread at 0 ms on the 1000-policy OTLP rows is
  run-to-run noise on a CPU-bound scenario, not an axis effect.
- **At 10 ms the intake is the ceiling, not the edge.** Every scenario but one
  converges on about 1090 req/s with a p50 of 62 ms and the edge at 10 to 40
  percent of one core. 64 connections over 1090 req/s is 59 ms per round trip:
  the echo server's 10 ms sleep runs at about 60 ms on this host, as noted
  under the sweep table above. The edge adds under 1 ms to that.
- **DD Logs at 1000 policies is CPU-bound at about 445 req/s** at both
  latencies, with the edge at 15.5 cores of 16 and 190 MB RSS. That is the
  4 MiB decoded batch against 1000 policies. It is the one scenario where
  the edge, not the intake, sets the rate.
