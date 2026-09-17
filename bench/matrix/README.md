# Fault matrix

What a customer hits when something goes wrong on either side of the edge: the
agent that sends to us, and the intake we send to. Every case runs against both
frontends, and **neither frontend is the oracle** — both are judged against what
the customer needs, and either can fail.

```sh
UV="./bin/uv run --python ./bin/python3 --with requests --with zstandard"
$UV bench/matrix/run.py                      # both frontends, every case
$UV bench/matrix/run.py --fast               # skip the 30 s deadline cases
$UV bench/matrix/run.py --frontend stdio -k b05
```

`--fast` skips the cases that wait for a 30 s deadline. `--skip-build` reuses
the binaries already in `zig-out/` and `zig-out-stdio/`.

## How a case is written

One case per file, one class per case, inheriting `MatrixCase`:

```python
from harness import MatrixCase


class RejectEarly(MatrixCase):
    def test_an_early_rejection_is_relayed(self):
        self.intake.arm("reject_early", count=1)
        self.assert_status(self.post_logs(), 400)
```

The base class starts the fault-injecting intake and the edge binary under
test, and tears both down. It also asserts, after every case:

- the edge process is alive and still answers `/_health`;
- connection slots returned to their baseline;
- no connection was shed unless the case said it would be;
- every 5xx the edge produced itself left a log line.

Useful attributes: `EDGE_CONFIG`, `EDGE_ENV`, `EDGE_POLICIES`,
`INTAKE_LATENCY`, `SLOW`, `EXPECT_SHED`, `DEFECTS`.

## Declared defects

A case never lowers its expectation to accommodate a frontend. Behaviour we
have already found and recorded is declared instead:

```python
class Pipelined(MatrixCase):
    DEFECTS = {"httpz": "answers 400 to a pipelined pair"}
```

The assertion still runs at full strength. The runner reports `xfail` with the
note, so the defect stays counted and visible, and reports `XPASS` on the day
it starts passing, which means the note must go.

## Injecting intake faults

The intake is the real `zig-out/bin/echo-server`. Faults are armed over HTTP,
and `count` limits them to the next N requests, so a case can fault the first
attempt and let the retry succeed:

```python
self.intake.arm("close_early", count=1)
```

| mode | what the intake does |
|---|---|
| `status` | answers with `arg` as the status code |
| `slow` | answers after `arg` milliseconds |
| `hang` | reads the body and never answers |
| `close_early` | reads part of the body, then closes with no answer |
| `reject_early` | answers before reading the body, as an intake does when it rejects on headers |
| `reset` | closes with RST |
| `garbage` | writes bytes that are not HTTP |
| `truncate` | declares more body than it writes, then closes |
| `oversize` | answers with a body of `arg` bytes |
| `stale_keepalive` | answers, then drops the connection the client just pooled |

`GET /stats` reports `fault`, `fault_arg` and `fault_applied`, so a case can
assert the fault actually fired.

## Injecting sender faults

`self.raw()` owns a socket, so a case can send a partial head, a body shorter
than its `Content-Length`, one byte per second, pipelined requests, or bytes
that are not HTTP at all. `self.post_logs()` and `requests` cover the
well-formed cases, and `harness.load` drives `oha` where a case needs real
load.

## The cases

`slow` waits on a 30 s deadline and is skipped by `--fast`. `xfail` is a
declared defect: the case still runs and still fails, and the runner reports it
with its note.

### `a*` — the sender to the edge

| Case | Fault injected | Must happen | Notes |
|---|---|---|---|
| a01 | Connects, never sends a byte | The slot is reclaimed at the idle deadline, counted by phase | slow |
| a02 | Part of a head, then stalls | 408, because a request is in flight | slow, xfail httpz: closes with no status |
| a03 | `Content-Length` larger than the body sent | 408 naming `InboundBodyTimeout` | slow, xfail httpz: closes with no status |
| a04 | Body dripped one byte per second | Cut off inside the deadline, by status or by close | slow |
| a05 | POST with no `Content-Length` and no chunking | Any answer, never a hang | |
| a06 | Well-formed chunked body | 202, and the intake receives it | |
| a07 | Chunk size that is not a number | Refused at once, not after the deadline | slow, xfail stdio: waits for the deadline |
| a08 | Body above `max_body_size` (16 KiB here) | 413, and nothing is forwarded | |
| a09 | Corrupt gzip, no policies loaded | Forwarded; the intake's answer is relayed | |
| a09 | Corrupt gzip, policies loaded | Fails open and forwards, with `policy.failed.open` | |
| a10 | `content-encoding: br` | Forwarded raw, per the router's documented intent | xfail stdio: std refuses the head. Skipped on httpz: our std-based intake refuses brotli too |
| a11 | Sender vanishes mid-body, five times | Slots return, and nothing blames the intake | |
| a12 | Two requests written in one packet | Both are served | xfail httpz: answers 400 |
| a13 | 50 requests on one keep-alive connection | All 202, and the connection count stays at one | |
| a14 | 80 request headers | Refused with a 4xx, never accepted with headers dropped | |
| a15 | Complete but invalid head | 400 at once | slow |
| a15 | Incomplete garbage, no head terminator | Bounded by the deadline | slow |
| a16 | zstd batch, what a current agent sends | 202, and the intake receives it | |
| a19 | `Content-Length` with chunked, two lengths, a length that is not a number | A 4xx, and nothing reaches the intake | the smuggling surface |
| a22 | `HEAD /_health`, `POST /_health` | Answered by the edge, never forwarded | |
| a22 | `GET http://example.com/_health` | Not forwarded as a mangled target | xfail stdio |
| a30 | 60 KiB batch, intake closes mid-request | Replayed, 202 | the resident side of the threshold |
| a30 | 300 KiB batch, intake closes mid-request | Replayed, 202 | xfail both, by design: a streamed batch cannot be replayed, and the agent retries the 502 |
| a35 | Small gzip that expands past the decoded cap, policies loaded | Bounded, and the batch is not lost | fails open; the raw cap still answers 413 |
| a35 | The same body with no policies loaded | Forwarded untouched, 202 | nothing reads it |

### `b*` — the edge to the intake

| Case | Fault injected | Must happen | Notes |
|---|---|---|---|
| b01 | Nothing listening | 502, after the dial is retried once | |
| b02 | Intake reads the body and never answers | 504 at the watchdog, with the timeout counted | slow |
| b03 | Intake answers after 6 s | 202, and `request.slow` records it | |
| b04 | Intake closes mid-request | Retried on a fresh connection, 202 | |
| b05 | Intake rejects on the head, before the body | The 400 is relayed, not turned into a 502 | the reported production signature |
| b06 | Intake answers 429, 500, 503 | Each is relayed verbatim | three methods |
| b07 | Response body above the response cap | A 5xx or a closed relay, never a silent 2xx | |
| b08 | Intake answers with bytes that are not HTTP | 5xx, and the connection is evicted | |
| b09 | Pooled keep-alive is already dead | Retried on a fresh dial, 202 | log intake clients do not retry |
| b10 | Intake resets the connection | Retried, 202 | |
| b11 | Intake declares more body than it sends | Never 202; `UpstreamResponseTruncated` | |
| b11b | Intake truncates *before* reading the body | The batch never arrived, so a retry repairs it | settles the b11 challenge |
| b11b | Intake reads the batch, *then* truncates | The batch is in, so our 502 costs a duplicate | settles the b11 challenge |
| b12 | Dial into a full accept queue, so SYNs are dropped | An answer inside 35 s | slow, xfail both: the dial has no deadline |
| b23 | Intake reads the whole batch, then closes with no answer | Exactly two copies at the intake | pins at-least-once |
| b24 | Every request fails the same way, 100 of them | At most two attempts each, health unaffected | |

### `c*` — capacity

| Case | Fault injected | Must happen | Notes |
|---|---|---|---|
| c01 | More connections than the slab holds (8) | Shed with 503, counted by reason | |
| c02 | Health probe arrives with a 15-sender burst against a 3 s intake, 20 times | The probe stays under 1 s | slow, xfail httpz: a batch of 16 goes to one pool thread |
| c03 | 12 idle sockets against 8 slots | Recovers on its own, without the senders closing | slow |
| c04 | 48 senders against an intake that never answers | Health and the scrape answer inside a second | slow |
| c05 | A probe while every slot is held | Health answers at capacity | xfail both: shed with the rest, which restarts the sidecar during the spike |
| c09 | 400 failing requests with a log pipe nobody drains | The edge keeps serving | slow |

### `d*` — lifecycle

| Case | Fault injected | Must happen | Notes |
|---|---|---|---|
| d01 | SIGTERM with four exchanges open against a 4 s intake | Exit inside 35 s, and no 202 for a batch never forwarded | slow |
| d02 | SIGTERM while the intake is hung | Exit inside 20 s | slow |
| d03 | SIGTERM with eight idle keep-alive connections | Exit inside 10 s | |

Every case also asserts its telemetry, and the base class asserts that a
counter which moved is explainable from the log.

## Requirements

- `python3` and `uv` from hermit (`bin/`).
- `requests` and `zstandard`, supplied by `uv run --with`. Without `zstandard`
  the zstd case skips rather than fails.
- `oha` for the load cases (`brew install oha`); those cases skip without it.
