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

## Case groups

- `a*` the sender to the edge: framing, encodings, timeouts, disconnects.
- `b*` the edge to the intake: refusals, hangs, resets, truncation, relayed statuses.
- `c*` capacity: shedding, health under a burst, idle socket floods.

## Requirements

- `python3` and `uv` from hermit (`bin/`).
- `requests` and `zstandard`, supplied by `uv run --with`. Without `zstandard`
  the zstd case skips rather than fails.
- `oha` for the load cases (`brew install oha`); those cases skip without it.
