# Record path: where the time goes

Findings from profiling the Datadog logs record path, 2026-09-15. Written up
so the next person does not repeat the measurement.

Numbers marked **measured** come from the runs described under Method.
Numbers marked **estimated** are reasoning from those measurements and have
not been confirmed — treat them as hypotheses to test, not as results.

## Method

- Payload: 1,045,441 bytes gzipped expanding to 4,194,383 decoded, 8,181
  records, 4.0:1 (`bench/scaling/generate-bulk-payloads.py`).
- Upstream: `echo-server` with `ECHO_LATENCY_MS=0`, so wall time is Edge's own
  cost and nothing else.
- Binary: `zig build datadog -Doptimize=ReleaseFast -Dprofiling=true`.
- Profiler: `xcrun xctrace record --template "Time Profiler" --attach <pid>`.
  Set the upstream latency to 0 — Time Profiler samples on-CPU stacks, so with
  latency injected the handler threads sit parked in `readv` and the trace
  shows nothing useful.

## Cost breakdown

Fast path, meaning policies loaded but no record changed, so the re-encode is
skipped. 1,308 samples. **Measured.**

| Area | Share | Parallelizable |
|---|---|---|
| JSON framing, parse, scalar scan | ~33% | no, serial state machine |
| gzip decompress | 13% | no, sequential format |
| policy evaluation | ~20% | yes |
| hashmap, allocation, HTTP, event bus | ~34% | no |

About 8% of samples are unsymbolized addresses that are probably vectorscan
internals; they are counted under policy evaluation. If that guess is wrong,
evaluation is smaller than shown.

For contrast, before the re-encode skip landed, gzip *compression* alone was
25.7% of self time — the largest single item, more than decompression and
policy evaluation together.

## Policy count barely matters

Fast-path latency against the same batch. **Measured.**

| policies | latency |
|---|---|
| 5 | 17.4 ms |
| 100 | 29.9 ms |
| 1,000 | 30.1 ms |
| 4,000 | 31.2 ms |

Flat from 100 upward. The matcher index scans every pattern in one hyperscan
pass, so policy count is close to free after the first hundred. Any
optimization that assumes evaluation grows with policy count is aimed at a
problem this codebase does not have.

## Parallel evaluation: investigated, not recommended

The idea: split a batch into N slices and evaluate them concurrently.

It is structurally possible. `policy-zig src/policy/matcher_index.zig:648-672` already has a 64-slot
hyperscan scratch pool with per-thread slot assignment and atomic locks, so
concurrent scanning is supported today. That is the hard part and it is done.

It still does not pay, for three reasons.

1. **Most of the work cannot be split.** gzip decode is a sequential stream
   with a back-referencing window, so block N needs N-1. Record delimitation
   is a depth-and-string state machine (`src/pipeline/frame_json_array.zig:94-103`) that
   has to run serially to find where records begin. You would decode
   serially, delimit serially, and only then fan out.
2. **The parallelizable slice is ~20%.** Amdahl caps the speedup at about
   1.25x with infinite cores: 17.4 ms to roughly 14 ms. **Estimated**, from
   the breakdown above.
3. **Edge already parallelizes per request.** Up to 128 handler threads. Under
   real concurrency every core is busy with a different request, so
   intra-request parallelism contends with request-level parallelism instead
   of adding to it. It only helps latency when concurrency is low.

## Worthwhile: the JSON scanning shape

`std.mem.findScalarPos` already vectorizes (`std/mem.zig:1245-1250`), so there
is no missing-SIMD problem. The opportunity is the shape of the access.

### 1. The zimdjson parser is rebuilt per record

`src/signals/datadog/log.zig:407-409` constructs a fresh `Parser` and tears it
down on every call:

```zig
var parser: Parser = .init;
defer parser.deinit(allocator);
const doc = parser.parseFromSlice(allocator, raw) catch return;
```

simdjson-family parsers allocate a structural-index buffer sized to the
document and are meant to be reused so that cost amortizes. `RecordScratch`
(`frontend/exec.zig`) already holds such a parser, reused across records and
requests — `ensureUnwrapped` simply does not receive it. Threading it through
is a signature change, not a redesign.

This is invisible in every number above, because the bench payload's `message`
fields are plain text and bail at the `head[0] != '{'` check. It is hot for
any customer whose logger nests JSON inside `message`, which is common.
`src/signals/datadog/log.zig:407` is the only production site; the other `Parser = .init` uses in
that file are tests.

**Measured afterwards: worth nothing.** 12.564 ms against a 12.559 ms
baseline. `parseFromSlice` is 0.20% of the profile because zimdjson is lazy —
the cost is in navigation, not construction, so there is no setup to amortize.
This section originally said "start here"; that was wrong, and the measurement
is left in place as the correction. The change is still carried, because
building a structural index per record is the wrong shape and the borrowed
parser is what makes item 2 cheap — but on its own it earns nothing.

### 2. Per-field search versus one structural pass

`json_scan.FieldWalker` walks fields one at a time, calling `findScalarPos`
for each closing quote (`src/signals/json_scan.zig:114`). On a ~500 byte record with ~12
fields each search covers 10-20 bytes, shorter than the vector width, so the
SIMD path barely engages and per-call overhead dominates. That is roughly
100,000 short searches per batch.

zimdjson's `indexer.zig` does one pass per document, producing bitmasks of
every structural character, after which field navigation is bit manipulation.

**Measured afterwards, on a different target than this section proposed.** The
win was not in `FieldWalker`'s scanning at all. On GCP-shaped logs the real
cost is `ensureUnwrapped`, 68.5% inclusive, of which `flattenValue` is 58.0%:
answering "does the body match" materialized every string leaf of the wrapped
document into a hash map. Navigating straight to `data.jsonPayload` and
reading only its immediate fields gives:

| | latency | throughput |
|---|---|---|
| baseline | 12.56 ms | 1,003 req/s |
| direct lookup | 8.80 ms | 1,415 req/s |

−30% latency, +41% throughput. The `FieldWalker` scanning shape described
above remains untested.

### 3. Index the whole batch at once — rejected

The purest simdjson shape indexes the entire 4 MB decoded batch once instead
of per record. It requires the whole document resident, which is exactly the
memory tradeoff removed from #274 at review. It trades back the property this
codebase is built around. Not recommended.

## Read the existing comments first

`src/signals/json_scan.zig` is tuned, and its header says so. The per-record path avoids
zimdjson deliberately ("Single-pass zero-copy parse for the per-record eval
path — no zimdjson", `src/signals/datadog/log.zig:129`), and that header records a
measured decision to accept raw control bytes because rejecting them costs
10-15% per record (lines 14-21, repeated at line 432). Assume these choices had reasons.

`bench/datadog/` has `datadog-log-bench`, a log-eval matrix with a `--profile`
mode and a `wrapped_log.json` payload wired in at `build.zig:283`. That is the
right harness for items 1 and 2: it isolates record evaluation from HTTP,
gzip, and the upstream.

## What the measurements changed

Both items in this section were written before they were measured, and both
guesses were wrong in instructive ways. Item 1 targeted a setup cost that a
lazy parser does not have. Item 2 aimed at the per-field scanning when the
real cost was eager materialization one layer up. The profile pointed at
`flattenValue` in both cases; the prose did not read it closely enough.

Profile first, and read inclusive time before picking a target.

## Loose end

`src/frontend/exec.zig:207` says the per-record prefilter port is "tracked in
TODO.md". **There is no TODO.md in this repo.** That work — short-circuiting
evaluation per record even when policies are loaded — is referenced nowhere
else. It needs a real home, or the comment needs to stop pointing at a file
that does not exist.
