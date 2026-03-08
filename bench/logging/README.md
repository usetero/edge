# Logging Integration Tests

Black-box integration tests for `edge-tail` live under `bench/logging/tests` and
are run with `pytest` via `uv`.

## Run

```bash
./bench/logging/run.sh
```

Or directly:

```bash
uv run --project bench/logging pytest bench/logging/tests
```

## Test layout

- `test_startup_positions.py`: startup semantics (`head`, `tail`, `checkpoint`)
- `test_transport_modes.py`: stdin/file input and stdout/file output paths
- `test_line_framing.py`: partial lines, empty lines, max-line boundaries
- `test_rotation_lifecycle.py`: rename/create, copytruncate, delete/recreate,
  missing/reappear
- `test_glob_behaviors.py`: overlap, discovery, re-match, large directory scans
- `test_checkpoint_recovery.py`: clean restart, `SIGKILL`, WAL corruption, TTL,
  slot pressure
- `test_output_contract.py`: ordering and output-file behavior contracts
- `test_error_handling.py`: invalid args and permission failures
- `test_concurrency_stress.py`: concurrent writers, bursts, tiny writes, short
  soak rotation
- `test_perf_guards.py`: burst latency and multi-file throughput guardrails
- `test_benchmark_metrics.py`: sustained benchmark profiles with:
  - proc-time CPU%
  - RSS distribution
  - throughput distribution (logs/sec)
  - latency distribution (ms)
  - input/output integrity checks (loss/dup)
  - stdin stress profile (`cat` of 1,000,000-line file)
  - `EDGE_TAIL_STDIN_LINES` env var to scale stdin stress size

## Notes

- The session fixture builds `edge-tail` once with `zig build tail`.
- Each test uses its own temporary directory and file set.
- Test stderr from `edge-tail` is captured per test to simplify failure
  debugging.
- Benchmark metric report uses scaling-style run folders:
  `bench/logging/results/<YYYY-MM-DDTHH-MM-SS>/logging_metrics.json`.

## Benchmark numbers

Run only benchmark metrics tests:

```bash
uv run --project bench/logging pytest -s tests/test_benchmark_metrics.py
```

Progress bars are rendered by `tqdm` during sustained benchmark execution.

Then inspect:

```bash
ls -1dt bench/logging/results/* | head -n1
cat "$(ls -1dt bench/logging/results/* | head -n1)/logging_metrics.json"
```

Report includes per-profile:

- `logs_per_sec_avg`
- `cpu_avg_pct_proc_time`
- `throughput_lps_dist` (`avg/p50/p95/p99/min/max`)
- `latency_ms_dist` (`avg/p50/p95/p99/min/max`)
- `rss_mib_dist` (`avg/p50/p95/p99/min/max`)
- `lines_in_total` vs `lines_out_total`
- `duplicates_out`, `bad_lines_out`

## Persistent workload for Instruments (macOS)

Use this when you want a long-running steady workload and manually attach Apple
Instruments CPU Profiler.

```bash
task benchmark:logging:persistent
```

Common overrides:

```bash
task benchmark:logging:persistent FILES=1 TARGET_LPS=12000 FORMAT=raw IO_ENGINE=kqueue
task benchmark:logging:persistent FILES=12 TARGET_LPS=18000 FORMAT=raw IO_ENGINE=auto
task benchmark:logging:persistent FILES=1 TARGET_LPS=10000 FORMAT=json DROP_50PCT=1
```

The runner prints:

- `pid` for `edge-tail` (attach this in Instruments)
- `work_dir` with generated input files and `persistent.err`
- rolling sent-line counters and average LPS

Optional finite run:

```bash
task benchmark:logging:persistent DURATION_S=120
```
