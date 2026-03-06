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

## Notes

- The session fixture builds `edge-tail` once with `zig build tail`.
- Each test uses its own temporary directory and file set.
- Test stderr from `edge-tail` is captured per test to simplify failure
  debugging.
