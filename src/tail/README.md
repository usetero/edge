# edge-tail Architecture

This document explains how the `edge-tail` binary is structured today and how
data moves through the system.

## Entry point

`edge-tail` is orchestrated in
[src/edge_tail_main.zig](/Users/jea/Code/tero/edge/src/edge_tail_main.zig).

Main responsibilities:

- Parse CLI flags and validate combinations.
- Load config with `zonfig` (precedence: CLI > `TERO_*` env > config file >
  defaults).
- Choose stdin mode or file-tail mode.
- Initialize tail submodules (`glob`, `watcher`, `reader`, `checkpoint`).
- Run the poll/read/write loop.

## High-level pipeline

File mode is a polling pipeline:

1. Expand input paths/patterns via
   [glob.zig](/Users/jea/Code/tero/edge/src/tail/glob.zig).
2. Track open files and offsets via
   [watcher.zig](/Users/jea/Code/tero/edge/src/tail/watcher.zig).
3. Read byte ranges and frame lines via
   [reader.zig](/Users/jea/Code/tero/edge/src/tail/reader.zig).
4. Write emitted lines to output (`stdout` or file) from `edge_tail_main`.
5. Enqueue offset checkpoints to
   [checkpoint/store.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/store.zig).

Stdin mode bypasses watcher/glob and directly feeds stdin bytes into
`LineReader`.

## Module breakdown

### glob

[glob.zig](/Users/jea/Code/tero/edge/src/tail/glob.zig)

- Detects glob patterns (`*`, `?`, `[]`).
- Expands patterns against directory entries.
- Preserves explicit non-glob paths.

### watcher

[watcher.zig](/Users/jea/Code/tero/edge/src/tail/watcher.zig)

- Owns tracked files (`path`, open fd, identity, offset).
- Polls each tracked file and emits
  `FileEvent { index, start_offset, end_offset }`.
- Handles rotation:

1. `rename + create`: keeps pending replacement fd and switches after
   drain/grace (`rotate_wait_ms`).
2. `copytruncate`: detects `size < offset` and resets offset to `0`.

- Supports path reconciliation for glob refresh:

1. add newly discovered paths
2. mark unseen paths
3. expire unseen paths after `removed_expire_ms`

- Exposes identity for checkpoint keys (`dev`, `inode`, fingerprint).

### reader

[reader.zig](/Users/jea/Code/tero/edge/src/tail/reader.zig)

- Uses `pread`-based range reads (`readRange`) into a reusable buffer.
- Splits on `\n` and emits complete lines.
- Carries partial trailing bytes between chunks (`remainder`).
- Enforces `max_line` cap to prevent unbounded line growth.
- `finish` flushes a final unterminated line at stream end (stdin mode).

### checkpoint store

[checkpoint/store.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/store.zig)

- Accepts async offset updates via enqueue from the hot path.
- Persists state using:

1. mmap slot map:
   [checkpoint/map.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/map.zig)
2. append-only WAL:
   [checkpoint/wal.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/wal.zig)
3. TTL index:
   [checkpoint/ttl.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/ttl.zig)
4. shared structs/checksums:
   [checkpoint/types.zig](/Users/jea/Code/tero/edge/src/tail/checkpoint/types.zig)

- Recovers from WAL on startup and compacts periodically.

## Runtime loop behavior

In file mode, the main loop in `edge_tail_main` does:

1. Periodically refresh glob matches (`glob_interval_ms`) and reconcile tracked
   files.
2. Poll watcher for new byte ranges.
3. For each event, read `[start_offset, end_offset)` and emit lines.
4. Enqueue checkpoint update for the file identity and new offset.
5. Flush output when events were emitted.
6. Sleep for `poll_ms`.

This is intentionally simple and single-threaded on the read path. Checkpoint
durability is moved off the hot path via background work inside
`CheckpointStore`.

## Current scope and non-goals

Implemented now:

- Functional tailing from files and stdin.
- Rotation handling (`rename+create`, `copytruncate`).
- Glob discovery and removed-path expiration.
- Checkpoint persistence/recovery.

Not implemented yet:

- Streaming policy evaluation (`eval_stream` bridge).
- `io_uring` fast path and zero-copy splice optimizations.
- Multi-sink/network output.

## Test strategy

Public API unit tests live with each Zig module under `src/tail`.

Integration coverage for end-to-end behavior lives in:

- [bench/logging](/Users/jea/Code/tero/edge/bench/logging)

Run integration tests:

```bash
task benchmark:logging
```
