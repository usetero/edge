# Edge Tail Implementation Plan

## Scope and Sequencing

### 1) Define v1 scope (1-2 days)

- Lock v1 scope to:
  - watcher
  - line reader
  - stream eval bridge
  - output writer
  - checkpoint store
  - CLI
- Explicitly defer to v2+:
  - io_uring fast path
  - splice pass-through
  - custom SIMD scanner
  - multiline aggregation
  - network sinks
- Decision: start with raw inotify/kqueue abstraction (pluggable for later
  engine backends).

### 2) Create module boundaries (2-3 days)

- `src/tail/watcher.zig`
- `src/tail/reader.zig`
- `src/tail/eval_stream.zig`
- `src/tail/writer.zig`
- `src/tail/checkpoint/{map,wal,ttl_store,recovery,compact}.zig`
- `src/cmd/edge_tail.zig` (or equivalent main entrypoint)

### 3) Implement hot path first (week 1)

- Single-threaded loop first:
  - file change event -> read delta -> split lines -> eval -> emit output
- Bounded queue only where needed (reader -> checkpoint writer).
- Track per-file state:
  - `(dev, ino, fingerprint, offset, remainder, line_no, last_seen_ns)`

---

## Detailed Steps 4+

### 4) File lifecycle and rotation correctness (week 1-2)

#### Goal

Guarantee robust behavior across file creation, deletion, and rotation
strategies while preserving at-least-once semantics.

#### 4.1 Discovery and registration

- Inputs:
  - file paths and/or glob patterns
- Maintain:
  - `path -> tracked file`
  - `(dev, ino) -> tracked file` identity map
- Re-evaluate globs on interval (`--glob-interval`, default 5s).
- On new match:
  - open file
  - stat for `(dev, ino, size)`
  - compute fingerprint window
  - initialize offset from `--read-from` (`head|tail|checkpoint`)

#### 4.2 Rename + create rotation

- Detect old file moved/replaced and new file created at original path.
- Behavior:
  - keep old FD alive up to `--rotate-wait` seconds
  - drain trailing bytes from old FD
  - open new path at offset 0
  - register new identity `(dev, ino)`
- Ensure no duplicated tracking entries for same identity.

#### 4.3 Copytruncate rotation

- Detect truncation when `tracked.offset > current_stat.size`.
- Behavior:
  - reset offset to 0
  - continue reading same path/FD as needed
  - preserve line framing state safely

#### 4.4 Inode reuse protection

- On open/reopen:
  - verify `(dev, ino)` and fingerprint
- If inode same but fingerprint changed:
  - treat as new file
  - reset offset to 0

#### 4.5 Failure handling

- If file disappears:
  - keep track entry but close FD
  - retry open on future polls/events
- If permissions change:
  - log + backoff retry
- Never crash event loop for single-file errors.

#### 4.6 Acceptance criteria

- Integration tests:
  - rename/create -> no gap, no stuck FD
  - copytruncate -> resumes at 0, no panic
  - delete/recreate -> resumes correctly
  - inode reuse simulation -> stale offset not reused

---

### 5) Checkpoint subsystem (week 2)

#### Goal

Persist offsets durably without blocking the hot read path.

#### 5.1 Data model

- `FileIdentity`:
  - `dev`, `inode`, `fingerprint`, `fingerprint_offset`
- `PositionState`:
  - `byte_offset`, `last_seen_size`, `last_seen_ns`, `lsn`

#### 5.2 Storage layout

- `checkpoint.map`
  - fixed header + fixed slot array
  - slot contains identity + position + checksum + seqlock sequence
- `checkpoint.wal`
  - append-only records with `lsn`, timestamp, identity hash, slot idx, offset,
    checksum

#### 5.3 Write pipeline (background thread)

- Reader thread pushes updates into bounded SPSC queue.
- Checkpoint thread:
  - append WAL entry
  - `fdatasync(wal)`
  - update map slot under seqlock
  - `msync(MS_ASYNC)` map page
  - `ttl_store.touch(identity_hash, now_ns)`

#### 5.4 Recovery

- Startup:
  - scan WAL backward for latest valid per identity
  - validate checksums
  - rebuild stale/corrupt slots from WAL
  - keep valid slots if consistent
- After successful recovery:
  - compact map
  - truncate WAL

#### 5.5 TTL and slot reuse

- In-memory:
  - min-heap by `last_seen_ns`
  - hashmap `identity_hash -> entry`
  - bitset for free slots
- Periodic eviction:
  - pop expired entries (`--checkpoint-ttl`)
  - zero slots
  - mark slots free

#### 5.6 Crash-safety tests

- Kill process between:
  - WAL append and fsync
  - fsync and map update
  - odd seqlock begin/end
- Validate:
  - no corruption panic
  - replay to latest valid LSN
  - at-least-once preserved

#### 5.7 Acceptance criteria

- Deterministic recovery test suite.
- Queue backpressure does not block reader loop.
- WAL compaction works under churn.

---

### 6) CLI and configuration (week 2)

#### Goal

Expose all v1 controls cleanly and predictably.

#### 6.1 Required flags

- I/O and parsing:
  - `-o, --output`
  - `--read-from`
  - `--read-buf`
  - `--max-line`
  - `-f, --format` (raw/json/logfmt)
- Discovery/lifecycle:
  - `--glob-interval`
  - `--rotate-wait`
- Checkpointing:
  - `--state-dir`
  - `--checkpoint-interval`
  - `--checkpoint-ttl`
  - `--max-slots`
- Runtime:
  - `--io-engine`
  - `-v, --verbose`

#### 6.2 Config loading

- Support config file + env + CLI precedence:
  - `CLI > env > config > defaults`
- Print effective startup configuration in verbose mode.

#### 6.3 UX and validation

- Validate incompatible combinations early.
- Return actionable error messages (missing file, invalid enum value, etc).
- Keep `-` meaning stdout for output and optional stdin mode if enabled.

#### 6.4 Acceptance criteria

- `--help` complete and accurate.
- Invalid inputs fail fast with clear message.
- Default run path works with minimal args.

---

### 7) Test and harden (week 3)

#### Goal

Catch correctness regressions before performance tuning.

#### 7.1 Integration matrix

- Rotation:
  - rename/create
  - copytruncate
- Framing:
  - partial line across chunk boundaries
  - oversized line truncation
  - EOF without trailing newline
- Recovery:
  - restart from checkpoints
  - corrupted WAL entries skipped
- Throughput sanity:
  - 1 file high-rate append
  - 100 files mixed append

#### 7.2 Fault injection

- Simulate:
  - intermittent open/stat failures
  - delayed fsync
  - queue saturation
- Assert:
  - no deadlocks
  - no unbounded memory growth
  - graceful degradation

#### 7.3 Metrics to capture in tests

- lines/sec
- p50/p99 end-to-end latency
- dropped checkpoint updates count
- RSS and allocator high-water mark

#### 7.4 Acceptance criteria

- Green CI on Linux and macOS.
- Reproducible integration harness.

---

### 8) v1 performance pass (week 3-4)

#### Goal

Hit v1 targets with current architecture before adding v2 complexity.

#### 8.1 Profile-first

- Measure:
  - syscall counts per line
  - allocator calls on hot path
  - lock contention (if any)
- Tools:
  - perf/dtrace/instruments depending on platform

#### 8.2 Tuning knobs

- Read buffer size (`--read-buf`)
- Output flush interval/threshold
- Poll/watch intervals
- Checkpoint flush interval

#### 8.3 Hot-path rules

- No per-line allocations in steady state.
- Keep copies minimal and bounded.
- Avoid synchronous checkpoint I/O in reader thread.

#### 8.4 Acceptance criteria

- Meets baseline targets for v1:
  - single-file throughput target
  - acceptable memory envelope
  - low idle CPU in watch mode

---

### 9) v2 preparation hooks (parallel track)

#### Goal

Avoid redesign when adding io_uring and advanced fast paths.

#### 9.1 Abstractions to keep stable

- `IoEngine` interface:
  - `auto|uring|epoll|kqueue`
- Reader API should support batched completion model.
- Writer API should permit future `writev`/splice optimizations.

#### 9.2 Data-flow contracts

- Keep line framing and eval boundaries explicit.
- Keep per-file state independent for future file-level parallelism.

#### 9.3 Acceptance criteria

- v1 code paths remain simple.
- v2 can be added mostly behind engine/writer backends.

---

### 10) Merge exit criteria

#### Required before merge

- CI passing on supported platforms.
- Recovery/fault-injection tests passing.
- Benchmarks and methodology recorded.
- Documentation added:
  - architecture
  - operational tuning guide
  - known limitations
  - v2 roadmap and non-goals

#### Deliverables

- runnable `edge-tail` binary
- test harness scripts
- sample config + CLI docs
- benchmark report with baseline numbers
