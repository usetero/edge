# tail

Performance migration modules for `edge-tail`.

Architecture:

- `types.zig`: shared config and enums (`ReadFrom`, `IoEngine`).
- `io.zig`: `std.Io.Reader`/`std.Io.Writer` endpoint wrappers.
- `watch.zig`: data-oriented watcher with enum backend dispatch (`poll`,
  `inotify`).
- `read_scheduler.zig`: batched read execution surface.
- `framer.zig`: incremental line framing with max-line capping.
- `checkpoint.zig`: async checkpoint lane with non-blocking enqueue.
- `runtime.zig`: orchestrates watcher -> read batch -> framer -> sink flush.

Perf-focused properties:

- no vtable polymorphism; enum/union dispatch only
- hot/cold watcher state split (SoA style)
- dirty-file dedupe bitset + queue
- optional Linux inotify event path
- no per-iteration allocation in framer pump
- timed + threshold-based output flushing

Current caveat:

- checkpoint lane is asynchronous and in-memory for now; durable WAL/map
  persistence is planned as the next increment.
