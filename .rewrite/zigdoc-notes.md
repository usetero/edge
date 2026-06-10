# zigdoc findings for the 0.16 rewrite

Record every verified std API here with the zigdoc snippet that justifies it.

## std.Io.Threaded (verified 2026-06-10, zig 0.16.0)
- `Threaded.init(gpa: Allocator, options: InitOptions) Threaded`; gpa must be
  thread-safe and is used ONLY for async/concurrent/group closures (per-task
  closure allocation happens inside the Io impl — above our data plane).
- `pub const init_single_threaded: Threaded` — concurrent() fails with
  error.ConcurrencyUnavailable; cancel requests are no-ops; deinit optional.
- `t.io()` returns the Io interface; Threaded installs SIGIO/SIGPIPE handlers
  so blocking syscalls are interruptible (cancellation mechanism).
- InitOptions: stack_size, async_limit: ?Io.Limit (default cpu_count-1),
  concurrent_limit: Io.Limit, environ, argv0, disable_memory_mapping.

## std.Io.Group (verified 2026-06-10)
- Fields: token, state. Constants: `init`. Fns: async/concurrent/await/cancel.
- `Group.concurrent(g: *Group, io: Io, function: anytype, args: ArgsTuple) ConcurrentError`
- Task fn return type must coerce to `Cancelable!void`. Returning error.Canceled
  is a propagation boundary (absorbed).
- CRITICAL: `Group.async` tasks are "not guaranteed to run until Group.await or
  Group.cancel is called" → connection tasks MUST use Group.concurrent;
  error.ConcurrencyUnavailable is a load-shed signal (503).
- Per-task resources released when the task returns (long-lived groups OK).
