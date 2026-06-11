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

## Phase 2 findings
- 0.16 std has BOTH flate.Compress and flate.Decompress (compression is back)
  with .raw/.gzip/.zlib containers, plus zstd.Decompress. Only zstd ENCODE
  needs libzstd (ZSTD_compressStream2 behind a custom Writer drain).
- flate.Compress.init asserts inner writer buffer > 8 bytes; flate buffers
  must be >= flate.max_window_len (64 KiB); zstd decode buffer >=
  window_len + zstd.block_size_max (128 KiB); Options.window_len is u32.
- Reader.stream returning 0 does NOT mean EOF (vtable contract); loop until
  error.EndOfStream.
- LATENT BUG found & fixed in compress_buffered.zig (NOT in old proxy copy):
  decompressGzip only updated total_out on Z_BUF_ERROR; Z_OK with a full
  output buffer (multi-block streams from any *streaming* gzip compressor)
  rewound next_out to 0 and overwrote earlier output. Old tests never caught
  it because one-shot-compressed fixtures decode in a single inflate call.

## Phase 5 net/http server APIs (verified)
- net: `IpAddress.parse(text, port)`; `address.listen(io, options) !net.Server`;
  `server.accept(io) !Stream`; `Stream.Reader.init(stream, io, buf)` /
  `Stream.Writer.init(...)` each expose `.interface`; `stream.close(io)`.
- std.http.Server: `init(in: *Io.Reader, out: *Io.Writer)` — plain reader/writer,
  no net dependency. `receiveHead() !Request`.
- Request.Head: method, target, version, content_type, content_length,
  transfer_encoding, transfer_compression (http.ContentEncoding), keep_alive.
  Head.parse can fail CompressionUnsupported/UnknownHttpMethod/etc.
- Body in: `request.readerExpectContinue(buffer)` (handles 100-continue) /
  `readerExpectNone(buffer)`. Body out: `request.respond(bytes, options)` or
  `request.respondStreaming(buffer, .{ .content_length = null → chunked })`
  returning http.BodyWriter (has .writer iface; must call .end() then flush).
- HEAD handled transparently via eliding BodyWriter.
- `request.iterateHeaders()` for header passthrough.
