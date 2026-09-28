# Edge redesign — working notes

Purpose: hand-off notes for the from-scratch redesign of Tero Edge. Read this
first if you pick up the work. `proposal.md` is the polished output. This file
is the raw trail: facts verified, decisions made, open questions.

Status legend: `[fact]` verified against code or docs, `[decision]` design
choice made, `[open]` unresolved, `[todo]` work item.

**Review update:** Read §13 first. Earlier sections are historical and contain
superseded assumptions about snapshot safety, allocation, routes, durability,
and defaults. The revised [proposal.md](proposal.md) is the current design.

## 0. Ground rules from the user (2026-09-11)

- Design from scratch. Same features as today's edge. Zig 0.16 only.
- Pass `io: std.Io` and `allocator` everywhere. "Juicy main"
  (`pub fn main(init: std.process.Init) !void`).
- Data-oriented design. TigerBeetle style where it fits; diverge where our
  needs differ (we are a proxy, not a database).
- Test-driven development.
- Performance and minimal memory. Prefer the stack. Predictable footprint.
- Use `policy-zig` unchanged. Use `zonfig` (src/zonfig) unchanged.
- Strong fail-open semantics. Durability matters.
- Use the OS as much as possible (epoll, kqueue, io_uring, sendfile, mmap...).
- Output: `proposal.md` with architecture diagram and tradeoffs.

## 1. Repository facts

- `[fact]` Toolchain: `./bin/zig` = 0.16.0 (hermit). Std lib at
  `/Users/jea/Library/Caches/hermit/pkg/zig-0.16.0/lib/std`.
- `[fact]` Deps in `build.zig.zon`: zimdjson (SIMD JSON), metrics.zig, httpz
  (current inbound frontend), zbench, policy_zig 0.7.1. Links libc, `z`, `zstd`.
  Vectorscan (hyperscan) comes through policy_zig.
- `[fact]` Six binaries: `edge` (full), `edge-datadog`, `edge-otlp`,
  `edge-prometheus`, `edge-tail`, `edge-lambda`. Build option `-Dfrontend=httpz|stdio`.
- `[fact]` Deploy targets: Alpine/musl Docker image (static vectorscan),
  Kubernetes DaemonSet with hostPort 8080 (chart requests 32Mi, limit 512Mi),
  ECS/Fargate sidecar next to the Datadog agent, AWS Lambda layer (arm64 and
  amd64). Dev on macOS arm64. CI builds linux amd64/arm64 on GitHub runners
  with `-Dcpu=baseline`.
- `[fact]` Config: JSON file loaded by zonfig. `TERO_`-prefixed env vars override
  whole fields. `${VAR}` inside the file substitutes from the environment.
  Existing config files in the repo root must keep loading.
- `[fact]` Policy providers: `file` (path) and `http` (url, headers,
  poll_interval_secs, content_type). Loader is async; server starts before
  policies arrive.

## 2. History that shapes the redesign

Two rewrites already happened. Their lessons are binding input.

- `[fact]` 2026-06 rewrite (PLAN.md): moved everything to `std.Io`, built a
  std.Io-native HTTP server on `Io.Threaded`. Result at `oha -c 150`: 40.7k rps
  and 145 MB RSS versus httpz 80k rps and 10 MB. Cause: `Io.Threaded` runs one
  OS thread per blocking task, so one thread per connection. 154 threads, each
  dirtying ~515 KiB of stack, never reaped. All 150 threads parked in
  `http.Client.Request.receiveHead` waiting on the upstream.
- `[fact]` 2026-06 frontend swap (PLAN-FRONTEND-SWAP.md): inbound went back to
  httpz (event loop + 32 handler threads). Ceiling then: the synchronous
  upstream round trip occupies the handler threads (~0.49 ms per request).
  Both frontends hit ~64k rps at 0 policies.
- `[fact]` Bench today (bench/scaling 2026-09-11, `-c 50`, 50k requests):
  ~71k rps at 0 policies, 24 MB RSS. At 4000 policies: ~55-67k rps, 82-87 MB
  RSS. RSS growth is the hyperscan database plus per-thread codec scratch.
- `[fact]` Verified in the 0.16.0 std sources (2026-09-11): `std/Io/` holds
  `Threaded.zig`, `Kqueue.zig` (1520 lines, fiber M:N scheduler, 4 MiB stack
  reserve per fiber), `Uring.zig` (6118 lines), `Dispatch.zig` (5022 lines).
  There is no `Evented.zig` and no epoll backend. `Uring` and `Dispatch` mark
  every `net*` op as Unavailable. `Kqueue` implements `netRead`/`netWrite`
  but `netListenIp`, `netAccept`, and `sleep` are `@panic("TODO")`. So no std
  backend can serve sockets without one OS thread per blocking task in
  0.16.0. The `Io.VTable` has about 130 operations.
- `[fact]` `Io.Threaded` maps `EAGAIN` on socket read/write to
  `error.WouldBlock` (Threaded.zig around lines 10747 and 10909). A reactor
  can therefore use nonblocking sockets and call std ops only when ready,
  but the std `Stream.Reader` will surface `WouldBlock` as a failure, not a
  suspension. Raw `recv`/`send` in the reactor is simpler.
- `[fact]` Known posture change from the 0.16 rewrite: `std.http.Server` rejects
  unknown Content-Encoding at head parse (400). The old httpz stack forwarded
  exotic encodings opaquely.
- `[fact]` Streaming coverage today: datadog logs (JSON array), OTLP protobuf,
  prometheus text, passthrough stream. Datadog metrics (object body) and OTLP
  JSON (object body) buffer the whole body.
- `[fact]` Upstream pool poisoning bug class exists (ziglang/zig#30165, stale
  keep-alive). Fix today: evict and retry replayable intake requests.
- `[fact]` Fail-open rules already normative (PLAN.md §6.5): parse error keeps
  the raw record, framer desync copies the remainder through, oversized record
  passes through unfiltered, engine error means keep, upstream write error
  means 502.

## 3. Decisions so far

- `[decision]` Inbound must not be thread-per-connection. Use a fixed set of
  worker threads (default = CPU count, min 1) that each run a readiness loop
  over nonblocking sockets. Connection state lives in a slab indexed by
  `ConnId` (SoA). This is the only way to keep RSS flat at 150+ connections
  on 0.16 std.
- `[decision]` `io: std.Io` still flows everywhere for files, timers, sleep,
  mutexes, the policy loader, and tests. The socket readiness loop is the one
  place that talks to the OS directly (epoll, kqueue, io_uring when allowed).
  Reason: std has no evented networking in 0.16.0.
- `[decision]` The Docker default seccomp profile blocks io_uring, and Lambda
  and Fargate kernels do not offer it. io_uring is an opt-in fast path on
  Linux with runtime probe and epoll fallback. epoll is the Linux default.
  kqueue on macOS. Never fail startup because a backend is missing.
- `[decision]` Upstream forwarding must not hold an inbound worker for the
  upstream round trip. See §5 for the two forwarding modes.
- `[decision]` No custom `std.Io` implementation and no fibers. Reasons: the
  vtable has ~130 ops and tracks every Zig release; fibers hide control flow
  and cost dirty stack per connection (the measured failure mode of the 2026-06
  rewrite). Instead: reactor threads with explicit per-connection state
  machines (TigerBeetle style), one shard of the connection slab per reactor.
  When std ships an evented Linux backend with networking, the reactor is the
  single file to replace.
- `[decision]` Process a request inline on the reactor thread once its body
  is complete. Bodies are bounded (`max_body_size`, `max_decoded_bytes`), so
  buffering is the fast path (httpz measured fastest with buffered bodies).
  Per-reactor scratch (decode, encode, hyperscan) is allocated once and
  reused because processing is serial per reactor. This makes memory
  `reactors x scratch + connections x small_buffer + body_pool`, all
  closed-form.
- `[decision]` Upstream leg runs on a bounded forwarder thread pool that does
  blocking I/O through `io` (`Io.Threaded`) with std TLS. Completion returns
  to the owning reactor through eventfd (Linux) or `EVFILT_USER` (kqueue).
  Reactors never block on the network.
- `[decision]` One listener socket per reactor with `SO_REUSEPORT` on Linux
  so the kernel balances accepts. macOS: single listener, accept on reactor
  0, hand off by connection id (dev only).
- `[decision]` Own HTTP/1.1 parser (request head, chunked, content-length,
  100-continue, keep-alive) and own upstream HTTP/1.1 client over
  `std.Io.net.Stream` + `std.crypto.tls.Client`. Reasons: a proxy must pass
  unknown headers and encodings through opaquely; `std.http.Server` rejects
  unknown Content-Encoding; `std.http.Client` pool poisoning (zig#30165)
  already forced eviction hacks. The parser is pure over byte slices, so it
  is unit-testable and fuzzable without sockets.

## 4. Open questions

- `[open]` Does `Io.Threaded` return `error.WouldBlock` for reads on an
  O_NONBLOCK socket, or does it retry? Determines whether the reactor can call
  `std.Io.net.Stream.read(io, ...)` on ready sockets or must call `recv` itself.
- `[open]` Exact `std.http.Client` pool behavior and whether it can be driven
  with nonblocking sockets. If not, the upstream path needs its own HTTP/1.1
  client over the reactor.
- `[open]` TLS to upstream inside a readiness loop: `std.crypto.tls.Client`
  pulls from a `*std.Io.Reader`. Need a driver that feeds it only when the
  socket is readable.

## 5. Forwarding modes (draft)

- Relay: synchronous proxy, client sees the upstream status. Required for
  Prometheus scrapes and for parity on every route today.
- Spool: accept, evaluate, append to an on-disk queue, ack 202, forward from
  the queue with retries. Durable across upstream outages and restarts. Opt-in
  per route. Uses mmap, fdatasync, and sendfile (plaintext upstream only).

## 6. Log of agent explorations

- 2026-09-11: launched four Explore agents: policy-zig API, HTTP data plane
  inventory, tail + lambda inventory, Zig 0.16 std Io survey. Results are
  summarized in §7 onward when they arrive.

## 7. Inventory: edge-tail (from src/tail, agent report 2026-09-11)

- `[fact]` Precedence CLI > `TERO_*` env > config file > defaults. Config type
  `TailConfig` (src/tail/types.zig:51-72) loaded by zonfig with
  `.env_prefix = "TERO"`, `.allow_env_only` when no config path.
- `[fact]` Defaults: poll_ms 200, glob_interval_ms 5000, rotate_wait_ms 5000,
  removed_expire_ms 60000, checkpoint_interval_ms 5000, checkpoint_sync_batch
  64, checkpoint_snapshot_interval_ms 60000, checkpoint_ttl_ms 72h,
  checkpoint_max_slots 256, state_dir `.tero`, read_buf 64 KiB, max_line
  256 KiB, write_buf 64 KiB, flush_interval_ms 100, flush_lines 1024,
  read_from tail|head|checkpoint, format raw|json|logfmt, io_engine
  auto|uring|kqueue|poll|inotify|epoll, output `-` (stdout) or append file.
- `[fact]` Modes: stdin (single thread, no checkpoint) or files/globs. Globs
  are single-directory, `*` and `?` only (`[...]` detected but not matched).
- `[fact]` Watch backends: poll (stat compare), Linux inotify read through a
  64-entry io_uring POLL_ADD->READ chain with per-file and per-dir watches,
  macOS kqueue EVFILT_VNODE. Read schedulers: io_uring with registered
  buffers (256 x 64 KiB = 16 MiB scratch) on Linux, scalar pread elsewhere.
  The main loop still sleeps `poll_ms` each tick, so poll_ms is the latency
  floor for every engine.
- `[fact]` Rotation: identity = (dev, inode, CRC32 of first 1 KiB). Path
  inode change -> pending file; switch when old file drained and
  rotate_wait elapsed. Truncate: size < offset -> offset 0. Rewrite: FNV-1a
  of first 64 bytes changes -> offset 0. Output path is never tracked.
- `[fact]` Framing: newline only, SIMD scan (pipeline/frame_ndjson.zig).
  Lines > max_line pass through verbatim, unevaluated (fail open). No
  multiline.
- `[fact]` Policy eval: file provider only, loaded once, no reload. Accessor
  exposes body, severity_text, flat log attributes. Transforms cannot change
  output bytes (sink is keep/drop only).
- `[fact]` BUG to fix in redesign: eval or parse error fails CLOSED and
  terminates the process (one malformed JSON line under `-f json` kills tail).
- `[fact]` Checkpoint: WAL of 64-byte CRC32 records ("WWAL" magic), snapshot
  file with atomic rename ("CPKS"), in-memory maps by (dev,inode,fingerprint)
  and (dev,inode), TTL at read, fsync on batch/interval, snapshot truncates
  the WAL. Queue capacity hardcoded 4096, drops silently when full. Worker
  is a lifecycle task that wakes at >=100 Hz. At-least-once semantics.
- `[fact]` Coverage gaps: no tests for rotation, copytruncate, rewrite,
  glob match, eviction, uring/kqueue backends, checkpoint resume end to end.

## 8. Inventory: Lambda extension (agent report 2026-09-11)

- `[fact]` It is the Datadog proxy plus Extensions API lifecycle. No Telemetry
  API subscription exists. Function or Datadog library POSTs intake traffic
  to 127.0.0.1:port; edge filters and forwards.
- `[fact]` Extensions API: register (INVOKE, SHUTDOWN), blocking
  `/event/next` with no timeout, poll errors are logged and retried. On
  INVOKE: flush s3-dump extension (sandbox freeze makes wall-clock flush
  unreliable). On SHUTDOWN: flush, `loader.close()` (sends policy stats),
  stop server, flush again. `deadline_ms` is parsed but never enforced.
- `[fact]` Config is env only (`LambdaConfig`, zonfig, no JSON file):
  TERO_LISTEN_ADDRESS 127.0.0.1, TERO_LISTEN_PORT 8080, TERO_UPSTREAM_URL,
  TERO_LOGS_URL, TERO_METRICS_URL, TERO_MAX_BODY_SIZE 5 MiB,
  TERO_MAX_DECODED_BYTES, TERO_MAX_CONNECTIONS 256, TERO_WORKER_COUNT,
  TERO_THREAD_POOL_COUNT (128 default), TERO_SERVICE_NAME/NAMESPACE/VERSION,
  TERO_POLICY_STATIC (inline JSON), TERO_POLICY_URL, TERO_POLICY_POLL_INTERVAL
  60, TERO_POLICY_API_KEY, TERO_LOG_LEVEL, TERO_S3_DUMP_ENABLED,
  TERO_S3_DUMP_TARGETS_JSON, TERO_S3_ACCESS_KEY_ID/SECRET/SESSION_TOKEN,
  AWS_LAMBDA_RUNTIME_API (required).
- `[fact]` Packaging: lambda/Dockerfile, Alpine, ReleaseSafe, musl loader
  wrapper script at /opt/extensions/tero-edge exec-ing /opt/bin/tero-edge-bin
  with /opt/lib (libhs, libz, libzstd, libstdc++). Layers published per
  region as Tero-Edge-Extension and Tero-Edge-Extension-ARM.
- `[fact]` Lambda memory pressure: 128 MB functions with max_connections 256
  x per-connection buffers. The redesign's closed-form budget matters most
  here.
- `[fact]` s3-dump extension (policy-zig `extensions` module) batches records
  and flushes to S3; active only when enabled, targets set, and a loaded
  policy carries a `com.usetero/s3-dump` entry. Needs `exts.flush(io, .{})`.

## 9. Inventory: HTTP data plane today (agent report 2026-09-11)

### 9.1 Routes and outcomes
- `[fact]` Service order per distro (src/runtime/distro.zig:14-21): health first,
  passthrough last. edge = health, datadog_logs, datadog_metrics, otlp,
  prometheus, passthrough. datadog = health, dd logs, dd metrics, passthrough.
  otlp = health, otlp, passthrough. prometheus = health, prometheus, passthrough.
- `[fact]` Routes: GET /_health (200 `{"status":"ok"}`); POST /api/v2/logs
  (upstream `.logs`, JSON array stream, non-JSON or unknown codec ->
  forward_raw replayable); POST /api/v2/series (upstream `.metrics`, buffered
  object body, forward_raw not replayable); POST /v1/{logs,metrics,traces}
  (upstream `.default`, protobuf stream or JSON buffered, replayable only
  for logs); GET /metrics and /metrics/* (upstream `.metrics`,
  fetch_filtered response side); any /* passthrough (`.default`).
- `[fact]` Admin: GET /_edge/metrics (Prometheus text), GET
  /_edge/policies?format=json, GET /_edge/tap/pre|post?n=N gated by
  `tap_enabled` (404 disabled, 409 armed, n clamped 1..1000, 8 MiB cap).
  Policies and tap exist only on the httpz frontend today.
- `[fact]` Upstreams: three ids default/logs/metrics from upstream_url,
  logs_url, metrics_url. URL rebuilt as scheme://host[:port][base][path][?q].

### 9.2 Fail-open matrix and status codes
- 404 unknown route. 413 raw body > max_body_size or decoded >
  max_decoded_bytes. 431 headers too big. 400 corrupt gzip/zstd. 504 upstream
  watchdog 30 s. 503 OOM, shutting down (keepalive false), slab full. 502
  upstream open failure, transport failure after retries, response body >
  limit, any uncaught error.
- Fail open to forward_raw unevaluated: non-JSON content type on DD/OTLP,
  unsupported or multi-value content-encoding (deflate, br, "gzip, deflate"),
  no policies active for the signal (no decode at all).
- Per record: oversized record (> 256 KiB scratch) copied verbatim; framer
  desync copies the rest verbatim; DD log parse failure -> keep; buffered
  transform error -> forward original body (warn).
- Response relay: status verbatim, headers relayed minus content-length and
  transfer-encoding, max 64 headers.

### 9.3 Datadog and OTLP details
- `[fact]` Headers forwarded except host, connection, content-length,
  transfer-encoding. DD-API-KEY passes through. accept-encoding omitted on
  the upstream request. Gap: keep-alive, te, trailer, upgrade, proxy-* are
  not stripped.
- `[fact]` Replayable retry: attempt 0 pooled client, attempt 1 a second
  client with free_size 0. Retryable errors are transport only. Eviction of
  the pooled connection on any failure (workaround for zig#30165 send side).
  Metrics edge_upstream_attempts_total, edge_upstream_retries_total.
- `[fact]` allDropped on buffered paths: respond 200 `{}` without calling
  upstream. Stream path forwards an empty `[]` instead.
- `[fact]` Re-encode in the same codec as the request (gzip via zlib, zstd
  via libzstd with a hardcoded 8-slot CCtx cache).
- `[fact]` OTLP protobuf: one record = one top-level ResourceLogs/Metrics/
  Spans submessage; eval wraps into a one-element Export*Request and
  unwraps. No partialSuccess response is ever synthesized (gap).
- `[fact]` OTLP accessors expose body, trace_id, span_id, string fields,
  log/resource/scope attributes with nested paths, set/delete/move; metrics
  name/description/unit/schema urls/scope, datapoint_attribute,
  aggregation_temporality; traces name/ids/trace_state/scope,
  span_attribute, span_kind, span_status; trace_state is writable for
  sampling threshold writeback.

### 9.4 Prometheus
- `[fact]` Response side streaming filter, 14 KiB scratch (4 KiB line, 2 KiB
  metadata, 8 KiB staging). Per-scrape input/output caps 10 MiB (0 =
  unlimited). Truncation drops the partial trailing line silently, no
  header or metric. Lines > 4 KiB silently truncated. HELP/TYPE emitted only
  when a sample survives. Accessor: name, description (HELP), labels, value,
  timestamp, metric_type.

### 9.5 Memory and threads today
- `[fact]` limits.zig: RECV/SEND/UPSTREAM_WRITE 20 KiB, RECORD_SCRATCH 256 KiB,
  ENCODE 192 KiB, DECODE_SLACK 192 KiB, BODY 8 KiB, CHUNK 4 KiB, zstd window
  clamp(max_body, 256 KiB, 8 MiB), CONN_ARENA_RESERVE 16 KiB, defaults
  max_connections 256, max_body 1536 KiB, max_decoded 16 MiB, handler
  threads 128, request and keepalive timeout 30 s.
- `[fact]` httpz: per-thread lazily grown ThreadBufs retained for life; each
  handler thread owns a whole upstream exchange, so handler count = upstream
  concurrency. stdio: page-aligned ConnSlab with madvise on release, ArenaPool
  per connection, one Io.Group task per connection.
- `[fact]` RLIMIT_NOFILE raised toward 65536 at startup.

### 9.6 Upstream client today
- `[fact]` std.http.Client with connection_pool.free_size = max_connections
  (default 32 exhausted ephemeral ports), TLS buffers =
  max_ciphertext_record_len. No per-request timeout in std; a watchdog task
  polls every 100 ms and shuts down sockets past 30 s.

### 9.7 Config schema (must load unchanged)
- `[fact]` ProxyConfig (src/config/types.zig:95-151): listen_address [4]u8
  dotted (default 127.0.0.1), listen_port u16 8080, upstream_url string
  (http://127.0.0.1:80), logs_url ?string, metrics_url ?string, service
  ServiceMetadata, log_level debug|info|warn|err, max_body_size u32 1572864,
  max_decoded_bytes ?u32, max_connections u32 256, worker_count ?u16,
  thread_pool_count ?u16, tap_enabled bool false, policy_providers
  []ProviderConfig, prometheus.{max_input,max_output}_bytes_per_scrape usize
  10 MiB, s3_dump.{enabled, flush_interval_ms 30000, max_batch_bytes 4 MiB,
  max_batch_records 10000, max_batch_age_ms 30000, max_sealed_bytes 32 MiB,
  max_attempts 1, targets[], targets_json}. validate() rejects zero or
  > 65535 connections, zero body sizes, zero worker or pool counts.
- `[fact]` Env-only knobs: TERO_LOG_LEVEL, TERO_IO_BACKEND, TERO_S3_* creds
  with AWS_* fallback.
- `[fact]` zonfig API: `load(comptime T, allocator, io, LoadOptions{json_path,
  env_prefix, allow_env_only, environ}) LoadError!*T`, `deinit(T, allocator,
  *T)`, env name = UPPER(prefix)_UPPER(field_path joined by _), precedence
  env > JSON > defaults, optionals set to null by empty string, `[N]u8` as
  dotted IPv4, slices of structs not settable by env, `${VAR}` unset expands
  to empty string silently, `$${X}` escapes. `T.validate()` hook runs last.
  ignore_unknown_fields = true, 10 MiB file cap.

### 9.8 Runtime and observability
- `[fact]` Signals: sigwait thread over {INT, TERM, USR1}; first -> graceful,
  second -> exit(1). SIGSEGV handler prints address and stack, aborts.
  Shutdown order: stop accepting, cancel group, s3 flush, loader.close()
  (pushes policy stats; needed for Cloud Run scale to zero), join waiter.
- `[fact]` Metrics exported (metrics.zig, pre-initialized to 0):
  edge_upstream_attempts_total, edge_upstream_retries_total,
  edge_requests_total{method,known_path},
  edge_request_duration_seconds{known_path} 15 buckets 0.0001..5,
  edge_responses_total{known_path,status_class},
  edge_prefilter_decisions_total (dead), edge_request_errors_total{known_path,
  class}, edge_policy_records_{evaluated,kept,dropped}_total{telemetry},
  edge_policies_loaded{signal} gauge, edge_build_info{version,commit,
  distribution}, edge_s3_dump_* counters and backlog gauge. known_path set:
  api_v2_logs, api_v2_series, v1_logs, v1_metrics, v1_traces, metrics,
  health, edge_metrics, other.
- `[fact]` Logging: o11y StdioEventBus installed as std.log backend; event
  payload type name is the event name; per request only a debug
  RequestCompleted; error events RequestFailed, UpstreamRetried,
  UpstreamConnectionEvicted, UpstreamConnectionError, PipelineAborted.
- `[fact]` Tests registered from src/root.zig test block; both frontends
  compiled in tests; s3 e2e test behind a filter. Harnesses: echo_server,
  upstream_pool_harness (spawns the real binary), datadog_log_bench,
  json_framer_bench, bench/scaling run.sh.

### 9.9 Warts to fix in the redesign
- Frontend divergence (admin routes, retry, timeouts only on httpz).
- stdio closes connections without status on errors; no passthrough cap.
- OTLP all-dropped returns `200 {}`, not a valid OTLP response.
- Prometheus truncation silent. Hop-by-hop header filtering incomplete.
- zonfig silent empty `${VAR}` (cannot change zonfig; validate URLs after
  load instead and warn on `..` or empty host).
- Per-record prefilter (skip decode when no policy can match) not ported.
- `config.test.json` holds a live-looking bearer token in git.

## 10. policy-zig 0.7.1 API (agent report 2026-09-11; design against this)

- `[fact]` Modules: `proto`, `observability` (edge imports it as `o11y`),
  `policy_zig`, `extensions` (s3-dump, pulls z3 S3 client). The module links
  libc and system `hs` (vectorscan) itself. Deps: protobuf fork, regex.zig.
- `[fact]` Engine: `PolicyEngine.init(bus, registry)` (two pointers, cheap
  to build per call). `evaluate(comptime T, comptime accessor, ctx:
  *anyopaque, policy_id_buf: [][]const u8, EvaluateOptions{scratch, io,
  extension_sink}) PolicyResult{decision keep|drop|unset,
  matched_policy_ids, was_transformed}`. `max_matches_per_scan = 256`.
  Sampling and rate limit fold into the decision. Drop beats keep.
- `[fact]` Registry: `getSnapshot()` is a lock-free acquire load. Retired
  snapshots are freed after a 100 ms grace (max 8 pending). Never hold a
  snapshot pointer across work that can exceed 100 ms. Per-signal emptiness
  check: `snapshot.log_index.isEmpty()` (and metric/trace). `registry.volume
  .addBytes(.log, n)` reports uncompressed bytes to the control plane.
- `[fact]` Loader: `Loader.init(allocator, io, bus, &registry, provider_configs,
  service)`, `startAsync(io)` spawns a std.Thread, `loadSync(io)`,
  `waitForInitialLoad()`, `close()` does the final stats sync (call before
  deinit), `deinit()` joins. Providers: file (SHA-256 poll, 10 MiB cap) and
  http (POST JSON SyncRequest, fixed poll, no backoff). Static policies:
  `parser.parsePoliciesBytes` + `registry.updatePolicies(p, "static", .file)`.
- `[fact]` Accessor contract: comptime `*const LogAccessor{typed_value
  (required), exists, set, delete, move}`, `MetricAccessor{typed_value,
  exists}`, `TraceAccessor{typed_value, exists, set}`. `ctx` is our record
  pointer. Return null for absent; wrong type is a non-match. Id fields
  return `.bytes` raw. Bytes passed to `set` come from `options.scratch`
  and must live until re-encode. Missing primitives silently disable the
  matching transform at comptime.
- `[fact]` Field refs: log_field {BODY, SEVERITY_TEXT, TRACE_ID, SPAN_ID,
  EVENT_NAME, RESOURCE_SCHEMA_URL, SCOPE_SCHEMA_URL}, log_attribute,
  resource_attribute, scope_attribute (nested paths). metric_field {NAME,
  DESCRIPTION, UNIT, schema urls, SCOPE_NAME, SCOPE_VERSION},
  datapoint_attribute, metric_type, aggregation_temporality. trace_field
  {NAME, TRACE_ID, SPAN_ID, PARENT_SPAN_ID, TRACE_STATE, schema urls,
  scope}, span_attribute, span_kind, span_status, event_name,
  event_attribute, link_trace_id. Matchers: exact, regex, exists,
  starts_with, ends_with, contains, equals, gt/gte/lt/lte, negate,
  case_insensitive.
- `[fact]` Transforms are log only: remove, redact, rename, add, applied in
  place through the accessor. Trace sampling writes a threshold to
  TRACE_STATE via set; we must merge `ot=th:VALUE` into tracestate
  (`probabilistic_sampler.updateTracestateInPlace`).
- `[fact]` Hot path allocation: none except regex-redact output from
  `options.scratch`. Hyperscan scratch: 64-slot lock-free pool per database
  with thread-local home slot; more than 64 concurrent scanners spin. Keep
  evaluating threads <= 64. Regex redact serializes on a mutex.
- `[fact]` EventBus: `init(io, writer)`, `initDual`, `debug/info/warn/err(event)`
  where the event type name is the event name; every emit takes a mutex and
  flushes. Guard with `isEnabled(level)`. `NoopEventBus` is zero cost. Buses
  embed self pointers: init in place, never copy. `StdLogAdapter` routes
  std.log to the bus.
- `[fact]` proto: OTLP data messages only (no Export*Request wrappers), each
  with `encode(writer, allocator)`, `decode(reader, allocator)`, `jsonDecodeOpts`,
  `jsonEncode`, `deinit`. Allocates through the passed allocator (use an
  arena). `protobuf.json.Options{emit_oneof_field_name,
  hex_bytes_fields}`. Nothing for Datadog or Prometheus formats.
- `[fact]` Limits: 8192 policies per signal index, pattern < 4096 bytes,
  policy compile failures are skipped fail-open and reported on next sync.
- `[fact]` Extensions: `Extensions.init/enable/enableS3Dump/register/resolver/
  sink/syncHooks/applyExtensionConfigs/flush`; sink fires after the keep
  decision and before transforms, also for dropped records. We supply the
  `EncodeFn` per signal.

## 11. Where the design lives and how to pick up

- `proposal.md` is the deliverable. Sections: summary, goals, architecture
  (process view, sequence, layout), data model (slab SoA, body pool,
  scratch, upstream lanes), threads and OS (reactor loop, forwarders, spool,
  io_uring position), request processing (plan, pipeline, fail-open matrix,
  headers), config, memory budget, observability, distributions, testing,
  tradeoffs, TigerBeetle adoption, delivery plan, open questions.
- `[todo]` Fill proposal §"std API usage" table once the std 0.16 survey
  agent reports (net listen options, compress signatures, File positional
  APIs, Mutex/Condition, testing fuzz). Verify each name with `zigdoc`
  before coding, per AGENTS.md.
- `[todo]` Phase 1 starts with tests for `http/head.zig` (RFC 9112 vectors,
  resumable partial input) and `http/conn.zig` transitions against
  `os/fake.zig`.
- `[decision]` Keep `worker_count` = reactors and `thread_pool_count` =
  forwarders so no config key changes meaning in a breaking way.
- `[decision]` Spool is opt-in, off by default, relay fallback when full.
- `[decision]` Fast path: when every record is kept and none transformed,
  forward the original compressed bytes without re-encode.
- `[decision]` OTLP all-dropped answers a valid Export*ServiceResponse.
- `[open]` See proposal §15: focused-distro 404 vs passthrough, Lambda spool
  default, libzstd removal.

## 12. Zig 0.16.0 std survey (agent report 2026-09-11; corrects §2)

- `[fact]` Correction: `Io.Kqueue.io()` does not compile (about 90 vtable
  fields missing, two removed fields set). `Io.Evented` maps to Uring on
  Linux and Dispatch on macOS, and both stub every `net*` op with
  `error.NetworkDown`. `Io.Threaded` is the only networking backend.
- `[fact]` `std.process.Init{minimal{environ,args}, arena, gpa, io,
  environ_map, preopens}`. start.zig hardcodes `Io.Threaded` for `init.io`.
  gpa = DebugAllocator in Debug, c_allocator with libc, else smp_allocator.
  `environ_map` is not thread-safe.
- `[fact]` `Threaded.InitOptions{stack_size 16 MiB default, async_limit
  cpu-1, concurrent_limit unlimited}`. `async` past the limit runs inline.
  Threads are detached and never reaped. Cancellation = pthread_kill SIGIO.
  SIGIO and SIGPIPE handlers are installed by Threaded; never touch them.
- `[fact]` No socket sendfile: `Stream.Writer.sendFile` returns
  `error.Unimplemented`, `netWriteFile` panics. File-to-file copy uses
  copy_file_range/fcopyfile. `std.os.linux.sendfile` raw wrapper exists.
  `splice` has no wrapper (syscall number only).
- `[fact]` `std.posix` keeps only: mmap/munmap/madvise/msync, sigaction,
  sigprocmask, signalfd, setsockopt, getpeername, poll/ppoll, memfd_create,
  getrlimit/setrlimit, prctl, getrusage, fdatasync, kill. Socket syscalls
  live in `std.c` (libc externs: accept4, recv, send, writev, sendmsg,
  setsockopt, fcntl, close, kqueue, kevent, socket, bind, listen) and in
  `std.os.linux` (accept4, epoll_*, eventfd, timerfd, fallocate, sendfile,
  copy_file_range, inotify, IoUring complete with multishot accept,
  provided buffers, send_zc, splice).
- `[fact]` `std.Io.net`: `ListenOptions{kernel_backlog, reuse_address (sets
  REUSEADDR+REUSEPORT), mode, protocol}`, no nonblocking option, no socket
  option API, `connect` has a timeout, `accept` does not. `Socket.address`
  gives the peer. `HostName.lookup(io, *Io.Queue, opts)`; no getAddressList.
- `[fact]` `std.http.Server`: max head = reader buffer len; rejects unknown
  encodings (`HttpTransferEncodingUnsupported`), obs-fold, duplicate
  content-length; content-length BodyWriter asserts exact length (panic on
  mismatch). `std.http.Client`: no init (struct literal), pool free_size 32,
  `resize` broken, no timeouts anywhere, CA bundle rescanned once (`now`
  never refreshed), `connectUnix` does not compile. Supports our decision
  to own the HTTP layer.
- `[fact]` TLS: `tls.Client.init(in, out, Options{host, ca{bundle{gpa, io,
  lock, bundle}}, write_buffer, read_buffer (each >= max_ciphertext_record_len
  ~16.6 KiB), entropy [240]u8, realtime_now})`; `Bundle.rescan(gpa, io,
  now)`. Budget ~64 KiB per HTTPS lane.
- `[fact]` compress: flate Compress.init(output, buffer >= 64 KiB, container,
  opts) and Decompress.init(input, container, buffer empty or >= 64 KiB);
  zstd Decompress only, Options.window_len default 8 MiB, buffer >=
  window_len + 128 KiB. No brotli, no lz4, no zstd compressor.
- `[fact]` Sync: `std.Thread` lost Pool/WaitGroup/ResetEvent/Mutex/Condition.
  Use `Io.Mutex`, `Io.Condition`, `Io.Event`, `Io.Semaphore`, `Io.RwLock`,
  `Io.Queue(T)` (bounded MPMC over a caller buffer, `min = 0` is
  nonblocking), `Io.Group` (`concurrent` for real parallelism), `Io.Select`.
  `Io.Batch.cancel` does not compile.
- `[fact]` Files: `Dir.cwd().openFile/createFile(io, ...)`, `File.
  readPositionalAll/writePositionalAll/sync/createMemoryMap`,
  `Dir.createFileAtomic` -> `File.Atomic.replace`. No fs watch in Io.
- `[fact]` Containers: `ArrayList` unmanaged by default, `MultiArrayList`,
  new `std.Deque` (`initBuffer` fixed capacity), `StaticStringMapWithEql`
  for case-insensitive header lookup. Removed: BoundedArray, RingBuffer,
  fifo, SegmentedList.
- `[fact]` Testing: `std.testing.fuzz(ctx, fn(ctx, *Smith), .{corpus})` is
  Smith based; `checkAllAllocationFailures`; `tmpDir` uses `testing.io`.
- `[fact]` Log: `std_options.logFn(comptime level, comptime scope:
  @EnumLiteral(), comptime fmt, args)`. `std.debug.print` is thread-safe
  through `debug_io`. `std_options_debug_io` is a separate root decl.
- `[decision]` Reactor socket calls use libc through `std.c` on both OSes;
  readiness through `std.os.linux.epoll_*` and `std.c.kqueue`. Listeners
  are created through `io` (`IpAddress.listen`) then switched to
  nonblocking with fcntl.
- `[decision]` Forwarder job queue is `std.Io.Queue(Job)` with nonblocking
  `put(min = 0)` from reactors.
- `[decision]` Signals: sigaction for INT/TERM, handler sets an atomic and
  writes each reactor's eventfd. No dedicated signal thread.
- `[done]` The `[todo]` in §11 about the std API table is complete
  (proposal §11.1). `[open]` questions in §4 are resolved: Threaded returns
  WouldBlock on nonblocking sockets so the reactor uses libc directly;
  std.http.Client cannot be driven nonblocking so we own the client; TLS
  runs on forwarder threads in blocking mode.

## 13. Proposal review and revision (2026-09-11)

**Read this section before acting on earlier decisions.** Sections 0–12 are the
historical exploration record, not a consistent normative specification.
The revised `proposal.md` supersedes their conflicting recommendations. No
implementation, dependency update, or library patch was made in this review.
The original proposal and notes were already untracked on entry; they remain
user documents, not newly staged files.

### 13.1 Scope and method

- `[fact]` User requested a critique and update of the existing proposal, in the
  context of the original from-scratch Zig 0.16 design request. Work stayed in
  Markdown; no rewrite of the running Edge was authorized by implication here.
- `[fact]` Read all 666 lines of the original proposal, existing notes, repository
  AGENTS.md, current config/service/provider implementations, and selected pinned
  std and dependency sources. Used `zigdoc` to discover APIs as instructed.
- `[fact]` This review's `zig` reports 0.16.0. `zigdoc` resolves std to
  `/Users/jea/.asdf/installs/zig/0.16.0/lib/std`, while earlier notes cite Hermit.
  Use the toolchain actually selected for a future build and record it in probes.
- `[fact]` No subagents were launched for this review. Earlier agent reports are
  historical and were not accepted as proof where source contradicted them.
- `[decision]` Preserve the architectural direction where justified, but replace
  unsupported guarantees with explicit contracts and gates. Do not present
  unmeasured rps, memory, stack sizes, or estimated parser line counts as facts.

### 13.2 Prioritized critique

| Priority | Original issue | Revision / reason |
|---|---|---|
| Critical | Acknowledge after append under interval sync | Durable acknowledgement follows data and recovery-metadata sync, including group commit |
| Critical | Skip bad CRC records; drop all 4xx | Corrupt committed records stop a lane; retained failures remain durable; classify retryable responses including 429 |
| Critical | Snapshot pointer considered safe if evaluation is fast | Edge reader/writer gate protects all reads and public-provider update callbacks; preemption defeats timed grace |
| Critical | Failed registry update assumed to leave a safe snapshot | Quarantine after observable update error; fail open without touching potentially inconsistent state; no repeated rebuild leaks |
| Critical | Connection generation assumed to protect buffers | Independent request leases pin data through disconnect, cancellation, and completion; use wide generations |
| High | Inline decode/eval/extension work on socket reactor | Bounded processing pool separate from I/O; unchanged regex/extension code can lock and allocate |
| High | No heap allocation anywhere after init | Core uses fixed storage; bounded scratch and separately measured dependency/control allocations are explicit exceptions |
| High | Arena retain limit treated as peak cap | FixedBufferAllocator backing; reset retention is not a memory ceiling |
| High | 256 KiB stacks assumed adequate | Flate state alone ~224 KiB; require real call-depth/stack high-water tests |
| High | SO_*TIMEO called a request deadline | Absolute deadline spans queue/DNS/connect/TLS/read/write/retry; manager shutdown fallback with fd-reuse protection |
| High | 32 forwarders assumed sufficient for 100k rps | Same occupancy ceiling as prior httpz architecture; F/latency arithmetic and end-to-end benchmarks |
| High | Fixed-window parser assumed to stream arbitrary OTLP object bodies | Explicit resource/scope context and envelope limits; preserve metadata/order/unknown fields; measure bypass coverage |
| High | Framer desync appended raw suffix to rewritten prefix | Buffered processing discards entire candidate on structural uncertainty |
| High | 2 × request cap reused for arbitrary responses | Independent input/output/response pools and overlap accounting |
| High | Spool applied universally with 202 response | Tested route allowlist and protocol-specific success; scrapes/passthrough excluded |
| High | Unlimited Prometheus cap silently becomes finite | Streaming variant with record-level rollback and bounded channels; no whole-response promise after write |
| High | Tail checkpoint advancement not tied to output durability | Explicit written/synced/checkpointed offsets, contiguous prefix, source/sink-specific guarantee |
| Medium | Focused distros said to return 404 | All current focused HTTP distros include wildcard passthrough; preserve it |
| Medium | Existing config defaults claimed unchanged while changed | Keep effective null → one HTTP reactor / 32 forwarders; new processing knob; tune deliberately |
| Medium | OTLP `{}` called invalid everywhere | Correct for JSON empty success; protobuf uses zero-length message with correct content type |
| Medium | IO backend absent based on cloud product name | Deployment probe; distinguish kernel support and security policy |
| Medium | Signal handler writes eventfd on every OS | Normal signal-wait thread can wake macOS safely; do not call kevent arbitrarily in handler |
| Medium | Static hop-by-hop header blacklist sufficient | Strip Connection-nominated fields on both legs; handle trailers and stale validators |
| Medium | Slot exhaustion called no-drop forever | Bounded fair wait, wakeup, admission deadline; return 503 when no capacity exists |
| Medium | All-keep means encoder did no work | Candidate may already be encoded; retained-input fast path avoids wire rewrite, not necessarily CPU |
| Medium | Benchmark gate uses byte equality for transformed compressed data | Entity equality for opaque paths, semantic and field-preservation tests for transformations |
| Medium | SIGKILL called a power-loss test | Volatile/durable storage simulation plus actual kill tests; page cache survives process kill |
| Medium | HTTP before forwarders in delivery plan | Vertical raw relay slice first, then policy, protocol parity, spool, distributions |

### 13.3 Source evidence — policy integration

Pinned package directory (relative to repo):
`zig-pkg/policy_zig-0.7.1-5_dp3p2xFQBbmLeyvcX53ti9iBJhzcn-e1EccJeb0UKF`.
Multiple older policy-zig packages exist locally; avoid wildcarding all versions
when verifying the pinned dependency. The build manifest remains unchanged.

- `[fact]` `src/policy/registry.zig:271–275`: 100 ms grace period, eight pending
  snapshots threshold. `:845` onward frees expired/over-limit snapshots.
  `getSnapshot` is an atomic acquire load without a reader guard.
- `[fact]` `registry.zig:552` onward: `updatePolicies` locks its mutex, removes
  old policies and calls `Policy.deinit`, then fallibly adds policies and builds
  a snapshot. `createSnapshot` shallow-copies policy structs before building
  indices. A gate is needed around the entire mutation, not just publication.
- `[fact]` That update is not a strong exception-safety boundary. Allocation or
  compilation-path errors can occur after replacing data. The adapter cannot
  assume a failed update leaves the previous snapshot valid or safely destructible.
- `[decision]` On observable update error, mark policy runtime unavailable under
  its exclusive guard. All later readers (evaluation, stats, admin) and writers
  avoid the registry. Retain its ownership until process exit once, report
  degraded mode, and continue raw forwarding. Recovery uses a controlled restart.
  Do not attempt repeated in-process retries into possibly invalid state. This
  avoids inventing transactional guarantees without modifying the dependency.
- `[open]` Phase 0 must prove error propagation is early enough to fence the
  registry and that dependency-internal allocation failures do not panic before
  returning. A panic cannot be caught as an ordinary Zig error. A stronger
  transactional registry adapter would be additional work and memory, with
  sampling/rate-limit/stat continuity requirements, not a free substitute.
- `[fact]` `policy_engine.zig:331` evaluate returns `PolicyResult`; `:346` obtains
  a snapshot internally. Result IDs and extension bindings are borrowed. No
  fictional `try engine.evaluate` or panic recovery should appear in new code.
- `[fact]` `registry.zig:380` subscribe installs an internal update callback.
  `Loader.loadSync` also sets up providers whose `subscribe` starts polling;
  simply calling loadSync under a lock does not guard later callbacks.
- `[fact]` Public `Provider` union in `types.zig:667` exposes `subscribe`,
  `setStatsCollector`, `setExtensionSyncHooks`, `sourceType`, `close`, `deinit`.
  Public `PolicyCallback` and `PolicyUpdate` are exported. FileProvider and
  HttpProvider are public. This permits Edge to install gated callbacks without
  patches or private imports.
- `[decision]` Reproduce the small loader orchestration in Edge's PolicyRuntime;
  reuse unchanged provider polling, parsing, request/stat formats and priority
  behavior. Pass updates synchronously to registry under exclusive gate so
  borrowed provider slices remain valid. Do not call Registry.subscribe alongside
  this adapter or any bypassing mutator.
- `[fact]` `Registry.collectStats` gets the snapshot BEFORE acquiring registry
  mutex; adapter must take shared publication guard around that call as well.
  Copy IDs/errors to caller storage while protected. Empty degraded stats avoid
  dereferencing quarantined state; report degradation separately.
- `[decision]` Fixed lock order: Edge publication gate → registry mutex; audit
  extension capabilities/config application/sinks for cycles. No network wait
  while holding a read guard. Buffered request processing can hold a read guard
  for the in-memory pass; streaming scrape processing guards each record.
- `[fact]` HttpProvider `close` shuts down/join poll thread then performs final
  fetch-and-notify. A final close can therefore deliver another update callback.
  Keep the gate and dependencies alive until every provider is joined.
- `[decision]` All evaluators live in P ≤64 processing workers, including
  Prometheus. The old independent R≤64 and F≤64 statements allowed 128 evaluators.
- `[open]` Library-internal transform error handling and extension dispatch can
  have side effects before an outer rollback. Never claim rollback undoes S3
  capture, policy hits/volume, sampling/rate-limit state, or partial external work.

### 13.4 Source evidence — Zig and current Edge

`zigdoc` commands executed in this review:

```text
zigdoc std.Io.Queue
zigdoc policy_zig.Registry
zigdoc std.heap.FixedBufferAllocator
zigdoc std.heap.ArenaAllocator.ResetMode
zigdoc policy_zig.PolicyEngine.evaluate
zigdoc std.Io.Mutex
zigdoc std.compress.zstd.Decompress
zigdoc std.compress.flate.Compress
zigdoc std.Io.net.HostName.lookup
zigdoc policy_zig.provider.PolicyCallback
zigdoc policy_zig.FileProvider
zigdoc std.Io.RwLock
zigdoc std.compress.flate.Compress.init
zigdoc std.compress.zstd.Decompress.init
zigdoc std.process.Init
```

- `[fact]` zigdoc's rendered signature for flate Compress.init abbreviates the
  return; pinned source at `std/compress/flate/Compress.zig:303` shows
  `Writer.Error!Compress`, embedded lookup/token arrays, and an immediate header
  write. ~224 KiB embedded state is separate from its supplied history buffer.
- `[fact]` `ArenaAllocator.ResetMode.retain_with_limit` describes retained capacity
  after reset. It does not restrict allocations during the record.
- `[fact]` `HostName.lookup` docs guarantee a queue of capacity 16 will not block
  result insertion; they do not establish a DNS resolution deadline.
- `[fact]` `std.Io.RwLock` has tryLockShared(io), unlockShared(io), and exclusive
  operations. Raw pointer lifetime still depends on Edge consistently using it.
- `[fact]` `src/runtime/distro.zig:14` servicesFor includes `.passthrough` for
  edge, datadog, otlp, prometheus; a test asserts health first/passthrough last.
  `src/service/passthrough.zig` registers `.any(.all)` and forwards `.default`.
- `[fact]` `src/config/types.zig` ProxyConfig comments explicitly document null
  worker_count as httpz's one worker and null thread_pool_count as 32 handlers.
  Lambda current source documents the same null meanings. Earlier notes claiming
  Lambda 128 as the current effective default are not reliable against this code.
- `[fact]` `src/service/otlp.zig` exact route registration covers POST /v1/logs,
  /v1/metrics, /v1/traces; raw fallback retryable only for logs. Preserve processed
  path replay defaults by inspecting service.Outcome and frontend execution too.
- `[decision]` Keep old benchmark figures labeled historical. This review did not
  rerun baseline binaries, scaling scripts, or measure runtime memory.

Primary external references read during review:

- [TigerStyle](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
  and its raw file: engineering principles, static allocation, assertions, explicit
  bounds. Multiple OS threads are not a valid claimed divergence by themselves.
- [Zig 0.16 release notes](https://ziglang.org/download/0.16.0/release-notes.html):
  context for the I/O transition; local pinned source is the API authority here.
- [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html): framing, ambiguous
  lengths, persistence, response association, and partial messages.
- [OTLP specification](https://opentelemetry.io/docs/specs/otlp/): HTTP 200 and
  success/partial-success response representation. Empty JSON object is valid
  for empty JSON export success; protobuf representation is an empty message.

### 13.5 Architectural decisions to carry forward

- `[decision]` R reactors own inbound sockets; P processors own codec scratch;
  F forwarders own upstream exchanges; request descriptors own persistent bytes
  through explicit leases. The reactor schedules stage changes after completion.
- `[decision]` Body admission reserves storage plus queue/completion credits.
  Response capacity is independently reserved before buffered forwarding.
  Completion publication cannot lose the only ownership-release record.
- `[decision]` Full-input/candidate retention supports exact entity rollback
  before upstream commitment. Never mix a transformed prefix with an uncertain
  framing suffix. Streaming unlimited scrapes have a weaker, per-record contract.
- `[decision]` Use wide generations and reject stale events, but never mistake
  identity checking for memory pinning. Preserve headers after read-buffer reuse.
- `[decision]` Core fixed pools, stack-local small operations, and startup-allocated
  large workspaces. Dependency/C/control allocations are exceptions to measure,
  not reason to falsify the core allocation test.
- `[decision]` Deadline starts before queues and covers all attempt phases.
  Kernel per-call timeout alone fails on trickle traffic. Safe watchdog fd
  registration/close ordering is a required spike if std TLS cannot enforce it.
- `[decision]` Spool acknowledgements follow durable group commit. Persist
  versioned destination/request representation; local integer IDs cannot survive
  restart/config changes. Replay never reevaluates policy or reruns extensions.
- `[decision]` Corruption stops/retains, permanent reject retains, retryable
  failure backs off, disk-full tries live relay. No acknowledged silent loss.
- `[decision]` Tail checkpoint format and spool format stay independent. Shared
  CRC/short-write helpers are fine; shared format and recovery semantics are not
  justified by superficial similarity.
- `[decision]` No custom Io vtable, fibers, or initial io_uring proxy backend.
  Probe deployment support before a later implementation; treat late completions
  as a different ownership contract from epoll readiness.

### 13.6 How to resume implementation

Start with proposal §14 phase 0, not the old notes' parser-only phase 1.
Before major code, add focused failing tests/probes for:

1. Gated public provider callback wiring, stats reads, extension config, initial
   fetch failure, >100 ms paused reader, >8 updates, partial mutation failure,
   quarantine, close callback, and teardown. No ungated registry access.
2. Absolute deadline through stalled DNS/TLS/trickle responses and safe socket
   shutdown while lanes recycle. Identify actual std boundaries before coding a
   substitute transport or assuming kernel timeouts solve it.
3. Capacity arithmetic for actual sizes and simultaneous input/candidate/response
   retention; safe stack sizing. Record C/dependency allocations separately.
4. Current route/config/retry and policy semantics fixtures including S3 and
   Prometheus zero-cap meaning. Tests must distinguish intentional bug fixes.

Then implement one complete raw relay slice, one Datadog policy slice, remaining
formats/distributions, durability, and tuning. Preserve the current binary for
comparison and rollback. Use `zigdoc` for every newly needed std/dependency API.
Run meaningful implementation tests and `task lint` before merging code.

Review validation here is document consistency/source verification, not a
claim that any new architecture compiles. No Zig source changed, so runtime
unit tests and lint were not run for this Markdown-only revision.

## 14. Implementation continuation — 2026-09-14

The current implementation/handoff checklist is
[IMPLEMENTATION-PROGRESS.md](IMPLEMENTATION-PROGRESS.md). Its phase 1 was expanded
after the user reviewed the phase-0 results and authorized continuation.

- `[verified]` The policy-zig fix is PR #97, merged commit
  `a652ae9573ca9f318fc1bf6c60b1abe8240bc160`. Edge now pins that immutable archive
  and its verified Zig package hash. The package still identifies as 0.7.1;
  neither release availability nor issue closure was assumed. The transitive
  protobuf update comes from the upstream package, not an Edge modification.
- `[verified]` Original allocation #3 hang no longer reproduces. Default Edge
  tests run a successful policy cycle and 83 fault points covering publish,
  same-ID replacement, duplicate-ID publication, and removal. Failed callbacks
  return and the gate releases; reads/stats remain fenced. The old detached
  timeout thread was unsafe to retain and has been removed.
- `[unresolved dependency]` `checkAllAllocationFailures` using direct dependency
  cleanup fails at allocation #17 with an 8-byte leak in
  `matcher_index.storePolicyInfo`: a duplicated ID is not yet owned when the
  ownership-list append fails. `TERO_V2_REGISTRY_LEAK_PROBE=1 zig build test`
  is the retained reproducer. Do not report this as an unfixed double-free hang.
- `[unresolved dependency]` `compilePatterns` requests `alloc(u8, ...)`, then
  requires word alignment when casting the result to `hyperscan.Pattern`.
  A bare arena panics during the successful multi-publication fixture.
  `TERO_V2_REGISTRY_ALIGNMENT_PROBE=1 zig build test` reproduces the observed
  failure. Production allocator selection must supply sufficient alignment.
- `[test boundary]` A test-only alignment adapter and per-case arena permit the
  OOM sweep to reclaim orphaned Zig memory. Explicit dependency cleanup releases
  native indices in these tests. This is not a production allocator design or
  evidence of leak-free arbitrary dependency failure handling. Keep the current
  single-failure quarantine; no repeated rebuild leak accumulation.
- `[implemented]` Phase 1A request table: stable bounded head/body/response storage,
  generation retirement, reactor-only transitions, detached-client work ownership,
  completion consumption and checked startup admission. Metadata/header sizes
  feed the shared budget formula. The formula now rejects aggregate over-budget
  reservations, rather than merely checking whether one request fits.
- `[remaining]` Readiness adapters, queues and completion credits, HTTP framing,
  upstream relay, opt-in composition, full runtime budgeting, and benchmarks.
  All remain explicit unchecked phase-1 tasks. Production still uses the existing
  runtime. Native Linux x86_64 and DNS-injection constraints remain unchanged.

Verification: 562 pass / 2 skip in Debug and ReleaseSafe, all six distribution
builds, lint, and diff checks on macOS arm64. Consult the progress log for commands,
TDD evidence and the scope of the two opt-in failing dependency probes.

## 15. Local dependency accepted and queue slice — 2026-09-14

This section supersedes the blocker status of the dependency findings in §14.
The local policy-zig agent fixed builder/finish teardown, typed-byte ownership,
hex validation, temporary pattern alignment and redaction-template defer order.
Independent review passed the original 83 fault points, 71 byte-equality fault
points, 65 hex-fixture fault points and the no-OOM malformed-hex case. The reviewed
library suite passed 452 tests. Later local commits are recorded with final Edge
verification in the progress log.

The user authorized `.path = "../policy-zig"` until merge. Edge now uses that path.
Direct dependency leak checking and the plain-arena alignment/fault sweep run in
the default suite. Removed the alignment adapter and obsolete opt-in probe gates.
Neither policy-zig nor zonfig source was edited by Edge implementation work.

Phase 1B now has `WorkChannel`, backed by two fixed `std.Io.Queue` buffers. The
single owning reactor reserves a credit before body admission; a reservation then
becomes queued work, executing work, and a completion. Receiving a completion
does not return its credit: acknowledgement does. Therefore completed workers have
capacity even while the reactor is stalled. RequestTable tracks the matching
reserved/work/completion lease and pins detached-client storage until its owner
returns it. Channel operations do not allocate their own storage after startup.

Canceling unpublished admission returns its credit; canceling an active worker
must publish an error completion. Closing the job queue drains its existing jobs
and wakes blocked consumers. Completions remain open during shutdown. The runtime
must cancel unpublished reservations, drain/acknowledge, then join and destroy.

No custom atomic ring was added. Std queue operations use min=0 for capacity
checks and uncancelable publication where cancellation could lose a lease. Its
short internal lock remains; contention is a measurement question. Reactor OS
wakeups must be added after publication when the readiness driver exists.
Fair admission and generation-safe readiness tokens are still unchecked work.

Actual Job/Completion/table layouts feed checked reservation sizes. These are
component budgets, not a complete process RSS bound. Full configuration binding,
OS adapters, HTTP framing and a serving v2 composition remain outstanding.

## 16. Readiness registration and wakes — 2026-09-14

`Readiness` now owns a fixed socket table and two fixed event buffers (native and
normalized). Its native boundary is `os/Poller.zig`: level-triggered kqueue/epoll,
EVFILT_USER/eventfd, descriptor flags, and close. Only `wake` is producer-safe;
all table mutations and socket IO belong to the reactor. Allocators are explicit
at construction/destruction; `Io` supplies wait deadlines. Raw syscalls intentionally
avoid the standard threaded IO backend for this dedicated reactor's readiness.

Tokens are not pointers or compacted RequestTable IDs. Slot i starts at i+1; every
reuse adds table capacity N, with retirement if u64 addition would overflow.
Modulo N selects the slot, exact comparison validates it. Capacity cannot change
within a poller lifetime. A fake event batch tests stale events after close/reuse,
including invalid/wake tokens. This preserves direct lookup without hash storage.
Token safety does not replace request leases or future connection-state checks.

`adopt` consumes the descriptor even on failure. This makes exhausted admission
and failed native registration deterministic cleanup paths. A failed interest
change closes/invalidates the socket because kqueue can apply changes partially.
Do not duplicate adopted descriptors: epoll registrations otherwise can outlive
one close. CLOEXEC/nonblocking are enforced using flag-preserving fcntl; the future
accept loop should supply atomic accept4 flags on Linux. macOS kqueue CLOEXEC has
an unavoidable fcntl step in this implementation; no concurrent exec contract has
been added. These APIs are not yet called by the serving runtime.

Wake hints coalesce. Linux reads one eventfd aggregate per delivered wake, and a
saturated eventfd write succeeds logically because readability is already pending.
The Linux fixture fills the counter to force EAGAIN. A real worker publishes four
completions then wakes; a simulated reactor drains two completions per turn and
must immediately schedule another turn once its budget is exhausted. It cannot
rely on a second wake. Test coverage also includes a delayed wake interrupting a
wait, an idle deadline, half-close with pending data, disabled write interest,
flag preservation, failed registration/update cleanup and startup OOM unwinding.

Wait deadlines use the awake clock and are recomputed on EINTR; Linux rounds
positive sub-millisecond waits upward. Interrupted syscall branches are implemented
but not forced by a signal-injection test. Producer wake failure leaves queue
publication intact. Runtime composition must select a finite maximum poll interval,
record wake/poller faults, and schedule shutdown through explicit state plus wake.
It must join producers before destroying the wake fd. No throughput, scheduler
fairness, full RSS, listener/handoff or serving relay claim follows from these tests.

The progress log records final platform/test results. This section supersedes the
unchecked-readiness statements in §15; fair admission and HTTP framing remain next.

## 17. Connection ownership and FIFO admission — 2026-09-15

`Connections` now composes Readiness with fixed metadata/head storage. Waiter
links live in the connection slots, so enqueue and arbitrary removal are O(1)
without tombstones or extra queue nodes. The readiness token identifies the same
incarnation in both arrays; RequestTable stores that token once at admission and
retains it through disconnect until the request slot is recycled. No separate
completion-routing map or truncated connection handle is needed.

One Connections belongs to one reactor/RequestTable/WorkChannel. All socket
registration mutations go through it. Workers still access only WorkChannel jobs
and pinned RequestTable spans. The caller revalidates a returned event's token
AND connection phase before using it. The framer will own initialized lengths and
copy request bytes into request storage, preserving unread connection-head bytes.
These interfaces do not parse HTTP yet or provide a local/admin response path.

Every completed head enqueues, including the next request on a keep-alive client.
`admitNext` examines the oldest waiter, checks channel capacity without acquiring
and discarding request generations, then reserves both a request and a completion
credit. It grants one request per call. The runtime must budget calls per turn and
retry on both completion acknowledgement and response/request-storage release.
A connected response keeps its request slot after the channel credit is returned.
FIFO guarantees admission order among waiting connections, not worker completion
order, weighted tenant fairness or bounded wait duration without deadlines.

Dispatch disables native interest before publishing the job. If that fails, the
body-read reservation is returned and no job was published. Input validation can
fail while leaving the reservation available for correction/close. Completion
acknowledgement has no following native operation that could make its ownership
ambiguous: it returns a live token (response storage remains pinned) or null
(detached request may be freed). Response framing then precedes `responseReady`;
if arming writes fails, the response/client closes without a second ack.

Tests cover FIFO middle removal, keep-alive reentry, independent queue/request
exhaustion, each disconnect phase, mixed-state shutdown with outstanding work,
stale/duplicate completion, native interest failures at each ownership boundary,
head storage surviving request turnover, startup allocation failure and exact
component budgeting. A FailingAllocator armed after application initialization
permits a full connection/request lifecycle without another application allocation.
This excludes allocations within the independently owned std.Io backend and OS.

Remaining work: listener acceptance and bounded descriptor handoff, deadline-driven
waiter removal, grant scheduling in a real reactor turn, HTTP/local reply framing,
reserved health/fallback capacity, complete runtime budgets and serving composition.
Use the latest progress log for commands, test counts and platform limitations.

## 18. Bounded TCP accept and descriptor handoff — 2026-09-15

`Acceptor` and `AcceptChannel` complete the standalone 1B mechanisms. The first
acceptor is single-thread-owned, with only wake callable externally; it borrows a
stable target array (at most 64 reactors). Every accept syscall uses one turn
attempt, including EINTR and aborted/pending-network errors. Handoff probes each
target at most once, advances round-robin after success, and closes the accepted
fd if all queues refuse. Target/attempt limits bound this work without heap state.

`AcceptChannel` is a fixed std.Io.Queue of descriptors. Offer transfers ownership
only on success, allowing a full/closed target to be skipped. Publication is
uncancelable; a later failed wake increments a report counter and leaves ownership
with the queue. Receive transfers ownership to the reactor. Bounded drain invokes
Connections.adopt, whose always-consuming contract closes on reactor exhaustion or
registration failure. Budget exhaustion schedules another immediate turn. No queue
entry or socket can be silently abandoned by a wake failure or a closed target.

Linux accepts atomically with CLOEXEC/NONBLOCK. macOS accepts then applies flags
before publishing. The listener uses a READ-only native registration, avoiding a
WRITE filter for listening sockets. Listener creation/close use the explicit Io
backend; native readiness/accept calls stay in os/Poller. Native errno mapping
separates empty backlog, retryable accept attempts and reported failures.

Descriptor/resource exhaustion pauses listener readiness with a configurable
backoff (50 ms default), preserving the native control wake. The absolute retry
time caps wait; once due, the next turn reenables the listener. Failure to change
listener interest stops acceptance and reports both the accept and control errors.
This avoids spinning against an accept-ready backlog under EMFILE without reserving
an extra fd or changing process resource limits. The test injects quota failure at
the accept boundary, proves a pending backlog does not wake the paused listener,
then forces the retry deadline due. It does not exhaust real RLIMIT_NOFILE.

Tests include bounded real TCP backlog draining, round-robin/closed-target skip,
all-available-capacity saturation, accepted-socket flags, wake failure with a queued
fd, descriptor teardown, OOM, a real receiver task using the handed-off socket,
retry storms bounded by attempts, stopped acceptance and backoff-registration
failure. Queue close preserves previously accepted entries; deinit drains/closes
them after all producers/consumers join. Acceptor stop does not destroy target
queues. Queued sockets have no acknowledged HTTP request at this stage.

Application bytes: sizeof(Acceptor), caller-owned target array, and each queue's
actual Self/fd-array layout. Fd demand includes queues, active connections, one
transient accepted socket, listeners and poller/wake fds. Kernel backlog/socket
buffers and std.Io backend storage are outside those byte reservations. The final
runtime must validate combined budgets, pick finite wait deadlines, report turn
failures and coordinate shutdown state. HTTP framing, local replies, admission
request deadlines and the serving reactor remain phase-1C/1D work.

## 19. httpz decision and first head scanner — 2026-09-15

See [HTTPZ-TRANSPORT-REVIEW.md](HTTPZ-TRANSPORT-REVIEW.md) for the full pinned-source
audit, five executable boundary probes and alternatives. The public lazy-read
hook permits Content-Length admission before the body, but delegates body size
checks to the handler. Chunked requests still buffer before dispatch; Continue
is emitted before handler admission. Disown transfers the socket, while handler
return still resets request storage. Retaining a synchronous handler through
completion is a safe alternative with different scheduling/memory tradeoffs.
Existing httpz already uses native readiness; no performance improvement from
replacing it has been demonstrated. Keep it as production default through cutover.

Continue the v2 ownership architecture. The first head mechanism reuses
`std.http.HeadParser` with a byte cap and precise consumed lengths for CRLF heads.
`HeadScanner` stores only scalar parsing state, borrows each new input slice and
does not retain pointers or allocate. At capacity, complete beats oversized;
after completion or capacity failure, the owner must reset before feeding again.
Six tests cover incremental input, all split positions, read-ahead preservation,
capacity, reuse and 129 header alignments across std's scanning vectors.

This scanner is not an HTTP validator. Std can mark malformed LF-only input
complete; one longer LF-only fixture also returned a later-than-expected boundary.
Do not depend on meaningful consumed offsets for invalid heads. The forthcoming
strict validator must reject bare LF/CR, folding, invalid tokens/controls and
ambiguous framing before admission. Full `std.http.Server.Request.Head.parse`
also rejects unknown Content-Encoding, so it cannot be used unchanged for opaque
proxying. Both std behaviors were inspected through zigdoc and local source.

An existing acceptor test assumed client connect implied immediate acceptability.
ReleaseSafe exposed the race; its fixture now waits for real listener readiness
with an absolute deadline, and the stop test checks the handoff before unwrapping.
Multi-client tests also accumulate bounded turns instead of assuming all expected
peers arrive in one OS batch. No production acceptor behavior changed.
Final counts, dependency HEAD, logs and
remaining work are in IMPLEMENTATION-PROGRESS.md. The original checkpoint is
`0a72fbc`; subsequent audit/scanner work is separate from that commit.

## 20. Strict request-head metadata — 2026-09-15

`RequestHead` completes the standalone head slice on top of `HeadScanner`. It
accepts exactly the completed head and returns scalar framing/expectation state
and u32 offsets into caller-owned bytes. Header descriptors remain in a supplied
slice; no pointers or allocations are retained in metadata. Copy bytes unchanged
to request storage before workers borrow them, and carry/rebuild descriptors
according to that owner's lifetime. On parse error, discard the partial descriptor
array and close/reply through the future serving layer. Validation cannot admit
work or send network bytes by itself.

Why separate the two: the scanner bounds incremental input and preserves the
unconsumed suffix; the validator rejects malformed line endings and ambiguous
framing before any resource admission. It performs one bounded pass over lines,
fields and special-header tokens. Repeated end-to-end fields and unknown encoding
values survive as independent descriptors, in order. There is no dictionary,
string normalization or content decoding here. The later planner/writer must
respect duplicate field semantics, remove Connection-nominated fields, and avoid
mistaking a first encoding value for the complete representation encoding.

The initial request acceptance profile is documented in proposal §6.4 and the
progress log. It deliberately refuses duplicate/list CL, empty Host, folding and
CL/TE ambiguity. It recognizes all four request-target forms needed to classify
HTTP requests; CONNECT recognition does not enable a tunnel. Only HTTP(S)
absolute targets are accepted. Unknown method tokens remain raw for the planner
to classify. Host syntax validation does not resolve hosts or choose destinations.
Configured upstream routing remains authoritative. Empty absolute paths need
slash/asterisk normalization in the later writer while preserving query bytes.

Connection close is sticky across lists/fields. HTTP/1.0 requests are marked
nonpersistent, following the proxy rule in
[RFC 9112 §9.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3).
Expect handling produces a pure action only; the owner supplies real admission
state, enforces the admission deadline and prevents repeated interim responses.
Unsupported expectations remain rejected even if a later field requests Continue.
No-body/already-received-body and HTTP/1.0 Continue cases require no interim write.
Body limits are admission decisions; checked u64 CL parsing is not a body-memory
reservation. Refer to [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1)
for expectation semantics.

Fourteen parser tests follow twelve initially failing cases. They cover strict
syntax tables, all 256 field-value bytes, decimal overflow, caps, repeated fields,
opaque encodings, method-independent framing, offset relocation, Expect and
Connection lists, and scanner/validator composition at every split. Layout gates
require metadata <=128 bytes and 64 field descriptors <=1 KiB. Neither their
ultimate reactor/request residency nor the aggregate runtime budget is wired.
The test suite is deterministic, not a substitute for later wire fixtures,
differential/fuzz testing or measured throughput. See the latest implementation
log for verification and the next body/trailer-framing work.

## 21. Bounded body and trailer framing — 2026-09-15

`BodyFramer` adds the standalone transfer-framing half of phase 1C. It owns only
scalar parser state while borrowing fixed line, trailer and trailer-descriptor
stores. Entity output goes to caller-provided storage. The caller must retain all
stores for the message lifetime and must never move an owning structure holding
borrowed storage. The framer does not allocate, perform IO, emit Continue, reserve
queue credit, process policies or forward upstream bytes.

For Content-Length, it copies the available bulk suffix until the exact length;
for no-body messages it completes without consuming a following request. Chunked
framing reads one strict CRLF line at a time, validates checked hex size and
extension syntax, copies each data segment, requires CRLF after it, then validates
the zero chunk and trailers. It returns exact consumed/written counts, so caller
read-ahead is preserved. If the output buffer is full, it stops before consuming
the next entity byte. It accepts an aggregate body only after every last trailer
byte validates. `finish` rejects all unfinished states and fences the framer;
later feed calls fail. This is the boundary that prevents fail-open logic from
mistaking a truncation or malformed suffix for a complete original request.

The default caller-selected limits distinguish body bytes from metadata work.
Body limits include decoded transfer-framing payload bytes but intentionally do
not claim to bound content decoding, compressed history or eventual policy output.
Metadata includes chunk-size and trailer bytes, which blocks a peer from spending
unbounded CPU on tiny chunks/extensions/trailers. The later configuration/budget
root must reserve actual body + line + trailer + descriptor layouts together and
apply turn/input limits around `feed`; it is not currently wired.

Trailer descriptors use the same strict field parser and offsets as heads,
against the separate trailer store. Order, casing and repeated end-to-end fields
are retained. Critical framing, routing, connection, representation and auth
fields are rejected as late overrides. This list is conservative. The future
header writer must additionally apply Connection-nominated field removal from the
original head, route-specific policy, and protocol-specific trailer rules. It
must never merge trailer fields into the head simply because the framer parsed
them. Refer to [RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1)
when extending coding support.

## 22. Reserved request-slot ingress — 2026-09-15

`RequestIngress` connects the completed standalone parsers to the existing
request-table and work-channel ownership. It is reactor-local and takes an
already reserved `RequestTable.Id`; callers must reach that state through the
FIFO `Connections.admitNext` path, which reserves both request bytes and a future
completion credit before body reads. Ingress copies a complete head from the
reusable connection buffer into the request slot before parsing it, then frames
the body directly into the request slot. All head metadata spans therefore refer
to immutable-per-request bytes while the connection head can be reused.

Ingress preserves its temporary head and trailer descriptors only for the ingress
lifetime. Worker jobs carry immutable head/body/trailer spans, an absolute
deadline, and exclusive response storage. Trailer bytes now live directly in a
separate RequestTable span; the framer writes there without an intermediate copy.
Do not capture ingress pointers or descriptor scratch in worker code. The request
table's work/completion lease pins all input spans after disconnect. Workers can
reparse their raw metadata into their own bounded scratch for header rewriting.

An ingress exposes `WorkChannel.Input` only after body framing reaches done. It
does not publish by itself; `Connections.dispatch` turns the reservation into an
uncancelable job after disabling client read interest. Malformed/EOF-framed input
fences the body framer and leaves the reservation so the connection owner can
close and explicitly cancel it. A disconnect before publish follows the existing
close/cancel path; after publication the existing completion lease owns storage.
The integration test overwrites the connection head after construction, proves
the worker receives the old copied head/body, completes the job and returns the
connection to `reading_head`. There is no serving reactor loop yet.

Continue remains a pure ingress/head action. `admitNext` makes capacity real;
the future loop must decide whether a full body prefix already arrived, enforce
the absolute admission deadline, emit at most one interim response, and track
the write result. It must not call this a grant merely because head scanning or
validation completed. No-body requests consume zero bytes of a pipelined suffix.

The ownership review found that generation validation alone allowed ingress to
touch a dispatched worker's still-live slot. `RequestTable.ingressBuffers` now
requires a live generation, attached client, reading state and reserved lease.
Ingress init/feed/input/Continue/trailer access and channel submission all use
that guard on the reactor. A failed body framer also rejects Continue. Stop using
ingress and its borrowed views on cancellation or publication; do not revive an
old ingress if a caller cancels and re-reserves the same request ID.

`RequestTable.Limits.trailer_bytes` reserves raw trailer bytes, including the final
empty CRLF for chunked messages. Zero is useful for callers that never accept
chunked input; chunked ingress requires at least two bytes. This capacity is
separate from the body limit and response buffer. RequestTable's exact byte budget
includes it; WorkChannel's budget includes the enlarged Job layout. The combined
runtime budget still must include ingress metadata, scratch and all other owners.
The handoff now preserves trailers through scratch reuse and disconnect. The next
writer/relay slice must filter Connection-nominated fields and frame outbound
trailers correctly; retaining bytes alone does not implement forwarding.

## 23. Bounded outbound raw request preparation — 2026-09-15

`RequestWire` is the next phase-1C component. It prepares the entire request's
metadata before upstream commitment, using `std.Io.Writer.fixed` over caller-owned
buffers and no allocator or IO. Its result contains three borrowed spans: generated
head plus optional chunk size line, original entity body, and generated tail. No
full-body copy or decode occurs. The value has no pointers into itself, so moving
it is safe while the external buffers remain fixed. `pending`/`advance` traverse
short writes without interpreting retries, scheduling, cancellation or deadlines.

The raw contract requires the complete original entity from successful ingress.
Content-Length must match the supplied body exactly, and unframed requests must
have an empty body. Chunked input must include a complete trailer section, even
when it is only CRLF. Reparse head/trailer metadata into bounded worker scratch;
do not capture reactor ingress descriptors. A returned plan is the only valid
publication boundary; all partial output on preparation failure is discarded.
Success does not extend the WorkChannel lease: keep the job's body pinned until
upstream sending finishes and publish completion only after all borrows end.

Destinations come from the route owner. Host is regenerated from the selected
authority, which is syntax checked using RequestHead's shared rules. The optional
target override accepts only origin form or OPTIONS `*`; route/base-path building
is still future work. Otherwise absolute-form input loses its authority, retains
the encoded path/query and gets `/` for an empty path (or `*` for server-wide
OPTIONS without a query). CONNECT is rejected; this never enables tunneling or
chooses a network destination from inbound Host/absolute authority.

Headers are emitted in their original order with name casing and repeated values
preserved; outer whitespace is normalized. Fixed connection/transport fields and
every field named by any original Connection value are removed. Incoming Expect
is consumed, proxy credentials are not forwarded to the origin, and ordinary
Authorization/opaque Content-Encoding remain unless nominated for removal. Host,
Via and framing are generated and count against the output header limit. The
received version is appended in Via with pseudonym `tero-edge`; no host identity
is leaked. Existing end-to-end Via values remain separate ordered fields.

The shared critical-trailer blacklist moved to `http_field.zig` so ingress and
outbound preparation cannot drift. Noncritical Connection-nominated trailers are
filtered; surviving trailer order/casing/duplicates are preserved separately from
headers. The original Trailer declaration is replaced with the actual retained
names. Chunk boundaries/extensions are not entity data and are regenerated as one
data chunk, followed by the zero chunk and trailers. Empty chunked bodies emit a
single zero chunk; emitting an empty data chunk first would terminate too early.
These choices follow [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1)
and [RFC 9112 §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1).

Resource contract: defaults bound input head/trailer bytes and output HTTP head to
16 KiB each, and output fields to 64 including generated metadata. Descriptor
slices bound input field counts, including discarded trailers. The original head
and Connection token lists are rescanned for each candidate field; cost is bounded
by candidate count times head bytes. This avoids allocating a hash table or token
index. Measure before replacing it with a more complex representation. Normal
request processing only borrows the body and copies metadata into fixed buffers.

The output head buffer additionally needs up to 18 bytes beyond the HTTP head cap
for a 64-bit hexadecimal chunk-size line plus CRLF. A tail buffer of input trailer
capacity + trailer descriptor capacity + 5 covers normalized fields (at most one
extra space per field) and framing for nonempty chunked bodies. Short buffers fail
explicitly before publication. The runtime must bind these sizes to its aggregate
budget and reserve room for generated Host/Via/framing/Trailer fields. The 64-field
and 16 KiB tests deliberately reject overflowing regenerated output instead of
silently truncating metadata.

Tests include exact wire expectations, selected-destination injection attempts,
empty chunks, 1–31-byte write windows, blocked-write cursor behavior, malformed
tails, exact byte/field limits, and RequestIngress → WorkChannel → RequestWire
after client disconnect. The latter reparses the output and recovers the original
binary body and retained trailers, while asserting source body/trailers remain
unchanged and the slot cannot recycle before completion. This is still an
in-memory composition test, not an upstream socket exchange.

Raw preparation preserves representation metadata because the entity is unchanged.
Do not reuse this API with transformed bytes merely because their lengths match:
Content-Encoding, validators, digests and signature semantics need explicit policy
pipeline handling. Response framing, real upstream exchanges, TLS/DNS lifetimes,
route binding and serving-loop backpressure remain open; no production cutover.

## 24. Buffered upstream response framing — 2026-09-16

`ResponseHead` and `ResponseIngress` extend phase 1C through upstream response
reception, still without network IO. The response-head tests first failed with
`NotImplemented`, followed by the receiver tests failing behaviorally after their
compile issues were corrected. The receiver borrows bounded storage; there are
no allocations during parsing or any hidden owning slices.

The Zig 0.16 `std.http.Client.Response.Head.parse` API was inspected with zigdoc
and in the installed source. It rejects unknown Content-Encoding, accepts equal
duplicate Content-Length values and does not interpret Connection lists with the
strictness our contracts require. We reuse `std.http.HeadParser` via HeadScanner,
plus the existing strict field parser, rather than wrapping that response parser
with a second complete validation pass. Strict CRLF line extraction, decimal
length parsing and Connection token validation moved to `http_field.zig`; existing
request-head behavior remains covered by its tests.

Response metadata keeps status as u16 (including unregistered 100–599 values),
reason bytes as a span, version, field count, optional declared Content-Length,
effective body framing and persistence. Reasons accept HTAB/SP/VCHAR/obs-text;
controls, malformed status codes, folding and malformed fields are errors. The
mandatory space after the status code is enforced even for an empty reason.
Metadata remains relocatable and <=128 bytes. Repeated end-to-end headers, such as
Set-Cookie, retain order and case without combining values or interpreting codecs.

Body framing follows request method and response status. HEAD and 304 retain
declared representation length while consuming no body. 1xx/204 reject CL/TE;
101 and successful CONNECT are explicitly unsupported. A 205 still consumes
ordinary framing but has a zero content limit, including chunked and EOF-delimited
forms. All repeated CL/TE and CL+TE combinations are rejected, even on a bodyless
message. Only a single chunked transfer coding is supported in this slice; coding
chains and other transfer codings are an explicit pre-cutover compatibility gate.
Unknown Content-Encoding remains opaque. HTTP/1.0 never enters the reusable pool.
See [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) and
[RFC 9110 §15.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.6).

Receiver ownership and sequencing:

- Give each receiver disjoint stable head/body/descriptor/chunk-line/trailer
  buffers. Input read buffers must not alias them. Initialization checks that the
  configured body/head capacities fit; additional chunk storage requirements are
  checked before consuming a chunked body. Keep any containing buffer owner fixed.
- `feed` copies only consumed bytes. It returns immediately at each 1xx head with
  an informational event; `informational()` borrows that head and its descriptors
  until the next feed. The owner must rewrite/forward applicable 1xx responses
  before allowing overwrite. The parser does not silently discard 103, emit a
  second local Continue, or treat interim output as final-response commitment.
- Default ceilings are eight informational heads, 16 KiB per head, 64 KiB across
  all informational plus final heads, and 64 KiB chunk/trailer framing work.
  Body bytes are caller-configured; descriptor and trailer buffers impose their
  own limits. Count and total-byte limits include every accepted interim head.
- Final fixed/chunked bodies reuse BodyFramer; EOF-delimited bodies copy directly
  into the bounded body span. `message()` is unavailable until the complete final
  body/trailers validate. Errors fence feed/finish/views permanently. Valid prefixes
  cannot be promoted to responses after malformed input, truncation or overflow.
- `finish(.clean_eof)` may complete an EOF-delimited body. This is an assertion by
  the transport owner about the termination, not something the parser can infer.
  Reset, timeout, cancellation, watchdog shutdown and TLS truncation must use
  `.transport_failure`. In particular, a socket shutdown returning zero bytes is
  not sufficient: disarm/check UpstreamWatch and consult transport/TLS state before
  classifying EOF or publishing completion. Clean EOF cannot prove an origin's
  semantic intent when no length was declared; that limitation is inherent in HTTP.
- Informational Connection: close stays sticky through the final response, and
  observed EOF always forbids reuse. The returned reusable flag is only a framing
  precondition; the pool owner must also check request completion, deadline result,
  transport health and unsolicited read-ahead. Extra bytes are preserved, never
  automatically assigned to a future request that has not yet been sent.

Tests exercise every split of 103 + chunked final + following head, every truncated
prefix of fixed/chunked finals, bytewise input, empty/bodyless/205 responses,
interim-only EOF, clean EOF versus transport failure, reason-byte exhaustiveness,
Connection persistence, exact limits and input-buffer overwrite. They establish
parser and borrowed-storage contracts, not real upstream or downstream IO.

At this slice's boundary, RequestTable had a single response span and WorkChannel
completion carried its length. The following §25 adds budgeted downstream
serialization and response metadata handoff so no completion refers to recycled
forwarder scratch. Interim delivery still needs bounded handoff and write ordering.
This finite buffered receiver must not silently replace the unlimited Prometheus
streaming path. No serving runtime, TLS/DNS lifecycle or network backpressure is
claimed complete by this slice.

## 25. Request-owned final response handoff — 2026-09-16

`ResponseWire.prepare` accepts a completed `ResponseIngress`, not arbitrary
unvalidated metadata. It serializes the unchanged final entity into three
request-owned spans. Response body storage must be the same destination used by
the receiver; it is not copied again. Head/tail metadata is copied from forwarder
scratch before publication. The cursor in `Response` tracks only span/offset and
advances by actual successful write counts, including zero; it performs no IO,
allocation or retry decision. The reactor applies its own write-turn budget.

The memory choice is explicit: each admitted request reserves independent response
head/body/tail capacities. Metadata consumes request capacity even while receiving
the input, but it remains valid after the worker starts another exchange. Retaining
worker scratch would tie worker availability to slow clients; copying a combined
body into a second buffer would waste memory and bandwidth. Existing contiguous
response outcomes remain usable with zero metadata capacities. Runtime composition
must configure the new capacities, not rely on those compatibility defaults.

`RequestTable.requiredBytes` includes these actual regions. `WorkChannel` derives
queue bytes from the enlarged Job/Completion layouts. Startup exact-ceiling and
allocation-failure tests exercise the new layout. For a chunked output head, reserve
the allowed HTTP head size plus up to 18 bytes for the chunk-size prefix. A safe
tail bound is input trailer capacity plus its maximum field count plus five bytes;
rewriting a field can insert one space absent from its source. Ordinary fixed
responses consume no tail bytes. Default head limits are 16 KiB and 64 fields;
generated Via/framing/Trailer/Connection fields count toward those limits. Failure
may leave partial output metadata, which must never be published as success.

Header behavior:

- Preserve status/reason, ordered repeated end-to-end fields, opaque content
  encoding and representation metadata for an unchanged body. Remove transport
  fields and every Connection-nominated field from both headers and trailers.
  Via records the upstream protocol; its connection persistence is independent
  of the downstream client's persistence.
- With no retained trailers, emit Content-Length for complete ordinary bodies,
  including formerly chunked or EOF-delimited bodies. HEAD/304 retain any declared
  representation length, rather than substituting zero; 204 has no framing fields.
- Retained trailers produce a generated Trailer declaration, one data chunk when
  nonempty, then the terminating chunk and ordered trailers. An empty entity emits
  only the terminal chunk. If every trailer is removed by Connection nominations,
  the ordinary fixed-length output is valid.
- HTTP/1.0 always closes; requests asking to close also produce Connection: close.
  HTTP/1.0 with retained trailers currently returns `TrailersUnsupported` before
  commitment. Silent removal or merging into the header section would change
  semantics. Decide this compatibility limit before cutover.

Completion ordering and lifetime:

1. Give ResponseIngress the worker job's response body destination. Keep receive
   scratch and outgoing head/tail regions disjoint and stable during preparation.
2. Validate the entire final response, prepare head/tail, then publish exactly one
   `.framed_response` outcome with lengths and the downstream close flag. On error,
   publish a failed outcome; error response/fail-open decisions belong to the
   exchange owner. Stop using all job spans at publication and then wake the reactor.
3. The reactor acknowledges completion once. A detached completion can recycle
   immediately; it has no sendable view. A live completion retains the request slot,
   even though its queue credit is returned. `responseView` requires the current
   generation, responding state, attached client and no outstanding worker lease.
4. Hold the resulting cursor only while that slot remains live. Finish all partial
   writes, drop the cursor, then release/close via Connections. Honor its close flag.
   A cursor's borrowed slices cannot themselves detect a later close/reuse.

Behavioral tests first failed against a NotImplemented stub. Coverage includes
scratch overwrite after publication, live versus detached acknowledgement, no slot
reuse while responding, stale generations, invalid view lengths, one-byte writes,
empty-trailer framing, exact byte/field limits, HTTP/1.0, HEAD/304/204, and a fresh
receiver parsing the serialized binary body/trailers. These are in-memory exchange
and ownership fixtures. They do not prove socket backpressure or TLS termination.

Next work: bounded informational-response delivery and ordering, including avoiding
duplicate local/upstream Continue, then real upstream IO with watchdog deadlines
and transport-aware EOF. A final completion cannot carry an unbounded interim queue
or point into reused receive scratch. Expand that mechanism before implementation.
The transformed-body policy path and unlimited Prometheus streaming path remain
separate. No serving runtime or dependency changes are part of this slice.

## 26. Phase 1 integrated and runnable — 2026-09-17

`src/v2/Relay.zig` and `main.zig` complete the raw HTTP vertical slice. Build with
`zig build v2 -Doptimize=ReleaseSafe`; the runnable contract, architecture, knobs,
shutdown order and benchmark are in [src/v2/README.md](src/v2/README.md). The current
handoff and exact validation logs are in IMPLEMENTATION-PROGRESS.md. This replaces
the outstanding integration work recorded at the end of §25.

Implementation decisions worth preserving:

- One reactor/acceptor and a fixed upstream pool establish the first working path.
  Workers own blocking upstream streams; only the reactor owns clients and request
  transitions. Accepted sockets pass through the existing bounded queue. Native
  readiness handles partial client writes; budget exhaustion polls immediately.
- Zig 0.16 Threaded's IP connect timeout currently panics. The first actual socket
  fixture exposed this. `os/connect.zig` uses nonblocking connect plus finite poll,
  SO_ERROR and the request's absolute deadline, restores blocking mode for the
  worker, and observes shutdown between polls. Watchdog ownership starts before
  blocking request writes and ends before the sole worker closes the stream.
- The buffered contract permits informational heads to be copied into a bounded
  prefix of request-owned response storage. They are delivered in order before
  final output; no extra queue/lease protocol is needed. This delays Early Hints.
  Local admission owns Continue; upstream 100 is suppressed. No informational
  responses go to HTTP/1.0, covered by a failing-then-passing socket regression.
- Original bodies remain retained; incomplete/malformed upstream responses never
  become partial successes. Local error responses use static bytes and consume no
  extra request credit. Health bypasses work admission but still needs fd/client
  space. No automatic retry was added: acceptance before a network failure is
  ambiguous without the later replay contract.
- Actual connection/request/queue/client layouts and fixed thread stacks feed one
  validated startup ceiling. FD demand is checked against RLIMIT_NOFILE. Body
  stores allocate at init; request operation state/scratch uses existing slots and
  bounded stacks. This is not an exact RSS claim. Startup OOM sweeps and equality
  at the memory ceiling pass. Peak request occupancy and child RSS were measured.
- SIGINT/SIGTERM use an atomic stop flag and finite reactor waits. Stop/join accept,
  detach clients, close work, shut down armed upstreams, acknowledge completions,
  join workers, then destroy owners. Native connect observes stop independently.
  Phase 1 chooses bounded abort over pretending shutdown completed delivery.
- Quarantine decision: keep raw forwarding and expose degraded policy state, stop
  affected providers, retain failed registry allocation ownership until process
  exit, and require operator restart. Do not auto-exit or retry mutation. This is
  a phase-2 integration requirement; the raw executable creates no registry.

The initial executable deliberately uses a numeric-IP HTTP origin, one upstream
connection per request, bounded buffered responses and small explicit CLI config.
DNS/TLS/pooling and production routing/config compatibility remain later work;
TLS deadline probes are not an implemented HTTPS relay. This is the planned first
vertical slice, not permission to cut over production. Policy processing is next.
No policy-zig or zonfig changes were made; preserve the authorized local reference.
