# Rewrite TODO — tracks PLAN.md execution

Mark items `[x]` as they complete. Resume from the first unchecked item.
Every phase ends with: `zig build test` green, `task lint` green, all six distro
builds green, test-parity diff clean (PLAN.md §0), one commit.

## Phase 0 — Baseline + scaffolding
- [x] 0.1 Verify toolchain: zig 0.16.0; baseline = 364/365 pass (1 known failure from USER's uncommitted otlp_metrics.zig edit — see .rewrite/test-run-baseline.txt; do not "fix")
- [x] 0.2 Capture baseline: `.rewrite/tests-baseline.txt` (403 tests), `.rewrite/test-counts-baseline.txt`, `.rewrite/test-run-baseline.txt`
- [x] 0.3 Create `.rewrite/zigdoc-notes.md` + `.rewrite/test-exceptions.md` (empty scaffolds)
- [x] 0.4 Create new dirs: `src/core`, `src/http`, `src/pipeline`, `src/signals/{datadog,otlp,prometheus}`, `src/service`
- [x] 0.5 Commit Phase 0 (ce7dcea). NOTE: PLAN.md is gitignored by repo convention — it lives untracked in the worktree; read it before resuming.

## Phase 1 — src/core/  ✅ DONE
- [x] 1.1 `core/limits.zig` (bounds + fromConfig + steadyStateBytes + locked budget test; TERO_MAX_CONNECTIONS env override)
- [x] 1.2 `core/io_select.zig` (IoBackend enum incl. reserved evented/uring → error.IoBackendUnavailable; TERO_IO_BACKEND env; IoRuntime pins owned Threaded)
- [x] 1.3 `core/conn_slab.zig` (MultiArrayList SoA; ConnId packs gen<<16|slot; ConnState machine asserted; 4 tests)
- [x] 1.4 `core/arena_pool.zig` (reset .retain_capacity; reserve high-water warn)
- [x] 1.5 `core/lifecycle.zig` (Io.Group + Io.Event; spawn = Group.concurrent ONLY — Group.async tasks may never run, see zigdoc-notes; sigwait wiring deferred to Phase 5 app.zig as planned)
- [x] 1.6 Registered in src/root.zig test block (+ pub exports core_*)
- [x] 1.7 Gate: 378/379 pass (the 1 fail is the pre-existing user-WIP otlp_metrics failure), lint green, 6 distros build. Committed.

## Phase 2 — src/pipeline/ (pure, no network)  ✅ DONE
- [x] 2.1 zigdoc: Reader vtable = stream(r,w,limit); Writer vtable = drain(w,data,splat); stream() returning 0 ≠ EOF. Findings in zigdoc-notes.md
- [x] 2.2 Ported compress.zig → compress_buffered.zig. FIXED LATENT BUG in decompressGzip (total_out only updated on Z_BUF_ERROR → Z_OK-with-full-buffer overwrote output; triggered by multi-block streams from any streaming compressor). Old proxy copy untouched.
- [x] 2.3 encoding.zig: 0.16 std has flate.Compress AND Decompress natively + zstd.Decompress — only zstd ENCODE uses libzstd (ZstdCompressor = custom Writer drain over ZSTD_compressStream2). Oracle-verified round trips at chunk 1/7/4096.
- [x] 2.4 framer.zig: WireFormat enum + Framer union(WireFormat) with inline-else dispatch. Sinks are COMPTIME DUCK-TYPED (anytype, onRecord(bytes)!Decision) not vtables. Framers own all wire syntax; keep-all sink reproduces input.
- [x] 2.5 frame_ndjson.zig: SIMD scanner; eval bound enforced even on the zero-copy fast path (deterministic vs chunk boundaries)
- [x] 2.6 frame_json_array.zig: depth/string state machine; canonical re-emission; desync→verbatim
- [x] 2.7 frame_protobuf.zig: incremental varint tag/len; non-LEN fields copy verbatim; byte-fidelity keep-all (synthetic fixtures; .pb fixture deferred — it's a module import not embeddable here)
- [x] 2.8 prom_text = NdjsonFramer alias in Framer union (line framing identical; prometheus sink semantics live in signals/, Phase 4/5). No separate file needed.
- [x] 2.9 pipeline.zig: PipelineSpec/Buffers/run() + streamReaderToWriter ported with test; §6.5 tests (bomb bound abort, corrupt-gzip ReadFailed)
- [x] 2.10 Registered in root.zig (test block + pub exports)
- [x] 2.11 Gate: 426/426 tests pass (user's otlp_metrics rework also landed → known failure gone), lint green, 6 distros build. Committed.

## Phase 3 — src/signals/ (ports)  ✅ DONE
- [x] 3.1–3.9 All moves done via git mv (history preserved); intra-signal imports fixed; old-tree wrappers (datadog_module/otlp_module/prometheus_module) repointed at ../signals/ so old tree keeps compiling until Phase 5
- [x] SCOPE DECISION: kept the moved files' public APIs intact (incl. processXxxStream readAll wrappers) because old modules/ wrappers still call them until Phase 5; the strata split / record-level sink API extraction happens in Phase 4/5 when service sinks define the exact shape needed. readAll wrappers die with modules-old in Phase 5.
- [x] 3.10 Parity diff: 1 missing test = removed by USER's own otlp_metrics rework (recorded in test-exceptions.md). build.zig anonymous import unchanged (name-based, path-independent).
- [x] 3.11 Gate: 426/426 tests, lint green, 6 distros build. Committed (includes user's in-flight otlp_metrics.zig rework which travels with the rename).

## Phase 4 — src/service/ + http/router  ✅ DONE
- [x] 4.1 Wiring recorded in `.rewrite/wiring-notes.md` (health first, passthrough last; logs_url/metrics_url fallbacks; prometheus scrape caps; req-body caps)
- [x] 4.2 http/router.zig ported keyed by ServiceIndex (RouteSet replaces ModuleConfig); all 6 router tests ported with assertions unchanged
- [x] 4.3 service/service.zig: ServiceKind, Service union (inline-else plan dispatch), RoutePattern/HttpMethod/MethodBitmask ported, Outcome = respond | forward_raw | pipe_stream | pipe_buffered | fetch_filtered, Signal, UpstreamChoice, BufferedKind
- [x] 4.4–4.7 All five service files with plan() + tests. KEY DESIGN NOTES:
      * pipe_buffered covers JSON OBJECT bodies (datadog series {"series":[...]}, OTLP/JSON) that top-level-array/protobuf framers don't; streaming covers datadog logs (json_array), OTLP protobuf, prom text, passthrough
      * fail-open: unknown content-type or content-encoding → forward_raw (matches old module gates)
      * BEHAVIOR CHANGE (streaming only): old "all records dropped → respond 200 {} without forwarding" can't exist when streaming — empty filtered batch is forwarded instead. Buffered path keeps old semantics. Documented in wiring-notes.
- [x] 4.8 runtime/distro.zig: comptime servicesFor(distribution) + buildService; mirrors bundlesFor exactly
- [x] 4.9 Old server.zig test parity: toHttpMethod → HttpMethod.fromStd test; CompressionEncoding → ContentEncoding tests (already); streamReaderToWriter both tests in pipeline.zig; header-skip tests port with conn.zig in 5.3
- [x] 4.10 Gate: 448/448 tests, lint green, 6 distros. Committed.

## Phase 5 — src/http/ + runtime/ + cutover (THE BIG ONE)
- [x] 5.1 zigdoc: net listen/accept/Stream.Reader|Writer, http.Server init/receiveHead/respondStreaming/readerExpectContinue, Head fields (transfer_compression!), unknown content-encoding → 400 posture change recorded in wiring-notes. Cancellation surfaces as ReadFailed through interfaces (no Canceled prongs in http error sets).
- [x] 5.2 http/upstream.zig: UpstreamManager port (tests renamed UpstreamClientManager→UpstreamManager), header-skip helpers + tests (old skip list kept EXACTLY — content-encoding passes through since we re-encode same codec)
- [x] 5.3 http/conn.zig: serveConnection keep-alive loop over slab buffers; outcome exec (respond/forward_raw/pipe_stream/pipe_buffered/fetch_filtered); /_edge/metrics short-circuit ported; request metrics (classifyKnownPath + recordRequest/Duration); RecordSink = wrap-record-as-one-element-batch through the EXISTING signal batch fns (identical filter semantics, memory bounded per record via reset-retain arena; future opt: direct engine binding); BatchSummary normalizes distinct per-signal result types; §6.5 abort→502 for mid-stream pipe errors; buffered path captures RAW body first → fail-open forwards original bytes (old semantics, incl. allDropped→200 {})
- [x] 5.4 http/server.zig: accept loop, Lifecycle.spawn(concurrent), ConcurrencyUnavailable→503 shed
- [x] 5.5 runtime_metrics.zig was already httpz-free — kept in place, no port needed
- [x] 5.6 New runtime/app.zig with reusable Engine (heap-alloc'd for pointer stability; create/start/requestShutdown/awaitShutdown/stop/destroy); run() = juicy main → io_select → config → registry/loader → Engine → sigwait waiter → awaitShutdown → structured cancel. Limits.resolve(max_body_size, env) decoupled from ProxyConfig; distro.buildService takes ServiceOptions
- [x] 5.7 Four proxy mains unchanged (app.run signature kept); lambda_main cut over to Engine (datadog service set, extension loop calls engine.requestShutdown on SHUTDOWN event); edge_tail_main untouched (tail-only)
- [x] 5.8 bench/echo_server.zig rewritten on std.Io.net + std.http.Server + Io.Group (stats/capture logic kept verbatim)
- [x] 5.9 Moves done: proxy-old, modules-old, io-old, runtime-old/{app,pipeline}.zig
- [x] 5.10 .ziglint.zon unchanged (scans src incl. -old which passes; -old dies in Phase 7)
- [x] 5.11 build.zig: httpz dependency + all addImport("httpz") removed from compiled tree; step names unchanged
- [x] LIMITS GROWTH: per-conn now includes decode (zstd window+192K) + encode (192K) + body (8K) + chunk (4K) regions → 1736K/conn, 438 MiB reserved at 256 conns (virtual; RSS tracks touched pages). Budget test re-locked. TERO_MAX_CONNECTIONS tunes it.
- [x] 5.12 Integration smoke PASSED: health 200; plain + GZIP json_array bodies filtered per record at upstream (gzip re-encoded — NEW capability, old stack never filtered compressed bodies); passthrough relay; /_edge/metrics; SIGTERM structured-cancel clean exit. Results in wiring-notes.md
- [x] 5.13 Budget emitted as DataPlaneBudget bus event; slab buffers via page_allocator; ReleaseFast RSS = 4.5 MiB idle / 6.2 MiB under traffic (438 MiB is virtual reservation; Debug RSS inflated by 0xaa memset)
- [x] 5.14 Phase 5 COMPLETE: 416/416 tests, lint green, 6 distros httpz-free, smoke green. Exceptions table finalized.

## Phase 6 — Tail convergence  (DEFERRED by user — resume here)
- [ ] 6.1 uring scheduler takes `io` in init; tail framer retires in favor of pipeline/frame_ndjson
- [ ] 6.2 Checkpoint Lane worker → io.concurrent task in Lifecycle.group
- [ ] 6.3 Tail smoke test (grow file + policy + SIGTERM)
- [ ] 6.4 Phase 6 gate + commit

## Phase 7 — Cleanup  ✅ DONE (run before Phase 6 at user request)
- [x] 7.1 httpz removed from build.zig.zon (build.zig + sources were already clean); supersedes the user's WIP hash bump. zig-pkg/httpz-* vendor dirs left in place (prune whenever).
- [x] 7.2 Bench vs old stack (worktree @ dba3aaf, same old-echo upstream, user's exact oha scenario): NEW +24% throughput (66.2k vs 53.6k rps), p99 4.6x tighter (2.7ms vs 12.5ms), 100%/100% success. Three production fixes found via the user's failing c=150 run: 502 on upstream-open failure (was silent close → reconnect storm), kernel_backlog 128→1024 (edge + echo), std.http.Client pool free_size 32→max_connections (root cause: ephemeral port exhaustion / AddressUnavailable). Full write-up in .rewrite/bench-results.md.
- [x] 7.3 Claude.md: 0.15 reference section marked HISTORICAL with 0.16-native pointer
- [x] 7.4 -old dirs verified unreferenced (kept on disk per original instruction); final gate 416/416 + lint + 7 binaries. Committed.
