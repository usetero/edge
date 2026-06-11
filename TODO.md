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

## Phase 4 — src/service/ + http/router
- [ ] 4.1 Read runtime/app.zig:389-489 wiring; record authoritative route/service map in `.rewrite/wiring-notes.md`
- [ ] 4.2 Port `proxy/router.zig` → `http/router.zig` (tests verbatim)
- [ ] 4.3 `service/service.zig`: ServiceKind, Service union, Route, Outcome, PlanError
- [ ] 4.4 `service/health.zig` + `service/passthrough.zig` (+ported tests)
- [ ] 4.5 `service/datadog.zig` (+ported dispatch tests)
- [ ] 4.6 `service/otlp.zig` (+ported tests)
- [ ] 4.7 `service/prometheus.zig` (fetch_filtered outcome; +ported tests)
- [ ] 4.8 `runtime/distro.zig` (comptime DistroSpec per distribution)
- [ ] 4.9 Port route-plan classification tests from proxy/server.zig
- [ ] 4.10 Register in root.zig; Phase 4 gate + commit

## Phase 5 — src/http/ + runtime/ + cutover (THE BIG ONE)
- [ ] 5.1 zigdoc pre-work (PLAN §1 list): std.Io.net, Io.Group, std.http.Server, std.http.Client.Request chunked send, Io.Threaded; commit findings to zigdoc-notes.md
- [ ] 5.2 `http/upstream.zig` (port manager + URL tests; streaming/chunked send per findings)
- [ ] 5.3 `http/conn.zig` (request loop state machine; outcome execution; header filtering port)
- [ ] 5.4 `http/server.zig` (listener, accept loop, Io.Group spawn, load shed)
- [ ] 5.5 `runtime/metrics.zig` (port runtime_metrics.zig)
- [ ] 5.6 New `runtime/app.zig` (juicy main → io_select → lifecycle → server; distro composition)
- [ ] 5.7 Rewire six `*_main.zig` (signatures unchanged) + lambda/ upstream import
- [ ] 5.8 Rewrite `bench/echo_server.zig` on new http core
- [ ] 5.9 Moves: `src/proxy`→`src/proxy-old`, leftover `src/modules`→`src/modules-old`, `src/io`→`src/io-old`, old `src/runtime` files→`src/runtime-old`
- [ ] 5.10 Update `.ziglint.zon` paths (explicit dir list, exclude -old)
- [ ] 5.11 Rewrite `build.zig` (helper fn, drop httpz from new tree, keep step names)
- [ ] 5.12 Integration smoke (PLAN §12 Phase 5 gate): echo upstream + edge + policy filtering + gzip + health + metrics + SIGTERM
- [ ] 5.13 steadyStateBytes logged; RSS sanity vs budget
- [ ] 5.14 Phase 5 gate + commit

## Phase 6 — Tail convergence
- [ ] 6.1 uring scheduler takes `io` in init; tail framer retires in favor of pipeline/frame_ndjson
- [ ] 6.2 Checkpoint Lane worker → io.concurrent task in Lifecycle.group
- [ ] 6.3 Tail smoke test (grow file + policy + SIGTERM)
- [ ] 6.4 Phase 6 gate + commit

## Phase 7 — Cleanup
- [ ] 7.1 Remove httpz from build.zig + build.zig.zon (verify nothing imports)
- [ ] 7.2 Bench comparison vs baseline → `.rewrite/bench-results.md`
- [ ] 7.3 Claude.md note (0.16-native pointer)
- [ ] 7.4 Verify `-old` referenced nowhere; final full gate; commit
