# Rewrite TODO — tracks PLAN.md execution

Mark items `[x]` as they complete. Resume from the first unchecked item.
Every phase ends with: `zig build test` green, `task lint` green, all six distro
builds green, test-parity diff clean (PLAN.md §0), one commit.

## Phase 0 — Baseline + scaffolding
- [ ] 0.1 Verify toolchain: `zig version` is 0.16.x; `zig build test` green on HEAD
- [ ] 0.2 Capture baseline: `.rewrite/tests-baseline.txt`, `.rewrite/test-counts-baseline.txt`, `.rewrite/test-run-baseline.txt`
- [ ] 0.3 Create `.rewrite/zigdoc-notes.md` + `.rewrite/test-exceptions.md` (empty scaffolds)
- [ ] 0.4 Create new dirs: `src/core`, `src/http`, `src/pipeline`, `src/signals/{datadog,otlp,prometheus}`, `src/service`
- [ ] 0.5 Commit Phase 0

## Phase 1 — src/core/
- [ ] 1.1 `core/limits.zig` (all bounds + `Limits.fromConfig` + `steadyStateBytes` + budget test)
- [ ] 1.2 `core/io_select.zig` (`IoBackend`, `IoRuntime`, env-driven selection)
- [ ] 1.3 `core/conn_slab.zig` (SoA slab, ConnId+generation, free list, buffer slicing; tests: claim/release/ABA/exhaustion/single-allocation)
- [ ] 1.4 `core/arena_pool.zig` (reset-retain pool; tests)
- [ ] 1.5 `core/lifecycle.zig` (Io.Group + shutdown flag + sigwait integration; zigdoc Io.Group first)
- [ ] 1.6 Register core tests in `src/root.zig` test block
- [ ] 1.7 Phase 1 gate + commit

## Phase 2 — src/pipeline/ (pure, no network)
- [ ] 2.1 zigdoc pre-work: confirm std.Io.Reader/Writer vtable shape for custom reader/writer impls; note in `.rewrite/zigdoc-notes.md`
- [ ] 2.2 Port `proxy/compress.zig` → `pipeline/compress_buffered.zig` (tests verbatim; old file untouched until Phase 5)
- [ ] 2.3 `pipeline/encoding.zig`: ContentEncoding enum + streaming GzipStream/ZstdStream decoders+encoders (C streaming APIs); round-trip tests vs compress_buffered
- [ ] 2.4 `pipeline/framer.zig`: WireFormat enum + Framer union + RecordSink type
- [ ] 2.5 `pipeline/frame_ndjson.zig` (SIMD scanner lifted from tail/framer.zig) + chunk-sweep tests
- [ ] 2.6 `pipeline/frame_json_array.zig` (depth/string-state scanner) + chunk-sweep + malformed-fixture tests
- [ ] 2.7 `pipeline/frame_protobuf.zig` (varint length-delimited top-level framing) + tests incl. otlp-metrics.pb fixture
- [ ] 2.8 `pipeline/frame_prom_text.zig` (adapter over prometheus streaming_filter)
- [ ] 2.9 `pipeline/pipeline.zig`: PipelineSpec, PipelineCtx, `run()` over fixed readers/writers; port `streamReaderToWriter` + pure transport tests; failure-semantics tests (PLAN §6.5)
- [ ] 2.10 Register pipeline tests in root.zig
- [ ] 2.11 Phase 2 gate + commit

## Phase 3 — src/signals/ (ports, test-heaviest)
- [ ] 3.1 `git mv src/modules/datadog_log.zig src/signals/datadog/log.zig` (+imports fix)
- [ ] 3.2 `git mv src/modules/datadog_metric.zig src/signals/datadog/metric.zig`
- [ ] 3.3 `git mv src/modules/otlp_attributes.zig src/signals/otlp/attributes.zig`
- [ ] 3.4 Move + restructure `datadog_logs_v2.zig` → `signals/datadog/logs.zig` (strata split per PLAN §7.2; batch fns preserved; readAll wrappers deleted → exceptions table)
- [ ] 3.5 Move + restructure `datadog_metrics_v2.zig` → `signals/datadog/metrics.zig`
- [ ] 3.6 Move + restructure `otlp_logs.zig` → `signals/otlp/logs.zig`
- [ ] 3.7 Move + restructure `otlp_metrics.zig` → `signals/otlp/metrics.zig` (update build.zig anonymous import path)
- [ ] 3.8 Move + restructure `otlp_traces.zig` → `signals/otlp/traces.zig`
- [ ] 3.9 `git mv src/prometheus/* src/signals/prometheus/` (verbatim; fix imports incl. prometheus_module reference)
- [ ] 3.10 Update root.zig test block; test-parity diff vs baseline; record exceptions
- [ ] 3.11 Phase 3 gate + commit

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
