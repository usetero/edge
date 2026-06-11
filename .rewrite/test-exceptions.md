# Test exceptions table

| Original test | File | Why not portable | Replacement test |
|---|---|---|---|
| processMetrics - benchmark protobuf exposes nested arena over httpz fallback allocator | signals/otlp/metrics.zig | Removed by the user's own otlp_metrics rework (allocator fix) during the rewrite, not by the migration | n/a — user decision |
| DatadogModule ×7 / OtlpModule ×9 / PrometheusModule ×4 dispatch tests | modules-old/ | Tested the module-wrapper interface (reader/writer + ModuleStreamResult) which no longer exists | Dispatch: service plan tests (service/*.zig). Filtering semantics: unchanged signal batch fns keep their own tests (signals/**). End-to-end: Phase 5 integration smoke verified policy drop + gzip re-encode + allDropped paths live |
| classifyRoute matches core routes / prefilter policy path | runtime-old/pipeline.zig | Decision logic moved into router + service.plan (each tested); metric classification ported | "classifyKnownPath matches core routes" in http/conn.zig |
| CompressionEncoding.fromHeader | proxy-old/server.zig | Type replaced by pipeline ContentEncoding | "ContentEncoding.fromHeader" in pipeline/encoding.zig |
| toHttpMethod | proxy-old/server.zig | renamed | "HttpMethod.fromStd" in service/service.zig |
| Router fallback match / prefix priority | proxy-old/router.zig | renamed ports | "Router wildcard fallback and registration order" / "Router longest prefix wins" in http/router.zig |
| UpstreamClientManager ×5 | proxy-old/upstream_client.zig | renamed type | Same tests as "UpstreamManager ..." in http/upstream.zig |
