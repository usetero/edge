# Authoritative wiring (from runtime/app.zig:389-501, old tree)

Registration order: health FIRST, then per-distro bundles, passthrough LAST.

| service | routes | upstream | max_req_body | notes |
|---|---|---|---|---|
| health | exact GET /_health | (unused) | 0 | responds 200 {"status":"ok"} |
| datadog_logs | exact POST /api/v2/logs | logs_url orelse upstream_url | max_body_size | body = TOP-LEVEL JSON ARRAY → json_array framer OK |
| datadog_metrics | exact POST /api/v2/series | metrics_url orelse upstream_url | max_body_size | body = OBJECT {"series":[...]} → NOT json_array; buffered path initially |
| otlp | exact POST /v1/{logs,metrics,traces} | upstream_url | max_body_size | protobuf → otlp_protobuf framer; JSON bodies are objects → buffered path initially |
| prometheus | exact GET /metrics + prefix GET /metrics/ | metrics_url orelse upstream_url | 1024 (req) | response-side filtering (fetch_filtered) |
| passthrough | any, all methods | upstream_url | max_body_size | raw copy |

Shared service deps: PolicyRegistry (lock-free snapshots), EventBus, RuntimeMetrics.
Prometheus extra: max_input/output_bytes_per_scrape from config.prometheus.

## Streaming coverage decision (Phase 4)
Streaming framers: datadog logs (json_array), OTLP protobuf (otlp_protobuf),
prometheus text (prom_text), passthrough (raw).
Buffered fallback (Outcome.pipe_buffered): datadog metrics (object body),
OTLP JSON (object body). These keep batch-fn semantics until object-keyed
framing is added later.

## Phase 5 behavior notes
- std.http.Server rejects unknown Content-Encoding values at head parse
  (HttpTransferEncodingUnsupported) → conn driver answers a raw 400 and
  closes. Old httpz stack forwarded exotic encodings opaquely. zstd/gzip/
  x-gzip/deflate/compress/identity all parse fine, so agent traffic is
  unaffected; recorded as a known posture change for e.g. brotli.
