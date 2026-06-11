# Test exceptions table

| Original test | File | Why not portable | Replacement test |
|---|---|---|---|
| processMetrics - benchmark protobuf exposes nested arena over httpz fallback allocator | signals/otlp/metrics.zig | Removed by the user's own otlp_metrics rework (allocator fix) during the rewrite, not by the migration | n/a — user decision |
