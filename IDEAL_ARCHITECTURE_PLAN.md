# Ideal Architecture Implementation Instructions

This is the execution playbook. We build scaffolding first, then fill behavior
part-by-part with tests at every stage.

## Stage 0: Global Rules

How this stage should work:

- No behavior regressions are accepted without explicit signoff.
- Fail-open remains default unless route-level policy says otherwise.

Implementation instructions:

1. Add migration status table in docs.
2. Make conformance + perf checks required for stage completion.

Exit criteria:

1. Baseline conformance/perf artifacts are captured.

## Stage 1: Scaffolding Only (No Functional Change)

How this stage should work:

- New architecture skeleton exists in parallel.
- Legacy path remains the only active path.

Implementation instructions:

1. Introduce interfaces:

- `Pipeline.process(req_ctx) -> ProcessResult`
- `PolicySnapshot` immutable runtime
- `FieldAccessor/FieldMutator` ABI by signal
- `UpstreamTransport` abstraction for streaming I/O

2. Add bounded queue + worker pool skeleton per signal.
3. Add thread-local arenas and reusable buffers.
4. Add segmented timers and counters for each request stage.

Exit criteria:

1. Existing tests pass unchanged.
2. New scaffolding tests pass.
3. No measurable regression in baseline benchmark.

## Stage 2: Streaming Dataflow Spine

How this stage should work:

- Request/response path is best-effort streaming with bounded fallback.
- Primary dataflow:
  - inbound request reader -> transform/filter writer -> upstream request body
    writer
  - upstream response reader -> response filter writer -> client response writer
- Materialization is used only when required by specific transform/matcher
  behavior.

Implementation instructions:

1. Implement request streaming adapter:

- reads from incoming request reader
- writes directly to upstream body writer
- supports optional in-flight filter/transform hook

2. Implement response streaming adapter:

- reads upstream response body
- writes directly to downstream/client writer
- supports optional response filter

3. Implement bounded fallback mode:

- explicit max-size and reason tags (`needs_materialization`, `codec_limit`,
  etc.)

4. Preserve compression contract:

- passthrough compressed streams on fast path
- decode/re-encode only when inspection/mutation is needed

Exit criteria:

1. Chunked streaming tests pass.
2. Large body memory-bound tests pass.
3. Conformance subset for streamed paths passes.

## Stage 3: Snapshot Compiler

How this stage should work:

- Policies are compiled to immutable snapshots.
- Data plane reads one atomically swapped snapshot pointer with lock-free
  lookup.

Implementation instructions:

1. Build policy IR.
2. Compile staged plan:

- route/content-type prefilter
- field-presence prefilter
- literal/prefix/hash stage
- regex/hyperscan stage
- transform stage

3. Implement atomic swap and safe snapshot retirement.
4. Emit snapshot version metadata in telemetry.

Exit criteria:

1. Snapshot churn/race tests pass.
2. Deterministic policy/transform ordering tests pass.
3. Conformance cases for complex matching/transforms pass.

## Stage 4: Fast Path and Policy Path

How this stage should work:

- Fast path: no relevant policy => pure stream passthrough.
- Policy path: decode once, evaluate, mutate/drop, encode only if modified.

Implementation instructions:

1. Add prefilter check at routing boundary.
2. Route no-policy requests to zero/near-zero overhead pass-through path.
3. Route matching-policy requests to staged evaluation path.
4. Keep request-level bounded memory guarantees in both paths.

Exit criteria:

1. Conformance pass for migrated signal.
2. Fast-path hit ratio observable.
3. Benchmark at policy counts `0,1,10,100,1000` shows expected scaling.

## Stage 5: Signal-by-Signal Migration

Migration order:

1. Logs
2. Metrics
3. Traces
4. Prometheus

How each migrated signal should work:

- Migrate one signal at a time directly.
- Full conformance for that signal before moving to the next signal.
- Performance gates pass before moving to the next signal.

Per-signal instructions:

1. Wire signal to new runtime path.
2. Remove avoidable copies/allocations in hot loops.
3. Validate transforms and filtering semantics.
4. Proceed to the next signal only after gates are green.

Exit criteria per signal:

1. Conformance green.
2. No perf gate failures.
3. Operational metrics stable under soak.

## Stage 6: Resilience Layer

How this stage should work:

- Upstream behavior remains stable under network faults and overload.

Implementation instructions:

1. Add per-destination pool + adaptive concurrency.
2. Add retry budget and retry classification.
3. Add circuit breaker with half-open probes.
4. Enforce timeout budget across connect/send/receive/total.
5. Define overload behavior (`queue`, `shed`, or route-specific fail-open).

Exit criteria:

1. Fault-injection tests pass.
2. Soak with policy churn + upstream faults remains stable.

## Stage 7: Default-On and Cleanup

How this stage should work:

- New architecture is default for all signals.
- Legacy path removed after sustained stability window.

Implementation instructions:

1. Remove legacy codepaths and unused switches.
2. Finalize ops runbook and incident triage workflow.

Exit criteria:

1. Full policy-conformance passes from edge wrapper task.
2. Performance gates pass on full benchmark matrix.
3. Canary/production signoff complete.

## Required Testing Cadence (Every Stage)

1. Implement scaffolding/components for the stage.
2. Add unit tests for new internals.
3. Add integration tests for new dataflow.
4. Run targeted conformance tests for impacted areas.
5. Run full impacted conformance suite.
6. Run benchmark comparison and archive artifacts.
7. Proceed only if all checks pass.
