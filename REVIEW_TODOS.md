# Edge design and implementation plan

Status: proposed architecture and acceptance criteria. This document assumes the [policy-zig contract](../policy-zig/REVIEW_TODOS.md) is implemented and validated. Edge's work is to integrate that contract into a bounded, observable streaming telemetry service.

## Objectives

Edge should keep serving through expected operational failures, use very little memory, and shed excess work before it threatens process health. Unrecoverable internal corruption should stop service promptly so a supervisor can restart it.

The performance target is 150,000 successfully handled requests/sec with low latency and low CPU and memory consumption on a declared workload and machine. Payload size, records/request, policy complexity, compression, TLS, network latency, CPU count, and memory limit are acceptance parameters. The target is established by measurements of delivered output, not inferred from evaluator speed.

Expose a small operational interface: a memory limit, optional CPU-worker/workload settings, routes and upstreams, and explicit failure dispositions. Implementation complexity belongs behind clear transport, scheduling, policy, and encoding boundaries.

## Policy dependency contract

Edge relies on policy-zig for:

- immutable programs with safe leases and complete ownership of native/regex artifacts;
- accurate program, projection, worker, state, and capability requirements;
- typed demanded-field plans, including repeated values and per-policy sampling keys;
- complete decisions and ordered effects with explicit borrowed lifetimes;
- unavailable-evaluation errors distinct from valid keep/drop results;
- sampling, quota, transform, and state-migration semantics;
- bounded diagnostic records and race-free statistics transfer.

Edge provides bounded source-fetching and compilation budgets, record projection, scheduling, execution inputs, and wire encoding. It uses policy-zig's state domains and transform semantics rather than implementing separate policy behavior for each protocol.

A candidate program becomes active only after Edge has reserved its requirements, prepared compatible runtime resources, and verified route capabilities. If preparation or publication cannot proceed, Edge retains the last good program and reports the condition. The program lease also protects metadata needed by pending effects or diagnostics.

## Architecture and ownership

```text
bounded transport admission
    -> streaming body decode
    -> logical record and inherited context
    -> policy demand projection
    -> policy evaluation and ordered effects
    -> record encoding and streaming compression
    -> bounded upstream output

control: sources -> bounded compile/prepare -> program publication
observe: bounded snapshots/events -> logs, metrics, optional capture
```

Services are pure planners: method, path, headers, and configuration produce a route plan. The plan declares signal, format, codecs, upstream, policy requirements, grouping mode, and failure disposition. Transport executes the plan; services do not allocate request bodies or perform network I/O.

Separate these lifetimes:

| Object | State and owner |
| --- | --- |
| Connection | Transport owns socket, bounded headers/buffers, generation, and deadlines |
| Admitted stream | Scheduler owns codec history, framing/context state, program lease, and bounded input/output blocks |
| CPU worker | Owns reusable projection, policy scratch, and transient transform/encoding workspace for one runnable step |
| Stateful policy domain | policy-zig owns semantics; Edge guarantees the selected assignment/consistency mode |
| Pending I/O operation | Transport owns stable buffer leases and an operation generation until completion or cancellation is resolved |
| Tail source | Tail adapter owns file identity, partial record state, and consumed/acknowledged offsets |

A slow stream retains its declared persistent state but releases CPU-worker execution capacity while waiting for I/O. Use bounded byte/record quanta and fair scheduling. Worker affinity can improve locality without preventing other streams from running.

Reserve output capacity before beginning a record step. Complete the step into stream-owned output storage or preserve continuation state entirely in the admitted stream. A suspended stream must not retain pointers into scratch that another worker step can overwrite. Large output and record expansion remain subject to declared bounds.

Use generation-bearing handles for reusable connections, streams, buffers, and I/O operations. Do not recycle storage while a queued callback or completion can still reference it. Queue lengths and operation counts are explicit capacities.

## Failure and delivery contract

Default to fail-open for recoverable policy or transform failures when the original record can still be forwarded correctly. Preserve original bytes until that record's effects complete. A strict route can explicitly reject unavailable policy evaluation. Every bypass has a stable reason and observable count.

“Fail closed for restart” means that internal corruption stops admission and terminates the process; it does not mean that ordinary provider, network, or capacity failures crash the service.

| Condition | Behavior |
| --- | --- |
| Policy provider unavailable or update exceeds its budget | Keep the last good program, report degradation, retry with bounded backoff/jitter |
| No program on cold start | Load a validated local last-good program, or use explicitly allowed forwarding-only mode; required-policy routes remain unready |
| Recoverable evaluation/effect failure with intact original record | Discard uncommitted edits, forward original on fail-open routes, count bypass; keep process alive |
| Request cannot obtain capacity before admission | Return 429 with `Retry-After` using reserved response storage |
| Permanently malformed or unsupported input | Return the appropriate protocol error when possible; use configured raw forwarding only when bytes and framing remain valid |
| Upstream timeout/refusal | Return a retryable failure if possible, evict broken connections, and keep process alive |
| Downstream cancellation | Stop work and release reservations after outstanding ownership is resolved |
| Optional observer/extension unavailable | Continue telemetry processing and report diagnostic/extension loss or saturation |
| Internal ownership/invariant failure | Stop serving, emit bounded emergency diagnostics, and exit nonzero for supervisor restart |

Capacity rejection must precede upstream side effects. For HTTP, perform bounded header parsing and reserve the required stream resources before accepting `100 Continue` or accumulating body data. If no socket/TLS/header capacity exists, refusal or connection close may be necessary; an HTTP response cannot be guaranteed before an HTTP exchange is available.

OTLP treats 429, 502, 503, and 504 as retryable HTTP failures and supports `Retry-After` for throttling. A populated partial-success response has different retry semantics. Emit the required protocol response body as well as the status. [OTLP specification](https://opentelemetry.io/docs/specs/otlp/#otlphttp-response)

### Commit boundaries

A streaming proxy cannot guarantee whole-request atomic delivery while retaining no replayable request data. Specify the boundaries explicitly:

1. Admission reserves resources without forwarding body bytes.
2. A logical record remains available in its original form through evaluation and effect application.
3. Successful record output becomes owned by the stream's outbound blocks before worker reuse.
4. Upstream writes make whole-request fallback or retry potentially duplicative.
5. Upstream acknowledgement determines the route's delivery result; a local write alone is not that acknowledgement.

After upstream bytes have escaped, do not restart the request with raw bytes or retry a POST internally without replayable input and an explicit duplicate-delivery contract. Abort an ambiguous exchange and report uncertainty. Policy quota accounting follows policy-zig's successful-evaluation boundary; encoding or delivery failures are recorded separately.

Reserve the maximum simultaneous memory needed by an admitted stream's supported profile. Ordinary pool pressure then causes backpressure, not allocation failure midway through a valid record. Late size/work violations remain possible: fail open only if the original record and valid framing can still be emitted. Corrupt compression or lost framing may require aborting the exchange.

Routes requiring validation before any delivery use an explicitly bounded whole-request buffer or separately budgeted spool. Inputs exceeding that route's permanent bound receive an appropriate client error rather than endless retryable overload responses.

## Memory configuration and admission

Expose `memory_limit_bytes = X` as the primary dial. The planner derives capacities from X, CPU availability, route profiles, codec limits, and policy-zig requirements. Optional overrides constrain the solution; no override authorizes exceeding the aggregate budget.

At startup, report the minimum viable budget and a manifest of region/pool sizes, counts, alignments, owners, and headroom. Reject impossible configurations with the exact incompatible requirement. Derive deployment/chart settings from the same resolved plan.

Distinguish application-owned memory from the full deployment envelope. Fixed pools and charged allocators enforce the application limit. Stack mappings, runtime/library mappings, socket and ring memory, file cache, and platform overhead require separate accounting and reserve. On Linux, cgroup containment is the final boundary: `memory.max` may trigger OOM killing and may temporarily be exceeded, so admission must operate below it rather than depend on catching allocation failure there. [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-interface-files)

Use checked arithmetic to satisfy:

```text
application_budget <= X - platform_reserve - emergency_reserve

application_budget >=
    base/configuration/routes/metrics
  + bounded source_fetch/compile/prepare peak
  + all live policy programs, native capabilities, and state domains
  + connections * small_transport_state
  + upstream_slots * (transport + TLS_state)
  + cpu_workers * transient_policy/projection/transform_workspace
  + sum(admitted_streams' persistent codec/context/record reservations)
  + bounded input/output block pools
  + journals/tap/extensions/tail/checkpoint storage
  + alignment and allocator bookkeeping
```

Memory terms represent simultaneous lifetimes. Share storage only when nonoverlap is proven. Codec history belongs to each suspended stream that needs it; it cannot be reused merely because another stream runs on the same CPU worker.

Count source parsing, native compiler scratch, candidate programs, retired generations, and prepared worker resources in update peak memory. Protect reload and emergency reservations from ordinary traffic. A provider outage or saturated output queue must not starve health checks, rejection responses, or the ability to repair configuration.

Use a small number of block classes and codec profiles. Identity traffic need not reserve a zstd window; expensive codec streams consume more credits. Idle capacity can be borrowed between pools when the aggregate limit and protected reserves still hold. The planner maximizes useful admitted work subject to those constraints, rather than consuming memory merely because it is available.

Every allocating component, including native codecs, TLS, metrics, extensions, and provider clients, participates in the budget. Bounded arenas may retain capacity inside their charged region; they cannot fall back to an unbounded allocator. Diagnostics identify capacity failures by subsystem.

Bound connections, admitted requests, active upstream connections, queue bytes, queue age, and codec slots separately. Idle upstream pool capacity does not define active connection capacity. Count per-worker/event-loop pools in the global limit. Add header/body/upstream deadlines and bounded rejection drain behavior; close HTTP/1.1 connections when safe reuse would require unbounded draining.

## Transport and I/O

Transport exposes real streaming body input and bounded output. Begin forwarding eligible records before ingress EOF. Preserve a direct raw path for routes with no policy work, while applying the same admission, deadlines, and observability controls.

Validate HTTP framing across arbitrary chunk boundaries, Content-Length, chunked transfer, trailers, keepalive, disconnects, and header limits. Downstream and upstream implementations must agree on message boundaries. Future multiplexed transports must account for both per-stream and per-connection flow control.

Inject `std.Io` at operational boundaries. Own/configure the execution backend at the composition root when necessary to enforce allocator, thread/concurrency, and stack limits. Include control, observer, and signal threads in the process budget. Keep unavoidable platform operations inside transport/backend modules.

Use a bounded evented networking implementation for Linux, with io_uring and an epoll reference/fallback measured on the same workload. Retain a supported development backend for other targets. Select capabilities by tested toolchain/kernel support; isolate backend choice from service, record, and policy interfaces.

io_uring ownership rules are mandatory:

- reserve stable input/output storage before preparing SQEs;
- retain buffers and handles through all relevant completions, including ownership-return notifications for zero-copy sends;
- bound SQ/CQ entries and handle short reads/writes, submission errors, and queue saturation;
- identify completions with generation-bearing operation handles;
- cancel/drain outstanding work before switching to a fallback or reusing storage;
- probe supported features and exercise cancellation, fd reuse, partial submission, and stale-completion cases.

Batch submissions and completions where latency permits. Fixed files/buffers and multishot operations are optimizations admitted by correctness and memory tests. Busy polling is opt-in and must justify its CPU cost. TLS, compression, and projection remain part of the end-to-end measurement.

## Record processing and formats

Project only fields demanded by the leased policy program. Preserve types, repeated values, per-policy sampling keys, and inherited resource/scope context. A projection overflow returns an explicit unavailable outcome; it must not look like a missing field.

Use policy-zig's complete ordered effects and semantic transform machinery. Edge supplies bounded record views and wire encoders. Finish borrowed effects before releasing their program/worker lifetimes. Shared context optimizations must not let one record's transform mutate sibling records accidentally.

### JSON and line-oriented formats

Retain one bounded logical record and reuse untouched byte spans. A bounded edit overlay supports ordered rename, upsert, removal, and redaction. Bound nesting depth, tokens, keys, record bytes, and output expansion. Whole-record decoding into a fixed workspace is acceptable when its complete memory cost is declared.

Provide streaming adapters for Datadog logs/metrics, OTLP JSON, and line-oriented input. Framing and policy outcomes have separate counters. Oversized passthrough, where allowed, is explicitly recorded as bypass rather than successful evaluation.

### OTLP protobuf

The unit of policy evaluation is a log record, span, or datapoint with the required context. Parent length prefixes and inherited fields constrain output scheduling. Offer two explicit route modes:

| Mode | Behavior |
| --- | --- |
| Preserve groups | Retain a bounded parent/group in blocks, determine transformed lengths, and emit valid grouping |
| Semantic regrouping | Emit small valid repeated resource/scope containers when destination semantics permit it |

Preserve required descriptors, schema URLs, attributes, temporality, exemplars, record order semantics, and the declared unknown-field behavior. Semantic regrouping can use repeated containers within one HTTP request; it does not require a separate request per record.

Do not assume context appears before child records on the protobuf wire. Hold or revisit a bounded parent where necessary. Beyond the bound, use the route's explicit overflow disposition. Measure duplicated context and framing overhead, especially for small records.

Test structural/wire validity, logical record equivalence, and actual destination interoperability. Metric datapoints and resource groups must not be conflated in evaluation or volume counters.

### Tail ingestion

Each file identity owns independent partial-line state. Interleaved reads cannot concatenate records across files. Bound open files, per-file fragments, pending events, read buffers, and checkpoint queues.

Schedulers report exact consumed ranges per source, including short reads and unprocessed events. Batch capacity limits must not cause remaining events to be marked consumed. Checkpoints advance only to acknowledged complete-record boundaries under the output's stated delivery contract.

Define separate read, framed, output-owned, and acknowledged offsets. A file ending in an incomplete record retains the appropriate fragment/offset across polling and rotation. Checkpoint queue failure is visible and cannot silently advance durable state.

Use the same policy projection/effects as network ingestion. State delivery guarantees for stdout, TCP, HTTP, and extensions, including possible replay/duplicates after crashes. Test rotation, truncation, delayed writes, batches larger than scheduler capacity, and crashes before output acknowledgement.

## Control, observability, and restart

Control fetches and compiles within bounded budgets, validates route capabilities, and publishes through policy-zig's store. Program consistency is request-scoped by default: an admitted policy stream pins its generation through effect application. Lease accounting follows admitted streams, independently of CPU-worker count. Long-lived streams may use an explicitly configured batch boundary if midstream policy changes are acceptable.

When pinned generations prevent publication, coalesce pending updates and retain the active program. Per-request deadlines bound operational stalls but never authorize reclaiming a live lease. Optional last-good persistence uses atomic replacement and validates compatibility/integrity on startup.

Liveness reports scheduler/control progress. Readiness reports ability to serve the configured routes. Allowed forwarding-only service or a usable cached policy can remain ready during provider failure, with degradation reported separately. Upstream outages should not cause restart storms. Unexpected accept-loop termination transitions service state rather than leaving an inert process marked ready.

Required bounded-cardinality metrics include:

- memory reserved/in-use/high-water by subsystem, RSS/cgroup pressure, free admission credits, and capacity rejection by reason;
- admitted/completed/aborted requests, evaluated/kept/dropped/bypassed records, and input/decoded/output bytes;
- queue occupancy and oldest age, active connection/upstream/codec slots, pending I/O, and completion progress;
- program generation/age, update outcomes, pinned generations, and compile/reload peak;
- observer/event loss, extension backlog/loss, and aggregated checkpoint lag;
- admission, policy/transform CPU, upstream wait, and total request latency histograms; worker utilization and scheduler stalls.

Transfer worker statistics safely to an observer. Use fixed histograms and bounded labels. Arbitrary paths, filenames, request IDs, policy IDs, and hashes do not become unbounded metric labels. Detailed captures are opt-in, sampled, and separately capped.

Log transitions into and out of overloaded/degraded states and periodic summaries of throughput, occupancy, age, progress, and bypass/loss. Rate-limit repeated errors. Logs, metrics, and health paths remain functional within emergency capacity and cannot block record processing.

A steady-state test must show bounded memory after warmup and reloads, stable backlog age, continuing progress, and reconciled admission/completion/abort/inflight counts. Changes in bypass or loss must be explainable by explicit reasons.

Ordinary shutdown stops admission, drains to a deadline, cancels outstanding work, and joins every worker/callback source before freeing reachable state. A timeout does not release ownership. If safe cancellation/joining cannot finish, exit at the deadline without tearing down memory still in use.

Fatal corruption uses a minimal best-effort diagnostic path and nonzero exit; it cannot depend on taking ordinary locks, allocating, exporting metrics, or completing arbitrary cleanup. The supervisor owns restart and restart-loop backoff. Measure fault-to-exit and restart-to-ready independently. Initial targets to validate are exit within 1s for fatal faults and readiness within 2s when a valid local last-good program is available.

## Zig and data-oriented implementation

Juicy main supplies allocation and I/O ownership. Pass allocators down every allocating path and use `errdefer` for partial initialization. Pure planning, framing, and policy computation receive only their required inputs. Use `zigdoc` for standard-library and dependency APIs.

Use the stack for small scalar work, short arrays, varints, and temporary headers whose references do not escape. Use explicit pools for large codec/projection workspaces and anything that survives a yield. Keep self-referential interfaces pinned after construction.

Prefer compact handles, contiguous hot state, and cold sidecars. Choose struct-of-arrays only where traversal benefits from it. Enforce bounds through checked arithmetic and explicit errors at external-input boundaries; assertions detect ownership and state-machine bugs.

Use ReleaseSafe as the production baseline. Apply chosen optimization modes to all relevant modules and measure justified exceptions. Register all handwritten tests explicitly. Run `task lint` before merge.

## Performance acceptance

A successful benchmark reports 150,000 handled application requests/sec at the declared policy behavior, with sink validation of forwarded records. Policy drops are reported separately. Rejections, errors, and empty fast responses do not inflate successful throughput.

Record the CPU model/cores, memory cap X, kernel/backend, network speed/RTT, TLS/compression mix, payload distribution, records/request, policy set, and p99/p99.9 targets. Sweep memory caps such as 64/128/256 MiB and CPU-worker counts such as 1/4/8 where those profiles can fit. Report infeasible combinations explicitly.

Capacity arithmetic guides the experiment:

- At 150k requests/sec, 1 KiB payloads require 153.6 MB/sec ingress payload bandwidth; 1 MiB payloads require about 157 GB/sec per leg before framing/filtering effects.
- At 10ms average request lifetime, 150k/sec requires about 1,500 concurrent requests. A worker held for that entire lifetime cannot also provide high concurrency at low worker count.
- Eight cores at 70% utilization provide about 37.3 microseconds of CPU per request at 150k/sec. At 100 records/request, that is about 373ns/record before fixed request overhead.
- Every suspended compressed stream retains its required history. Large windows and long network waits can make a low-memory target incompatible with a requested throughput profile.

Measure acquisition/projection, evaluation/effects, codecs, transport/TLS, and full upstream acknowledgement both separately and together. Include no-policy forwarding, keep/drop/sampling, overlapping policies, regex, transforms, logs/traces/multi-point metrics, mixed sizes, and invalid input. Sweep 0/1/10/100/1000 policies and slow/stalled peers.

Use open-loop offered load and latency reporting that accounts for coordinated omission. Isolate load generation and sink resources from constrained Edge CPUs. Include warmup, sustained repeated trials, long soaks, reloads, and overload/recovery cycles. Publish successful/rejected rates, CPU-seconds/request, peak memory, allocations, copied bytes, latency distributions, and delivered-record counts. Competitive comparisons use equivalent semantics, hardware, transport settings, and pinned versions.

## TODOs and acceptance gates

### E0 — runtime ownership and failure semantics

- [ ] Define route plans, typed failure dispositions, and admission/record/delivery commit states. Acceptance: operational errors retain availability where safe and never masquerade as delivered success.
- [ ] Implement connection/stream/worker/I/O ownership with generation-bearing handles. Acceptance: cancellation and delayed callbacks cannot reach recycled storage.
- [ ] Implement per-file fragments and exact acknowledged checkpoint offsets. Acceptance: interleaved partial lines, short reads, over-capacity event batches, rotation, and crashes preserve the delivery contract.
- [ ] Implement bounded shutdown and fatal exit. Acceptance: all normal cleanup follows joining/ownership release; deadline expiry exits without racing live users of freed state.

### E1 — memory planning and overload

- [ ] Implement X-based planning from policy-zig requirements and route profiles. Acceptance: the manifest covers all application, reload, stack/backend, native, and emergency reservations with checked arithmetic.
  - Current state: the httpz frontend computes a minimum viable HTTP budget (eager pools plus one recv buffer and arena reserve per connection) with checked arithmetic, refuses to start below it, and logs cap/minimum/headroom. No `memory_limit_bytes` dial yet; TLS, policies, native codecs and thread stacks remain outside the manifest.
- [ ] Wire global and per-shard connection/request/upstream/codec/queue limits. Acceptance: changing worker count cannot bypass the global cap.
- [ ] Implement transactional initialization and budgeted allocation throughout. Acceptance: allocation failure at every preparation point leaks nothing and leaves serving state valid.
- [ ] Implement pre-body admission and reserved 429 responses. Acceptance: rejected requests cause no upstream body side effects; admitted supported streams backpressure within reserved storage.
  - Current state: httpz answers a body allocation over `max_buffered_bytes` with a static 500 and closes the connection before any upstream side effect. A 429 with `Retry-After` needs a change in the pinned httpz dependency.
- [ ] Validate deployment memory profiles under load, reload, and recovery. Acceptance: application accounting remains bounded and measured platform usage fits the stated envelope.

### E2 — streaming policy integration

- [ ] Integrate program requirements, leases, state domains, demanded fields, and complete effects from policy-zig. Acceptance: Edge preserves the dependency's semantic and lifetime contract across interleaved streams.
- [ ] Implement true ingress/upstream streaming with bounded blocks. Acceptance: a gated producer/sink test proves upstream progress before ingress EOF and safe behavior at arbitrary chunk splits.
- [ ] Implement JSON/line adapters and bounded transform encoding. Acceptance: unchanged spans are reused and effect order/output expansion are validated.
- [ ] Implement OTLP logical records, inherited context, and both declared grouping modes. Acceptance: late context, varied wire order, multiple datapoints, and destination interoperability pass.
- [ ] Validate locally built Edge through `../policy-conformance` and intake-to-sink tests, recording the exact dependency revision. Acceptance: supported provider, decision, transform, volume, and transport cases run against the intended artifacts.

### E3 — steady-state operation

- [ ] Implement progress-aware health, readiness, degraded state, and reserved control capacity. Acceptance: overload and provider/upstream outages remain distinguishable and do not cause restart storms.
- [ ] Implement bounded stats/event transfer, transition logs, and saturation/age metrics. Acceptance: blocked observers and optional extensions do not stall telemetry; loss is counted.
- [ ] Implement last-good recovery and bounded update coalescing. Acceptance: pinned generations, compile failures, corrupt cached data, and unavailable providers follow the declared startup/update contract.
- [ ] Run fault-to-exit and restart-to-ready drills under full queues and stalled peers. Acceptance: the declared deadlines and ownership rules hold.

### E4 — performance signoff

- [ ] Validate Linux evented and io_uring backends with submission/completion/cancellation/fallback fault tests on x86_64 and ARM64.
- [ ] Prove runtime allocation, stack, native-memory, and reload bounds across complete request paths.
- [ ] Run the declared 150k requests/sec matrix with delivered-output validation, CPU/memory caps, and latency SLOs. Publish the supported operating envelope and overload recovery.
- [ ] Establish regression thresholds from repeated measurements; verify actual build modes and working benchmark entrypoints. Require Debug/ReleaseSafe tests and `task lint` at release gates.
