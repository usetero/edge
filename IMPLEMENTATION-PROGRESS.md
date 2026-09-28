# Edge v2 implementation progress

Design: [proposal.md](proposal.md). Review evidence: [REDESIGN-NOTES.md](REDESIGN-NOTES.md), §13.
Started: 2026-09-14. Branch: `edge-v2-foundation`.
Base: freshly fetched `origin/master` at `22629b0c4bc447d693e9f358de93e7e973e535a5`.

## Working agreement

- Expand a delivery phase into small tasks here before starting it.
- Check tasks only after implementation and relevant verification; record failures
  and unresolved limits rather than implying a whole phase is complete.
- Keep the current runtime available until the proposal's cutover gates pass.
- No changes to policy-zig or zonfig. Use `zigdoc` for std/dependency APIs.
- Write failing tests before implementing new behavior. Keep reusable v2 code
  under `src/v2` while current runtime modules remain in place.

## Delivery checklist

- [ ] Phase 0 — Feasibility and contracts (**local dependency verified**; platform, coverage and deferred items remain recorded).
- [x] Phase 1 — One vertical relay slice (**complete — opt-in raw HTTP relay, real socket tests, bounded deadlines/shutdown, aggregate budget and measured baseline**).
- [ ] Phase 2 — One policy slice.
- [ ] Phase 3 — Protocol parity.
- [ ] Phase 4 — Durability.
- [ ] Phase 5 — Tail and Lambda.
- [ ] Phase 6 — Tune and cut over.

## Phase 0 — Feasibility and contracts

Initial implementation slice: capture executable compatibility contracts and
prove publication guarding through the unchanged public provider API. This does
not replace the current loader or enable the new runtime.

### Repository and baseline

- [x] Inspect working tree and preserve proposal/notes already present.
- [x] Fetch master and create a new branch directly from `origin/master`.
- [x] Read repository instructions, test registration, build and lint configuration.
- [x] Verify Zig 0.16.0 and pinned policy-zig 0.7.1.
- [x] Run the existing tests and record the baseline.
- [x] Register v2 inline tests through the existing test root and `src/main.zig`.
- [x] `build.zig`: the `edge` module now takes `-Doptimize`, so `zig build test -Doptimize=ReleaseSafe`
  really builds ReleaseSafe tests (it silently built Debug before).

### Compatibility contracts

- [x] Capture distribution × method/path route behavior in table-driven tests.
- [x] Capture raw versus processed intake outcomes and selected upstream.
- [x] Capture raw intake replay eligibility through executable plan fixtures.
- [x] Capture processed replay behavior. Named the rule once as
  `processedReplayable(signal)` in `src/frontend/httpz/server.zig` (three call sites)
  and captured it in `compatibility.zig`. No wire-level exchange fixture; the
  retry itself is covered by the existing `retryableTransportError` tests.
- [x] Capture unknown encoding passthrough and Prometheus zero-means-unlimited limits.
- [x] Capture default configuration and existing validation boundaries.
- [x] Record discoveries where actual code differs from the proposal.
- [ ] Broader wire fixtures (expanded 2026-09-14):
  - [x] Admin/tap routes: `adminRoute(method, path)` now classifies once in
    `server.zig` (dispatch switches on it); `compatibility.zig` captures
    `/_edge/metrics`, `/_edge/policies`, `/_edge/tap/{pre,post}`, unknown tap →
    404, and that non-GET falls through to the router. `?format=json` stays a
    handler detail.
  - [x] Upstream URI composition: already locked by `frontend/upstream.zig` tests
    (base path, query, empty path, standard vs explicit port, multiple upstreams);
    referenced, not duplicated.
  - [x] Tail checkpoint on-disk format: golden 64-byte WAL record and 64-byte
    snapshot (header + entry) in `compatibility.zig`; today's writers produce the
    bytes and today's readers load them back to the same value.
  - [x] Headers: forward-header hop-by-hop drop and response-header skip list are
    already covered by `server.zig`/`upstream.zig` tests; reference, do not duplicate.
  - [x] Compression: unknown encoding passthrough is captured; streaming codec
    equivalence is covered by `encoding.zig` oracle tests; reference only.
  - [x] Sampling/tracestate: covered by `signals/otlp/traces.zig` tests; v2 must
    reuse those functions; reference only.
  - [x] S3 selection: credentials precedence covered by `runtime/extensions.zig`
    tests; the MinIO e2e stays env-gated; reference only.
  - [ ] Lambda lifecycle: only event parsing is pure today; the shutdown deadline
    budget lives inline in `lambda_main.zig`. Defer the contract to phase 5 expansion.

### Policy publication feasibility

- [x] Write failing tests for an Edge-owned guarded policy store.
- [x] Implement shared reads / exclusive updates with explicit `std.Io`.
- [x] Bind public provider callbacks and stats collectors without `Registry.subscribe`.
- [x] Verify real policies still evaluate through the guarded registry.
- [x] Prove a reader prevents update and reclamation; test >8 successive updates.
- [x] Verify writer contention causes explicit bypass rather than waiting on the data path.
- [x] Verify observable update failure permanently fences reads, updates and stats.
- [x] Exercise dependency allocation failure at a safe boundary and document limits
  of partial-mutation failure containment.
- [x] Full file/HTTP provider lifecycle, extension hooks/config lock order and close
  callbacks (see provider lifecycle slice below).
- [x] Quarantine process-exit decision: retain the failed registry/allocator until
  exit, keep raw forwarding, require operator restart; no automatic exit/retry.
  See the phase-1 README. Applying this to providers is phase-2 policy wiring.

### Provider lifecycle slice (2026-09-14)

- [x] Expand ownership contracts for a fixed set of provider slots and bindings.
- [x] Add failing tests for real file startup, missing-file isolation, and shutdown.
- [x] Implement provider construction/subscription and cleanup without changing the libraries.
- [x] Add loopback HTTP fixtures for initial sync, failed initial sync, and final close sync.
- [x] Preserve per-provider stats and extension capabilities/config-before-policy ordering.
- [x] Guard extension configuration/resolver access with the publication gate.
- [x] Test that close joins providers before final callbacks and is idempotent.
- [x] Test continued cleanup when one provider's final sync fails.
- [x] Run registered tests, all distribution builds and lint; record results and remaining limits.

### Other phase-0 gates (started 2026-09-14)

Deadline and shutdown ownership (`src/v2/UpstreamWatch.zig`):

- [x] Write failing probes: silent peer, trickling peer, stalled TLS handshake.
- [x] Implement per-slot arm/disarm/expire with the forwarder as the only closer.
- [x] Prove `stream.shutdown(.both)` unblocks a blocking read and a TLS `init` at the absolute deadline.
- [x] Prove a disarmed slot never touches a descriptor reused after close.
- [x] Prove `Future.cancel` interrupts a blocked read (the path a control-plane resolver must use).
- [ ] DNS deadline probe against a controlled resolver. Blocked: std reads `/etc/resolv.conf`
  with no injection point; recorded as a v2 design constraint instead.

Checked resource formulas (`src/v2/Budget.zig`):

- [x] Write failing tests for per-request overlap, overflow, and a too-small ceiling.
- [x] Implement checked arithmetic for connection, body, processing, forwarding and control terms.
- [x] Bind the formula to the real phase-1 layouts and runtime config. Relay now
  includes all raw-runtime tables, client scratch, queues and thread reservations.
  Future policy/codec layouts must extend this accounting when implemented.

Stack high-water and dependency allocations (`src/v2/StackProbe.zig`):

- [x] Implement a painted-stack probe on a dedicated thread.
- [x] Measure gzip compress/decompress and policy evaluation in Debug and ReleaseSafe.
- [x] Record `@sizeOf` for flate/zstd/TLS/engine state and libzstd `ZSTD_sizeof_CCtx`.
- [x] Fix the harness artifact where ReleaseSafe inlined all workloads into one frame.
- [ ] Measure hyperscan scratch and protobuf/JSON codec frames (later, with real request frames).

Platform validation:

- [x] macOS arm64: registered suite, lint, six ReleaseSafe builds.
- [x] Linux aarch64 musl (Alpine 3.24 container, Zig 0.16.0): suite run; only the
  pre-existing io_uring tail test fails under Docker's seccomp.
- [ ] Linux x86_64 musl: blocked locally; Zig's translate-c crashes under Rosetta
  emulation (`bss_size overflow`). Needs a native x86_64 runner.

Allocation-failure containment (original v0.7.1 findings; fixed-pin follow-up below):

- [x] Fault-injected allocation failures over a real registry publish. Result: one
  publish cycle is 54 allocations / ~4 ms, and **failing allocation #3 (inside
  proto `Policy.dupe` called by `addPolicyInternal`) hangs `updatePolicies`**:
  the loop `errdefer` frees the registered id copy, then the function-level key
  sweep frees it again and the thread spins inside `Allocator.free` while
  holding the registry mutex. `checkAllAllocationFailures` therefore never
  completes (the earlier ">10 min" was this hang, not slowness). The probe is
  `v2 policy store: registry publish survives each allocation failure without
  hanging`, gated behind `TERO_V2_ALLOC_PROBE=1`, and fails with
  `RegistryFailurePathHangs` until policy-zig fixes the double free.
- [x] Historical decision, superseded by fixed-pin evidence below: process isolation would not help; the fault happens inside the
  dependency's mutation while the registry lock is held, so readers deadlock
  and quarantine-after-return is too late. v2 must not let the registry
  allocator return OOM: give it a fixed reserve (fail admission of new policy
  sets before compilation instead) and treat reserve exhaustion as the
  process-exit quarantine case. Upstream report filed:
  https://github.com/usetero/policy-zig/issues/96 (also covers the dangling
  `policies` entry when `addPolicyInternal` fails after `append`).

Processed replay contract:

- [x] Name the processed replay rule once in the current runtime and capture it in
  `compatibility.zig` (the rule is `signal == .log` at three exchange call sites).

### Verification for the initial slice

- [x] Record the initial failing tests and subsequent passing results.
- [x] Run all registered tests.
- [x] Build all six distributions.
- [x] Run `task lint`.
- [x] Review diff; record next work and any remaining risks below.

## Resumed work checklist (2026-09-14)

- [x] Reconcile the live branch, existing code and other agent's progress entries.
- [x] Locate the upstream fix: policy-zig PR #97, merged commit
  `a652ae9573ca9f318fc1bf6c60b1abe8240bc160`; release 0.7.2 is not yet published.
- [x] Pin the immutable fixed dependency and fetch its transitive protobuf update.
- [x] Re-run the allocation-failure reproduction and remove the unsafe detached-thread
  timeout harness. Default containment sweep passes; direct leak checking exposes
  a residual matcher-index leak, so that stricter reproducer remains opt-in.
- [x] Verify guarded failure containment and update the non-failing-allocator decision.
  The old hang no longer requires that workaround. Quarantine remains necessary
  because failed publication is not transactional and cleanup still leaks.
- [x] Run Debug/ReleaseSafe tests and lint after integration (results in the work log).

## Phase 1 — One vertical relay slice (expanded before implementation)

The user authorized continuation after reviewing phase 0. Implement in dependency
order; the existing production frontend stays selected throughout this phase.

### 1A. Ownership and admission

- [x] Write failing tests for fixed request slots, exhaustion, stale handles,
  disconnect while work is outstanding, and generation overflow retirement.
- [x] Implement reactor-owned request metadata and explicit worker/completion leases.
- [x] Allocate stable body/head backing storage at startup; no admission-time allocations.
- [x] Derive request-table reservation from actual metadata/head/input/response
  layouts and reject a total above its configured ceiling. `Budget.core` now also
  rejects an aggregate above the ceiling; equality remains allowed.
- [x] Bind connection tables, queues, worker stacks and runtime config to the same
  budget after those phase-1 components exist. Table limits alone are not a full
  process RSS bound; allocator overhead, C allocations and OS memory are separate.
- [x] Prove error unwinding, exact credit return, and reuse with allocator-failure tests.

### 1B. Readiness and bounded queues

- [x] Define generation-safe readiness registration tokens and one socket closer.
- [x] Implement kqueue/epoll adapters plus deterministic scripted event batches.
- [x] Implement bounded stage/completion queues with reserved completion capacity.
- [x] Test stale events, canceled work, and saturation wakeups.
- [x] Implement/test fair FIFO admission and connection/request ownership.
- [x] Implement/test the bounded accept/handoff loop.

Queue slice (expanded before implementation, local policy-zig authorized):

- [x] Switch Edge to `.path = "../policy-zig"` until the user merges the fixes.
- [x] Promote the now-passing dependency leak/alignment probes to default coverage;
  remove the test-only alignment workaround and obsolete blocker claims.
- [x] Write failing tests for bounded submission, completion credit reservation,
  disconnected clients, shutdown/drain and returned credits.
- [x] Use caller-backed `std.Io.Queue` for jobs and completions; retain a credit
  from body admission through completion acknowledgement. No custom queue algorithm
  before contention measurements justify it.
- [x] Pass pinned request spans to workers; mutate request ownership only on the reactor.
- [x] Prove worker completion cannot run out of reserved space when the reactor stalls.
- [x] Test a real worker blocked on an empty queue, close wakeup, cancellation/error
  completion and startup allocation-failure cleanup.
- [x] Account for actual job/completion layouts and queue capacity in startup bytes.
- [x] Run Debug/ReleaseSafe tests, all distribution builds and lint; record limits.

Readiness slice (expanded before implementation):

- [x] Write failing tests for stale batched events, slot reuse, exhaustion and
  token overflow; use full 64-bit tokens without truncating request handles.
- [x] Implement a startup-sized registration table with direct token lookup and
  retirement before wrap; give the reactor sole ownership of adopted descriptors.
- [x] Add level-triggered kqueue/epoll adapters, bounded event batches and absolute
  wait deadlines that survive EINTR. Keep native syscalls in the OS adapter.
- [x] Add coalescing EVFILT_USER/eventfd wakeups; test wake before wait and during
  wait, plus completion publication before wake and bounded completion draining.
- [x] Exercise deterministic stale events and real socket readiness, pending data
  with half-close, disabled write interest, teardown and startup failure cleanup.
- [x] Record actual startup bytes, platform coverage, Debug/ReleaseSafe and lint.

The accept/handoff slice below completes the standalone phase-1B components;
the serving reactor and validated scheduling/config remain phase-1C/1D work.

Connection/admission slice (expanded before implementation):

- [x] Write failing FIFO tests with fewer request/queue credits than connections;
  include middle-waiter disconnect and keep-alive reentry behind existing waiters.
- [x] Add fixed connection metadata and head buffers around Readiness ownership;
  embed waiter links so enqueue/removal never allocate or accumulate tombstones.
- [x] Grant request storage and channel credit together; retain FIFO order on
  exhaustion and disable socket reads while waiting for admission.
- [x] Bind request IDs to their originating connection token so late completion
  cannot target a reused connection; integrate reservation, dispatch, completion,
  response release and disconnect ownership transitions.
- [x] Test disconnect before dispatch, during work, and during response; verify
  exact credit return, native interest failure cleanup and stale completion handling.
- [x] Account for actual connection/head layouts and test startup OOM unwinding.
- [x] Run Debug/ReleaseSafe, Linux isolated coverage, distribution builds and lint;
  update handoff notes with remaining listener/handoff and framing work.

Accept/handoff slice (expanded before implementation):

- [x] Write failing tests for bounded handoff, transfer-on-success ownership,
  closed/full queues and socket cleanup on failed reactor adoption.
- [x] Implement fixed descriptor queues with bounded reactor drains and teardown
  after acceptor shutdown; wake only after descriptor publication.
- [x] Add native nonblocking accept (atomic flags on Linux, macOS fallback), a
  read-only listener registration and a bounded acceptor turn with round-robin
  handoff across reactors. Bound interrupted/aborted accepts as well as successes.
- [x] Exercise real TCP acceptance, target saturation, coalesced wakes, descriptor
  flags, stopped acceptance and pending-descriptor cleanup on macOS/Linux.
- [x] Classify descriptor/resource exhaustion for timed backoff instead of a
  readiness busy loop; retain ownership on wake failure and document retry rules.
- [x] Verify startup accounting/OOM, Debug/ReleaseSafe, distribution builds and
  lint; update remaining framing/composition tasks and handoff notes.

### 1C. HTTP framing and relay

Transport decision gate (expanded before implementation, user requested httpz review):

- [x] Audit pinned httpz APIs and call paths for head-only admission, body-buffer
  allocation, async request ownership, response completion and transport reuse.
- [x] Build an executable fixture for the relevant public hooks, or capture a
  concrete blocker with source references; distinguish integration limits from
  fundamental library limits and performance assumptions.
- [x] Record the transport decision and implications before implementing HTTP
  framing. Production remains on httpz; v2's existing OS components are not proof
  that replacing httpz is faster.

Request-head slice (expanded before implementation):

- [x] Write failing tests for every split boundary, exact capacity, incomplete
  input and preservation of body/next-request read-ahead; inspect std scanner
  acceptance before reuse.
- [x] Implement nonallocating head boundary tracking over caller-owned bytes;
  return exact consumed lengths and distinguish incomplete from oversized input.
- [x] Write head validation cases for CL/TE ambiguity, duplicate framing/Host
  fields, overflow, strict CRLF, token syntax, controls, folding and field limits.
- [x] Parse request metadata as offsets into owned bytes; preserve unknown
  Content-Encoding, repeated end-to-end fields and query bytes.
- [x] Represent framing, keep-alive and Expect decisions without socket IO;
  reserve body/queue capacity before Continue in later runtime integration.
- [x] Verify Debug/ReleaseSafe, layout bounds and lint; record remaining body,
  response and runtime wiring work without marking the whole phase complete.

Strict head/metadata substeps (expanded before implementation):

- [x] Add failing cases for complete-head boundaries, request-line and field
  syntax, duplicate Host/CL/TE, decimal overflow, body framing and header limits.
- [x] Implement offset-only metadata with caller-owned header descriptors;
  validate without allocation, mutation, decoding or socket IO.
- [x] Test target forms, unknown methods/encodings, repeated fields, relocated
  backing bytes, HTTP/1.0 close behavior and Connection token lists.
- [x] Add pure Expect decisions for unsupported expectations, bodyless/already
  received bodies and pending versus granted admission; never emit Continue here.
- [x] Combine scanner and validator over split reads/read-ahead, verify layout
  limits and run native Debug/ReleaseSafe, Linux isolated coverage and lint.

Verification follow-up (expanded after the httpz ReleaseSafe run failed):

- [x] Locate the existing acceptor fixture's connect-to-accept timing assumption:
  two tests observed no handoff, one by null unwrap; no framing code was involved.
- [x] Wait for actual listener readiness with a finite deadline in the fixture
  before assuming a connected peer can be accepted; preserve production turn bounds.
- [x] Re-run isolated acceptor coverage and the complete Debug/ReleaseSafe suites.

Body/trailer slice (expanded before implementation):

- [x] Write failing tests for Content-Length/no-body/chunked framing, every split,
  output backpressure, terminal framing and untouched pipelined read-ahead.
- [x] Implement a pure bounded framer borrowing line/trailer/descriptor storage;
  copy entity bytes in bulk without content decoding or heap allocation.
- [x] Validate checked hexadecimal lengths, chunk extensions/quoted values and
  strict CRLF; bound cumulative framing work separately from entity-body bytes.
- [x] Retain trailer bytes/order/duplicates with relocatable descriptors; reuse
  field syntax validation and reject critical framing/routing/interpretation fields.
- [x] Test byte/capacity boundaries, malformed extensions/trailers, early EOF and
  sticky failure; provisional output must never authorize partial forwarding.
- [x] Compose head and body parsers over split input; run Debug/ReleaseSafe,
  isolated Linux checks and lint, update budgets/limitations and handoff.

Admission-copy slice (expanded before implementation):

- [x] Add tests that reserve RequestTable/WorkChannel before copying, retain
  copied head/body through worker take, and release on pre-submit failure.
  Correction: this slice added implementation and tests together; its initial
  compiler failures were not a behavioral TDD red run.
- [x] Implement an allocation-free ingress owner that validates/copies a complete
  head only after reservation, frames body bytes into the request slot and exposes
  dispatch input only after complete framing.
- [x] Preserve temporary head/trailer descriptors for the ingress lifetime;
  expose a pure Continue decision and exact unconsumed suffix without socket IO.
- [x] Test no-body, chunked trailers, copied-source overwrite, body/storage caps,
  transport failure fencing and disconnected-reservation cleanup.
- [x] Verify full suites, Linux isolated coverage and lint; record that reactor
  read-loop/deadline/timer wiring and actual one-time writes remain outstanding.

Ingress ownership/trailer handoff follow-up (expanded before implementation):

- [x] Reproduce access without reservation and after cancellation, disconnect,
  dispatch and slot reuse; verify rejected access leaves worker bytes untouched.
- [x] Require a live attached reading reservation at every ingress access;
  keep all checks on the reactor and preserve completion ownership.
- [x] Reserve distinct trailer bytes in RequestTable, account for them in its
  checked budget, and carry immutable initialized trailers in WorkChannel jobs.
- [x] Test trailer lifetime through scratch reuse/disconnect/completion, exact
  capacity and invalid handoff lengths; fix fixture allocation/credit cleanup.
- [x] Run Debug/ReleaseSafe, isolated Linux checks and lint; reconcile work log,
  handoff and proposal with actual implementation and remaining runtime work.

Raw outbound request slice (expanded before implementation):

- [x] Add behavioral red tests for selected Host/target, repeated fields, opaque
  encoded body bytes, Connection nominations, Expect removal and exact framing.
- [x] Prepare bounded HTTP/1.1 head/tail spans around the borrowed original body;
  validate all metadata before exposing output and allocate nothing per request.
- [x] Preserve ordered trailers separately with regenerated Trailer/chunk framing;
  reject critical trailers and filter fields nominated by every Connection value.
- [x] Test partial-write traversal, empty bodies, target forms, malformed input,
  exact byte/header limits and unchanged source buffers; compose ingress to wire.
- [x] Verify native Debug/ReleaseSafe, isolated Linux, lint and update handoff.
  This slice is raw relay only; transformed representation metadata, routing/base
  path construction, real upstream IO and response framing remain separate work.

Buffered upstream response slice (expanded before implementation):

- [x] Add failing strict response-head tests: status/reason syntax, duplicate and
  ambiguous framing, opaque/repeated metadata, HEAD/1xx/204/304 body rules, 205,
  Connection persistence, and explicit upgrade/CONNECT rejection.
- [x] Reuse bounded head scanning and shared field/framing validation; represent
  response metadata as offsets and keep declared length distinct from body rules.
- [x] Add failing incremental receive tests across every split, bounded 1xx events,
  chunked trailers, clean EOF versus transport failure, truncation and byte caps.
- [x] Implement allocation-free buffered response ownership over caller storage;
  expose informational heads until the next feed and final data only when complete.
- [x] Verify read-ahead, exact storage boundaries, sticky errors and connection
  reuse decisions; run Debug/ReleaseSafe, Linux checks and lint, update handoff.
  Downstream response rewriting, response-slot layout/queue handoff and socket IO
  remain follow-up work; unlimited Prometheus streaming is a separate contract.

Final response serialization/handoff slice (expanded before implementation):

- [x] Add behavioral red tests for final status/reason, duplicate end-to-end
  metadata, Connection filtering, trailers, HEAD/304 lengths and HTTP/1.0 close.
- [x] Serialize validated raw final metadata into request-owned head/tail spans;
  require the received body to already occupy the reserved response body span.
- [x] Budget separate response head/tail capacity and publish only lengths/close
  state through WorkChannel; validate reactor views after acknowledgement.
- [x] Test scratch overwrite, live/detached completion lifetimes, slot reuse,
  short writes, overflow and startup OOM/accounting with the new layouts.
- [x] Run full Debug/ReleaseSafe, isolated Linux, lint; update proposal and handoff.
  Interim delivery/ordering and socket IO are completed by the runtime below;
  transformed entities remain phase-2 work.

- [x] Write incremental request-head/body framing tests, including split boundaries,
  chunked trailers, ambiguous framing, Expect, and preserved pipelined bytes.
- [x] Wire raw HTTP ownership and bounded admission into the serving socket read
  loop, including read-ahead offsets, deadlines and one-time Continue writes.
- [x] Connect upstream lanes and `UpstreamWatch` absolute deadlines to real exchanges.
- [x] Relay response status/headers/body with bounded storage and backpressure.
- [x] Test disconnects, slow clients, exhausted queues, silent/trickling upstreams,
  and response order over keep-alive connections.

### 1D. Composition, verification and measurement

Phase-1 completion run (expanded before implementation, 2026-09-16):

- [x] Add a real-process relay fixture before wiring the runtime: opaque bodies,
  chunked trailers, Continue, interim/final ordering, keep-alive and health.
- [x] Compose one reactor, bounded accept handoff and fixed forwarder threads;
  integrate existing admission, ingress, wire preparation and completion ownership.
- [x] Enforce absolute client/upstream deadlines, bounded socket turns and output
  backpressure; test disconnects, saturation, silent/trickling peers and shutdown.
- [x] Bind actual tables, metadata, scratch and thread reservations to validated
  startup config; expose an opt-in executable without changing production defaults.
- [x] Decide quarantine behavior, document the runnable contract and record a full
  relay benchmark with memory data, rather than another isolated helper benchmark.
- [x] Run Debug/ReleaseSafe tests, real-process fixtures, six distribution builds,
  Linux checks and lint; update every phase-1 item against evidence.

- [x] Add opt-in v2 composition root with juicy main, explicit I/O/allocators,
  validated config, health, and ordered shutdown.
- [x] Decide quarantine lifecycle using the fixed dependency's tested guarantees.
- [x] Add an end-to-end raw relay integration fixture and benchmark full relay.
- [x] Run all tests, six distribution builds and lint; record memory/high-water data
  and platform limitations without declaring production cutover.

## Phase 2 — One policy slice (expanded before implementation, 2026-09-17)

- [x] Add failing Datadog policy tests for drop/transform/all-drop, malformed
  suffix rollback, output/scratch exhaustion, opaque encoding and empty snapshots.
- [x] Build bounded worker workspaces and a sticky allocation-failure adapter;
  reuse existing format accessors under PolicyStore guards, evaluate each record
  once, and publish candidate bytes only after framing/encoding finishes.
- [x] Wire providers and extension callbacks into the runnable composition;
  retain original encoded entities, rewrite changed representation metadata and
  release policy guards before upstream IO. Apply quarantine recovery decision.
- [x] Exercise reload under traffic, sampling counts, extension ordering and
  processing/bypass counters with real socket fixtures. Include gzip/zstd paths.
- [ ] Validate memory accounting, fault injection, Debug/ReleaseSafe, distribution
  builds and lint; record coverage and remaining dependency/platform limitations.

## Phase 3 — Protocol parity (expanded 2026-09-17)

Format/route substeps (write fixtures before enabling each route):

- [ ] Add a pure route table for Datadog logs/series, OTLP signals and Prometheus;
  retain query bytes, support absolute request targets and select separate origins.
- [ ] Apply existing Datadog metric and OTLP nested accessors inside bounded
  transactional workspaces; test compressed input, all-drop responses, malformed
  input, unknown fields and resource/scope context before marking parity.
- [ ] Add Prometheus sample/metadata and overlong-line fixtures, then finite
  filtering; add bounded streaming for explicitly unlimited scrape settings.
- [ ] Load existing ProxyConfig through unchanged zonfig; validate/derive v2
  reservations and map provider, origin and distribution settings explicitly.
- [ ] Add DNS resolution, authenticated TLS and origin connection reuse with
  cancellation/deadlines; test DNS/TLS failure, stale pooled connections and EOF.
- [ ] Wire admin routes and metrics, optional tap, extension resolver/S3 flush
  ownership and HTTP-provider final sync; test shutdown and quarantine ordering.
- [ ] Run old/new wire fixtures and representative full-path benchmarks, then
  record remaining compatibility differences and cutover gates.


- [ ] Route/config parity across HTTP distributions and separate upstreams.
- [ ] Datadog metrics and OTLP JSON/protobuf with preserved envelopes/unknown fields.
- [ ] Prometheus finite/unlimited response filtering and backpressure.
- [ ] Upstream DNS/TLS/pooling with bounded deadlines and authenticated TLS.
- [ ] Admin metrics/policies/tap, providers, S3 extension and observability parity.
- [ ] Compare wire/semantic fixtures and full-path measurements against both
  existing frontends; document intentional fixes, run acceptance checks.

The user requested continuous work up to phase 4. Phases are checkpoints in this
document, not permission stops. Whether phase 4 itself is included was asked
asynchronously; phases 2 and 3 proceed independently of that clarification.

## Work log

### 2026-09-14 — branch and phase 0 started

Created `edge-v2-foundation` from freshly fetched master. Only the existing
untracked proposal and redesign notes were present before work. Baseline: `zig build test --summary all` passed (519 passed, 1 skipped).
No production runtime has been switched.

### 2026-09-14 — first contracts and policy store implemented

- Added `src/v2/compatibility.zig`: 56 route cases across four HTTP distribution
  tables, raw destinations/retry flags, processed JSON/protobuf signal and codec
  selection, unsupported encodings, zero scrape limits, and config defaults /
  explicit thread values / validation boundaries.
- Added `src/v2/PolicyStore.zig`: stable store, scoped read guard, shared/exclusive
  publication gate, announced pending updates (new readers bypass), synchronous
  public provider callback binding, guarded stats copies, and volume draining.
- Observable registry update errors quarantine the store. New reads/updates/stats
  refuse dependency access; teardown reports retained ownership instead of calling
  an unproven destructor. The current fault test fails the *first* allocation,
  where no memory/native index has been acquired; it does not prove arbitrary
  dependency OOM safety. Process-isolated deeper probes remain required.
- Reader test announces a queued writer, holds the real snapshot for 150 ms,
  verifies it stays usable, releases it, and then exercises ten more updates.
  New-reader bypass, copied stats surviving replacement, real drop/non-match
  evaluation, one-time volume drain, and clean teardown are covered.
- Test registration is in both `src/main.zig` and the existing library test root;
  v2 code is not yet selected by any distribution at runtime.

TDD evidence: the first read test failed against the deliberately unavailable
read stub (`TestUnexpectedResult`). Provider tests then failed to compile before
`Binding` existed. After implementation the registered suite passes: **532 passed,
1 skipped** (533 total). The increase includes module-registration tests.
Verification:

- `zig build test --summary all`: 532 passed, 1 skipped (533 total).
- `zig build edge datadog otlp prometheus tail lambda -Doptimize=ReleaseSafe --summary all`:
  all six distribution build steps passed (22/22 steps). The existing `edge`
  named step installs `edge-edge`; `zig build -Doptimize=ReleaseSafe --summary all`
  also passed for the default `edge` binary (7/7 steps).
- `task lint`: passed. Initial lint failures were limited to the new files:
  long fixture lines, the struct-root file name, and teardown invalidation.
  Renamed the root-struct module to `PolicyStore.zig`, formatted fixtures, and
  made teardown invalidate the store after releasing the lock. No lint rules
  were disabled. A quarantine result refers to retained dependency allocations;
  the store itself must not be accessed after `deinit`.
- `git diff --check`: passed. Dependency manifest and `src/zonfig` unchanged.
- Tests/builds ran on the local macOS arm64 Zig 0.16.0 toolchain; no Linux,
  container, network integration, or performance claims are made by this slice.

Compatibility discovery: the wildcard routes accept the enumerated standard
methods, but `HttpMethod.OTHER` does not match `.all`. The fixture records this;
CONNECT/unknown methods are not implicitly supported passthrough. The full wire
retry behavior is not inferred from raw flags because processed outcomes have
no `replayable` field.

### 2026-09-14 — provider lifecycle slice verified

- Added `src/v2/ProviderSet.zig`: fixed provider slots with per-slot start/close
  errors, construction of real `FileProvider`/`HttpProvider` instances through the
  public policy-zig API, binding through `PolicyStore.Binding`, `stopAll` before
  final close syncs, idempotent `close`, and `deinit` that joins without a final
  network sync.
- Added `src/v2/testing/SyncServer.zig` (loopback `std.http.Server` fixture on a
  cancellable `io.concurrent` task; captures request bodies per exchange) and
  `src/v2/testing/ExtensionProbe.zig` (records capability/config/resolve order and
  probes the publication gate from inside each callback).
- `PolicyStore` gained `setExtensionResolver` (refused after the first update)
  and gated extension hooks: capabilities under the shared gate, `apply_configs`
  under the exclusive gate with pending-update announcement.
- Covered: missing file isolated while the valid watcher publishes; invalid
  provider configs recorded per slot; empty startup; HTTP initial sync then final
  close sync carrying `last_successful_hash` and per-policy stats exactly once;
  HTTP initial 503 leaves the store readable with no snapshot and recovers on the
  final sync; one failing final sync does not stop the other provider's sync and
  `close` returns the first error; extension config applied before policy compile
  with the resolver called once and no gate violation observed.
- Fixture discovery: the HTTP provider decodes proto-JSON, so policies need a
  matcher (`{"logField":1,"exists":true}`); a policy without matchers is rejected
  before extension compilation, which is why the extension test first failed with
  `resolved == 0`. The file provider uses the human JSON schema (`log_field`).
- Not established: the failing-first evidence for the provider tests before the
  implementation existed was not re-recorded in this session; the extension
  ordering test is the one observed failing before its fixture fix. No Linux run.
- The test runner prints `run test w` / `failed command: ...` before a passing
  summary on the unmodified baseline too (519 pass); it is not from v2 code.

Verification:

- `zig build test --summary all`: 538 passed, 1 skipped (539 total), three
  consecutive runs.
- `zig build edge datadog otlp prometheus tail lambda -Doptimize=ReleaseSafe --summary all`: 22/22 steps.
- `task lint`: passed after splitting a compound assert, hoisting duplicate test
  imports, wrapping two long signatures, and replacing an empty `catch {}` in the
  fixture with `error.Canceled` handling plus an error log. `git diff --check`: clean.

### 2026-09-14 — remaining phase-0 gates probed

- `src/v2/UpstreamWatch.zig`: per-forwarder slots (`arm`/`disarm`/`expire`) where
  the watchdog shuts down an armed stream past its absolute deadline and the
  forwarder disarms under the slot lock before closing. Probes on loopback:
  silent peer read unblocked at ~100 ms; trickling peer (one byte / 10 ms) ended
  at the 150 ms absolute deadline after receiving several bytes; `tls.Client.init`
  against a peer that never answers returned an error after shutdown; a disarmed
  slot left a recycled descriptor untouched under a forced pass; `Future.cancel`
  interrupted a blocked read (the mechanism a control-plane resolver needs, since
  socket shutdown cannot reach std's DNS). Timing assertions use wide windows and
  passed three consecutive local runs plus the Linux aarch64 container run.
- `src/v2/Budget.zig`: checked `core()` with connection, per-request overlap
  (input + candidate output + response), processing, forwarding and control
  terms. Tests lock the proposal's correction (64 × 19 MiB bodies, 32 × 320 KiB
  forwarders), `error.Overflow` on wrapped products/sums, and
  `error.CeilingBelowOneRequest`.
- `src/v2/StackProbe.zig`: paints a 3 MiB region of a 4 MiB thread stack, runs
  one workload, scans for the deepest clobbered byte. Measured (64 KiB payload):

  | Workload | Debug | ReleaseSafe |
  |---|---|---|
  | gzip compress (flate.Compress on stack) | 1,118,272 | 533,216 |
  | gzip compress + decompress | 1,207,200 | 625,184 |
  | policy evaluate (registry compiled off-thread) | 20,160 | 7,728 |

  Sizes: `flate.Compress` 230,096 B, `flate.Decompress` 3,384 B, `zstd.Decompress`
  6,616 B, `tls.Client` 384 B, `PolicyEngine` 16 B, libzstd `ZSTD_sizeof_CCtx`
  after a level-3 compress 664,600 B. A 256 KiB forwarder/worker stack cannot
  host std gzip in either mode. First ReleaseSafe numbers (~600 KiB for every
  workload, including evaluate) were a harness artifact: LLVM inlined all three
  workloads into one frame; `@call(.never_inline, ...)` fixed it.
- `build.zig`: the `edge` module now receives `-Doptimize`; before this, ReleaseSafe
  test runs silently compiled Debug tests.
- Linux aarch64 musl (Alpine 3.24 container, Zig 0.16.0, tests copied from the
  working tree): 548/550, the one failure is the pre-existing io_uring tail
  scheduler test (`PermissionDenied` under Docker seccomp). All v2 tests passed.
  Linux x86_64 under Rosetta emulation failed inside Zig's translate-c
  (`rosetta error: bss_size overflow`), so x86_64 needs a native runner.
- Processed replay rule named once (`processedReplayable`) and captured as a
  contract; distributions rebuilt (22/22) after that production edit.
- Allocation-failure probe over publish → replace → teardown is written but gated
  behind `TERO_V2_ALLOC_PROBE=1`: `checkAllAllocationFailures` reruns the whole
  registry compile once per allocation and the first attempt with the
  stack-tracing test allocator did not finish in 10 minutes.

Verification after this slice: `zig build test`: 550 passed, 2 skipped (552 total);
`zig build test -Doptimize=ReleaseSafe`: passed; `task lint`: passed;
`git diff --check`: clean; six ReleaseSafe distribution builds: 22/22.

### 2026-09-14 — wire fixtures and runtime naming

- `server.zig`: admin endpoints are classified once by `adminRoute(method, path)`
  and `dispatch` switches on the result; behavior unchanged (GET only, precedes
  routing, unknown tap path → 404). `processedReplayable(signal)` replaced three
  inline `signal == .log` checks. Both are captured in `compatibility.zig`.
- `compatibility.zig`: golden 64-byte tail WAL record and 64-byte snapshot; the
  current writers emit exactly those bytes and the current readers load them back.
- Upstream URI composition, header skip lists, codec equivalence, tracestate
  merging and S3 credential precedence already have tests in the current runtime;
  the checklist references them instead of duplicating.
- Verification: `zig build test`: 553 passed, 2 skipped (555 total); `task lint`
  passed; `git diff --check` clean; six ReleaseSafe distribution builds 22/22.

### 2026-09-14 — allocation-failure probe finding

- One registry publish cycle (one policy, contains matcher) is 54 allocations in
  about 4 ms. The exhaustive `checkAllAllocationFailures` run never finished
  because failing allocation #3 hangs: proto `Policy.dupe` fails inside
  `addPolicyInternal` (registry.zig:626, called from updatePolicies:597), the
  loop `errdefer` frees the registered id copy, the function-level key sweep
  frees it again, and the thread spins inside `Allocator.free` (Debug `memset`
  of freed bytes, no symbol) while holding the registry mutex. Sampled twice with
  `sample(1)`; the failing allocation's stack came from `FailingAllocator`.
- The gated probe now iterates failure indexes with a 3 s per-run timeout and
  fails with `RegistryFailurePathHangs` at #3. Default suite: 553 passed,
  2 skipped (555). `task lint` and `git diff --check` clean.

### 2026-09-14 — fixed dependency verified; phase 1A implemented

Reconciled the full working tree before continuing. Preserved the provider lifecycle,
`UpstreamWatch`, budget, stack probe, compatibility fixtures, and existing frontend
naming changes added by the other agent. Branch remains `edge-v2-foundation`;
no reset, rebase, commit or push was performed.

Dependency integration:

- Upstream PR #97 is merged at `a652ae9573ca9f318fc1bf6c60b1abe8240bc160`.
  The issue itself still showed open and release PR #98 was pending when checked;
  verified the code change rather than relying on issue status. Updated only
  Edge's pin and package hash. The new package includes its upstream protobuf pin
  `918588bd2692e76c96e262ee48ec1cf23190cd08`. No policy-zig or zonfig source edits.
- The old gated timeout probe passed with the fixed pin. Replaced its detached
  thread (which could outlive stack-owned probe state) with synchronous default
  regression coverage. Baseline plus **83 allocation failure points** pass for
  publish, same-ID replacement, duplicate-ID batch, and removal. Each observable
  update error leaves reads/stats unavailable and releases pending-writer admission.
- A direct `checkAllAllocationFailures` cleanup test fails at allocation #17 of 83:
  `matcher_index.zig:1500` appends `policy_id_copy` to `policy_id_storage`; the
  failed append leaves the 8-byte copy unowned. This is a leak, not the fixed hang.
  The opt-in `TERO_V2_REGISTRY_LEAK_PROBE` preserves that stricter regression.
- A plain arena exposed `compilePatterns` allocating `u8` temporary storage then
  casting it to `hyperscan.Pattern` with `@alignCast` (`matcher_index.zig:2222`).
  The third publication panicked for incorrect alignment. The test-only
  `testing/AlignedAllocator.zig` raises alignment to a machine word. The opt-in
  `TERO_V2_REGISTRY_ALIGNMENT_PROBE` bypasses it to reproduce the dependency bug.
- Default fault cases use an aligned arena to reclaim orphaned Zig memory between
  cases, and explicitly call the dependency destructor to release native indices.
  This proves return/fencing/destruction for this fixture, not leak-free dependency
  cleanup for arbitrary policies or a bound on C malloc. Production still retains
  a quarantined registry until process exit; successful reloads must not use a
  monotonically growing arena. No in-process recovery or non-failing allocator
  is introduced on the strength of a partial fix.

Phase 1A:

- Expanded all of phase 1 into minor tasks before implementation. Added
  `src/v2/RequestTable.zig`, a reactor-owned fixed table with wide generations,
  explicit work/completion ownership and startup-reserved head/input/response
  storage. No table operation allocates after initialization. Stale handles return
  an error; slots retire instead of wrapping a generation.
- A client disconnect only releases client ownership. A queued/running job and
  then its completion keep spans alive until the reactor consumes completion.
  A connected client keeps its response slot until the response write finishes.
  Duplicate transitions cannot return credit twice.
- The table passes real `@sizeOf` metadata and owned head bytes into the shared
  budget formula. `Budget.core` now rejects total reservations above the ceiling;
  it previously checked only one request. Tests cover exact equality, one byte
  below required capacity, arithmetic overflow and allocation-failure unwinding.
- This is the raw relay's ownership foundation. Queue reservation, connection
  slots, readiness adapters, HTTP framing, main/config integration and an actual
  relay are still unchecked phase-1 work. It is not serving production traffic.

TDD and validation:

- The direct cleanup test first failed against the retained-quarantine teardown;
  allowing dependency teardown exposed the residual 8-byte leak, so that proposed
  cleanup change was discarded. Quarantine semantics remain conservative.
- Request-table tests failed to compile before its types/methods existed.
  The budget regression observed an over-budget successful result before the
  new ceiling check. Both pass after implementation.
- `zig build test --summary all`: **562 passed, 2 skipped (564 total)**.
- `TERO_V2_ALLOC_PROBE=1 zig build test -Doptimize=ReleaseSafe --summary all`:
  **562 passed, 2 skipped**, confirmed ReleaseSafe compilation and 83 fault points.
- Six ReleaseSafe distribution build steps: **22/22 passed**. Default `edge`
  binary built separately. `task lint` passed; `git diff --check` clean.
- Current validation is macOS arm64. Prior Linux aarch64 evidence is historical;
  no new native Linux/x86_64 or performance validation is claimed.

### 2026-09-14 — local policy-zig and bounded queue slice

- User authorized the sibling checkout until merge; `build.zig.zon` now contains
  `.policy_zig = .{ .path = "../policy-zig" }`. The sibling agent committed further
  fixes during this work; final checks use HEAD
  `aee8c1323b54e7579f1c74e2eb8ef91f58426f81`. No sibling source changes were made here.
- Latest independent review passes all earlier reproductions: original 83 fault
  points, typed-byte 71 points, hex 65 points and malformed hex without OOM. The
  reviewed policy-zig suite passed 452 tests. See `POLICY-ZIG-REVIEW.md` for scope.
- `PolicyStore` now runs direct dependency cleanup checks by default and uses a
  plain arena for its alignment/failure sweep. Removed `AlignedAllocator` and the
  opt-in leak/alignment gates. The now-unused probe teardown mode was removed too.
  Conservative production quarantine remains a separate runtime decision.
- Added `WorkChannel` with fixed job/completion buffers and `std.Io.Queue`.
  Reserve credit before body admission, publish only initialized input spans, then
  hold credit through completion acknowledgement. Queue storage is allocated only
  at startup; exact bytes include the actual queue and element layouts.
- `RequestTable` gained a `reserved` lease, explicit reservation/cancellation, and
  a checked transition from reservation to work. An admission disconnect leaves
  storage pinned until the channel returns its reserved credit. Once submitted,
  cancellation cannot release worker ownership; completion must return it.
- Tests cover FIFO work, reverse completion order, a stalled reactor with every
  completion slot occupied, received-but-unacknowledged credit, duplicate reserve /
  acknowledge rejection, invalid input lengths, reservation cancellation, detached
  spans, queue-close drain, an empty-queue worker waking on close, and a canceled
  worker publishing its completion before ownership ends.
- Checked component budgeting covers exact capacity, too-small ceilings and partial
  startup allocation cleanup. The existing memory budget still needs composition
  with connection/readiness layouts, worker stacks and runtime configuration.
- Queue close stops admission and wakes workers; it does not close completion
  publication. The runtime must cancel unpublished reservations, drain/acknowledge,
  join workers and only then deinitialize buffers. Worker completion must be followed
  by an OS reactor wake once the readiness adapter exists.

TDD evidence: the initial channel tests failed with six missing-declaration/type
errors before implementation. The first implementation passed 568 tests; real
worker close/cancellation coverage brought the suite to **570 passed, 1 skipped**.
No v2 runtime is serving requests, and no queue throughput or lock-free claim is made.

Verification (macOS arm64, Zig 0.16.0):

- Debug registered suite: **570 passed, 1 skipped (571 total)**.
- ReleaseSafe registered suite: **570 passed, 1 skipped (571 total)**.
- Six ReleaseSafe distribution build steps plus default `edge`: **25/25 steps
  passed** in the final combined install build.
- `task lint` passed; `git diff --check` clean. Final logs use the prefix
  `/tmp/edge-v2-channel-final-`.

### 2026-09-14 — readiness ownership and OS wake slice

- Added `src/v2/Readiness.zig`: fixed socket slots and native/normalized event
  buffers, checked startup budget, no allocation on adoption or event dispatch.
  Independent u64 tokens use slot congruence plus exact equality; retire before
  addition would wrap. A returned batch must be resolved immediately before each
  dispatch, so earlier events that close/reuse a slot cannot revive stale events.
- Added `src/v2/os/Poller.zig`: level-triggered kqueue/epoll, coalescing
  EVFILT_USER/eventfd, awake-clock absolute deadlines and EINTR retry, CLOEXEC and
  nonblocking flag preservation. macOS interest changes are submitted together;
  unchanged interests avoid native calls. Native syscalls stay in this boundary.
- `adopt` always consumes the fd, including exhausted/failed admission. Updating
  interest can fail after a partial kqueue change, so failure closes/invalidates
  the registration. Neither workers nor other code may duplicate or close it.
  Shutdown closes live registrations and requires wake producers to join first.
- Added deterministic scripted event batches and real TCP fixtures for stale
  events, token retirement, exhaustion, half-close with pending data, disabled
  writes, descriptor flags, registration/update failures, and startup OOM cleanup.
  The fake batches exercise the production resolver; there is no separate fake
  scheduler or syscall-fault framework. Invalid poller fd injection checks failure
  ownership; signal-driven EINTR and partially applied kevent failure are not
  forced by the current tests.
- Added real worker/queue/readiness integration: four detached requests complete
  into reserved slots, coalesced wakes are consumed, and two completions per turn
  are acknowledged without sleeping for a nonexistent second wake. A separate
  delayed producer wakes a waiting reactor; an idle wait expires at its deadline.
  Linux fills eventfd to max-1 to force saturated wake writes through EAGAIN.
- TDD evidence: initial tests failed to compile against missing Event/init before
  implementation (`/tmp/edge-v2-readiness-red.log`). They subsequently passed on
  macOS, then Linux. This is missing-API failing-first evidence, not a claim of
  every branch having an independently recorded behavioral red state.
- Updated the proposal and redesign notes with token encoding, fd ownership,
  bounded-drain rules, finite wait fallback after wake failure, and coverage limits.
  Full connection state, admission fairness, listener/handoff, HTTP framing and
  the opt-in serving composition remain unchecked. No v2 runtime serves traffic.

Final verification (Zig 0.16.0):

- macOS arm64 `zig build test --summary all`: **579 passed, 1 skipped (580 total)**.
- macOS arm64 `zig build test -Doptimize=ReleaseSafe --summary all`: **579 passed,
  1 skipped (580 total)**.
- `zig build install edge datadog otlp prometheus tail lambda
  -Doptimize=ReleaseSafe --summary all`: **25/25 steps passed**.
- `task lint`: passed; `git diff --check`: clean.
- Linux arm64 musl isolated suite: cross-built `src/v2/WorkChannel.zig` with `-lc
  -target aarch64-linux-musl --test-no-exec`, then ran in an Alpine 3.24 arm64
  container: **27/27 passed**, including Readiness, RequestTable and Budget.
  The final Linux run includes forced eventfd saturation and batched kqueue-source
  changes (the latter are compiled out on Linux).
- Linux x86_64 musl: the same isolated suite **cross-compiles** with
  `--test-no-exec`. This does not close the native x86_64 full-dependency validation
  gate, and no Linux full-distribution test run is claimed in this slice.
- Final host logs: `/tmp/edge-v2-readiness-final-{debug,release,builds}.log`.
  Linux run: `/tmp/edge-v2-readiness-linux-final.log`; x86_64 cross-build:
  `/tmp/edge-v2-readiness-amd64-build.log`. Recorded bytes cover real Self/Slot/
  native-event/normalized-event layouts and exclude kernel/allocator overhead.

The local policy dependency remains `.path = "../policy-zig"`; final tested
sibling HEAD is `aee8c1323b54e7579f1c74e2eb8ef91f58426f81`, clean. Neither dependency
was edited.

### 2026-09-15 — connection ownership and fair admission slice verified

- Added `src/v2/Connections.zig`: fixed head buffers/metadata alongside Readiness,
  an intrusive FIFO with O(1) removal, and the head/waiting/body/processing/response
  lifecycle. Each ready head joins the tail; keep-alive clients cannot jump ahead
  of existing waiters. Body reads require both a request slot and a channel credit.
- Added `WorkChannel.canReserve` to check capacity before touching the request
  freelist. FIFO order and request storage remain unchanged while saturated.
  Acknowledging a live completion returns channel credit but keeps response bytes
  pinned, so a subsequent grant may still wait for request storage.
- Added RequestTable connection-token binding and validated Readiness slot indexing.
  Late completion resolves the original token before acknowledgment; a disconnected
  request cannot respond on a reused connection. Binding resets only on request
  recycle. Its added metadata is included automatically in the real-layout budget.
- Connection methods own native interest changes and close. Dispatch disables
  readiness before publication; registration failure cannot leave a queued job
  mistaken for unsubmitted work. Completion ack is separate from arming response
  writes, preventing a later native error from prompting a duplicate ack.
- Tests cover middle-waiter removal, keep-alive FIFO reentry, separate queue/request
  exhaustion, disconnect and mixed-state shutdown, stale/duplicate completion,
  native failure before enqueue/admission/dispatch/response/keep-alive, initialized
  connection bytes surviving request turnover, exact startup accounting and OOM
  unwind. A FailingAllocator armed after startup observes no further application
  allocation through admission, dispatch, disconnect, completion and readmission.
- TDD evidence: FIFO and stale-completion tests first failed on missing Admission/
  init (`/tmp/edge-v2-admission-red.log`). Additional lifecycle/fault tests were
  added during implementation; no independent behavioral red state is claimed
  for every branch. The initial integration compile found an `index` name shadow,
  resolved by naming the public method `slotIndex`. Lint found four long lines;
  wrapped them without rule exceptions.
- Updated proposal and redesign notes with FIFO scope, dual resource ownership,
  event-phase revalidation, completion routing, and runtime scheduling requirements.
  The accept/handoff loop remains the unfinished 1B item. HTTP length/framing,
  local/admin replies, admission deadlines, health/fallback reservations and the
  serving reactor remain unimplemented. No production frontend cutover.

Verification (Zig 0.16.0, final local policy-zig HEAD
`aee8c1323b54e7579f1c74e2eb8ef91f58426f81`, clean):

- macOS arm64 Debug: **590 passed, 1 skipped (591 total)**.
- macOS arm64 ReleaseSafe: **590 passed, 1 skipped (591 total)**.
- ReleaseSafe six distribution build steps plus default install: **25/25 passed**.
- `task lint` and `git diff --check`: passed.
- Linux arm64 musl: cross-built `zig test src/v2/Connections.zig -lc
  -target aarch64-linux-musl --test-no-exec`, then ran the isolated binary in
  Alpine 3.24 arm64: **38/38 passed**. Includes Connections, RequestTable,
  WorkChannel, Readiness and Budget; not the full dependency/distribution suite.
- Linux x86_64 musl: the same isolated suite cross-compiles with `--test-no-exec`;
  native execution/full-dependency validation still requires its recorded runner.
- Logs: `/tmp/edge-v2-admission-final-{debug,release,builds}.log`,
  `/tmp/edge-v2-admission-linux-final.log`,
  `/tmp/edge-v2-admission-amd64-build.log`.

Preserved `.path = "../policy-zig"` as authorized. Neither policy-zig nor zonfig
source was changed. Component ceilings include actual layouts and backing storage;
full runtime/allocator/kernel memory accounting remains in phase 1D.

### 2026-09-15 — bounded accept/handoff slice verified

- Added `AcceptChannel`: fixed std.Io.Queue of accepted fds, transfer-on-success
  offers, nonblocking receive, bounded reactor drain through Connections.adopt,
  and teardown that closes all unadopted descriptors after producers/consumers
  join. Full/closed offers retain caller ownership; adoption consumes on error.
- Added `Acceptor`: explicit Io listener lifecycle, stack-owned control state and
  native event batch, caller-owned target array, configurable attempt budget and
  round-robin target selection (hard maximum 64). Every accept syscall, including
  interrupted/aborted attempts, consumes budget. Full/closed targets are skipped;
  if none takes the descriptor it is closed without acknowledging HTTP data.
- Extended the native adapter with read-only listener registration, enable/disable
  control, accept4(CLOEXEC|NONBLOCK) on Linux and accept-plus-flags on macOS.
  Resource/descriptor failures pause the listener for backoff; waits remain
  interruptible by the control wake and expire by the retry deadline. A failed
  listener pause/resume stops acceptance and reports the control failure.
- Successful queue publication precedes reactor wake. Wake failure increments
  the report and never revokes/reoffers/closes the queued descriptor. Finite
  reactor waits and bounded-drain rescheduling remain composition requirements.
- Real TCP tests cover turn budgets, round-robin handoff, closed target skipping,
  saturation close, descriptor flags, coalesced wakes, a real receiver task using
  the accepted fd, failed wake ownership, stopping with pending handoff, reactor
  table exhaustion, queue teardown, startup OOM and exact queue bytes.
- Deterministic accept-boundary fixtures cover retry storms, process-fd exhaustion
  and listener control failure. The backoff test suspends a genuinely readable
  listener, exercises its control wake, waits a shorter deadline without a busy
  wake, then forces retry_at due and accepts the pending connection. No real
  process RLIMIT was exhausted; EINTR is classified/injected rather than delivered
  by a signal storm. This keeps the test deterministic and process limits intact.
- TDD: initial queue and acceptor tests failed on missing Offer/Stop/Target/init
  APIs (`/tmp/edge-v2-accept-red.log`, `/tmp/edge-v2-acceptor-red.log`). Additional
  lifecycle cases were added during implementation; not every branch has a
  recorded independent behavioral red state. Fixed test-capture name shadowing
  and kept ownership transfer outside debug assertions.
- The top-level checklist now reflects completed readiness, connection admission
  and accept/handoff work. All standalone 1B components are implemented. Next is
  phase 1C incremental HTTP head/body framing, then raw exchanges. The integrated
  serving reactor, fd/config budgets, local/admin replies and admission deadlines
  remain phase-1C/1D tasks; this still does not select v2 in production.

Final verification, Zig 0.16.0:

- macOS arm64 Debug: **602 passed, 1 skipped (603 total)**.
- macOS arm64 ReleaseSafe: **602 passed, 1 skipped (603 total)**.
- All six ReleaseSafe distribution steps plus default install: **25/25 passed**.
- `task lint` and `git diff --check`: passed.
- Linux arm64 musl isolated Acceptor suite: cross-compiled with `-lc -target
  aarch64-linux-musl --test-no-exec`, executed in Alpine 3.24 arm64:
  **50/50 passed**. Includes the acceptor/handoff and imported ownership/readiness
  fixtures, not the complete dependency/distribution suite.
- Linux x86_64 musl: the same isolated suite cross-compiles; native execution of
  the full dependency suite still requires its recorded runner.
- Logs: `/tmp/edge-v2-acceptor-final-{debug,release,builds}.log`,
  `/tmp/edge-v2-acceptor-linux-final.log`,
  `/tmp/edge-v2-acceptor-amd64-build.log`.

Final local policy-zig HEAD remains `aee8c1323b54e7579f1c74e2eb8ef91f58426f81`,
clean. Preserved `.path = "../policy-zig"`; neither dependency was edited.
Acceptor/target state and actual queue arrays are bounded, but fd demand, kernel
backlog/socket buffers and the complete runtime budget still need composition.

### 2026-09-15 — checkpoint, httpz audit and first request-head mechanism

The user's requested checkpoint is `0a72fbc`
(`feat(v2): establish bounded transport and policy ownership foundations`).
It contains the prior implementation and notes, including the authorized sibling
policy dependency. It was not pushed. Work described below follows that commit.

Completed the phase-1C transport decision gate before writing a head scanner.
[HTTPZ-TRANSPORT-REVIEW.md](HTTPZ-TRANSPORT-REVIEW.md) records exact dependency
identity, APIs, source paths, fixtures and alternatives. The proposal now links
that decision. Continue Edge-owned v2 reactors and bounded HTTP framing while
keeping httpz as the production frontend through cutover. Performance remains
unmeasured; httpz already has native event loops.

Five new inline dependency probes establish:

- Public lazy Content-Length dispatch can expose only a read-ahead prefix;
  lazy reads bypass httpz's configured body-size check, so the application must
  enforce it. Earlier blanket "fully buffered" descriptions are too broad.
- Chunked bodies still reserve decoded/raw buffers before application dispatch.
  The desired head-only assertion failed first (`/tmp/edge-v2-httpz-red.log`);
  the final test characterizes that blocker rather than pretending to fix it.
- The parser sends Continue before rejecting an oversized non-lazy body.
- A CL body followed by another request head in one read is rejected by this pin.
- Disown removes a real readiness registration and leaves a usable socket, but
  requestDone clears request state and the arena. The fixture never dereferences
  released objects. Actual handler-return scheduling was verified in source;
  this is not a complete httpz server/concurrency fixture.

Expanded the request-head slice before implementing `HeadScanner`. It borrows
newly received bytes, tracks a bounded total with `std.http.HeadParser`, and
reports exact consumed/head lengths for CRLF heads. No IO, allocator, heap storage
or body copy is required. At the exact byte cap, a complete head succeeds and
an incomplete head fails; completion/exhaustion require reset before more input.
The connection owner retains head bytes for subsequent strict validation.

TDD: the five initial scanner tests failed on the stub
(`/tmp/edge-v2-head-scanner-red.log`). The four valid-input/capacity tests then
passed. An additional assertion assumed the std scanner would locate a malformed
LF-only head exactly; it instead returned a later boundary (64 versus 27 bytes).
That assumption is not a supported v2 protocol contract. The final negative
probe only demonstrates that invalid input can appear complete (`x\n\n` in Zig
string notation). Strict validation must reject it before queue admission,
Continue or forwarding. Added a sixth test varying CRLF header padding across
129 lengths and every split to verify boundaries for supported line endings.

The initial full ReleaseSafe run also exposed an existing acceptor test race:
two immediate post-connect turns observed no handoff; one test unwrapped null.
The test fixture now waits for actual listener readiness with a two-second
absolute deadline before returning a connected peer. The stop test asserts the
handoff count before inspecting its fd. Production acceptor code/turn bounds are
unchanged. Repetition then exposed the same assumption for multiple clients:
one ready connection does not guarantee the whole expected backlog is present.
Those two tests now accumulate bounded turns under an absolute deadline, assert
each turn's attempt bound and inspect the resulting distribution/saturation.
They no longer require a particular OS batch size. Ten successive isolated native
ReleaseSafe runs passed all 50 tests after this adjustment.

Final validation:

- `zig build test --summary all` and `zig build test -Doptimize=ReleaseSafe
  --summary all`: **613 passed, one skipped (614 total)** in each mode.
- `zig test src/v2/HeadScanner.zig`: **6/6 passed**.
- `zig test src/v2/Acceptor.zig -lc -O ReleaseSafe`: **50/50 passed**.
- Cross-compiled those two isolated roots with `-O ReleaseSafe -target
  aarch64-linux-musl --test-no-exec`, then ran in Alpine 3.24 arm64:
  **6/6 and 50/50 passed**, respectively.
- `task lint` passed. No serving/distribution code changed; prior distribution
  build evidence remains attached to the checkpoint rather than being rerun.
- Current sibling policy-zig HEAD:
  `502efcc67bda53b07cc715a42390cfba61d28303`, clean during final verification.
  The local ref remains selected. The new httpz boundary fixture ran on macOS;
  isolated Linux tests above do not include that dependency fixture.
- Logs: `/tmp/edge-v2-httpz-scanner-final-{debug,release,lint}.log`,
  `/tmp/edge-v2-head-scanner-final.log`, `/tmp/edge-v2-httpz-acceptor-release.log`,
  `/tmp/edge-v2-httpz-acceptor-linux.log`, `/tmp/edge-v2-head-scanner-linux.log`,
  `/tmp/edge-v2-acceptor-readiness-repeat.log`. Lint was also rerun directly after
  the final fixture adjustment.

Remaining 1C work: strict head metadata/framing validation, no-IO Expect and
keep-alive decisions, incremental body/trailer parsing, request admission wiring,
header rewriting, upstream exchanges, response framing and real wire tests.
Head scanning is not a complete HTTP parser and no v2 runtime serves traffic.

### 2026-09-15 — strict request heads and admission-independent metadata

Implemented `src/v2/RequestHead.zig`, imported by the v2 test root. Expanded the
strict-head substeps before writing the first 12 tests. All 12 failed on the
unimplemented parser while the six imported scanner tests passed
(`/tmp/edge-v2-request-head-red.log`). Implemented the parser and pure Continue
decision, then added exhaustive field-value byte coverage and method-independent
framing cases. There are now 14 request-head tests plus six scanner tests.

The parser accepts exactly one complete head, including its terminating CRLF.
It reports incomplete input, trailing body/pipelined bytes passed by mistake,
oversized heads and exhausted header-descriptor capacity. The default head cap
is 16 KiB; the caller's descriptor slice sets the header count cap. A caller with
64 entries accepts exactly 64 fields and rejects the next. Descriptor capacity
above u16 and a zero byte cap are invalid startup/API parameters.

Metadata consists of scalar state and u32 spans into caller-owned bytes. It
includes raw method/target, target form, path/query, authority and Host spans,
field count, version, framing, persistence and expectation state. Each field has
name/value spans; field order, casing and repeated values survive unchanged.
The parser trims only outer field OWS in its value view and never changes input.
No allocator or IO is needed. Span access checks bounds, but the owner remains
responsible for supplying identical bytes with the correct request lifetime.
On parse error, discard partially populated descriptor storage; no valid head is
returned or published. Layout tests cap metadata at 128 bytes and the 64-entry
descriptor array at 1 KiB. This is not full runtime budget/config binding; the
composition still has to decide where these layouts reside and count them.

Implemented acceptance profile:

- Strict CRLF, token method/field names, no whitespace before colon, no folding,
  no forbidden controls or DEL in values; HTAB and obs-text remain permitted.
- One nonempty, syntactically valid Host required for HTTP/1.1. Duplicate Host,
  CL or TE is rejected, including identical values; CL lists are rejected too.
  CL accepts only decimal digits with checked u64 arithmetic, independently of
  method. No CL/TE means no body, not a connection-close-delimited request.
- Only a single case-insensitive `chunked` transfer coding is supported; CL/TE
  coexistence and HTTP/1.0 TE are rejected. Content-Encoding is intentionally
  opaque, including unknown or repeated values, and does not change framing.
- Origin and HTTP(S) absolute targets preserve escaped path/query bytes.
  OPTIONS `*` and CONNECT authority syntax are recognized. No tunnel support
  was added. Relative targets, fragments, userinfo, invalid percent escapes and
  invalid URI characters are rejected. Host authorities support reg-name,
  bracketed IPv6 and IPvFuture syntax without DNS. IPv6 scope identifiers are
  unsupported by the reused pure std parser. Port syntax is checked, not used
  as an upstream destination. Empty absolute paths remain empty spans; the later
  request writer must apply HTTP's slash/asterisk rules rather than dropping query.
- Connection tokens are case-insensitive, tolerate empty list members, and keep
  close sticky across repeated fields. HTTP/1.0 always closes, including a
  keep-alive request. Header forwarding still needs to remove every nominated
  hop-by-hop field; parsing the token list does not perform that rewrite.
- `continueAction` returns none, wait-for-admission, send-continue or rejection
  for unsupported expectations. No body, already-received body bytes, and a
  recognized HTTP/1.0 Continue expectation suppress the interim response.
  The runtime must supply real reservation state, enforce its deadline, track
  whether Continue was sent, and send final responses. The parser does none of
  those effects. Unsupported expectations stay rejected across repeated fields.

Protocol references checked during implementation:
[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) for framing,
[persistence](https://www.rfc-editor.org/rfc/rfc9112.html#section-9.3), and
[RFC 9110 Expect](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1).
The explicit refusal of duplicate/list CL and empty Host is the initial Edge
acceptance profile, not a claim to accept every valid HTTP variation. Run the
broader compatibility/wire suite before cutover. API discovery used zigdoc;
generic std head parsing was not reused because it rejects opaque encodings,
and numeric parsing that accepts signs/underscores was not used for CL.

Tests include all split positions through scanner + owned-buffer assembly +
validation, relocation, 16 KiB and 64-header boundaries, malformed-line/Host/URI
tables, CL overflow, repeated encodings, Connection/Expect lists and every byte
value in a field-value position. These are deterministic unit/integration tests
of parsing components, not fuzzing or a serving relay fixture.

Verification before the final formatting cleanup: Debug and ReleaseSafe each
passed **627 tests, one skipped (628 total)**. Isolated Linux arm64 musl on
Alpine 3.24 passed **20/20**. Lint initially requested line wrapping and separate
span bounds assertions; those were corrected, and `task lint` passed. Final
verification after cleanup:

- `zig build test --summary all`: **627 passed, one skipped (628 total)**.
- `zig build test -Doptimize=ReleaseSafe --summary all`: **627 passed, one skipped**.
- `zig test src/v2/RequestHead.zig -O ReleaseSafe -target aarch64-linux-musl
  --test-no-exec`, then execute in Alpine 3.24 arm64: **20/20 passed**.
- The same isolated root cross-compiles for `x86_64-linux-musl`. This does not
  close the native x86_64 full-dependency validation gate.
- `task lint` and `git diff --check` pass. Current distribution code is untouched;
  prior distribution build evidence remains attached to the checkpoint.
- Logs: `/tmp/edge-v2-request-head-final-{debug,release}.log`,
  `/tmp/edge-v2-request-head-linux.log`,
  `/tmp/edge-v2-request-head-{arm64,amd64}-build.log`.

Preserved `.path = "../policy-zig"`; observed clean sibling HEAD
`502efcc67bda53b07cc715a42390cfba61d28303`. No dependencies or current serving
runtime were changed. This continues the uncommitted work after `0a72fbc`.

Next: expand the body-framing slice into minor tasks before implementation.
Implement Content-Length/chunked consumption with bounded chunk-line/trailer
storage, exact consumed-byte counts and untouched encoded entity bytes. Then
wire body/queue reservation, admission deadlines and Continue to Connections /
RequestTable. Response framing, upstream lanes and the real relay remain open.

### 2026-09-15 — body framing and admission bridge verified

The body/trailer slice implements `BodyFramer` with caller-owned bounded storage,
bulk entity copying, strict Content-Length/chunked framing, checked hexadecimal
lengths, extensions, trailer validation and separate cumulative metadata limits.
Every consumed-byte count preserves read-ahead. Output remains provisional until
complete framing validates; malformed input or early EOF fences the parser.
`http_field.zig` shares field syntax and offset descriptors with RequestHead.

The initial nine body tests failed behaviorally with `NotImplemented`, then passed
after implementation. Additional tests cover tiny output windows, exact metadata
capacities, u64 lengths and full head/body composition across every split. Recorded
body validation: full Debug/ReleaseSafe **640 passed, one skipped (641 total)**;
isolated Linux arm64 **33/33 passed**, x86_64 musl compile-only, lint passed.
Logs: `/tmp/edge-v2-body-final-{debug,release}.log` and
`/tmp/edge-v2-body-linux.log`.

`RequestIngress` then connected reserved request storage to head/body parsing and
`WorkChannel.Input`. A Connections fixture validates FIFO admission, copies the
head before connection-buffer reuse, preserves the next-request suffix, dispatches
the copied entity and returns to reading after completion. This is an in-memory
handoff fixture, not a serving reactor or upstream exchange. That slice's tests
and implementation were introduced together; initial compiler errors did not
constitute behavioral TDD. Its checklist now reflects that distinction.

The interrupted ingress ReleaseSafe run finished successfully. Before the next
review, both full modes had **646 passed, one skipped (647 total)**; isolated
Connections Linux arm64 had **78/78 passed** and x86_64 musl compiled. Logs:
`/tmp/edge-v2-ingress-final-{debug,release}.log` and
`/tmp/edge-v2-ingress-linux.log`.

### 2026-09-15 — ingress ownership and trailer handoff corrected

Review found two production-contract gaps before building further on ingress:
`RequestTable.buffers` checked only generation, so a still-live worker-owned slot
was accessible to ingress; trailers lived in temporary scratch and never reached
the worker. Regression tests reproduced unreserved construction and post-dispatch
access (**67 passed, two failed**) before the fix. Fixture fault injection also
found leaked RequestTable allocations on channel startup OOM and a lost request
slot on failed reservation; both cleanup paths now unwind explicitly. A separate
test reproduced Continue being offered after body-framing failure.

Changes:

- `ingressBuffers` requires the current generation, attached client, reading state
  and reserved lease. Ingress operations and WorkChannel submission check this
  boundary on the reactor. Cancellation, disconnect and dispatch revoke ingress
  access; stale generations remain rejected after slot reuse. Failed framing also
  blocks Continue, and incomplete trailers return an error rather than asserting.
- RequestTable reserves distinct head/body/trailer/response spans. Trailer bytes
  contribute to its checked startup budget and exact ceiling/OOM tests. A zero
  trailer capacity is valid for non-chunked users; chunked framing requires at
  least two bytes for the final CRLF. No allocation was added to request handling.
- BodyFramer writes trailers directly into the request slot. WorkChannel.Input
  carries their initialized length; Job borrows immutable raw bytes pinned by the
  same work/completion lease. Oversized trailer handoff lengths fail before
  publication and leave the reservation available for cleanup.
- The trailer handoff test first failed with an empty worker trailer span, then
  passed after wiring. It overwrites ingress scratch and disconnects the client,
  verifies duplicate trailer order/casing and proves the slot cannot recycle before
  acknowledgement. Capacity tests cover one-byte rejection, exact empty-trailer
  capacity and overflow without overwriting response storage.

Final verification:

- Full native Debug and ReleaseSafe: **653 passed, one skipped (654 total)**.
- Isolated Connections suite on Linux arm64 musl, ReleaseSafe in Alpine 3.24:
  **85/85 passed**. The same root compiles for x86_64 musl; native full-dependency
  x86_64 execution remains open.
- `task lint` and `git diff --check` pass. Logs:
  `/tmp/edge-v2-ingress-owned-full-{debug,release}.log`,
  `/tmp/edge-v2-ingress-owned-linux.log`,
  `/tmp/edge-v2-ingress-owned-{arm64,amd64}-build.log` and
  `/tmp/edge-v2-ingress-owned-lint.log`. Behavioral red evidence:
  `/tmp/edge-v2-ingress-{ownership,cleanup,trailers,continue}-red.log`.
- The local policy-zig checkout remains clean at
  `502efcc67bda53b07cc715a42390cfba61d28303`; `.path = "../policy-zig"` remains.
  No dependency changes. All work after checkpoint `0a72fbc` remains uncommitted.

Next: expand header/trailer rewriting and outbound framing into minor tasks before
coding. Preserve end-to-end duplicates and opaque content encodings, filter
Connection-nominated fields, derive framing from the actual body/trailer spans,
and test bounded output before connecting a real upstream exchange. Phase 1C is
still open: socket read/write scheduling, admission deadlines, Continue writes,
response framing and upstream deadlines are not wired into a serving runtime.

### 2026-09-15 — bounded outbound raw request framing verified

Added `RequestWire` and registered its inline tests through `v2/root.zig`. The
first five behavioral tests failed with `NotImplemented` (**20 imported tests
passed, five failed**). They passed after implementing preparation. A subsequent
input-trailer-byte-limit test failed before adding that limit, then passed. Red
evidence is in `/tmp/edge-v2-request-wire-red.log` and
`/tmp/edge-v2-request-wire-limits-red.log`.

The allocation-free preparer builds a complete HTTP/1.1 head/tail in caller-owned
storage and borrows the unchanged entity body between them. It validates supplied
body length and trailer completeness before returning any sendable spans. All
generated metadata must fit before network commitment. Destination authority and
optional route-built target are syntax checked; the original absolute URI never
selects the network peer. Query/path bytes remain encoded and unchanged when no
override is supplied. CONNECT and unsupported expectations return explicit errors.

The output rebuilds Host and Content-Length/chunk framing, adds Via, consumes
Expect, strips fixed connection fields and every original Connection nomination,
and preserves ordered repeated end-to-end fields and opaque content encodings.
Trailers remain separate, retain order/casing/duplicates and receive a generated
Trailer declaration after filtering. A shared critical-trailer predicate now
serves BodyFramer and RequestWire. Nonempty chunked input becomes one data chunk;
empty input goes directly to its zero chunk/trailers. This deliberately preserves
entity bytes rather than original transfer chunk boundaries/extensions.

The cursor returns a contiguous pending span and advances only by the bytes the
transport reports as written. Tests cover blocked and 1–31-byte short writes,
invalid advances, empty body framing, destination injection, incomplete/forbidden
trailers, filtered-field accounting, exact head/tail/chunk-prefix capacity, the
64-output-field ceiling including generated fields, and a full 16 KiB output head.
The ingress/channel composition test detaches the client, prepares the worker's
pinned job, overwrites descriptor scratch, traverses output one byte at a time,
and reparses it to the same binary entity and retained trailers. Source body and
trailer bytes stay unchanged; no extra body copy occurs. These are in-memory
wire fixtures; actual socket writes and upstream response handling remain open.

Final verification:

- Native `zig build test --summary all` and ReleaseSafe: **665 passed, one skipped
  (666 total)**. Twelve new RequestWire tests run in the full suite.
- Isolated RequestWire plus imported ownership/parser tests: **86/86 passed** on
  native Debug and Linux arm64 musl ReleaseSafe in Alpine 3.24.
- The same isolated root cross-compiles for x86_64 musl. This does not close the
  full native x86_64 dependency validation gate.
- `task lint` and `git diff --check` pass. Lint initially caught long lines and
  local helper imports; corrected before final verification.
- Logs: `/tmp/edge-v2-request-wire-full-{debug,release}.log`,
  `/tmp/edge-v2-request-wire-final-isolated.log`,
  `/tmp/edge-v2-request-wire-linux.log` and
  `/tmp/edge-v2-request-wire-{arm64,amd64}-build.log`.
- Preserved local policy-zig reference; sibling remains clean at
  `502efcc67bda53b07cc715a42390cfba61d28303`. No dependency or production runtime
  edits. Work after checkpoint `0a72fbc` remains uncommitted.

See REDESIGN-NOTES §23 and proposal §6.4 for buffer formulas, ownership and
tradeoffs. Default output caps can reject a maximal input after generated fields
are added; runtime admission/config must reserve that room explicitly. Worker
head/tail and descriptor residency still need aggregate budget binding. This API
is raw-only: processed entities require separate truthful encoding/validator
handling. Next: expand response framing and ownership, then wire real upstream
exchanges/deadlines and serving-loop backpressure. Phase 1C remains open.

### 2026-09-16 — buffered upstream response framing verified

Implemented `ResponseHead` and `ResponseIngress`, registered through `v2/root.zig`.
The response-head slice began with five behavioral failures against the stub;
the receiver began with six behavioral failures after correcting test declaration
names. Red logs: `/tmp/edge-v2-response-head-red.log` and
`/tmp/edge-v2-response-ingress-red.log`. Added boundary and lifecycle coverage after
the initial green runs; the final additions total 17 new tests (seven head, ten
receiver), plus imported request/framing regressions.

ResponseHead validates status/reason/field syntax and retains offset metadata,
unknown content encodings and ordered repeated fields. It distinguishes declared
representation length from body framing for HEAD/304, rejects prohibited 1xx/204
framing, rejects upgrades/successful CONNECT, and requires empty 205 content while
still consuming ordinary framing. Repeated/ambiguous framing is rejected, and
Connection close remains sticky across repeated fields. The shared strict line,
decimal-length and Connection validators moved into `http_field.zig`; the request
parser uses those same functions without changing its acceptance contract.

The receiver borrows fixed head/body/chunk-line/trailer/descriptor storage. It
reuses HeadScanner and BodyFramer for fixed/chunked responses and implements
bounded EOF-delimited copying separately. It returns one event per informational
head so the transport can rewrite/relay it before another feed overwrites that
store. Both informational count and total head bytes are bounded. Final message
views remain unavailable until full framing completes; every parser/transport
failure permanently fences the receiver. EOF-delimited completion requires an
explicit clean EOF classification from the transport owner, including checking
the watchdog/TLS result. Informational Connection close persists through the final
response, and observed EOF prohibits connection reuse.

Tests cover every split of informational + chunked final + following head, every
truncated fixed/chunked response prefix, bytewise reads, clean EOF versus transport
failure, HEAD representation length, 205 framing, interim-only EOF, exact head/
body/trailer/metadata/field capacities, source-buffer reuse and all 256 reason
bytes. Extra bytes are preserved, and complete metadata/body/trailers remain in
caller-owned storage. The reuse flag is a framing prerequisite, not permission to
pool a socket without checking request/transport/deadline state.

Final verification:

- Full native Debug and ReleaseSafe: **682 passed, one skipped (683 total)**.
- Isolated ResponseIngress plus imported parser tests: **50/50 passed** native
  Debug and Linux arm64 musl ReleaseSafe in Alpine 3.24.
- Isolated x86_64 musl root compiles; native full-dependency validation is still
  outstanding. `task lint` and `git diff --check` pass after style cleanup.
- Logs: `/tmp/edge-v2-response-full-{debug,release}.log`,
  `/tmp/edge-v2-response-final-isolated.log`, `/tmp/edge-v2-response-linux.log`,
  `/tmp/edge-v2-response-{arm64,amd64}-build.log`.
- Local policy-zig remains clean at `502efcc67bda53b07cc715a42390cfba61d28303`;
  `.path = "../policy-zig"` is unchanged. No dependencies or current serving path
  were edited. Work after checkpoint `0a72fbc` remains uncommitted.

See REDESIGN-NOTES §24 and proposal §6.4. Next: expand downstream response
serialization and budgeted response-slot handoff, including preserving status,
repeated fields/trailers and HEAD/304 metadata lengths. Forwarder scratch cannot
be referenced by a final completion after reuse; interim responses need bounded
handoff and write ordering too. Then wire the real upstream exchanges, watchdog,
socket scheduling and downstream backpressure. Non-chunked transfer codings/coding
chains remain an explicit compatibility gate, and unlimited Prometheus streaming
is not implemented by this finite receiver. Phase 1C remains open.

### 2026-09-16 — final response serialization and completion ownership verified

Expanded the final-response slice before implementing it. `ResponseWire` began
with five behavioral failures against its stub; the final slice adds eight tests.
Red evidence: `/tmp/edge-v2-response-wire-red.log`. `Response` and `ResponseWire`
are registered through the v2 test root. The final tests also cover RequestTable,
WorkChannel, Readiness and the existing parser/framer contracts.

ResponseWire serializes a completed raw response into request-owned head/body/tail
spans. The upstream receiver writes its body directly into the worker job's
reserved response buffer, so final completion does not copy the body again.
Metadata is prepared before publication and never borrows reusable worker scratch.
Status/reason, duplicate fields, opaque Content-Encoding, authentication challenges
and validated trailers survive. All Connection nominations are filtered from both
metadata sections. Framing and Via are regenerated, HEAD/304 representation lengths
are preserved, and 204 framing is omitted. Ordinary complete bodies use CL unless
retained trailers require chunked framing. HTTP/1.0 closes and rejects retained
trailers before commitment; this is a recorded compatibility gate, not silent loss.

RequestTable now separately budgets response head/tail capacity around its existing
response body region. Defaults of zero preserve existing contiguous-response users;
composition must supply capacities for framed responses. WorkChannel jobs expose
the three regions and `.framed_response` completions carry only lengths/close state.
Queue accounting uses the new actual element layouts. `responseView` rejects stale
IDs, unacknowledged work, detached clients and lengths beyond reserved capacity.
After acknowledgement, a live response retains its request slot through the last
write even though its queue credit is returned. Detached completions recycle.

Tests overwrite receive scratch after publication, traverse output a byte at a
time, parse the resulting wire with a fresh receiver, and verify binary body and
trailer preservation. They exercise live/detached completion, slot reuse, exact
head/tail/field limits, wrong body storage, short-write cursor bounds, empty bodies,
filtered trailers and bodyless status semantics. Existing exact-budget/OOM tests
now cover the new response metadata regions and enlarged queue layouts. The final
round-trip fixture initially omitted the trailer section's terminal CRLF from its
expectation; corrected that expectation against BodyFramer's existing contract.

Final verification:

- Full native Debug and ReleaseSafe: **690 passed, one skipped (691 total)**.
- Isolated ResponseWire plus imported tests: **87/87 passed** native Debug and
  Linux arm64 musl ReleaseSafe in Alpine 3.24.
- Isolated x86_64 musl root compiles. This does not close the native full-dependency
  x86_64 execution gate. `task lint` and `git diff --check` pass.
- Logs: `/tmp/edge-v2-response-wire-full-{debug,release}.log`,
  `/tmp/edge-v2-response-wire-handoff.log`, `/tmp/edge-v2-response-wire-linux.log`,
  `/tmp/edge-v2-response-wire-{arm64,amd64}-build.log`.
- Local policy-zig remains clean at `502efcc67bda53b07cc715a42390cfba61d28303`;
  `.path = "../policy-zig"` is unchanged. No dependency or production serving-path
  changes. Work after checkpoint `0a72fbc` remains uncommitted.

See REDESIGN-NOTES §25 and proposal §6.4 for capacity formulas and ownership order.
Phase 1C remains open: next expand interim-response handoff/ordering, then connect
actual upstream exchanges with deadlines, partial writes and downstream
backpressure. Runtime close handling, transformed-entity metadata and unlimited
Prometheus streaming are not implemented by this buffered serializer. Combined
config/budget binding and the serving composition root remain phase-1 work.

### 2026-09-17 — phase 1 completed with a runnable relay

Implemented the phase-1 completion checklist as one integrated delivery. The real
process fixture preceded the executable (`/tmp/edge-v2-runtime-red.log`); its first
socket run exposed Zig 0.16 Threaded's panic on connect timeout. `os/connect.zig`
uses nonblocking connect, finite poll, SO_ERROR and the absolute deadline instead,
checking shutdown between waits. A separate red config test caught accepting an
upstream port of zero; a wire regression caught forwarding 103 to HTTP/1.0. Both
were fixed and verified. See `src/v2/README.md` for the runtime contract and diagram.

`Relay` composes one reactor, one acceptor and fixed upstream workers. It retains
read-ahead over keep-alive, bounds every socket turn, sends Continue after admission,
reserves body/completion capacity before reads, and writes final responses directly
from pinned request spans. Deadlines cover head/body/admission and upstream work;
stalled downstream output has its own absolute budget. Health bypasses work credits.
Turn-budget exhaustion schedules an immediate poll; finite 10 ms waits recover
lost wake hints. Shutdown detaches clients, shuts down upstreams, drains completion
ownership and joins producers before releasing storage. No automatic raw replay or
local durability acknowledgement was introduced.

Startup validation binds the actual connection/request/queue/client layouts and
configured stacks to one memory ceiling, and checks calculated fd demand against
RLIMIT_NOFILE. Exact ceiling and all application allocation-failure paths pass.
Application reservations and observed peak RSS/request occupancy are distinct;
allocator/OS/backend overhead and future codec/regex allocations remain explicit.
Quarantine lifecycle is decided in the README; its policy wiring belongs to phase 2.

Verification:

- Native full Debug and ReleaseSafe: **693 passed, one skipped (694 total)**.
- Real-process fixture: **13/13 passed** in native Debug, native ReleaseSafe and
  Linux arm64 musl ReleaseSafe (Alpine 3.24). Includes opaque/chunked bodies,
  trailers, Continue/1xx, pipelining, queue pressure, health, half-close, disconnect,
  silent/trickling upstreams, truncated responses, slow/stalled readers and shutdown.
- Isolated Linux arm64 component suite: **103/103 passed**. Linux x86_64 musl
  executable compiles; native full-dependency x86_64 execution remains a phase-0 gate.
- Six production distributions: **22/22 build steps succeeded** in ReleaseSafe.
  `task lint` and `git diff --check` pass. Existing production defaults are unchanged.
- Full-relay baseline: 1,000 verified sequential 4 KiB POST/echo round trips,
  **6,161 requests/s, p50 0.152 ms, p99 0.280 ms**, 4,915,200 B peak child RSS,
  12,714,782 B calculated reservation, peak one active request, zero failed.
  This measures the complete raw path against a Python loopback origin; it is
  neither an old/new comparison nor production sizing evidence.
- Logs: `/tmp/edge-v2-phase1-{debug,release,distributions,benchmark}.log`,
  `/tmp/edge-v2-phase1-native-{debug,release}-integration.log`,
  `/tmp/edge-v2-phase1-linux-{integration,tests}.log`,
  `/tmp/edge-v2-phase1-{arm64,amd64}-build.log`. Source at `tests/v2/relay.py`
  reproduces the checks and benchmark.
- Local policy-zig remains clean at `502efcc67bda53b07cc715a42390cfba61d28303`;
  its local path is unchanged. No dependency edits. Changes after `0a72fbc`
  remain uncommitted; phase completion does not imply a merge or production cutover.

Phase 1 is complete as a **raw HTTP vertical slice**. Numeric-IP HTTP endpoints,
one origin, buffered responses and one upstream connection per exchange are the
explicit initial contract. TLS/DNS/pooling and full production protocol/config
parity remain later work. Next: phase 2 Datadog policies, bounded scratch and
whole-request fail-open through this executable. Do not start another transport
foundation phase or claim full Edge replacement.

## Handoff

Latest review: all earlier policy-zig findings are resolved for the tested cases.
[POLICY-ZIG-REVIEW.md](POLICY-ZIG-REVIEW.md) contains the current sendable review.
Historical failing results in the work log above are not current blockers.

The user explicitly requested `.path = "../policy-zig"` until merge. Preserve
that local dependency selection; replace it with the reviewed immutable release
or commit after the user merges. The sibling checkout is being updated by its
implementing agent, so record its actual HEAD with final verification. Do not
edit policy-zig or zonfig as part of Edge work.

Phase 1 is complete for the planned raw HTTP vertical slice. Build with
`zig build v2 -Doptimize=ReleaseSafe`; see [src/v2/README.md](src/v2/README.md)
for commands, bounds, benchmark and the exact runnable contract. `Relay` connects
Acceptor/Connections/RequestIngress/WorkChannel/RequestWire/ResponseIngress/
ResponseWire with real sockets, native bounded connect, UpstreamWatch deadlines,
request-owned response writes, health and ordered abort/drain/join shutdown.
Aggregate config accounting includes real tables, scratch, queues and explicit
thread reservations. Health bypasses work admission but still needs fd/client
capacity. Production remains on httpz; no default distribution was switched.

The executable intentionally serves a single configured numeric-IP HTTP origin.
TLS/DNS/pooling, production routing/config parity and policy processing are not
claimed complete. Informational responses are bounded and delayed until the final
response, with 100 handled locally and no 1xx forwarded to HTTP/1.0. See the README
for remaining compatibility limits and why application reservation is not RSS.

Next delivery work is **phase 2: one Datadog policy slice through this working
relay**, with retained original bytes and whole-request fallback. Expand it into
minor tasks before coding. Quarantine decision: continue raw forwarding, expose
degraded policy status, stop affected providers, retain the failed registry until
process exit and require operator restart; do not auto-exit or silently resume
mutation. Phase 1 has no registry, so applying that decision belongs to phase 2.

Ownership rules:

- Each `WorkChannel` belongs to one reactor/request table. That reactor reserves
  channel credit before admitting body bytes, fills the request spans, and then
  submits. Workers only take jobs and publish exactly one completion each.
- The credit covers reservations, queued/running jobs and completions already
  dequeued but not yet acknowledged. Receiving alone does not return a credit.
- A disconnected reservation needs `cancelReservation`; after submission, only
  completion acknowledgement releases worker ownership. Cancellation must still
  publish a completion. A connected client's response storage stays pinned until
  its write ends. All table transitions remain on the reactor.
- `close` stops admission and wakes queue consumers; queued work still drains and
  completions stay publishable. Cancel unpublished reservations, consume/acknowledge
  completions, and join workers before deinit. Closing is not proof that work ended.
- Publish a completion before calling `Readiness.wake`; the integration fixture
  exercises this ordering. A bounded drain that exhausts its turn budget must
  schedule another immediate turn, even after the single coalesced wake is gone.
  Relay applies FIFO admission and polls immediately after exhausting a turn cap.
  Queue min=0 operations avoid waiting for capacity but take an internal lock.
- `Readiness.adopt` ALWAYS consumes its fd, including errors/exhaustion. Never
  duplicate or separately close an adopted fd. An interest-update error closes
  the registration and requires detaching its request. Resolve every event just
  before dispatch, including events later in the same batch after a close/reuse.
- `AcceptChannel.offer` transfers the fd ONLY on `.accepted`; `.full`/`.closed`
  leave it with the acceptor, which may try another target and ultimately closes
  it if all refuse. This differs deliberately from always-consuming
  `Connections.adopt`. Never close/re-offer an accepted fd after wake failure.
- `Acceptor.turn` bounds accepts (including retries) and round-robin probes. Its
  `.budget` result schedules another turn; `.backoff` requires waiting through
  the disabled listener registration and retry deadline. Pause/resume failure
  stops acceptance. Consume/report failure and wake-failure fields in composition.
- Drain handoff queues with a bounded budget; budget exhaustion schedules another
  immediate reactor turn. Stop/join the acceptor before tearing down target queues
  and wakes. Queue deinit closes all descriptors that were never adopted. The
  Relay binds accept/drain turn budgets, fd demand, memory limits and backoff.
- `Connections` owns all registration changes when wrapping Readiness. Use its
  embedded poller only to wait/resolve/wake; direct adoption/close/interest mutation
  would bypass connection and request ownership. Revalidate both token and current
  connection state before acting on a batched event.
- A parsed head always calls `enqueue`; grant only through `admitNext`, bounded by
  the reactor turn budget. Retry after queue acknowledgement AND response-storage
  release/canceled admission. Available queue credit does not imply request space.
  Copy initialized head/body bytes to RequestTable before dispatch; worker jobs
  cannot reference reusable connection heads or ingress scratch. RequestIngress
  performs that copy and body/trailer framing into reserved request spans. Stop
  using ingress and any borrowed views after cancellation or publication.
  Relay now manages partial reads, read-ahead and one-time Continue.
- `Connections.complete` consumes acknowledgement and returns the live connection
  token or null for a detached request. Null may free the request bytes immediately.
  A live response is framed before `responseReady` arms writes. Calling complete
  again after a later interest failure is a duplicate acknowledgement bug.
- For `framed_response`, receive the upstream body directly into `job.response`,
  then prepare metadata into `job.response_head`/`response_tail` before publishing.
  Publish errors as failed outcomes; partially prepared metadata is not sendable.
  Stop using all job spans at publication. After a live acknowledgement, obtain
  `RequestTable.responseView` and retain the slot through the last downstream byte.
  Drop the cursor before close/release; it cannot validate its own borrowed lifetime.
  Honor `response.close` at write completion rather than returning that connection
  to reading. HTTP/1.0 with retained trailers currently fails before commitment.
- `closeAll` unlinks waiters, returns unpublished reservations and detaches clients;
  it does not drain jobs. Keep Connections/RequestTable/WorkChannel alive through
  all late completions, then join wake producers and deinit.
- Stop/join wake producers before poller destruction. Native waits are canceled
  through explicit wake/shutdown state, not `Io` cancellation. Use finite wait
  deadlines to recover from wake failure; the composition root must choose the
  maximum fallback interval and report errors. Relay uses a 10 ms fallback.

Dependency and validation limits:

- The plain-arena fault sweep and direct `checkAllAllocationFailures` cleanup run
  by default. The alignment adapter and old opt-in skip have been removed.
- `PolicyStore` still permanently fences a failed publication and conservatively
  retains that registry until process exit. Tested cleanup is now safe for the
  fixtures, but failed updates are not transactional. Recovery will keep raw
  forwarding and require operator restart, as decided above. No non-failing
  allocator workaround is needed.
- The dependency's regex-engine OOM exclusion and native C allocation accounting
  remain outside the verified fault fixture. Do not claim universal cleanup safety.
- Linux x86_64 still needs a native runner. A controlled DNS deadline probe still
  lacks local injection. The new isolated readiness/queue Linux aarch64 coverage is recorded above;
  the older full-distribution Linux run predates current dependency changes.
- Phase-1 raw-runtime budget binding is complete. Codec/hyperscan scratch and
  Lambda lifecycle remain with the phases defining those paths. Native Linux
  x86_64 full-dependency execution and controlled DNS fault injection remain
  phase-0/platform gates; neither is silently marked complete by this slice.

`ProviderSet` and `PolicyStore` still do not replace `Loader`. Keep stores and
callback contexts stable, join providers before teardown, and honor read guards.
Disarm `UpstreamWatch` slots before the owning forwarder closes a stream.

### 2026-09-17 — phase 2 integrated policy path in progress

- Bounded worker workspaces and sticky OOM tracking are implemented. Datadog
  log candidates remain private until JSON grammar, framing and encoding finish.
  Unchanged requests use the original encoded bytes; failed candidates roll back
  without evaluating a record twice. Changed bodies regenerate length and remove
  stale representation digests/validators in both headers and trailers.
- Runnable `--policy-file` starts a ProviderSet watcher. Registry quarantine is
  monitored off the reactor: stop publishers, retain unsafe registry storage
  until process exit, and keep forwarding raw. Registry allocations currently
  use page_allocator; these control-plane/C allocations are outside the core
  reservation, as are codec cache allocations. This is not a process RSS cap.
- Native real-process suite: 15/15, including gzip processing, malformed suffix
  rollback, unsupported encoding passthrough, file reload and output exhaustion
  (`/tmp/edge-v2-phase2-integration.log`). Additional transform, sticky OOM,
  extension-order and zstd tests are being validated; phase 2 is not checked off.
- Existing zstd encoding uses a global eight-slot C context cache (~3.5 MiB each)
  and its default streaming window exceeds the 256 KiB decoder cap. Tests must
  distinguish accepted windows from intentional fail-open of oversized windows;
  include C codec retention in deployment measurements.

### 2026-09-17 — phase 3 formats and transport integrated

- Phase 2's policy path is integrated, including sticky swallowed-OOM detection,
  transform/drop rollback, gzip/zstd round trips, one-time pre-transform extension
  delivery and reload under socket traffic. Native Debug and ReleaseSafe passed
  701 tests with one existing skip before phase-3 work; final broad checks remain.
- `Routes.zig` reuses the existing pure service tables without allocating a hash
  map for six services. `--distribution` selects edge/datadog/otlp/prometheus;
  routing excludes query bytes and uses parsed path for absolute request targets.
- `--config` and TERO environment loading use unchanged zonfig and ProxyConfig.
  `logs_url`/`metrics_url` select separate origins; explicit CLI values win.
  Root composition maps provider configs and S3 resolver/sink/flush tasks. HTTP
  provider shutdown/final sync still needs bounded lifecycle integration; this
  is NOT checked off as complete.
- `Origin.zig` validates HTTP(S) authorities and resolves DNS in a cancellable
  task under the exchange deadline. It tries addresses before sending HTTP;
  no request replay occurs. `UpstreamLane.zig` reserves one stable TLS/HTTP
  connection per worker; stale/dirty idle sockets are evicted before reuse.
  Authenticated TLS verifies CA and hostname and flushes both plaintext and
  underlying ciphertext buffers. Real socket tests prove localhost DNS,
  certificate success and hostname rejection (16/16, integration2 log).
- Nested Datadog metrics/OTLP JSON/protobuf run inside bounded scratch. Top-level
  unknown OTLP envelope fields are restored after transformation; no second
  policy evaluation occurs. Nested unknown schema fields still need a lossless
  strategy or explicit conservative bypass before claiming complete parity.
- Finite Prometheus filtering preserves full metadata lines and passes overlong
  lines intact, fixing the old silent truncation behavior. HELP/TYPE are retained
  even if every sample in a family is dropped. Unlimited scrape transport is
  still outstanding; zero policy caps currently do NOT make response storage
  unlimited. Do not claim phase 3 done or use this as production cutover.
- Admin policy rendering, v2 counters and optional Datadog record taps are being
  wired and tested. Full metrics-name/OTLP tap parity remains to verify.
- Latest full green before admin additions: 708 passed, one skip (709 total),
  Debug, plus v2 executable (`/tmp/edge-v2-phase3-envelope2.log`). This is a
  checkpoint, not acceptance of untested later edits.
