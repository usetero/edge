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
- [ ] Phase 1 — One vertical relay slice (**in progress — phase-1B foundations implemented; HTTP framing/relay next**).
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
- [ ] Quarantine process-exit behavior: the store reports `quarantined` from `deinit`;
  what the process owner does with retained allocations is a phase-1 runtime decision.

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
- [ ] Bind the formula to all real v2 layouts and config once phase 1 defines them.
  Request-table layouts and their startup ceiling are now bound (phase 1A).

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
- [ ] Bind connection tables, queues, worker stacks and runtime config to the same
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

- [ ] Write incremental request-head/body framing tests, including split boundaries,
  chunked trailers, ambiguous framing, Expect, and preserved pipelined bytes.
- [ ] Implement raw HTTP request ownership and bounded body admission.
- [ ] Connect upstream lanes and `UpstreamWatch` absolute deadlines to real exchanges.
- [ ] Relay response status/headers/body with bounded storage and backpressure.
- [ ] Test disconnects, slow clients, exhausted queues, silent/trickling upstreams,
  and response order over keep-alive connections.

### 1D. Composition, verification and measurement

- [ ] Add opt-in v2 composition root with juicy main, explicit I/O/allocators,
  validated config, health, and ordered shutdown.
- [ ] Decide quarantine lifecycle using the fixed dependency's tested guarantees.
- [ ] Add an end-to-end raw relay integration fixture and benchmark full relay.
- [ ] Run all tests, six distribution builds and lint; record memory/high-water data
  and platform limitations without declaring production cutover.

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

## Handoff

Latest review: all earlier policy-zig findings are resolved for the tested cases.
[POLICY-ZIG-REVIEW.md](POLICY-ZIG-REVIEW.md) contains the current sendable review.
Historical failing results in the work log above are not current blockers.

The user explicitly requested `.path = "../policy-zig"` until merge. Preserve
that local dependency selection; replace it with the reviewed immutable release
or commit after the user merges. The sibling checkout is being updated by its
implementing agent, so record its actual HEAD with final verification. Do not
edit policy-zig or zonfig as part of Edge work.

Phase 1A ownership and all standalone phase-1B components, including bounded
accept/handoff, are implemented. Next work: phase 1C HTTP framing and raw relay.
The combined runtime budget/config gate in 1A remains open. Admission deadlines and reserved health/fallback capacity must be wired
before serving traffic. Expand any newly started mechanism into minor tasks
before coding it. No v2 runtime is serving requests yet.

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
  FIFO admission is implemented; the serving worker/reactor loop is outstanding.
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
  runtime still needs accept/drain budgets, fd demand and backoff config binding.
- `Connections` owns all registration changes when wrapping Readiness. Use its
  embedded poller only to wait/resolve/wake; direct adoption/close/interest mutation
  would bypass connection and request ownership. Revalidate both token and current
  connection state before acting on a batched event.
- A parsed head always calls `enqueue`; grant only through `admitNext`, bounded by
  the reactor turn budget. Retry after queue acknowledgement AND response-storage
  release/canceled admission. Available queue credit does not imply request space.
  Copy initialized head/body bytes to RequestTable before dispatch; worker jobs
  cannot reference reusable connection heads. HTTP framing/length tracking is not
  implemented by this ownership layer.
- `Connections.complete` consumes acknowledgement and returns the live connection
  token or null for a detached request. Null may free the request bytes immediately.
  A live response is framed before `responseReady` arms writes. Calling complete
  again after a later interest failure is a duplicate acknowledgement bug.
- `closeAll` unlinks waiters, returns unpublished reservations and detaches clients;
  it does not drain jobs. Keep Connections/RequestTable/WorkChannel alive through
  all late completions, then join wake producers and deinit.
- Stop/join wake producers before poller destruction. Native waits are canceled
  through explicit wake/shutdown state, not `Io` cancellation. Use finite wait
  deadlines to recover from wake failure; the composition root must choose the
  maximum fallback interval and report errors. No runtime does this yet.

Dependency and validation limits:

- The plain-arena fault sweep and direct `checkAllAllocationFailures` cleanup run
  by default. The alignment adapter and old opt-in skip have been removed.
- `PolicyStore` still permanently fences a failed publication and conservatively
  retains that registry until process exit. Tested cleanup is now safe for the
  fixtures, but failed updates are not transactional; process-owner recovery is
  still a composition decision. No non-failing allocator workaround is needed.
- The dependency's regex-engine OOM exclusion and native C allocation accounting
  remain outside the verified fault fixture. Do not claim universal cleanup safety.
- Linux x86_64 still needs a native runner. A controlled DNS deadline probe still
  lacks local injection. The new isolated readiness/queue Linux aarch64 coverage is recorded above;
  the older full-distribution Linux run predates current dependency changes.
- Full runtime budget binding, codec/hyperscan scratch measurement and Lambda
  lifecycle remain with the phases defining those layouts and execution paths.

`ProviderSet` and `PolicyStore` still do not replace `Loader`. Keep stores and
callback contexts stable, join providers before teardown, and honor read guards.
Disarm `UpstreamWatch` slots before the owning forwarder closes a stream.
