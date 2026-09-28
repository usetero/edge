# httpz transport suitability for Edge v2

Reviewed 2026-09-15, following checkpoint `0a72fbc`. Scope: the dependency
resolved by this checkout and Zig 0.16.0, not all versions of httpz.

## Decision

Continue phase 1C with Edge-owned inbound readiness, admission and HTTP/1
framing. Keep the existing httpz frontend as the production default through
the proposal's verification and cutover gates.

The current httpz hooks do not jointly provide admission before body allocation
for both supported body framings, application-controlled `100 Continue`, and
request storage that can survive asynchronous processing and forwarding without
occupying a handler thread. Those are requirements of the proposed ownership
model. This is **not evidence that v2 is faster**. httpz already uses epoll/kqueue
and a handler pool; replacing it does not remove a per-idle-connection thread.

The earlier description of httpz as fully buffering requests needs qualification:
that describes our current integration and httpz's chunked path. Its public
`lazy_read_size` hook supports dispatch before a Content-Length body is complete.

## Audited dependency and evidence

`build.zig.zon` selects httpz commit
`9b14af98fde5e98abb9a8376fe02b42003e835bf`, package hash
`httpz-0.0.0-PNVzrMgTCQDhzfBLRRebTx9LU056Ph2erdN9-42rFbhj`.
Source references below are relative to that package's `src/` directory under
`zig-pkg/`. API discovery used `zigdoc`; the implementation was read locally.
No dependency sources were edited.

The executable probes are in [httpz_contract.zig](src/v2/httpz_contract.zig),
registered in the ordinary Edge test suite. They use `httpz.testing` to construct
a connection with a real socket pair and feed `Request.State.parse` directly.
The disown probe supplies a real OS readiness registration. These are boundary
fixtures, **not** an end-to-end httpz server or concurrency test. The actual
dispatch and cleanup scheduling is established by the source call path below.

| Requirement | Observed behavior in this pin | Consequence |
| --- | --- | --- |
| Head-only Content-Length dispatch | `lazy_read_size = 0` returns ready with a static read-ahead prefix and `unread_body` | Useful existing hook; application must reserve and enforce the body limit |
| Lazy body size enforcement | A 1024-byte CL passes a configured 64-byte limit when lazy reading is enabled | Do not enable this hook without application size checks |
| Head-only chunked dispatch | Header-only parse returns false and creates decoded-body and raw-input buffers even with lazy reads | Handler admission is too late for v2's body-storage reservation |
| Continue after admission | Parser writes `100 Continue` before application dispatch; the fixture sees it even before `BodyTooBig` | A head admission/Expect hook would need a dependency change |
| Retained async request storage | Handler return is followed by unconditional request cleanup, including disowned connections | Capturing request/response pointers for a later completion is invalid |
| Socket takeover | `Response.disown()` removes readiness registration and leaves the socket open | Supports raw stream takeover; does not retain request storage or HTTP keep-alive management |
| Preserve following request bytes | A CL=3 body and the next request head in one read produce `InvalidContentLength` | V2 needs its own tested read-ahead contract or changes to this parser |
| Absolute body deadline | Lazy `Request.reader(timeout_ms)` switches to blocking IO and configures `SO_RCVTIMEO` | Per-read socket timeout alone does not establish an absolute request deadline |

### Call paths

- `config.zig:72`: request config exposes `lazy_read_size`, `max_body_size`,
  header limits and buffer size. No separate admission or retained-completion
  hook was found in the public server/request/response APIs.
- `request.zig:1050` (`prepareForBody`): CL/TE validation and eager Continue;
  CL limit is conditional on lazy reads being disabled. The lazy branch exposes
  the already-read prefix and missing length. `read > cl` rejects extra bytes.
- `request.zig:1146` (`prepareForChunkedBody`): no lazy-read branch; tries the body
  pool, falls back to the request arena, and allocates a separate raw buffer.
  Further chunk reads accumulate the decoded body until the terminal framing.
- `request.zig:185` (`Request.reader`): reader points into the request's
  `unread_body` field. It cannot safely outlive that request object.
- `worker.zig:619` onward: parse must report ready before a handler job is
  scheduled. A false parse result returns to request readiness.
- `httpz.zig:521` (`handleRequest`): request and response objects are stack locals;
  handler execution is synchronous. Afterward it writes the response and drains
  unread request bytes when retaining keep-alive.
- `worker.zig:849` (`processHTTPData`): calls `handleRequest`, then `requestDone`
  before acting on the handover state, including `.disown`.
- `response.zig:80` and `worker.zig:1785`: disown marks the response written and
  transfers socket responsibility by removing its native registration.
- `worker.zig:1815` (`requestDone`): resets parser/response state and request
  arena. The fixture verifies that cleanup releases the arena while the socket
  still carries data; it never dereferences freed request/response pointers.

The test helper uses a two-entry, 256-byte body pool internally. The chunked
fixture proves pre-dispatch allocation/storage behavior, not production pool
occupancy or an RSS measurement. The coalesced-input finding is restricted to
the exact tested Content-Length case; it is not a claim about every keep-alive
exchange.

## Alternatives and tradeoffs

1. **Keep httpz for v2 and use lazy CL reads.** Least HTTP maintenance. Safe
   ownership is possible by keeping the handler alive through downstream work
   and response completion. That occupies a handler lane during queue/upstream
   waits, and chunked requests still buffer before application admission. It
   requires revising the proposed scheduling and memory contract. Existing pool
   knobs and overall connection limits still give useful bounds; httpz is not
   inherently incapable of controlled resource use.
2. **Extend a fork of httpz.** Add header admission/Continue decisions, chunked
   pause/resume, retained request completion with cancellation/shutdown, and
   preservation of following request bytes. This could reuse more of its HTTP
   implementation, but transfers significant parser and lifecycle maintenance
   to Edge. No such patch was made or requested as part of this audit.
3. **Use Edge's reactor and bounded HTTP state machines (chosen).** Fits the
   existing connection/request/queue ownership directly. Costs: protocol
   conformance work, security-sensitive framing, cross-platform IO maintenance,
   and benchmarks before claiming a benefit. A disown-based bridge would still
   need framing for later requests and copies of borrowed header/read-ahead data,
   so it does not remove these obligations.

Use Zig std helpers when their contracts fit. `std.http.HeadParser` is a
nonallocating incremental delimiter scanner and can be reused; it accepts LF
delimiters too, so finding a boundary is not validation. Zig 0.16's
`std.http.Server.Request.Head.parse` rejects unknown Content-Encoding, which
conflicts with opaque fail-open proxying, and is not a drop-in v2 head validator.
Audit acceptance behavior before reusing either. Do not hide a permissive parser
behind a stricter-looking interface.

## Verification and next implementation

The desired chunked head-only dispatch assertion was run first and failed at
that assertion: 606 passed, one skipped, one failed (`/tmp/edge-v2-httpz-red.log`).
The committed-shape probe then records the observed buffering behavior; a green
characterization test does not mean that httpz satisfies v2's admission gate.
All five probes pass in Debug as part of 607 passing tests, one skipped.
Final validation and dependency HEAD are recorded in the implementation log.

The bounded `HeadScanner` is now implemented with six additional tests; it reuses
the std delimiter scanner and leaves validation to the next step. A malformed
LF-only probe returned a later boundary than expected, reinforcing that offsets
for invalid input cannot establish a forwarding boundary. CRLF split/alignment
tests cover the supported scanner contract. The combined suite now passes
613 tests with one skip in both Debug and ReleaseSafe.

Subsequent work implemented strict `RequestHead` validation, metadata offsets,
opaque encoding preservation and a pure admission/Expect decision. See
[IMPLEMENTATION-PROGRESS.md](IMPLEMENTATION-PROGRESS.md) for current verification
and outstanding work. Chunk decoding, header rewriting and actual relay remain
later tasks in 1C.
Keep phase 1 incomplete until a real vertical relay and its failure tests pass.
