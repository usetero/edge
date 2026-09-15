# Review of local policy-zig changes — latest result

No blocking findings remain for the ownership/alignment fixes reviewed here.
The original failures and both typed-value failures now pass their reproductions.

- Typed equality reserves list capacity before compiling owned bytes. A failure
  cannot strand the compiled value outside builder ownership.
- Hex decoding validates all nibbles before allocating. Invalid input returns null
  without allocating a decode buffer. Valid hex still produces the expected bytes.
- Builder and partial-finish cleanup, explicitly aligned Hyperscan temporary storage,
  and redaction-template defer ordering address the earlier findings.

Validation against the local checkout, Zig 0.16.0 / macOS arm64 / Debug:

- policy-zig's suite: **452/452 passed** at the reviewed snapshot.
- Original Edge probes: **83 fault points**, direct cleanup and plain-arena alignment passed.
- Typed-byte reproduction: **71 fault points**, direct cleanup passed.
- Hex reproduction: **65 fault points**, direct cleanup passed, including the
  separate malformed-hex test that previously leaked without any injected OOM.
- policy-zig lint and diff checks passed.

The regex-engine OOM exclusion remains an explicit limitation, not a new blocker
in the changes reviewed. These results do not prove arbitrary policy updates are
transactional or measure native C allocation behavior.

Edge now uses `.path = "../policy-zig"` at the user's request until merge. Its
normal tests include direct dependency cleanup and a plain-arena allocation sweep;
the former opt-in gates and alignment adapter have been removed. The library
source itself was not modified by this review or by Edge implementation work.

Evidence: `/tmp/policy-review3-tests.log`, `/tmp/edge-policy-review3-original.log`,
`/tmp/edge-policy-review3-bytes.log`, `/tmp/edge-policy-review3-hex.log` and
`/tmp/policy-review3.patch`. Earlier findings are preserved in the implementation
progress work log; their blocker status is superseded by this review.
