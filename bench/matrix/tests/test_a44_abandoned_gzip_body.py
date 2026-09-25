"""A44: a sender gives up partway through a gzip batch, with policies loaded.

The body is short of its
`Content-Length`, the sender half-closes, and the edge decoded the partial
gzip stream as a whole batch. The decoder in Zig 0.16.0 then reached
`unreachable`, which is undefined behaviour in a ReleaseFast build.

A partial batch must never reach the intake, and must never get a 2xx. If the
sender still reads, the answer must be one the agent retries: a drop-class
status discards a batch the sender can still send in full.
"""

import gzip

from harness import MatrixCase
from harness.agent import drops_payload

POLICIES = {
    "policies": [
        {
            "id": "drop-debug",
            "name": "drop-debug",
            "log": {"match": [{"log_field": "body", "regex": "^DEBUG"}], "keep": "none"},
        }
    ]
}


class AbandonedGzipBody(MatrixCase):
    EDGE_POLICIES = POLICIES
    # The metrics carry only the status class, so the invariant reads any
    # retryable 4xx as a drop. The case checks each status itself.
    EXPECT_PERMANENT_DROP = True
    FORBID_LOGS = ["upstream", "policy.failed.open"]

    def assert_abandoned(self, answer, why: str) -> None:
        if answer is None or answer.status is None:
            return
        self.assertFalse(200 <= answer.status < 300, "%s: answered %r" % (why, answer))
        self.assertFalse(drops_payload(answer.status), "%s: answered %r" % (why, answer))

    def test_a_partial_gzip_batch_is_never_decoded_or_forwarded(self):
        body = gzip.compress(self.log_batch(20_000, level="DEBUG"), 1)
        self.assertLess(len(body), 64 * 1024, "the case needs the resident body path")
        # Inside the gzip header, just past it, early in the first block, the
        # middle, and short by the trailer only.
        for cut in (5, 10, 19, 40, len(body) // 2, len(body) - 1):
            answer = self.abandon(body, cut, extra="Content-Encoding: gzip")
            self.assert_abandoned(answer, "cut at %d of %d" % (cut, len(body)))
            self.assertTrue(self.edge.alive(), "the edge died at cut %d:\n%s" % (cut, self.edge.logs()))

        self.assertEqual(
            self.intake.requests_seen() - self.baseline_intake,
            0,
            "a partial batch reached the intake",
        )

    def test_a_sender_that_closes_mid_body_leaves_the_edge_up(self):
        body = gzip.compress(self.log_batch(40_000, level="DEBUG"), 1)
        for cut in (19, 64, 512, len(body) // 3):
            self.abandon(body, cut, extra="Content-Encoding: gzip", half_close=False)
        self.assertEqual(self.health().status_code, 200)
        self.assertEqual(self.intake.requests_seen() - self.baseline_intake, 0)
