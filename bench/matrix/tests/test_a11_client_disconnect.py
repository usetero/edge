"""A11: the sender vanishes mid-body.

Nothing to answer, but the slot must come back, the upstream connection must
not leak, and the partial body must not reach the intake.
"""

from harness import MatrixCase


class ClientDisconnect(MatrixCase):
    FORBID_LOGS = ["upstream.timed.out"]
    # The metrics carry only the status class, so the invariant reads the
    # retryable 408 as a drop. The case checks the intake instead.
    EXPECT_PERMANENT_DROP = True
    def test_disconnect_frees_the_slot(self):
        for _ in range(5):
            client = self.raw(timeout=10)
            client.send(self.head(body_len=4096))
            client.send(b'[{"message":"half')
            client.close()

        # The invariants in tearDown check that the edge still serves and that
        # no slot leaked.
        self.assertEqual(self.health().status_code, 200)
        self.assertEqual(
            self.intake.requests_seen() - self.baseline_intake,
            0,
            "a partial body reached the intake",
        )
