"""B23: the intake reads the whole batch, then dies before answering.

The batch arrived, so the retry delivers it twice. That is at-least-once, and
it is a deliberate choice rather than an accident: this case pins it, and pins
that it stops at two.
"""

from harness import MatrixCase


class DuplicateDelivery(MatrixCase):
    def test_a_retry_after_a_silent_close_delivers_twice(self):
        self.intake.arm("read_then_close", count=1)
        response = self.post_logs(timeout=60)

        self.assert_status(response, 202, "the retry must succeed")
        seen = self.intake_saw(2)
        self.assertEqual(
            seen,
            2,
            "at-least-once means exactly two copies here, not %d" % seen,
        )
        self.assertGreaterEqual(self.metric_delta("edge_upstream_retries_total"), 1)
