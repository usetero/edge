"""B10: the intake resets the connection instead of closing it."""

from harness import MatrixCase


class IntakeReset(MatrixCase):
    EXPECT_METRICS = {"edge_upstream_retries_total": 1}
    EXPECT_LOGS = ["upstream.retried"]
    def test_a_reset_intake_is_retried(self):
        self.intake.arm("reset", count=1)
        response = self.post_logs(timeout=60)

        self.assert_status(response, 202, "a reset is a transport failure, so retry it")
        self.assertGreaterEqual(self.metric_delta("edge_upstream_retries_total"), 1)
