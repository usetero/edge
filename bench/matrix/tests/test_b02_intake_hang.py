"""B02: the intake accepts the body and never answers.

The upstream watchdog owns this one. Without it the handler is held for as
long as the intake feels like.
"""

from harness import MatrixCase


class IntakeHang(MatrixCase):
    EXPECT_METRICS = {"edge_upstream_timeouts_total": 1}
    EXPECT_LOGS = ["upstream.timed.out", "request.failed", "request.slow"]
    SLOW = True

    def test_a_hung_intake_becomes_a_gateway_timeout(self):
        self.intake.arm("hang", count=1)
        response = self.post_logs(timeout=120)

        self.assert_status(response, 504, "a hung intake must surface as 504")
        self.assertGreaterEqual(self.metric_delta("edge_upstream_timeouts_total"), 1)
        self.assert_logged("upstream.timed.out")
