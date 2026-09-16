"""B04: the intake closes mid-request.

A log batch is replayable, so the edge owes the sender a retry rather than an
error.
"""

from harness import MatrixCase


class CloseEarly(MatrixCase):
    EXPECT_METRICS = {"edge_upstream_retries_total": 1, 'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    EXPECT_LOGS = ["upstream.retried"]
    def test_a_dropped_intake_connection_is_retried(self):
        self.intake.arm("close_early", count=1)
        response = self.post_logs(timeout=60)

        self.assert_status(response, 202, "a replayable batch must survive one dropped connection")
        self.assertGreaterEqual(self.metric_delta("edge_upstream_retries_total"), 1)
        self.assertGreaterEqual(self.intake.faults_applied(), 1, "the fault never fired")
