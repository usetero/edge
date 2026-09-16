"""B03: the intake is slow but healthy. The batch must still land."""

from harness import MatrixCase


class IntakeSlow(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    EXPECT_LOGS = ["request.slow"]
    FORBID_LOGS = ["request.failed", "upstream.timed.out"]
    def test_slow_intake_still_succeeds_and_is_logged(self):
        self.intake.arm("slow", arg=6000, count=1)
        response = self.post_logs(timeout=60)

        self.assert_status(response, 202)
        self.assert_logged("request.slow", "a six second request must leave a record")
