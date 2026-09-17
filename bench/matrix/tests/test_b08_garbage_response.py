"""B08: the intake answers with bytes that are not HTTP."""

from harness import MatrixCase


class GarbageResponse(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s5xx"}': 1}
    EXPECT_LOGS = ["request.failed", "upstream.connection.evicted"]
    def test_garbage_from_the_intake_is_a_bad_gateway(self):
        self.intake.arm("garbage", count=1)
        response = self.post_logs(timeout=60)

        self.assertEqual(response.status_code // 100, 5, "got %d" % response.status_code)
        self.assert_logged("upstream")
