"""B01: nothing is listening at the intake."""

from harness import MatrixCase


class ConnectionRefused(MatrixCase):
    def test_refused_dial_is_a_bad_gateway(self):
        self.intake.stop()  # the port is now dead
        response = self.post_logs()

        self.assertEqual(response.status_code // 100, 5, "a dead intake is our failure to report")
        self.assertEqual(response.status_code, 502, "got %d" % response.status_code)
        self.assert_logged("upstream")
        self.assertGreaterEqual(self.metric_delta("edge_upstream_retries_total"), 1,
                                "a failed dial must be retried once")
