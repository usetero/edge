"""B24: every request fails the same way, for a hundred requests.

An intake outage makes every batch retry. The cost must stay bounded: at most
one retry each, no descriptor growth from the pool-less retry client, and
health unaffected while it happens.
"""

from harness import MatrixCase


class RetryAmplification(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_retries_stay_bounded_under_a_total_outage(self):
        self.intake.arm("close_early")  # every request, no count
        for _ in range(100):
            try:
                self.post_logs(timeout=30)
            except Exception:
                pass

        attempts = self.metric_delta("edge_upstream_attempts_total")
        self.assertLessEqual(attempts, 220, "more than two attempts per request: %s" % attempts)
        self.assertEqual(self.health().status_code, 200, "health suffered during the outage")
