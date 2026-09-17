"""B14: the intake answers with `Connection: close`.

A connection the intake said it would close must not be pooled. If it is, the
next batch finds a dead socket and pays a retry for nothing.
"""

from harness import MatrixCase


class KeepAliveOff(MatrixCase):
    FORBID_LOGS = ["upstream.retried"]

    def test_a_closed_connection_is_not_pooled(self):
        self.intake.arm("keep_alive_off", count=1)
        self.assert_status(self.post_logs(timeout=30), 202)
        # The next batch must dial fresh and succeed without a retry line.
        self.assert_status(self.post_logs(timeout=30), 202)
        self.assertEqual(
            self.metric_delta("edge_upstream_retries_total"),
            0,
            "the edge pooled a connection the intake said it would close",
        )
