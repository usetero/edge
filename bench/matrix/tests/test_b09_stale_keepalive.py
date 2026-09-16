"""B09: the pooled intake connection is already dead.

The intake answers, then closes at once. The next batch picks the pooled
connection, finds it gone, and must recover on a fresh dial. Log intake clients
do not retry, so a 5xx here is data loss.
"""

from harness import MatrixCase


class StaleKeepalive(MatrixCase):
    def test_a_dead_pooled_connection_is_replaced(self):
        self.assert_status(self.post_logs(timeout=30), 202)
        self.intake.arm("stale_keepalive", count=1)
        self.assert_status(self.post_logs(timeout=30), 202)
        self.intake.arm("none")
        self.assert_status(self.post_logs(timeout=30), 202)
