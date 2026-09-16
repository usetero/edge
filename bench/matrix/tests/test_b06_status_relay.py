"""B06: real intake statuses must arrive unchanged."""

from harness import MatrixCase


class StatusRelay(MatrixCase):
    def _relay(self, status):
        self.intake.arm("status", arg=status, count=1)
        response = self.post_logs(timeout=60)
        self.assert_status(response, status, "status %d was not relayed" % status)

    def test_rate_limit_is_relayed(self):
        self._relay(429)

    def test_server_error_is_relayed(self):
        self._relay(500)

    def test_unavailable_is_relayed(self):
        self._relay(503)
