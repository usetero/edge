"""B11: the intake declares more response body than it sends.

The edge has already committed a status by then, so the only honest signal is
a truncated body plus a log line. What must not happen is a clean 202 with a
silent loss.
"""

import requests

from harness import MatrixCase


class TruncatedResponse(MatrixCase):
    def test_a_truncated_relay_is_visible(self):
        self.intake.arm("truncate", count=1)
        try:
            response = self.post_logs(timeout=60)
            status = response.status_code
            body_read = True
        except requests.exceptions.RequestException:
            status, body_read = None, False

        if body_read and status == 202:
            self.fail("a truncated intake response was reported as success")
        self.assert_logged("upstream")
