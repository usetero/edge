"""B11: the intake declares more response body than it sends.

The edge has committed a status by then, so the body truncates. What the
sender must never get is a clean success for a batch the intake never
confirmed: an agent that reads 202 deletes its copy.
"""

import requests

from harness import MatrixCase


class TruncatedResponse(MatrixCase):
    EXPECT_LOGS_FOR = {"stdio": ["response.truncated"]}
    DEFECTS = {
        "httpz": "answers 202 for a truncated intake response",
        "stdio": "answers 202 for a truncated intake response",
    }

    def test_a_truncated_relay_is_never_reported_as_success(self):
        self.intake.arm("truncate", count=1)
        try:
            response = self.post_logs(timeout=60)
            status = response.status_code
        except requests.exceptions.RequestException:
            status = None  # a broken relay is an honest answer

        if status == 202:
            self.fail("a truncated intake response was reported as success")
        self.assert_logged("upstream")
