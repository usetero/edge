"""A14: more forward headers than the edge will carry.

The cap is ours, and the sender is at fault, so the status must be a 4xx.
A 5xx would send an agent into a retry loop against a request that can never
succeed.
"""

from harness import MatrixCase


class TooManyHeaders(MatrixCase):
    def test_header_flood_is_a_client_error(self):
        headers = {"X-Matrix-%d" % i: "v" for i in range(80)}
        response = self.post_logs(headers=headers)
        self.assertEqual(
            response.status_code // 100,
            4,
            "too many headers is the sender's fault, got %d" % response.status_code,
        )
