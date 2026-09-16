"""A14: more headers than the edge will carry.

Two answers are defensible: forward every header, or refuse the request. What
is not defensible is accepting the request, dropping the headers above the cap
and answering 202, because the sender then believes an API key or a trace
header was forwarded when it was not.
"""

from harness import MatrixCase


class TooManyHeaders(MatrixCase):
    EXPECT_LOGS = ["request.failed", "TooManyHeaders"]
    FORBID_LOGS = ["upstream"]

    def test_a_header_flood_is_never_silently_truncated(self):
        headers = {"X-Matrix-%d" % i: "v" for i in range(80)}
        response = self.post_logs(headers=headers)
        self.assertEqual(
            response.status_code // 100,
            4,
            "headers above the cap must be refused, not dropped in silence "
            "(got %d)" % response.status_code,
        )
