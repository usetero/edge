"""B17: the intake answers with more headers than the relay carries.

The mirror of a14. Dropping the excess in silence loses whatever the intake
was trying to say, and `Retry-After` on a 429 is the header agents act on.
"""

from harness import MatrixCase


class ResponseHeaderFlood(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_response_header_flood_is_relayed_or_refused(self):
        self.intake.arm("header_flood", arg=80, count=1)
        response = self.post_logs(timeout=30)

        relayed = sum(1 for name in response.headers if name.lower().startswith("x-flood-"))
        if response.status_code == 202:
            self.assertGreaterEqual(
                relayed,
                64,
                "the relay kept %d of 80 response headers and still answered 202" % relayed,
            )
        else:
            self.assertEqual(response.status_code // 100, 5, repr(response))
