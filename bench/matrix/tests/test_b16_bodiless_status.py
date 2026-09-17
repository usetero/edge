"""B16: the intake answers 204, which carries no body.

A relay that re-frames a 204 as chunked breaks the protocol, and some clients
reject it outright.
"""

from harness import MatrixCase


class BodilessStatus(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_204_stays_bodiless(self):
        self.intake.arm("bodiless", count=1)
        response = self.post_logs(timeout=30)

        self.assert_status(response, 204, "the status must be relayed")
        self.assertEqual(response.content, b"", "a 204 must carry no body")
        self.assertNotIn(
            "chunked",
            response.headers.get("transfer-encoding", "").lower(),
            "a 204 was re-framed as chunked",
        )
