"""A04: the sender never stops, and never finishes.

One byte at a time keeps a per-read timeout alive forever. Only a whole-request
deadline cuts this off, which is the deadline httpz does not have.
"""

from harness import MatrixCase


class SlowDripBody(MatrixCase):
    SLOW = True

    def test_a_dribbling_sender_is_cut_off(self):
        self.expect_difference("httpz", "SO_RCVTIMEO restarts on every read")
        body = b'[{"message":"' + b"x" * 30 + b'"}]'
        with self.raw(timeout=90) as client:
            client.send(self.head(body_len=len(body) + 200))
            client.drip(body, interval=1.0)
            answer = client.read_response()

        self.assert_status(answer, 408, "the request deadline must fire")
        self.assertLess(answer.seconds + 40, 90, "the deadline fired far too late")
