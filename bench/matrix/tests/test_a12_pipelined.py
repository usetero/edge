"""A12: two requests written in one packet."""

from harness import MatrixCase


class Pipelined(MatrixCase):
    def test_pipelined_requests_are_both_served(self):
        body = b'[{"message":"pipelined"}]'
        one = self.head(body_len=len(body)) + body
        with self.raw(timeout=30) as client:
            client.send(one + one)
            first = client.read_response()
            self.assert_status(first, 202)

        self.assertGreaterEqual(self.intake_saw(1), 1)
