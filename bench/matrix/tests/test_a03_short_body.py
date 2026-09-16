"""A03: the head declares more body than the sender delivers."""

from harness import MatrixCase


class ShortBody(MatrixCase):
    SLOW = True
    DEFECTS = {"httpz": "closes the connection with no status"}

    def test_short_body_is_answered(self):
        with self.raw(timeout=60) as client:
            client.send(self.head(body_len=500))
            client.send(b'[{"message":"only the start')
            answer = client.read_response()

        self.assert_status(answer, 408, "a stalled body must be answered")
