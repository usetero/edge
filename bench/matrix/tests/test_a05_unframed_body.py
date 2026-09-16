"""A05: POST with neither Content-Length nor chunked framing."""

from harness import MatrixCase


class UnframedBody(MatrixCase):
    def test_unframed_post_gets_an_answer(self):
        with self.raw(timeout=40) as client:
            client.send(b"POST /api/v2/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        b"Content-Type: application/json\r\n\r\n")
            answer = client.read_response()

        # Either a status or a close is acceptable. A hang is not.
        self.assertLess(answer.seconds, 35, "an unframed body must not hang")
        if answer.status is not None:
            self.assertIn(answer.status, (202, 400, 411), repr(answer))
