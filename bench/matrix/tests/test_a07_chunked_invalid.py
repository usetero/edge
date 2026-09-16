"""A07: a chunk size that is not a number."""

from harness import MatrixCase


class ChunkedInvalid(MatrixCase):
    def test_invalid_chunk_is_rejected(self):
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(b"zzzz\r\ngarbage\r\n")
            answer = client.read_response()

        self.assertLess(answer.seconds, 25, "a bad chunk must not hang")
        if answer.status is not None:
            self.assertEqual(answer.status // 100, 4, repr(answer))
