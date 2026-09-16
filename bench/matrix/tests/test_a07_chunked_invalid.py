"""A07: a chunk size that is not a number.

The head is complete and the framing is broken, so the edge can answer at
once. Waiting for the request deadline holds a connection slot for 30 s on
input we have already proven bad.
"""

from harness import MatrixCase


class ChunkedInvalid(MatrixCase):
    SLOW = True
    DEFECTS = {"stdio": "waits for the request deadline instead of rejecting the bad chunk"}

    def test_invalid_chunk_is_rejected_promptly(self):
        with self.raw(timeout=60) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(b"zzzz\r\ngarbage\r\n")
            answer = client.read_response()

        self.assertLess(answer.seconds, 5, "broken framing should not hold a slot")
        if answer.status is not None:
            self.assertEqual(answer.status // 100, 4, repr(answer))
