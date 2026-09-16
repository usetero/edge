"""A06: a well-formed chunked request, which agents send when streaming."""

from harness import MatrixCase


class ChunkedBody(MatrixCase):
    def test_chunked_body_reaches_the_intake(self):
        payload = b'[{"message":"chunked","ddsource":"matrix"}]'
        framed = b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload)
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(framed)
            answer = client.read_response()

        self.assert_status(answer, 202)
        self.assertGreaterEqual(self.intake_saw(1), 1, "the intake never saw the batch")
