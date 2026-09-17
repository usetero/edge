"""A17: a head larger than the receive buffer.

One enormous header value, and many merely large ones. The edge owes a prompt
client error and a closed connection, not a 502 that blames the intake and not
a hang.
"""

from harness import MatrixCase


class OversizeHead(MatrixCase):
    EXPECT_PERMANENT_DROP = True
    FORBID_LOGS = ["upstream"]

    def test_one_enormous_header_is_refused(self):
        with self.raw(timeout=30) as client:
            client.send(
                b"POST /api/v2/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                b"X-Huge: " + b"a" * (24 * 1024) + b"\r\n\r\n"
            )
            answer = client.read_response()

        self.assertLess(answer.seconds, 10, "an oversize head must be refused at once")
        if answer.status is not None:
            self.assertIn(answer.status, (400, 431), repr(answer))
        self.assertEqual(self.intake.requests_seen(), 0, "an oversize head reached the intake")

    def test_many_large_headers_are_refused(self):
        headers = b"".join(b"X-Pad-%d: %s\r\n" % (i, b"b" * 1024) for i in range(40))
        with self.raw(timeout=30) as client:
            client.send(b"POST /api/v2/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n" + headers + b"\r\n")
            answer = client.read_response()

        self.assertLess(answer.seconds, 10)
        self.assertEqual(self.intake.requests_seen(), 0)
