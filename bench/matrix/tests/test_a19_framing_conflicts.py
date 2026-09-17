"""A19: framing the edge must refuse.

Content-Length together with chunked, two different lengths, a length that is
not a number. This is the request-smuggling surface: whatever status we pick,
the request must not reach the intake, and the two frontends must agree.
"""

from harness import MatrixCase

CONFLICTS = {
    "length_and_chunked": b"Content-Length: 18\r\nTransfer-Encoding: chunked",
    "two_lengths": b"Content-Length: 18\r\nContent-Length: 7",
    "negative_length": b"Content-Length: -1",
    "not_a_number": b"Content-Length: abc",
    "twenty_digits": b"Content-Length: 99999999999999999999",
}


class FramingConflicts(MatrixCase):
    EXPECT_PERMANENT_DROP = True
    def test_conflicting_framing_never_reaches_the_intake(self):
        body = b'[{"message":"x"}]'
        for name, framing in CONFLICTS.items():
            with self.subTest(framing=name):
                with self.raw(timeout=20) as client:
                    client.send(
                        b"POST /api/v2/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        b"Content-Type: application/json\r\n" + framing + b"\r\n\r\n" + body
                    )
                    answer = client.read_response()
                if answer.status is not None:
                    self.assertEqual(
                        answer.status // 100,
                        4,
                        "%s owes a client error, got %s" % (name, answer.status),
                    )
        self.assertEqual(self.intake.requests_seen(), 0, "ambiguous framing reached the intake")
