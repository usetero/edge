"""A15: bytes that are not HTTP, such as a TLS hello on the plaintext port."""

from harness import MatrixCase


class GarbageRequest(MatrixCase):
    SLOW = True

    def test_a_complete_but_invalid_head_is_rejected(self):
        with self.raw(timeout=30) as client:
            client.send(b"\x16\x03\x01\x02\x00 not a request line\r\nAlso: not a header\r\n\r\n")
            answer = client.read_response()

        self.assertLess(answer.seconds, 25, "an invalid head must be rejected at once")
        if answer.status is not None:
            self.assertEqual(answer.status, 400, repr(answer))

    def test_an_incomplete_head_is_bounded_by_the_deadline(self):
        with self.raw(timeout=60) as client:
            client.send(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc")
            answer = client.read_response()

        # Nothing here completes a head, so the deadline is the only bound.
        self.assertLess(answer.seconds, 45, "garbage held the slot past the deadline")
