"""A15: bytes that are not HTTP, such as a TLS hello on the plaintext port."""

from harness import MatrixCase


class GarbageRequest(MatrixCase):
    def test_garbage_is_rejected(self):
        with self.raw(timeout=30) as client:
            client.send(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03garbage")
            answer = client.read_response()

        self.assertLess(answer.seconds, 25, "garbage must not hang the connection")
        if answer.status is not None:
            self.assertEqual(answer.status, 400, repr(answer))
