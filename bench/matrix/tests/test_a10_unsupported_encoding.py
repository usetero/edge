"""A10: an encoding we cannot decode must fail open, not drop the batch."""

from harness import MatrixCase


class UnsupportedEncoding(MatrixCase):
    def test_unknown_encoding_forwards_raw(self):
        response = self.post_raw_body(b'[{"message":"brotli"}]', headers={"Content-Encoding": "br"})
        self.assert_status(response, 202, "an unknown encoding must forward, not drop")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
