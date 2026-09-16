"""A09: a body that claims gzip and is not."""

from harness import MatrixCase


class CorruptGzip(MatrixCase):
    def test_corrupt_gzip_is_rejected(self):
        response = self.post_raw_body(
            b"\x1f\x8b\x08\x00 not really gzip at all",
            headers={"Content-Encoding": "gzip"},
        )
        self.assertEqual(response.status_code // 100, 4, "a corrupt body is the sender's fault")
        self.assert_logged("request.failed")
