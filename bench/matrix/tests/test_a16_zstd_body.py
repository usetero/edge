"""A16: a zstd batch, which is what a current Datadog agent sends.

The codec is supported inside the pipeline, so this checks the transport: the
frontend must accept the head and hand the body over for decoding.
"""

from harness import MatrixCase

def _compress(raw: bytes):
    try:
        from compression import zstd  # python 3.14 and later

        return zstd.compress(raw)
    except ImportError:
        pass
    try:
        import zstandard

        return zstandard.ZstdCompressor().compress(raw)
    except ImportError:
        return None


class ZstdBody(MatrixCase):
    def test_zstd_batch_is_accepted(self):
        payload = _compress(b'[{"message":"zstd batch","ddsource":"matrix"}]')
        if payload is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        response = self.post_raw_body(payload, headers={"Content-Encoding": "zstd"})
        self.assert_status(response, 202, "a zstd batch must be accepted")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
