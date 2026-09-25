"""A51: valid compressed bodies with framing the edge must not lose.

- Two gzip members in one body (RFC 1952). The decoded batch is both members
  in order, so the policy must see the records of both, and none may be lost.
- Two zstd frames in one body. Both frames carry records, and the policy must
  see all of them.
- A zstd frame with no declared size whose window is above the cap. Decoding
  it would cost more memory than the edge allows, so it fails open.
"""

import gzip
import json

from harness import MatrixCase
from tests.test_a44_abandoned_gzip_body import POLICIES


def zstd(raw: bytes):
    try:
        import zstandard
    except ImportError:
        return None
    return zstandard.ZstdCompressor().compress(raw)


def records(level: str, count: int, tag: str) -> list:
    return [{"message": "%s %s record %d" % (level, tag, i), "ddsource": "matrix"} for i in range(count)]


class CompressedFraming(MatrixCase):
    EDGE_POLICIES = POLICIES

    def forwarded(self, body: bytes, encoding: str) -> bytes:
        self.intake.capture_start("a51")
        response = self.post_raw_body(body, headers={"Content-Encoding": encoding}, timeout=30)
        bodies = self.intake.capture_stop()
        self.assert_status(response, 202, "a valid %s body must pass" % encoding)
        self.assertEqual(len(bodies), 1, "expected one forwarded batch")
        return bodies[0]

    def test_two_gzip_members_are_both_filtered(self):
        # The members split one JSON array, as a streaming gzip writer that
        # flushes a member per chunk would.
        text = json.dumps(records("INFO", 5, "first") + records("DEBUG", 3, "second") + records("INFO", 5, "second"))
        half = len(text) // 2
        body = gzip.compress(text[:half].encode()) + gzip.compress(text[half:].encode())
        sent = gzip.decompress(self.forwarded(body, "gzip"))
        self.assertIn(b"INFO first record 4", sent)
        self.assertIn(b"INFO second record 4", sent, "the second member was lost")
        self.assertNotIn(b"DEBUG", sent, "the policy did not run on the second member")

    def test_two_zstd_frames_are_both_filtered(self):
        a = zstd(json.dumps(records("DEBUG", 3, "first") + records("INFO", 3, "first")).encode())
        if a is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        b = zstd(json.dumps(records("INFO", 3, "second")).encode())
        sent = self.forwarded(a + b, "zstd")
        import zstandard

        text = zstandard.ZstdDecompressor().decompressobj().decompress(sent)
        self.assertIn(b"INFO first record", text)
        self.assertNotIn(b"DEBUG", text, "the policy did not run on the first frame")

    def test_a_zstd_window_above_the_cap_fails_open(self):
        try:
            import zstandard
        except ImportError:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        # The frame declares an 8 MiB window and no content size, so libzstd
        # must hold the whole window. The edge caps it at 1 MiB by default.
        raw = json.dumps(records("DEBUG", 50, "wide") + records("INFO", 50, "wide")).encode()
        # A streaming compressor does not know the size, so it keeps the full
        # window. The one-shot API shrinks the window to fit the input.
        params = zstandard.ZstdCompressionParameters.from_level(3, window_log=23)
        stream = zstandard.ZstdCompressor(compression_params=params).compressobj()
        body = stream.compress(raw) + stream.flush()
        self.assertEqual(zstandard.get_frame_parameters(body).window_size, 8 << 20)
        self.assertEqual(self.forwarded(body, "zstd"), body)
        self.assert_logged("policy.failed.open")
