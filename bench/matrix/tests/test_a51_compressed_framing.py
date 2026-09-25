"""A51: valid compressed bodies with framing the edge must not lose.

- Two gzip members in one body. std flate stops after the first member, so
  the edge must not filter only the first and drop the second. It fails open
  and forwards the body as sent.
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

    def test_two_gzip_members_are_forwarded_as_sent(self):
        first = gzip.compress(json.dumps(records("INFO", 5, "first")).encode())
        second = gzip.compress(json.dumps(records("INFO", 5, "second")).encode())
        body = first + second
        self.assertEqual(self.forwarded(body, "gzip"), body, "a member was lost or re-encoded")
        self.assert_logged("policy.failed.open")

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
        params = zstandard.ZstdCompressionParameters.from_level(3, window_log=23)
        body = zstandard.ZstdCompressor(compression_params=params, write_content_size=False).compress(raw)
        self.assertEqual(self.forwarded(body, "zstd"), body)
        self.assert_logged("policy.failed.open")
