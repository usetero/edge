"""A47: a full-length compressed batch with a few corrupt bytes, policies loaded.

The framing is complete and the length is right. Only the compressed bytes are
wrong. The fixtures come from a fuzz run against the std decoders:

- `corrupt_full_length.gz` has 11 changed bytes. The corruption makes the
  deflate data ask for more bits than the stream holds, so the Zig 0.16.0
  gzip decoder reaches the same end-of-input fault as a46.
- `corrupt_full_length.zst` has two changed bytes. The Zig 0.16.0 zstd
  decoder reaches `unreachable` in `decodeLiterals`.

The edge must stay up and fail open: forward the bytes as sent, and let the
intake judge them.
"""

import os

from harness import MatrixCase
from tests.test_a46_truncated_compressed_stream import POLICIES

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def fixture(name: str) -> bytes:
    with open(os.path.join(FIXTURES, name), "rb") as handle:
        return handle.read()


class CorruptCompressedBody(MatrixCase):
    EDGE_POLICIES = POLICIES
    EXPECT_LOGS = ["policy.failed.open"]
    FORBID_LOGS = ["request.failed"]

    def send(self, name: str, encoding: str) -> None:
        response = self.post_raw_body(fixture(name), headers={"Content-Encoding": encoding}, timeout=30)
        self.assertTrue(self.edge.alive(), "the edge died on %s:\n%s" % (name, self.edge.logs()))
        self.assert_status(response, 202, "a corrupt %s batch must fail open" % encoding)
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")

    def test_a_corrupt_gzip_batch_fails_open(self):
        self.send("corrupt_full_length.gz", "gzip")

    def test_a_corrupt_zstd_batch_fails_open(self):
        self.send("corrupt_full_length.zst", "zstd")
