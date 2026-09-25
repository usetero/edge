"""A46b: the framing is complete, but the zstd stream inside it is cut.

The zstd half of a46. A current Datadog agent sends zstd, so the same cut
must fail open here too: forward the bytes as sent and let the intake judge.
"""

from harness import MatrixCase
from tests.test_a16_zstd_body import _compress
from tests.test_a46_truncated_compressed_stream import POLICIES


class TruncatedZstdStream(MatrixCase):
    EDGE_POLICIES = POLICIES
    EXPECT_LOGS = ["policy.failed.open"]
    FORBID_LOGS = ["request.failed"]

    def test_a_cut_zstd_logs_stream_fails_open(self):
        stream = _compress(self.log_batch(30_000, level="DEBUG"))
        if stream is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        for cut in (19, 40, 100, len(stream) // 2, len(stream) - 4, len(stream) - 1):
            response = self.post_raw_body(
                stream[:cut], headers={"Content-Encoding": "zstd"}, timeout=30
            )
            self.assertTrue(self.edge.alive(), "the edge died at cut %d:\n%s" % (cut, self.edge.logs()))
            self.assert_status(response, 202, "a cut zstd stream must fail open (cut %d)" % cut)
