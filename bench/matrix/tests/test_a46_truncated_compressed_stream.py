"""A46: the framing is complete, but the gzip stream inside it is cut.

`Content-Length` matches the bytes sent, so the transport sees a whole
request. The gzip stream ends early, as it does when a proxy or a
buggy sender cuts a payload and recomputes the length. The Zig 0.16.0 gzip
decoder reaches `unreachable` on a stream that stops before its end.

The edge must stay up and fail open, the same as a09: forward the bytes as
sent and let the intake judge them. Both policy paths are covered: the
streamed logs path and the buffered metrics path.
"""

import gzip
import json

from harness import MatrixCase

POLICIES = {
    "policies": [
        {
            "id": "drop-debug",
            "name": "drop-debug",
            "log": {"match": [{"log_field": "body", "regex": "^DEBUG"}], "keep": "none"},
        },
        {
            "id": "drop-load",
            "name": "drop-load",
            "metric": {"match": [{"metric_field": "name", "regex": "^system\\.load"}], "keep": False},
        },
    ]
}


def series_body() -> bytes:
    points = [
        {"metric": "system.load.%d" % i, "points": [{"timestamp": 1, "value": i}], "type": 3}
        for i in range(400)
    ]
    return json.dumps({"series": points}).encode()


class TruncatedCompressedStream(MatrixCase):
    EDGE_POLICIES = POLICIES
    EXPECT_LOGS = ["policy.failed.open"]
    FORBID_LOGS = ["request.failed"]
    DEFECTS = {
        "stdio": "the gzip decoder reaches unreachable on a cut stream, and the process dies",
        "httpz": "the gzip decoder reaches unreachable on a cut stream, and the process dies",
    }

    def send_cuts(self, stream: bytes, encoding: str, path: str) -> None:
        for cut in (19, 40, 100, len(stream) // 2, len(stream) - 4, len(stream) - 1):
            response = self.post_raw_body(
                stream[:cut], path=path, headers={"Content-Encoding": encoding}, timeout=30
            )
            self.assertTrue(self.edge.alive(), "the edge died at cut %d:\n%s" % (cut, self.edge.logs()))
            self.assert_status(response, 202, "a cut %s stream must fail open (cut %d)" % (encoding, cut))

    def test_a_cut_gzip_logs_stream_fails_open(self):
        self.send_cuts(gzip.compress(self.log_batch(30_000, level="DEBUG"), 1), "gzip", "/api/v2/logs")

    def test_a_cut_gzip_metrics_stream_fails_open(self):
        self.send_cuts(gzip.compress(series_body(), 1), "gzip", "/api/v2/series")
