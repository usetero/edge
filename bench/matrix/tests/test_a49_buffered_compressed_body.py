"""A49: a valid compressed batch on the buffered policy path.

Datadog metrics JSON and OTLP JSON go through the buffered path, which decodes
the whole body before policy runs. `streamReaderToWriter` stops when a decoder
returns 0 bytes, and std decoders return 0 before they have output. The
excess check then reads the rest of the body and answers 413, which the agent
discards for good.

A valid batch must pass: 202, and the intake receives it.
"""

import gzip
import json

from harness import MatrixCase
from tests.test_a16_zstd_body import _compress
from tests.test_a46_truncated_compressed_stream import POLICIES, series_body


def otlp_logs_body() -> bytes:
    records = [{"body": {"stringValue": "%s otlp record %d" % ("DEBUG" if i % 2 else "INFO", i)}} for i in range(50)]
    return json.dumps({"resourceLogs": [{"scopeLogs": [{"logRecords": records}]}]}).encode()


class BufferedCompressedBody(MatrixCase):
    EDGE_POLICIES = POLICIES
    FORBID_LOGS = ["request.failed"]

    def send(self, body: bytes, encoding: str, path: str) -> None:
        response = self.post_raw_body(body, path=path, headers={"Content-Encoding": encoding}, timeout=30)
        self.assert_status(response, 202, "a valid %s batch on %s must pass" % (encoding, path))
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")

    def test_a_gzip_metrics_batch_passes(self):
        self.send(gzip.compress(series_body()), "gzip", "/api/v2/series")

    def test_a_zstd_metrics_batch_passes(self):
        body = _compress(series_body())
        if body is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        self.send(body, "zstd", "/api/v2/series")

    def test_a_gzip_otlp_logs_batch_passes(self):
        self.send(gzip.compress(otlp_logs_body()), "gzip", "/v1/logs")
