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
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]
    def test_zstd_batch_is_accepted(self):
        payload = _compress(b'[{"message":"zstd batch","ddsource":"matrix"}]')
        if payload is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        response = self.post_raw_body(payload, headers={"Content-Encoding": "zstd"})
        self.assert_status(response, 202, "a zstd batch must be accepted")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")


class LargeZstdBatchWithPolicies(MatrixCase):
    """A zstd batch that decodes past max_body_size but under max_decoded_bytes.

    A one-shot libzstd frame past 2 MiB of content declares a 2 MiB window.
    The decode window cap must admit it, and the decoded cap must be the only
    gate, or every large compressed batch under a policy is refused. With
    policies loaded the edge decodes to evaluate, and the decoder returns 0
    mid-body between blocks, which the bounded copy must not read as EOF.
    """

    EDGE_CONFIG = {"max_body_size": 1572864, "max_decoded_bytes": 16777216}
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "keep-all",
                "name": "keep-all",
                "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
            }
        ]
    }
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]

    def test_a_3_mib_decoded_batch_is_accepted(self):
        record = b'{"ddsource":"matrix","message":"2019-11-19T14:37:58 INFO process hello world %06d"}'
        records = []
        size = 0
        i = 0
        while size < 3 * 1024 * 1024:
            piece = record % i
            records.append(piece)
            size += len(piece) + 1
            i += 1
        payload = _compress(b"[" + b",".join(records) + b"]")
        if payload is None:
            self.skipTest("no zstd binding; run the suite with --with zstandard")
        self.assertLessEqual(len(payload), self.EDGE_CONFIG["max_body_size"], "the case needs a compressible batch")
        response = self.post_raw_body(payload, headers={"Content-Encoding": "zstd"}, timeout=60)
        self.assert_status(response, 202, "a batch the decoded cap admits must be accepted")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
