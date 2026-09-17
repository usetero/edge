"""A09: a body the edge cannot decode.

The edge is a proxy, not a judge of the payload. A body it cannot decode must
still reach the intake, which is the only party that can accept or reject it.
The edge must never be the reason a batch disappears.

Three shapes, because they fail in different places: bytes that only claim to
be gzip (the header is refused), and a valid stream that stops early (the
decoder fails mid-body). The second is what a sender produces when its
connection breaks mid-send and it retries a half-flushed buffer, and it is
worth its own case: a customer met it, and the edge answered 400, which the
Datadog agent discards permanently.
"""

import gzip
import json

from harness import MatrixCase

KEEP_ALL = {
    "policies": [
        {
            "id": "keep-all",
            "name": "keep-all",
            "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
        }
    ]
}

#: A well-formed gzip stream with its tail missing, as a half-flushed buffer
#: arrives. The first bytes inflate; the stream then ends without its footer.
FULL_BATCH = json.dumps(
    [{"message": "record %d" % i, "ddsource": "matrix"} for i in range(200)]
).encode()
_COMPRESSED = gzip.compress(FULL_BATCH)
TRUNCATED_GZIP = _COMPRESSED[: len(_COMPRESSED) * 2 // 3]


class CorruptGzip(MatrixCase):
    def test_an_undecodable_body_still_reaches_the_intake(self):
        response = self.post_raw_body(
            b"\x1f\x8b\x08\x00 not really gzip at all",
            headers={"Content-Encoding": "gzip"},
        )
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch was dropped by the edge")
        self.assertEqual(response.status_code, 202, "the intake's answer must be relayed")


class CorruptGzipWithPolicies(MatrixCase):
    """The same body with policies loaded, so the decode path actually runs."""

    EXPECT_LOGS = ["policy.failed.open"]
    EDGE_POLICIES = KEEP_ALL

    def test_a_body_the_policy_path_cannot_decode_fails_open(self):
        response = self.post_raw_body(
            b"\x1f\x8b\x08\x00 not really gzip at all",
            headers={"Content-Encoding": "gzip"},
        )
        self.assertGreaterEqual(
            self.intake_saw(1),
            1,
            "a body the policy path could not decode was dropped instead of forwarded",
        )
        self.assertEqual(response.status_code, 202)


class TruncatedGzipWithPolicies(MatrixCase):
    """A valid gzip stream that stops early, which a retried half-flushed
    buffer produces. The decoder fails mid-body rather than at the header."""

    EXPECT_LOGS = ["policy.failed.open"]
    EDGE_POLICIES = KEEP_ALL

    def test_a_truncated_stream_is_forwarded_not_refused(self):
        response = self.post_raw_body(TRUNCATED_GZIP, headers={"Content-Encoding": "gzip"})
        self.assertEqual(
            202,
            response.status_code,
            "a truncated batch must be forwarded for the intake to judge, not refused",
        )
        self.assertGreaterEqual(
            self.intake_saw(1),
            1,
            "the batch never reached the intake",
        )
