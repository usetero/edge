"""A09: a body that claims gzip and is not.

The edge is a proxy, not a judge of the payload. A body it cannot decode must
still reach the intake, which is the only party that can accept or reject it.
The edge must never be the reason a batch disappears.
"""

from harness import MatrixCase


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

    DEFECTS = {
        "stdio": "drops a body the policy path cannot decode instead of failing open",
        "httpz": "drops a body the policy path cannot decode instead of failing open",
    }
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "keep-all",
                "name": "keep-all",
                "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"},
            }
        ]
    }

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
