"""A52: two redacts on the same wrapped path compose on the wire.

A Datadog `message` often wraps a JSON document. The engine reads the field
before each redact. If a read serves the value from before the first redact,
the second redact overwrites the first, and the scrubbed content leaks to the
intake. That is a PII leak a customer sees only in their intake, so the check
is at the intake, byte for byte.
"""

import json

from harness import MatrixCase

EMAIL_PATH = ["data", "jsonPayload", "email"]

WRAPPED = json.dumps(
    [
        {
            "ddsource": "matrix",
            "message": json.dumps({"data": {"jsonPayload": {"email": "alice@example.com", "note": "evidence"}}}),
        }
    ]
).encode()


class RedactionComposes(MatrixCase):
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "redact-email",
                "name": "redact-email",
                "log": {
                    "match": [{"log_field": "body", "regex": ".+"}],
                    "keep": "all",
                    "transform": {
                        "redact": [
                            {"log_attribute": EMAIL_PATH, "regex": "alice", "replacement": "ALICE_R"},
                            {"log_attribute": EMAIL_PATH, "regex": "example", "replacement": "EXAMPLE_R"},
                        ]
                    },
                },
            }
        ]
    }
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed", "policy.failed.open"]

    def test_both_redactions_reach_the_intake(self):
        self.intake.capture_start("a52-redact")
        response = self.post_raw_body(WRAPPED)
        self.assert_status(response, 202, "a redacted batch is still a success")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        forwarded = bodies[0]

        self.assertNotIn(b"alice", forwarded, "the first redact was lost:\n%r" % forwarded)
        self.assertNotIn(b"example.com", forwarded, "the second redact was lost:\n%r" % forwarded)
        self.assertIn(b"ALICE_R@EXAMPLE_R.com", forwarded, "the redactions did not compose:\n%r" % forwarded)
        self.assertIn(b"evidence", forwarded, "an untouched sibling was lost:\n%r" % forwarded)
