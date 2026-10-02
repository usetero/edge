"""A53: a record with a malformed container in an unknown field fails open.

The fast path scans a record without a full parse. A bracket-balanced but
malformed value such as `[1,]` must not let a policy verdict depend on which
parser ran. The contract is fail-open: the edge forwards the record as sent,
and the intake receives the bytes the sender sent. A drop policy that matches
the record must not drop it, because the record was never valid to evaluate.
"""

from harness import MatrixCase

#: Valid JSON array, one record. The `x` field is bracket-balanced and
#: malformed: a trailing comma inside the array.
MALFORMED = b'[{"ddsource":"matrix","message":"matched","service":"s","x":[1,]}]'


class MalformedContainerFailsOpen(MatrixCase):
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "drop-matched",
                "name": "drop-matched",
                "log": {"match": [{"log_field": "body", "regex": "matched"}], "keep": "none"},
            }
        ]
    }
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]

    def test_the_record_is_forwarded_as_sent(self):
        self.intake.capture_start("a53-malformed")
        response = self.post_raw_body(MALFORMED)
        self.assert_status(response, 202, "a malformed record is still accepted")
        self.assertGreaterEqual(self.intake_saw(1), 1, "a malformed record must fail open to the intake")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        self.assertEqual(MALFORMED, bodies[0], "a record the edge could not evaluate was rewritten")
