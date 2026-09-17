"""A41: a policy that keeps nothing, and the regex that cannot say so.

The sender must get a 2xx, because the edge accepted responsibility for the
batch, and the intake must receive either nothing or an empty batch. No
upstream error line either way.
"""

from harness import MatrixCase


class PolicyDropAll(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True
    # `.+`, not `.*`: Hyperscan rejects a pattern that can match an empty
    # buffer, so `.*` never compiles. See RejectedPatternIsVisible below.
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "drop-all",
                "name": "drop-all",
                "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "none"},
            }
        ]
    }
    FORBID_LOGS = ["request.failed", "upstream.retried"]

    def test_a_dropped_batch_is_still_a_success_for_the_sender(self):
        response = self.post_logs(timeout=30)
        self.assertEqual(response.status_code // 100, 2, "got %d" % response.status_code)
        self.assertGreaterEqual(
            self.metric_delta('edge_policy_records_dropped_total{telemetry="datadog_logs"}'),
            1,
            "the policy dropped nothing, so the case proved nothing",
        )


class RejectedPatternIsVisible(MatrixCase):
    """A pattern the engine will not compile must not look like a live policy.

    Hyperscan refuses a pattern that can match an empty buffer, so `.*` is
    invalid and `.+` or `^.*$` is the way to say "everything". That part is
    correct. What was wrong is what an operator saw: the matcher built nothing
    while the snapshot listed the policy as enabled, so a rule that does
    nothing looked live. The rejection is now named in three places.
    """

    # The rejection is settled before the case body runs, so these are
    # absolute checks rather than deltas.
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_REJECTED_POLICIES = True
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "drop-all-star",
                "name": "drop-all-star",
                "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "none"},
            }
        ]
    }

    def test_a_pattern_the_engine_rejects_is_named(self):
        import requests

        # The scrape is what refreshes the gauge and emits the warning.
        self.edge.metrics()
        snapshot = requests.get(self.edge.url + "/_edge/policies", timeout=10).text
        self.assertIn("REJECTED", snapshot, "the dump does not name the rejected policy")
        self.assertIn("drop-all-star", snapshot)
        self.assertIn(
            "invalid regex",
            snapshot,
            "the dump names the policy but not the reason:\n%s" % snapshot,
        )
        self.assertGreaterEqual(
            self.edge.metric("edge_policies_rejected"),
            1,
            "the rejected policy is not counted",
        )
        self.assertIn(
            "policies.rejected",
            self.edge.logs(),
            "nothing warned that a policy was refused",
        )
