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
    correct. What is not correct is what an operator sees: the matcher builds
    nothing (`matcher.index.build.completed ... policy_count=0`), while the
    loader reports `loaded_count=1 failed_count=0` and `/_edge/policies` lists
    the policy as enabled. A rule that silently does nothing looks live.
    """

    DEFECTS = {
        "stdio": "a rejected pattern still reports loaded_count=1, failed_count=0 and enabled",
        "httpz": "a rejected pattern still reports loaded_count=1, failed_count=0 and enabled",
    }
    ALLOW_PHANTOM_SUCCESS = True
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "drop-all-star",
                "name": "drop-all-star",
                "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "none"},
            }
        ]
    }

    def test_a_pattern_the_engine_rejects_is_reported(self):
        import requests

        logs = self.edge.logs()
        snapshot = requests.get(self.edge.url + "/_edge/policies", timeout=10).text

        built_nothing = "policy_count=0" in logs
        self.assertTrue(built_nothing, "the pattern compiled after all; update this case")

        reported = ("failed_count=0" not in logs) or ("enabled=true" not in snapshot)
        self.assertTrue(
            reported,
            "the matcher built nothing, yet the loader reports failed_count=0 "
            "and the snapshot lists the policy as enabled:\n%s" % snapshot,
        )
