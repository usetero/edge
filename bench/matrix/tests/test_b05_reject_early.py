"""B05: the intake rejects on the head, before it reads the body.

This is the reported production signature: a broken connection, then a 400 on
the immediate retry of the same chunk. The edge must relay that 400 rather
than turn it into a 502, so the sender stops retrying a batch the intake will
never accept.
"""

from harness import MatrixCase


class RejectEarly(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s4xx"}': 1}
    FORBID_LOGS = ["request.failed"]
    def test_an_early_rejection_is_relayed(self):
        self.intake.arm("reject_early", count=1)
        response = self.post_logs(timeout=60)

        self.assert_status(response, 400, "an intake rejection must reach the sender verbatim")
