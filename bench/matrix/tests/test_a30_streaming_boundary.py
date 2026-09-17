"""A30: a batch either side of the streaming threshold.

A body at or below the threshold stays resident and can be replayed after a
transport failure. A larger one streams, is consumed by its first send, and
cannot be retried, so an intake blip mid-exchange becomes a 502.

Deliberate, and documented rather than fixed. The agent retries a 5xx with
backoff (harness/agent.py), so the cost is a delayed batch and a duplicate
risk, not lost data. Making every batch replayable means holding up to
`max_body_size` per concurrent request, which is the memory a policy
deployment already pays and a passthrough deployment does not.
"""

import json

from harness import MatrixCase


class BelowTheStreamingThreshold(MatrixCase):
    def test_a_resident_batch_survives_a_mid_exchange_failure(self):
        body = json.dumps([{"message": "x" * 60 * 1024}]).encode()
        self.intake.arm("close_early", count=1)
        response = self.post_raw_body(body, timeout=60)
        self.assert_status(response, 202, "a resident batch must be replayed")
        self.assertGreaterEqual(self.metric_delta("edge_upstream_retries_total"), 1)


class AboveTheStreamingThreshold(MatrixCase):
    DEFECTS = {
        "stdio": "a streamed batch cannot be replayed, so a mid-exchange failure loses it",
        "httpz": "a streamed batch cannot be replayed, so a mid-exchange failure loses it",
    }

    def test_a_streamed_batch_survives_a_mid_exchange_failure(self):
        body = json.dumps([{"message": "x" * 300 * 1024}]).encode()
        self.intake.arm("close_early", count=1)
        response = self.post_raw_body(body, timeout=60)
        self.assert_status(response, 202, "a batch above the threshold is lost on one blip")
