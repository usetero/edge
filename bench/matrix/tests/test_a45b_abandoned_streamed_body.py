"""A45b: a sender gives up partway through a streamed plain batch.

The same fault as a45, above the streaming threshold. The edge streams this
body to the intake as it arrives, so the upstream request must end without a
complete body, and the intake must not accept it.
"""

from harness import MatrixCase
from tests.test_a45_abandoned_plain_body import check_abandoned


class AbandonedStreamedBody(MatrixCase):
    FORBID_LOGS = ["upstream.timed.out"]
    # The metrics carry only the status class, so the invariant reads a
    # retryable 4xx as a drop. The case checks each status itself.
    EXPECT_PERMANENT_DROP = True
    DEFECTS = {"httpz": "answers a 4xx for the batch and leaves requests counted in flight"}

    def test_a_partial_streamed_batch_is_not_forwarded(self):
        check_abandoned(self, 200_000)
