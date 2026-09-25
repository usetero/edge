"""A45: a sender gives up partway through a plain batch, with no policy.

Nothing decodes here. A partial body must still never reach the intake, or
the intake answers 202 for data the sender never finished.

This case covers the resident path below the streaming threshold. A45b
covers the streamed path above it.
"""

from harness import MatrixCase
from harness.agent import drops_payload


def check_abandoned(case: MatrixCase, size: int) -> None:
    """Abandons a plain batch of `size` bytes at three points."""
    body = case.log_batch(size)
    for cut in (1, len(body) // 2, len(body) - 1):
        answer = case.abandon(body, cut)
        if answer is not None and answer.status is not None:
            why = "cut at %d of %d: answered %r" % (cut, len(body), answer)
            case.assertFalse(200 <= answer.status < 300, why)
            case.assertFalse(drops_payload(answer.status), why)
    case.assertEqual(
        case.intake.requests_seen() - case.baseline_intake,
        0,
        "a partial batch of %d bytes reached the intake" % len(body),
    )


class AbandonedPlainBody(MatrixCase):
    FORBID_LOGS = ["upstream.timed.out"]
    # The metrics carry only the status class, so the invariant reads any
    # retryable 4xx as a drop. The case checks each status itself.
    EXPECT_PERMANENT_DROP = True
    DEFECTS = {"stdio": "forwards the partial body, and the intake answers 202"}

    def test_a_partial_resident_batch_is_not_forwarded(self):
        check_abandoned(self, 8_000)
