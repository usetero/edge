"""B18: the intake dribbles its answer.

The watchdog owns the whole attempt, so a body that never finishes must be cut
at the deadline with the slot returned, not held for as long as the intake
feels like dribbling.
"""

import time

from harness import MatrixCase


class SlowResponseBody(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_dribbled_answer_is_cut_at_the_deadline(self):
        self.intake.arm("slow_body", arg=5000, count=1)
        started = time.monotonic()
        try:
            self.post_logs(timeout=120)
        except Exception:
            pass
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 45, "the relay ran for %.0f s" % elapsed)
