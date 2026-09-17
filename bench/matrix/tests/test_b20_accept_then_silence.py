"""B20: the intake accepts the connection and does nothing at all.

Unlike `hang`, it never even reads the body, so the send blocks first. Both a
small and a streamed batch owe an answer at the deadline.
"""

import json
import time

from harness import MatrixCase


class AcceptThenSilence(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_silent_intake_is_bounded(self):
        self.intake.arm("accept_silence", count=1)
        started = time.monotonic()
        try:
            status = self.post_logs(timeout=120).status_code
        except Exception:
            status = None
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 70, "a silent intake held the sender for %.0f s" % elapsed)
        if status is not None:
            self.assertEqual(status // 100, 5, "got %d" % status)
