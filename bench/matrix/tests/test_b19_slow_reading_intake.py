"""B19: the intake reads the batch at a trickle.

With a body above the socket buffer our send blocks, so the watchdog has to
cover the send side as well as the read side.
"""

import json
import time

from harness import MatrixCase


class SlowReadingIntake(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_blocked_send_is_bounded(self):
        self.intake.arm("slow_read", arg=200, count=1)
        body = json.dumps([{"message": "x" * 400 * 1024}]).encode()
        started = time.monotonic()
        try:
            self.post_raw_body(body, timeout=120)
        except Exception:
            pass
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 45, "a blocked send ran for %.0f s" % elapsed)
