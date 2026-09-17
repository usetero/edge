"""B15: an HTTP/1.0 answer with no content-length.

The body ends when the intake closes. A relay that waits for a length instead
holds the exchange until the watchdog fires, 30 s later, for an answer that
already arrived.
"""

import time

from harness import MatrixCase


class Http10NoLength(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_relay_ends_at_the_close(self):
        self.intake.arm("http10_no_length", count=1)
        started = time.monotonic()
        try:
            self.post_logs(timeout=60)
        except Exception:
            pass
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            20,
            "the relay waited %.0f s for a body that ended at the close" % elapsed,
        )
