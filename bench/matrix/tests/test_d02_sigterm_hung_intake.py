"""D02: SIGTERM while the intake is hung.

Forced upstream expiry exists for this: the shutdown path cuts every tracked
exchange. Without it the container waits for the orchestrator's kill.
"""

import threading
import time

from harness import MatrixCase


class SigtermHungIntake(MatrixCase):
    TERMINATES_EDGE = True
    SLOW = True

    def test_a_hung_intake_does_not_delay_shutdown(self):
        self.intake.arm("hang")
        for _ in range(4):
            threading.Thread(target=self._quiet_post, daemon=True).start()
        time.sleep(2)

        code, seconds = self.edge.terminate_and_wait(timeout=45)
        self.assertIsNotNone(code, "the edge never exited with a hung intake")
        self.assertLess(seconds, 20, "shutdown waited %.0f s on a hung intake" % seconds)

    def _quiet_post(self):
        try:
            self.post_logs(timeout=60)
        except Exception:
            pass
