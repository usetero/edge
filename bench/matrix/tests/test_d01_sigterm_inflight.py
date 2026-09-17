"""D01: SIGTERM while requests are in flight against a slow intake.

Every ECS deployment sends SIGTERM. A batch that was accepted with 202 but
never forwarded is data the sender believes is safe, so the shutdown must
either finish the exchange or refuse it.
"""

import threading
import time

from harness import MatrixCase


class SigtermInFlight(MatrixCase):
    INTAKE_LATENCY = 4000
    TERMINATES_EDGE = True
    SLOW = True

    def test_shutdown_neither_hangs_nor_invents_success(self):
        answers = []

        def sender():
            try:
                answers.append(self.post_logs(timeout=60).status_code)
            except Exception as err:
                answers.append(type(err).__name__)

        threads = [threading.Thread(target=sender, daemon=True) for _ in range(4)]
        for thread in threads:
            thread.start()
        time.sleep(1.0)  # the exchanges are open against the slow intake

        code, seconds = self.edge.terminate_and_wait(timeout=45)
        for thread in threads:
            thread.join(timeout=60)

        self.assertIsNotNone(code, "the edge did not exit within 45 s of SIGTERM")
        self.assertLess(seconds, 35, "shutdown took %.0f s" % seconds)

        accepted = sum(1 for a in answers if a == 202)
        self.assertLessEqual(
            accepted,
            self.intake.requests_seen(),
            "a batch was accepted with 202 that the intake never received",
        )
