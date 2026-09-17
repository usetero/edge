"""B22: the intake goes away mid-burst and comes back on the same port.

A Datadog deployment looks like this. Pooled connections must be evicted and
the first batches after the restart must succeed.
"""

import threading
import time

from harness import MatrixCase, EchoIntake


class IntakeRestart(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_edge_recovers_when_the_intake_comes_back(self):
        port = self.intake.port
        for _ in range(5):
            self.assert_status(self.post_logs(timeout=30), 202)

        stop = threading.Event()

        def sender():
            while not stop.is_set():
                try:
                    self.post_logs(timeout=20)
                except Exception:
                    pass

        traffic = threading.Thread(target=sender, daemon=True)
        traffic.start()
        try:
            self.intake.stop()
            time.sleep(2)
            self.intake = EchoIntake(port=port)
            time.sleep(1)
        finally:
            stop.set()
            traffic.join(timeout=30)

        # The first batches after the restart must land.
        for _ in range(3):
            self.assert_status(self.post_logs(timeout=30), 202)
        self.assertEqual(self.health().status_code, 200)
