"""C02: a health probe during a burst against a slow intake.

This is the ECS failure: the probe shares the request path with a burst of log
batches, and an unlucky probe misses its window. Three misses and the
scheduler kills the task.
"""

import time

from harness import MatrixCase
from harness import load


class HealthUnderBurst(MatrixCase):
    INTAKE_LATENCY = 3000

    def test_health_stays_fast_while_the_intake_is_slow(self):
        self.expect_difference("httpz", "one batch of 16 goes to a single pool thread")
        if not load.available():
            self.skipTest("oha is not installed")

        import threading

        worst = {"seconds": 0.0}

        def probe():
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                started = time.monotonic()
                try:
                    self.health(timeout=30)
                except Exception:
                    worst["seconds"] = 999
                    return
                worst["seconds"] = max(worst["seconds"], time.monotonic() - started)
                time.sleep(0.25)

        watcher = threading.Thread(target=probe, daemon=True)
        watcher.start()
        load.run(self.edge.url + "/api/v2/logs", b'[{"message":"burst"}]', connections=15, seconds=10)
        watcher.join(timeout=30)

        self.assertLess(worst["seconds"], 1.0,
                        "a health probe waited %.1f s behind the burst" % worst["seconds"])
