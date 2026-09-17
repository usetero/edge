"""C04: more senders than handler threads, against an intake that never answers.

Every handler ends up waiting on the watchdog. The control plane must keep
working while that happens: a health probe and a metrics scrape both have to
answer, or an orchestrator kills a sidecar that is merely waiting.
"""

import threading
import time

from harness import MatrixCase


class HungIntakeSaturation(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True

    def test_health_and_metrics_answer_while_every_handler_waits(self):
        self.intake.arm("hang")
        senders = []
        for _ in range(48):
            thread = threading.Thread(target=lambda: self._quiet_post(), daemon=True)
            thread.start()
            senders.append(thread)
        time.sleep(3)

        started = time.monotonic()
        self.assertEqual(self.health(timeout=10).status_code, 200, "health stopped answering")
        health_seconds = time.monotonic() - started
        self.assertLess(health_seconds, 1.0, "health took %.1f s" % health_seconds)
        self.assertTrue(self.edge.metrics(), "the metrics scrape stopped answering")

        self.intake.arm("none")
        for thread in senders:
            thread.join(timeout=90)

    def _quiet_post(self):
        try:
            self.post_logs(timeout=90)
        except Exception:
            pass
