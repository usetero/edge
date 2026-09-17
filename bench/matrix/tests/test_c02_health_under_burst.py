"""C02: a health probe that arrives with a burst, against a slow intake.

This is the ECS failure the customer reported. The probe is a static route, so
it can only be slow if it cannot reach a thread. Arrivals are synchronised
here, because the effect depends on the probe landing in the same event batch
as the batches ahead of it: with per-thread queues the probe waits for every
request queued in front of it, however many threads are idle.
"""

import threading

from harness import MatrixCase


class HealthUnderBurst(MatrixCase):
    FORBID_LOGS = ["request.failed"]
    INTAKE_LATENCY = 3000
    DEFECTS = {"httpz": "a batch of up to 16 requests goes to one pool thread, so a probe waits behind it"}

    # The stall depends on the probe landing in the same event batch as the
    # senders, which is probabilistic: measured at roughly 3 in 10 bursts.
    # Eight bursts flapped, so run twenty.
    SLOW = True
    BURSTS = 20
    SENDERS = 15

    def test_health_stays_fast_when_a_burst_arrives_with_it(self):
        worst = 0.0
        for _ in range(self.BURSTS):
            start = threading.Barrier(self.SENDERS + 1)
            probe_seconds = {}

            def sender():
                start.wait()
                try:
                    self.post_logs(timeout=60)
                except Exception:
                    pass

            def probe():
                start.wait()
                import time
                began = time.monotonic()
                try:
                    self.health(timeout=60)
                    probe_seconds["value"] = time.monotonic() - began
                except Exception:
                    probe_seconds["value"] = 999.0

            threads = [threading.Thread(target=sender, daemon=True) for _ in range(self.SENDERS)]
            threads.append(threading.Thread(target=probe, daemon=True))
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=90)
            worst = max(worst, probe_seconds.get("value", 0.0))

        self.assertLess(
            worst,
            1.0,
            "a health probe waited %.1f s behind the burst; three such misses "
            "take the task down" % worst,
        )
