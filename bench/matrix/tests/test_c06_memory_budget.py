"""C06: memory under repeated saturation.

Three rounds of concurrent large batches. RSS must not climb between rounds:
a per-connection or per-thread buffer that is never reused shows up here and
nowhere else.
"""

import json
import subprocess
import threading

from harness import MatrixCase


def rss_mb(pid: int) -> float:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    try:
        return int(out.stdout.strip()) / 1024
    except ValueError:
        return -1.0


class MemoryBudget(MatrixCase):
    SLOW = True
    EDGE_CONFIG = {"max_body_size": 1048576}

    def test_rss_does_not_climb_between_rounds(self):
        body = json.dumps([{"message": "x" * 500 * 1024}]).encode()
        rounds = []

        for _ in range(3):
            threads = []
            for _ in range(32):
                thread = threading.Thread(target=lambda: self._quiet_post(body), daemon=True)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join(timeout=60)
            rounds.append(rss_mb(self.edge.pid))

        self.assertGreater(rounds[0], 0, "could not read RSS")
        growth = rounds[-1] - rounds[1]
        self.assertLess(
            growth,
            32,
            "RSS grew %.0f MB between rounds: %s" % (growth, [round(r) for r in rounds]),
        )

    def _quiet_post(self, body):
        try:
            self.post_raw_body(body, timeout=60)
        except Exception:
            pass
