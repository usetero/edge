"""C03: every slot taken by senders that never send.

The edge must reclaim the slots on its own, without the senders closing
anything, or one misbehaved client wedges the sidecar until it restarts.
"""

import time

from harness import MatrixCase


class IdleSocketFlood(MatrixCase):
    EXPECT_METRICS_FOR = {"stdio": {'edge_inbound_timeouts_total{phase="idle"}': 1}}
    EDGE_CONFIG = {"max_connections": 8}
    EXPECT_SHED = True
    SLOW = True

    def test_idle_sockets_do_not_wedge_the_edge(self):
        held = [self.raw(timeout=90) for _ in range(12)]
        recovered_at = None
        try:
            time.sleep(1)
            started = time.monotonic()
            while time.monotonic() - started < 60:
                try:
                    if self.health(timeout=2).status_code == 200:
                        recovered_at = time.monotonic() - started
                        break
                except Exception:
                    pass
                time.sleep(1)
        finally:
            for client in held:
                client.close()

        self.assertIsNotNone(recovered_at, "the edge never recovered while sockets were held")
        self.assertLess(recovered_at, 45, "reclaim took %.0f s" % recovered_at)
