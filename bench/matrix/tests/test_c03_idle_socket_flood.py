"""C03: every slot taken by senders that never send.

The edge must recover on its own, without the senders closing anything.
"""

import time

from harness import MatrixCase


class IdleSocketFlood(MatrixCase):
    EDGE_CONFIG = {"max_connections": 8}
    EXPECT_SHED = True
    SLOW = True

    def test_idle_sockets_do_not_wedge_the_edge(self):
        self.expect_difference("httpz", "reclaims through its own request timeout")
        held = [self.raw(timeout=90) for _ in range(12)]
        try:
            time.sleep(1)
            # The ceiling is reached, so health is expected to fail here.
            recovered_at = None
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
        self.wait_for_metric('edge_inbound_timeouts_total{phase="idle"}', 1, timeout=10)
