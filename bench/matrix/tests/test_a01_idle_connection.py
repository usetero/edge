"""A01: a sender connects and never sends a byte.

This is the case that wedged the stdio frontend before inbound deadlines
existed: 300 such sockets took every connection slot and the frontend never
served again.
"""

from harness import MatrixCase


class IdleConnection(MatrixCase):
    SLOW = True

    def test_idle_connection_is_reclaimed(self):
        with self.raw(timeout=60) as client:
            answer = client.read_response()

        # The edge closes rather than answering: no request ever arrived.
        self.assertTrue(answer.closed or answer.status is None, repr(answer))
        self.assertLess(answer.seconds, 45, "the idle socket was never reclaimed")

        if self.frontend == "stdio":
            self.wait_for_metric('edge_inbound_timeouts_total{phase="idle"}', 1, timeout=5)
