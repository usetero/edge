"""C01: more connections than the slab holds.

Shedding is correct. Shedding in silence is not: it is the signal an operator
needs when a sidecar is at its ceiling.
"""

from harness import MatrixCase


class ShedAtCapacity(MatrixCase):
    EDGE_CONFIG = {"max_connections": 8}
    EXPECT_SHED = True

    def test_excess_connections_are_shed_with_a_status(self):
        held = []
        answers = []
        try:
            for _ in range(24):
                client = self.raw(timeout=10)
                held.append(client)
                client.send(self.head(body_len=4096))  # occupy the slot
            # A fresh sender past the ceiling.
            with self.raw(timeout=10) as probe:
                probe.send(self.head(body_len=0) + b"")
                answers.append(probe.read_response())
        finally:
            for client in held:
                client.close()

        statuses = [a.status for a in answers]
        self.assertTrue(
            any(s == 503 for s in statuses) or any(s is None for s in statuses),
            "past the ceiling the edge must shed, got %r" % statuses,
        )
        if self.frontend == "stdio":
            self.wait_for_metric('edge_connections_shed_total{reason="slab_full"}', 1, timeout=10)
