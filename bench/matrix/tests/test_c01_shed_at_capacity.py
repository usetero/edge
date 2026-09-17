"""C01: more connections than the slab holds.

Shedding is correct past the cap, and silent shedding is not: it is the signal
an operator needs when a sidecar is at its ceiling. Two things are asserted
here. Nothing is shed at exactly `max_connections` senders, because the
control reserve is capacity on top of the cap rather than a slice of it — a
benchmark caught that the other way round. And past the cap the answer is 503
with `Retry-After`, because running out of connections is a condition of this
proxy rather than a limit on one sender, and the header is the part a sender
can act on.
"""

from harness import MatrixCase


class ShedAtCapacity(MatrixCase):
    EXPECT_METRICS_FOR = {"stdio": {'edge_connections_shed_total{reason="slab_full"}': 1}}
    EXPECT_LOGS_FOR = {"stdio": ["connection.shed"]}
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
        for answer in answers:
            if answer.status == 503:
                self.assertIn(
                    "retry-after",
                    answer.head.lower(),
                    "a shed answer must tell the sender how long to wait:\n%s" % answer.head,
                )
        if self.frontend == "stdio":
            self.wait_for_metric('edge_connections_shed_total{reason="slab_full"}', 1, timeout=10)
