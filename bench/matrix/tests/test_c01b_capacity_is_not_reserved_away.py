"""C01b: senders up to the cap are all served.

The control reserve exists so a health probe can be read while the slab is
full. It must be capacity on top of `max_connections`, not a slice of it: when
it was carved out of the cap, a deployment sized to its sender count shed the
last two senders forever. A benchmark caught that, not a test, so here is the
test.
"""

import threading

from harness import MatrixCase


class CapacityIsNotReservedAway(MatrixCase):
    EDGE_CONFIG = {"max_connections": 8}

    def test_every_sender_up_to_the_cap_is_served(self):
        cap = self.EDGE_CONFIG["max_connections"]
        answers = []
        lock = threading.Lock()
        start = threading.Barrier(cap)

        def sender():
            start.wait()
            try:
                status = self.post_logs(timeout=30).status_code
            except Exception as err:
                status = type(err).__name__
            with lock:
                answers.append(status)

        threads = [threading.Thread(target=sender, daemon=True) for _ in range(cap)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)

        self.assertEqual(
            answers,
            [202] * cap,
            "%d senders against a cap of %d were not all served: %r" % (cap, cap, answers),
        )
