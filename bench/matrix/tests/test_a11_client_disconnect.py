"""A11: the sender vanishes mid-body.

Nothing to answer, but the slot must come back and the upstream connection
must not leak.
"""

from harness import MatrixCase


class ClientDisconnect(MatrixCase):
    FORBID_LOGS = ["upstream.timed.out"]
    def test_disconnect_frees_the_slot(self):
        for _ in range(5):
            client = self.raw(timeout=10)
            client.send(self.head(body_len=4096))
            client.send(b'[{"message":"half')
            client.close()

        # The invariants in tearDown carry the assertion: the edge still
        # serves, and no connection slot leaked.
        self.assertEqual(self.health().status_code, 200)
