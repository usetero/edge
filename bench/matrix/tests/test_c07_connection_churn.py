"""C07: connect, send, close, over and over.

Gauges and descriptors must return to their baseline after thousands of
cycles, and nothing may be shed: this is ordinary agent behaviour when
keep-alive is off.
"""

from harness import MatrixCase


class ConnectionChurn(MatrixCase):
    SLOW = True

    def test_churn_leaves_no_residue(self):
        body = b'[{"message":"churn"}]'
        for _ in range(1500):
            with self.raw(timeout=20) as client:
                client.send(self.head(body_len=len(body)) + body)
                answer = client.read_response()
                if answer.status is not None:
                    self.assertEqual(answer.status, 202, repr(answer))

        # The teardown invariants carry the rest: in-flight back to zero,
        # descriptors back to baseline, nothing shed.
        self.assertEqual(self.health().status_code, 200)
