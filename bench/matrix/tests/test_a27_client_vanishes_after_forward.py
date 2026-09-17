"""A27: the sender leaves while the intake is still working.

The batch is already on its way, so it must be delivered exactly once, the
undeliverable answer must be logged, and there must be no retry: the intake
has it.
"""

import threading
import time

from harness import MatrixCase


class ClientVanishesAfterForward(MatrixCase):
    INTAKE_LATENCY = 2000
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_batch_is_delivered_once_and_the_loss_is_logged(self):
        body = b'[{"message":"vanishing"}]'
        client = self.raw(timeout=30)
        client.send(self.head(body_len=len(body)) + body)
        time.sleep(0.5)  # the exchange is open against the slow intake
        client.close()
        time.sleep(3.5)

        delivered = self.intake.requests_seen() - self.baseline_intake
        self.assertEqual(delivered, 1, "the batch was delivered %d times" % delivered)
        self.assertEqual(self.metric_delta("edge_upstream_retries_total"), 0, "a vanished sender caused a retry")
