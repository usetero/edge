"""A04: the sender never stops, and never finishes.

One byte at a time keeps a per-read timeout alive forever, so only a
whole-request deadline cuts this off. The edge must stop reading and free the
slot; whether the sender learns that through a 408 or through a closed socket
depends on how far its own write buffer got.
"""

import socket
import time

from harness import MatrixCase


class SlowDripBody(MatrixCase):
    EXPECT_METRICS_FOR = {"stdio": {'edge_inbound_timeouts_total{phase="request"}': 1}}
    FORBID_LOGS = ["upstream"]
    SLOW = True
    DEFECTS = {"httpz": "its per-read timeout restarts on every byte, so the sender holds a handler thread"}

    def test_a_dribbling_sender_is_cut_off(self):
        body = b'[{"message":"' + b"x" * 30 + b'"}]'
        cut_off_after = None
        answer = None
        with self.raw(timeout=90) as client:
            client.send(self.head(body_len=len(body) + 200))
            started = time.monotonic()
            try:
                for i in range(len(body)):
                    client.send(body[i : i + 1])
                    time.sleep(1.0)
                else:
                    answer = client.read_response()
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                cut_off_after = time.monotonic() - started

        if answer is not None and answer.status is not None:
            self.assert_status(answer, 408, "a dribbling sender must be answered")
            return
        self.assertIsNotNone(cut_off_after, "the sender was never cut off")
        self.assertLess(cut_off_after, 45, "the request deadline fired far too late")
