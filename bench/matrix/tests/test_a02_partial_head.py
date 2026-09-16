"""A02: a sender delivers part of a head, then stalls.

No request is complete, but the sender is waiting for an answer, so the edge
must not close in silence.
"""

from harness import MatrixCase


class PartialHead(MatrixCase):
    SLOW = True

    def test_partial_head_is_answered(self):
        self.expect_difference("httpz", "closes the connection with no status")
        with self.raw(timeout=60) as client:
            client.send(b"POST /api/v2/logs HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            answer = client.read_response()

        self.assert_status(answer, 408, "a stalled head must be answered")
        self.wait_for_metric('edge_inbound_timeouts_total{phase="request"}', 1, timeout=5)
