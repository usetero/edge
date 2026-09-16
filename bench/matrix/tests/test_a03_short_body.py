"""A03: the head declares more body than the sender delivers."""

from harness import MatrixCase


class ShortBody(MatrixCase):
    EXPECT_METRICS_FOR = {"stdio": {'edge_inbound_timeouts_total{phase="request"}': 1}}
    EXPECT_LOGS_FOR = {"stdio": ["request.failed", "InboundBodyTimeout"]}
    FORBID_LOGS = ["upstream"]
    SLOW = True
    DEFECTS = {"httpz": "closes the connection with no status"}

    def test_short_body_is_answered(self):
        with self.raw(timeout=60) as client:
            client.send(self.head(body_len=500))
            client.send(b'[{"message":"only the start')
            answer = client.read_response()

        self.assert_status(answer, 408, "a stalled body must be answered")
