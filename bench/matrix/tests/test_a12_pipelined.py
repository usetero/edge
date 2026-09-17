"""A12: two requests written in one packet.

Pipelining is legal HTTP/1.1. An agent that reconnects under load can produce
it, and rejecting the pair loses the second batch.
"""

from harness import MatrixCase


class Pipelined(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 2}
    DEFECTS = {"httpz": "answers 400 to a pipelined pair"}

    def test_pipelined_requests_are_both_served(self):
        body = b'[{"message":"pipelined"}]'
        one = self.head(body_len=len(body)) + body
        with self.raw(timeout=30) as client:
            client.send(one + one)
            first = client.read_response()
            self.assert_status(first, 202)

        self.assertGreaterEqual(self.intake_saw(2), 2, "the second pipelined batch was lost")
