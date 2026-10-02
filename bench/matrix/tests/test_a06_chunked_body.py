"""A06: a well-formed chunked request, which agents send when streaming."""

import http.client

from harness import MatrixCase


class ChunkedBody(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]
    def test_chunked_body_reaches_the_intake(self):
        payload = b'[{"message":"chunked","ddsource":"matrix"}]'
        framed = b"%x\r\n%s\r\n0\r\n\r\n" % (len(payload), payload)
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(framed)
            answer = client.read_response()

        self.assert_status(answer, 202)
        self.assertGreaterEqual(self.intake_saw(1), 1, "the intake never saw the batch")


def chunked(body: bytes, chunk: int = 8192) -> bytes:
    """Frames `body` as HTTP/1.1 chunks of `chunk` bytes."""
    out = []
    for start in range(0, len(body), chunk):
        piece = body[start : start + chunk]
        out.append(b"%x\r\n%s\r\n" % (len(piece), piece))
    out.append(b"0\r\n\r\n")
    return b"".join(out)


#: Larger than any per-thread pump buffer, so the body crosses many pump
#: iterations. Distinct bytes per record, so a dropped or duplicated chunk
#: changes the body.
BIG_BATCH = (
    b"["
    + b",".join(b'{"ddsource":"matrix","message":"chunk %05d %s"}' % (i, b"x" * 200) for i in range(800))
    + b"]"
)


class ChunkedBodyIdentity(MatrixCase):
    """No policies: the intake must receive the bytes the sender sent.

    The edge forwards a chunked body with no declared length by pumping it
    socket to socket. This pins the pump: every byte, once, in order.
    """

    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]

    def test_a_multi_chunk_body_arrives_byte_for_byte(self):
        self.intake.capture_start("a06-identity")
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(chunked(BIG_BATCH))
            answer = client.read_response()
        self.assert_status(answer, 202)
        self.assertGreaterEqual(self.intake_saw(1), 1, "the intake never saw the batch")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        self.assertEqual(BIG_BATCH, bodies[0], "the forwarded chunked batch is not the batch we sent")


class ChunkedBodyUnderPolicies(MatrixCase):
    """A keep-all policy: the policy path must drain a chunked body whole.

    With policies loaded the body is read twice (probe, then encode), so the
    edge drains it resident first. No record changes, so the original bytes
    forward (see a43).
    """

    EDGE_POLICIES = {
        "policies": [
            {
                "id": "keep-all",
                "name": "keep-all",
                "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
            }
        ]
    }
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 1}
    FORBID_LOGS = ["request.failed"]

    def test_a_chunked_body_survives_the_policy_path(self):
        self.intake.capture_start("a06-policies")
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            client.send(chunked(BIG_BATCH))
            answer = client.read_response()
        self.assert_status(answer, 202)
        self.assertGreaterEqual(self.intake_saw(1), 1, "the intake never saw the batch")
        bodies = self.intake.capture_stop()
        self.assertEqual(1, len(bodies), "the intake recorded %d bodies" % len(bodies))
        self.assertEqual(BIG_BATCH, bodies[0], "a kept chunked batch must reach the intake unmodified")


class ChunkedBodyKeepAlive(MatrixCase):
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s2xx"}': 2}
    FORBID_LOGS = ["request.failed"]

    def test_two_chunked_batches_share_one_connection_without_mixing(self):
        bodies = [b'[{"message":"first"}]', b'[{"message":"second"}]']
        self.intake.capture_start("a06-keep-alive")
        with self.raw(timeout=30) as client:
            for body in bodies:
                client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
                client.send(chunked(body, chunk=7))
                # Consume the full response so the next head cannot be
                # mistaken for bytes left over from the previous response.
                response = http.client.HTTPResponse(client.sock)
                response.begin()
                self.assertEqual(202, response.status)
                self.assertFalse(response.will_close, "the edge ended the keep-alive connection")
                response.read()
                response.close()
        self.assertEqual(bodies, self.intake.capture_stop())
