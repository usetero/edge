"""A08: a batch above max_body_size."""

from harness import MatrixCase


class BodyTooLarge(MatrixCase):
    EXPECT_PERMANENT_DROP = True
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s4xx"}': 1}
    EXPECT_LOGS = ["request.failed", "BodyTooLarge"]
    FORBID_LOGS = ["upstream"]
    EDGE_CONFIG = {"max_body_size": 16384}

    def test_oversize_body_is_rejected(self):
        response = self.post_raw_body(b"x" * 65536)
        self.assert_status(response, 413, "an oversize body must be refused")
        self.assertEqual(self.intake_saw(1, timeout=2), 0, "an oversize body reached the intake")


class ChunkedBodyTooLarge(MatrixCase):
    """A chunked batch above max_body_size.

    A chunked body declares no length, so the cap cannot be checked up front.
    The edge must refuse it mid-stream, and the intake must not record it. The
    streaming design may open the upstream before the cap trips, so this case
    does not forbid upstream log lines the way the Content-Length case does.
    """

    EXPECT_PERMANENT_DROP = True
    EXPECT_METRICS = {'edge_responses_total{known_path="api_v2_logs",status_class="s4xx"}': 1}
    EXPECT_LOGS = ["request.failed", "BodyTooLarge"]
    EDGE_CONFIG = {"max_body_size": 16384}
    DEFECTS = {
        "httpz": "httpz answers the chunked 413 itself, before the edge handler, so no log line and no response counter",
    }

    def test_oversize_chunked_body_is_rejected(self):
        body = b"x" * 65536
        framed = b"".join(
            b"%x\r\n%s\r\n" % (len(body[i : i + 8192]), body[i : i + 8192]) for i in range(0, len(body), 8192)
        ) + b"0\r\n\r\n"
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=None, extra="Transfer-Encoding: chunked"))
            try:
                client.send(framed)
            except OSError:
                pass  # the edge may answer and close before we finish sending
            answer = client.read_response()
        self.assert_status(answer, 413, "an oversize chunked body must be refused")
        self.assertEqual(self.intake_saw(1, timeout=2), 0, "an oversize chunked body reached the intake")
