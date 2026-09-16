"""A10: an encoding the edge cannot decode.

`service/datadog` documents the intent: an unsupported content encoding
forwards raw. No policy can read the body, but the batch is still the
customer's data, so it belongs at the intake. Both frontends fail this today,
in different ways, so both carry the defect.
"""

from harness import MatrixCase


class UnsupportedEncoding(MatrixCase):
    DEFECTS = {
        "httpz": "answers 502, which blames the intake for a request the sender framed",
        "stdio": "answers 400 and drops the batch instead of forwarding it raw",
    }

    def test_unknown_encoding_forwards_raw(self):
        response = self.post_raw_body(b'[{"message":"brotli"}]', headers={"Content-Encoding": "br"})
        self.assert_status(response, 202, "an unsupported encoding must forward, not drop")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
