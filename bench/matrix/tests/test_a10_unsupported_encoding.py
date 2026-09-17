"""A10: an encoding the edge cannot decode.

`service/datadog` documents the intent, and the router honours it: an
unsupported content encoding plans `forward_raw`, so no policy reads the body
and the batch still goes to the intake.

httpz does exactly that. Verified against a lenient intake: a brotli batch
comes back 200, relayed from upstream. It cannot be asserted here, because our
own intake is `std.http.Server` based and refuses the head for the same reason
stdio does.

stdio cannot accept the request at all. `std.http.Server` maps
`content-encoding` through `ContentEncoding.fromString`, and anything outside
its five known values fails the whole head with `HttpHeadersInvalid`. There is
no distinct error, so we cannot tell an unknown encoding from a malformed
head, and the sender gets 400. An agent using brotli would retry it forever.
"""

from harness import MatrixCase


class UnsupportedEncoding(MatrixCase):
    DEFECTS = {"stdio": "std.http.Server refuses the head, so the batch is dropped with 400"}
    FORBID_LOGS = ["upstream.timed.out"]

    def test_unknown_encoding_forwards_raw(self):
        if self.frontend == "httpz":
            self.skipTest("our std-based intake refuses brotli; httpz verified against a lenient one")
        response = self.post_raw_body(b'[{"message":"brotli"}]', headers={"Content-Encoding": "br"})
        self.assert_status(response, 202, "an unsupported encoding must forward, not drop")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")
