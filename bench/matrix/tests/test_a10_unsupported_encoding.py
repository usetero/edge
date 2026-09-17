"""A10: an encoding the edge cannot decode.

`service/datadog` documents the intent, and the router honours it: an
unsupported content encoding plans `forward_raw`, so no policy reads the body
and the batch still goes to the intake.

httpz always did that, because it passes the raw header string to the router.
stdio could not accept the request at all: `std.http.Server` maps
`content-encoding` through `ContentEncoding.fromString` (std/http.zig:283) and
`Request.Head.parse` fails the whole head for anything outside its table
(std/http/Server.zig:164), so the sender got 400 and the agent discarded the
batch for good.

The frontend now repairs such a head. `Head.parse` reports the cause
distinctly, as `HttpTransferEncodingUnsupported`, and `Server.receiveHead`
flattens it to `HttpHeadersInvalid` on one line (std/http/Server.zig:53), so
the frontend re-parses the head bytes to find out what really happened and
rewrites the value (src/frontend/stdio/head_repair.zig).

The fake intake shares that repair, because a real intake takes a coding it
cannot decode and this one is `std.http.Server` based too. Without it the case
would measure our test double instead of the edge.
"""

from harness import MatrixCase


class UnsupportedEncoding(MatrixCase):
    FORBID_LOGS = ["upstream.timed.out"]

    def test_unknown_encoding_forwards_raw(self):
        response = self.post_raw_body(b'[{"message":"brotli"}]', headers={"Content-Encoding": "br"})
        self.assert_status(response, 202, "an unsupported encoding must forward, not drop")
        self.assertGreaterEqual(self.intake_saw(1), 1, "the batch never reached the intake")

    def test_the_intake_receives_the_encoding_the_sender_sent(self):
        """The body is untouched, so the header must still describe it."""
        self.post_raw_body(b'[{"message":"brotli"}]', headers={"Content-Encoding": "br"})
        self.assertEqual(
            "br",
            self.intake.stats().get("last_content_encoding", ""),
            "a forwarded body must keep the sender's content-encoding",
        )
