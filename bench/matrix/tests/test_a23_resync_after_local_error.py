"""A23: a request the edge answers itself, with a body still on the wire.

After a 413 the rest of the body is still arriving. If the edge keeps the
connection and parses those leftover bytes as the next request, the following
batch dies with a bogus 400. Either a closed connection or a served second
request is correct; a 400 on the second request is not.
"""

from harness import MatrixCase


class ResyncAfterLocalError(MatrixCase):
    EDGE_CONFIG = {"max_body_size": 4096}
    EXPECT_PERMANENT_DROP = True

    def test_the_next_request_is_not_parsed_out_of_leftover_bytes(self):
        oversize = b"x" * 65536
        good = b'[{"message":"after"}]'
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=len(oversize)))
            try:
                client.send(oversize)
            except OSError:
                pass  # the edge answered and closed mid-send, which is correct
            first = client.read_response()
            self.assertEqual(first.status, 413, repr(first))

            try:
                client.send(self.head(body_len=len(good)) + good)
            except OSError:
                # A closed connection is one of the two correct answers.
                return
            second = client.read_response()

        if second.status is not None:
            self.assertNotEqual(
                second.status,
                400,
                "the second request was parsed out of the first body's leftovers",
            )
