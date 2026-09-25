"""A50: a header value that contains a bare LF.

`x-a: b\\nx-matrix-split: yes` parses in std as one header whose value holds
an LF. If the edge forwards that value, an upstream that accepts a bare LF as
a line end reads a second header the edge never checked. Hop-by-hop and
framing headers are filtered by name, so this is a way around the filter.

The edge must either refuse the request, or forward no header value with a CR
or LF in it. The intake here is a raw listener, because the echo intake
records bodies, not heads.
"""

import socket
import threading

from harness import MatrixCase


class RawIntake:
    """Accepts connections, records each request head, and answers 202."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.heads: list[bytes] = []
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                self.heads.append(data.split(b"\r\n\r\n", 1)[0])
                conn.sendall(b"HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")

    def close(self) -> None:
        self.listener.close()


class BareLfHeader(MatrixCase):
    # The raw listener is the upstream, so the echo intake counts nothing.
    ALLOW_PHANTOM_SUCCESS = True
    # A 400 is the right answer to a malformed head.
    EXPECT_PERMANENT_DROP = True
    DEFECTS = {"stdio": "forwards the header value with its bare LF"}

    def setUp(self) -> None:
        self.raw_intake = RawIntake()
        self.EDGE_CONFIG = {"upstream_url": "http://127.0.0.1:%d" % self.raw_intake.port}
        super().setUp()

    def tearDown(self) -> None:
        try:
            super().tearDown()
        finally:
            self.raw_intake.close()

    def test_a_bare_lf_never_reaches_the_upstream(self):
        body = b'[{"message":"bare lf"}]'
        with self.raw(timeout=15) as client:
            client.send(self.head(body_len=len(body), extra="x-a: b\nx-matrix-split: yes") + body)
            answer = client.read_response()

        if answer.status is not None and answer.status >= 400:
            return
        self.assertTrue(self.raw_intake.heads, "the request was accepted but never forwarded")
        for head in self.raw_intake.heads:
            lines = head.split(b"\r\n")
            self.assertFalse(
                any(b"\n" in line or b"\r" in line for line in lines),
                "a header value with a bare LF reached the upstream:\n%r" % head,
            )
