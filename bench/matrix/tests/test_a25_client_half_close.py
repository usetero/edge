"""A25: the sender shuts down its write side and waits for the answer.

A half-close is not a disconnect. A server that treats the FIN as one drops a
batch the intake may already have accepted.
"""

import socket

from harness import MatrixCase


class ClientHalfClose(MatrixCase):
    def test_a_half_closed_sender_still_gets_its_answer(self):
        body = b'[{"message":"half-close"}]'
        with self.raw(timeout=30) as client:
            client.send(self.head(body_len=len(body)) + body)
            client.sock.shutdown(socket.SHUT_WR)
            answer = client.read_response()

        self.assert_status(answer, 202, "a half-closed sender was dropped")
        self.assertGreaterEqual(self.intake_saw(1), 1)
