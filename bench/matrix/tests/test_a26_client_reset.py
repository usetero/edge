"""A26: the sender resets the connection mid-body.

The same shape as a disconnect, but an RST rather than a FIN. Slots must come
back and nothing may blame the intake.
"""

import socket
import struct

from harness import MatrixCase


class ClientReset(MatrixCase):
    def test_resets_free_their_slots(self):
        for _ in range(5):
            client = self.raw(timeout=10)
            client.send(self.head(body_len=8192))
            client.send(b'[{"message":"partial')
            client.sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
            )
            client.close()

        self.assertEqual(self.health().status_code, 200)
