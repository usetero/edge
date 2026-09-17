"""D03: SIGTERM with idle keep-alive connections open.

The idle deadline is 30 s. If shutdown waits for it, every deployment stalls
for half a minute per task.
"""

from harness import MatrixCase


class SigtermIdleKeepalive(MatrixCase):
    TERMINATES_EDGE = True
    DEFECTS = {
        "stdio": "shutdown waits out the 30 s idle deadline, so every deployment "
                 "stalls one task at a time against the orchestrator's kill timeout",
    }

    def test_idle_connections_do_not_delay_shutdown(self):
        held = [self.raw(timeout=30) for _ in range(8)]
        try:
            for client in held:
                client.send(self.head(body_len=0))
            code, seconds = self.edge.terminate_and_wait(timeout=45)
        finally:
            for client in held:
                client.close()

        self.assertIsNotNone(code, "the edge never exited with idle connections open")
        self.assertLess(
            seconds,
            10,
            "shutdown waited %.0f s for idle connections; the idle deadline is 30 s" % seconds,
        )
