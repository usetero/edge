"""C05: a health probe while every connection slot is taken.

Today the probe is shed with the rest, which on ECS restarts the sidecar during the
very spike that filled it. The case asserts the behaviour we want — health
answers — so the choice is explicit rather than implied by the shed path.
"""

from harness import MatrixCase


class HealthAtCapacity(MatrixCase):
    EDGE_CONFIG = {"max_connections": 8}
    EXPECT_SHED = True
    DEFECTS = {"httpz": "health waits behind the full connection table"}

    def test_health_answers_at_capacity(self):
        held = []
        try:
            for _ in range(16):
                client = self.raw(timeout=10)
                client.send(self.head(body_len=4096))  # hold the slot open
                held.append(client)
            self.assertEqual(
                self.health(timeout=5).status_code,
                200,
                "a probe at capacity must still answer, or the orchestrator "
                "restarts the sidecar during the spike",
            )
        finally:
            for client in held:
                client.close()
