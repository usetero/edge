"""D04: the intake is unreachable when the edge starts, then comes back.

ECS starts a sidecar before the network settles. The edge must come up, answer
health throughout, and recover on its own once the intake appears — without a
restart.
"""

import time

from harness import MatrixCase, EchoIntake
from harness.procs import Edge, free_port


class StartupWithIntakeDown(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def setUp(self):
        # Point the edge at a port nothing is listening on yet, and keep it so
        # the intake can appear there later.
        self.port = free_port()
        self.intake = EchoIntake(port=self.port)
        self.intake.stop()  # the edge starts blind
        self.edge = Edge("http://127.0.0.1:%d" % self.port)
        self.baseline = self.edge.metrics()
        self.log_snapshot = set(self.edge.logs().splitlines())
        self.baseline_descriptors = self.edge.descriptors()
        self.baseline_intake = 0

    def test_the_edge_starts_blind_and_recovers(self):
        self.assertEqual(self.health().status_code, 200, "health must not depend on the intake")
        try:
            first = self.post_logs(timeout=30).status_code
        except Exception:
            first = None
        self.assertNotEqual(first, 202, "a batch succeeded with no intake listening")

        # The intake appears on the port the edge was configured with.
        self.intake = EchoIntake(port=self.port)
        time.sleep(0.5)
        self.assertEqual(
            self.post_logs(timeout=30).status_code,
            202,
            "the edge did not recover once the intake appeared",
        )
        self.assertEqual(self.health().status_code, 200)
