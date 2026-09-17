"""C09: the log destination stops draining.

An ECS log driver in blocking mode does exactly this. A logger that blocks on
a full pipe takes the data plane with it, so the edge must keep serving even
when nothing reads its logs.
"""

from harness import MatrixCase, EchoIntake
from harness.procs import Edge


class LogBackPressure(MatrixCase):
    SLOW = True
    # The case is about staying alive with a stalled log pipe, not delivery.
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_PERMANENT_DROP = True

    def setUp(self):
        self.intake = EchoIntake()
        # Logs go to a pipe nobody reads. 64 KiB of pipe buffer fills fast
        # once every request fails.
        self.edge = Edge(self.intake.url, {"log_level": "info"}, stall_logs=True)
        self.baseline = self.edge.metrics()
        self.log_snapshot = set()
        self.baseline_descriptors = self.edge.descriptors()
        self.baseline_intake = self.intake.requests_seen()

    def test_the_edge_serves_while_its_logs_are_ignored(self):
        self.intake.arm("reject_early")  # every request logs
        for _ in range(400):
            try:
                self.post_logs(timeout=20)
            except Exception:
                pass
        self.assertEqual(
            self.health(timeout=10).status_code,
            200,
            "the edge stopped serving once its log pipe filled",
        )
