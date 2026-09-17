"""B12: the intake accepts nothing and the dial hangs.

`std.http.Client` takes no connect timeout and the upstream watchdog has no
socket to interrupt until the dial returns, so a handler is held for the
kernel's connect timeout. A sender should not wait minutes for an answer the
edge already knows it cannot give.
"""

import socket
import time

from harness import MatrixCase, free_port
from harness.procs import Edge


class DialBlackhole(MatrixCase):
    SLOW = True
    DEFECTS = {
        "stdio": "the dial has no deadline, so the sender waits for the kernel",
        "httpz": "the dial has no deadline, so the sender waits for the kernel",
    }
    ALLOW_PHANTOM_SUCCESS = True

    def setUp(self):
        super().setUp()
        # Replace the edge with one pointed at an address that swallows SYNs.
        self.edge.stop()
        self.blackhole = socket.socket()
        self.blackhole.bind(("127.0.0.1", free_port()))
        self.blackhole.listen(1)
        self.fillers = []
        for _ in range(8):  # fill the accept queue so further SYNs are dropped
            filler = socket.socket()
            filler.setblocking(False)
            try:
                filler.connect_ex(("127.0.0.1", self.blackhole.getsockname()[1]))
            except OSError:
                pass
            self.fillers.append(filler)
        self.edge = Edge("http://127.0.0.1:%d" % self.blackhole.getsockname()[1])
        self.baseline = self.edge.metrics()
        self.log_snapshot = set(self.edge.logs().splitlines())
        self.baseline_descriptors = self.edge.descriptors()
        self.baseline_intake = self.intake.requests_seen()

    def tearDown(self):
        for filler in self.fillers:
            filler.close()
        self.blackhole.close()
        super().tearDown()

    def test_a_blackholed_dial_is_bounded(self):
        started = time.monotonic()
        try:
            status = self.post_logs(timeout=120).status_code
        except Exception:
            status = None
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            35,
            "the sender waited %.0f s for a dial that never connects" % elapsed,
        )
        if status is not None:
            self.assertIn(status, (502, 504))
