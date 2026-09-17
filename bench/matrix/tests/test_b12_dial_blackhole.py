"""B12: the intake accepts nothing and the dial hangs.

`std.http.Client` takes no connect timeout and the upstream watchdog has no
socket to interrupt until the dial returns, so a handler is held for the
kernel's connect timeout. A sender should not wait minutes for an answer the
edge already knows it cannot give.

The blackhole is `198.51.100.1`, reserved for documentation by RFC 5737, which
swallows the SYN. An earlier version pointed at a loopback listener with a
filled accept queue; loopback accepted the connection anyway, so the case
measured the request deadline instead of the dial and passed for the wrong
reason. Where a host refuses the route rather than dropping it, the case skips
rather than claim a bound it did not test.
"""

import socket
import time

from harness import MatrixCase
from harness.procs import Edge

#: Reserved for documentation (RFC 5737), so nothing answers and nothing
#: refuses: the SYN goes nowhere.
BLACKHOLE = "198.51.100.1"


def route_drops_syns(timeout: float = 2.0) -> bool:
    probe = socket.socket()
    probe.settimeout(timeout)
    try:
        probe.connect((BLACKHOLE, 80))
    except socket.timeout:
        return True
    except OSError:
        return False
    finally:
        probe.close()
    return False


class DialBlackhole(MatrixCase):
    SLOW = True
    DEFECTS = {
        "stdio": "the dial has no deadline, so the sender waits for the kernel",
        "httpz": "the dial has no deadline, so the sender waits for the kernel",
    }
    ALLOW_PHANTOM_SUCCESS = True

    def setUp(self):
        super().setUp()
        if not route_drops_syns():
            self.skipTest("this host answers or refuses %s; nothing here swallows a SYN" % BLACKHOLE)
        # Replace the edge with one pointed at an address that goes nowhere.
        self.edge.stop()
        self.edge = Edge("http://%s:80" % BLACKHOLE)
        self.baseline = self.edge.metrics()
        self.log_snapshot = set(self.edge.logs().splitlines())
        self.baseline_descriptors = self.edge.descriptors()
        self.baseline_intake = self.intake.requests_seen()

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
