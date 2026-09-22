"""C06: memory under repeated saturation.

Three rounds of concurrent large batches. RSS must not climb between rounds:
a per-connection or per-thread buffer that is never reused shows up here and
nowhere else.
"""

import json
import subprocess
import threading
import time

from harness import MatrixCase


def rss_mb(pid: int) -> float:
    out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    try:
        return int(out.stdout.strip()) / 1024
    except ValueError:
        return -1.0


class MemoryBudget(MatrixCase):
    SLOW = True
    EDGE_CONFIG = {"max_body_size": 1048576}

    def test_rss_does_not_climb_between_rounds(self):
        body = json.dumps([{"message": "x" * 500 * 1024}]).encode()
        rounds = []

        for _ in range(3):
            threads = []
            for _ in range(32):
                thread = threading.Thread(target=lambda: self._quiet_post(body), daemon=True)
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join(timeout=60)
            rounds.append(rss_mb(self.edge.pid))

        self.assertGreater(rounds[0], 0, "could not read RSS")
        growth = rounds[-1] - rounds[1]
        self.assertLess(
            growth,
            32,
            "RSS grew %.0f MB between rounds: %s" % (growth, [round(r) for r in rounds]),
        )

    def _quiet_post(self, body):
        try:
            self.post_raw_body(body, timeout=60)
        except Exception:
            pass



def chunked(body: bytes, chunk: int = 16384) -> bytes:
    out = [b"%x\r\n%s\r\n" % (len(body[i : i + chunk]), body[i : i + chunk]) for i in range(0, len(body), chunk)]
    return b"".join(out) + b"0\r\n\r\n"


class ChunkedBodiesCostNoMoreThanContentLength(MatrixCase):
    """A chunked body must not cost more resident memory than a declared one.

    A chunked body has no declared length. A frontend that drains it into a
    per-connection arena retains body-sized capacity for the connection's
    life, and a frontend that buffers it whole grows with every round. Three
    Content-Length rounds warm the per-thread buffers and give the control.
    Four chunked rounds then follow on the same process.

    Twelve senders, so the upstream connections the client pools afterwards
    stay inside the descriptor budget the teardown checks.
    """

    SLOW = True
    EDGE_CONFIG = {"max_body_size": 1048576}
    DEFECTS = {
        "httpz": "RSS rises about 23 MB when bodies switch to chunked and about 12 MB per round after that",
    }
    SENDERS = 12

    def test_chunked_rounds_cost_no_more_and_do_not_grow(self):
        body = json.dumps([{"message": "x" * 900 * 1024}]).encode()
        declared = self.head(body_len=len(body)) + body
        framed = self.head(body_len=None, extra="Transfer-Encoding: chunked") + chunked(body)

        control = [self._round(declared) for _ in range(3)]
        chunked_rounds = [self._round(framed) for _ in range(4)]
        self.assertGreater(control[0], 0, "could not read RSS")

        switch_cost = chunked_rounds[0] - control[-1]
        self.assertLess(
            switch_cost,
            12,
            "the first chunked round cost %.0f MB more than a Content-Length round: control %s, chunked %s"
            % (switch_cost, [round(r) for r in control], [round(r) for r in chunked_rounds]),
        )
        growth = chunked_rounds[-1] - chunked_rounds[0]
        self.assertLess(
            growth,
            12,
            "RSS grew %.0f MB across chunked rounds: %s" % (growth, [round(r) for r in chunked_rounds]),
        )

    def _round(self, wire: bytes) -> float:
        threads = [threading.Thread(target=lambda: self._quiet_send(wire), daemon=True) for _ in range(self.SENDERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        time.sleep(1.0)
        return rss_mb(self.edge.pid)

    def _quiet_send(self, wire: bytes) -> None:
        try:
            with self.raw(timeout=60) as client:
                client.send(wire)
                client.read_response()
        except Exception:
            pass
