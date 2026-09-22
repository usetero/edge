"""C11: bodies survive connection slot churn.

Each connection owns a slot with its receive, send, and body buffers. When a
connection closes, the edge tells the OS it may discard the slot's pages. The
next connection reuses that slot at once. If the discard lands after the new
owner started to use the pages, the kernel zeroes live data, and the intake
receives a corrupt or short body.

A unit test cannot reach this: the test I/O is single-threaded. Here 64
senders open a fresh connection per batch and close it, so slots turn over
under load, and every body is checked at the intake byte for byte.
"""

import threading

from harness import MatrixCase

SENDERS = 64
BATCHES_PER_SENDER = 20
#: Larger than a receive buffer, so the body spans the slot's body pages.
FILLER = 20 * 1024


def batch(sender: int, seq: int) -> bytes:
    marker = b"s%03d-b%03d" % (sender, seq)
    return b'[{"ddsource":"matrix","message":"%s","fill":"%s"}]' % (marker, marker * (FILLER // len(marker)))


class SlotChurnIntegrity(MatrixCase):
    def test_every_body_arrives_intact_under_slot_churn(self):
        sent = [batch(s, b) for s in range(SENDERS) for b in range(BATCHES_PER_SENDER)]
        failures = []
        lock = threading.Lock()

        def sender(index: int) -> None:
            for seq in range(BATCHES_PER_SENDER):
                body = batch(index, seq)
                try:
                    response = self.post_raw_body(body, timeout=60)
                    status = response.status_code
                except Exception as exc:  # noqa: BLE001 - recorded, then asserted
                    status = repr(exc)
                if status != 202:
                    with lock:
                        failures.append((index, seq, status))

        self.intake.capture_start("c11-churn")
        threads = [threading.Thread(target=sender, args=(i,), daemon=True) for i in range(SENDERS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        self.assertEqual([], failures, "%d batches were not accepted: %r" % (len(failures), failures[:5]))

        self.assertGreaterEqual(self.intake_saw(len(sent), timeout=30), len(sent))
        bodies = self.intake.capture_stop()
        self.assertEqual(len(sent), len(bodies), "the intake recorded %d of %d bodies" % (len(bodies), len(sent)))
        missing = set(sent) - set(bodies)
        extra = set(bodies) - set(sent)
        self.assertEqual(
            set(),
            missing | extra,
            "%d bodies never arrived intact and %d unknown bodies arrived; first unknown: %r"
            % (len(missing), len(extra), sorted(extra)[:1]),
        )
