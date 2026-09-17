"""B11b: what a truncated answer means, and what our 502 costs.

The challenge to b11: if the intake wrote a 202 head, it accepted the batch,
so a truncated response body changes nothing about the data, and answering 502
makes a retrying sender deliver a second copy.

That depends entirely on *when* the answer broke, so this measures both:

  truncate             the intake answers before reading the body. The batch
                       never arrived, so a 502 and a retry repair it.
  truncate_after_read  the intake reads the whole batch, then breaks its
                       answer. The batch is already in, so a 502 and a retry
                       duplicate it.
"""

import json

from harness import MatrixCase

BATCH = [{"message": "truncation semantics", "ddsource": "matrix"}]
PAYLOAD = json.dumps(BATCH).encode()


class TruncatedBeforeTheBodyWasRead(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_batch_never_arrived_so_a_retry_repairs_it(self):
        self.intake.arm("truncate", count=1)
        try:
            self.post_raw_body(PAYLOAD, timeout=30)
        except Exception:
            pass

        received = self.intake.stats()["endpoints"].get("/api/v2/logs", {}).get("bytes", 0)
        self.assertEqual(received, 0, "the intake read %d bytes before truncating" % received)


class TruncatedAfterTheBodyWasRead(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True

    def test_the_batch_arrived_so_our_502_costs_a_duplicate(self):
        self.intake.arm("truncate_after_read", count=1)
        try:
            first = self.post_raw_body(PAYLOAD, timeout=30).status_code
        except Exception:
            first = None

        received = self.intake.stats()["endpoints"].get("/api/v2/logs", {}).get("bytes", 0)
        self.assertEqual(
            received,
            len(PAYLOAD),
            "the intake accepted %d of %d body bytes before its answer broke"
            % (received, len(PAYLOAD)),
        )

        # A sender that retries a transport failure or a 5xx, which is what a
        # log agent does.
        if first is None or first >= 500:
            self.post_raw_body(PAYLOAD, timeout=30)

        delivered = self.intake.requests_seen() - self.baseline_intake
        self.assertEqual(
            delivered,
            2,
            "the retry delivered %d copies of a batch the intake already had" % delivered,
        )
