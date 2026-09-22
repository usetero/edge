"""B29: the Prometheus scrape path, which nothing else covers.

`/metrics` fetches from the upstream and filters it. A refused dial and a hung
intake must both end in a status rather than a hang, and a scraper must never
read a partial exposition as a complete one.
"""

import time

from harness import MatrixCase


class ScrapeWithRefusedDial(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_PERMANENT_DROP = True

    def test_a_refused_scrape_answers_promptly(self):
        self.intake.stop()
        started = time.monotonic()
        try:
            status = self.session_get("/metrics", timeout=30)
        except Exception:
            status = None
        self.assertLess(time.monotonic() - started, 20, "the scrape hung")
        if status is not None:
            self.assertEqual(status // 100, 5, "got %d" % status)

    def session_get(self, path, timeout=30):
        import requests

        return requests.get(self.edge.url + path, timeout=timeout).status_code


class ScrapeWithHungIntake(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_PERMANENT_DROP = True

    def test_a_hung_scrape_is_cut_at_the_deadline(self):
        import requests

        self.intake.arm("hang")
        started = time.monotonic()
        status = None
        try:
            status = requests.get(self.edge.url + "/metrics", timeout=120).status_code
        except Exception:
            pass
        self.assertLess(time.monotonic() - started, 45, "the scrape outlived the deadline")
        # A stall must read as 504, not 502. The watchdog shuts the upstream
        # socket down, so the in-flight send/receive fails with a generic
        # transport error; without the timed_out check on this path that error
        # falls through to the 502 arm and a stalled upstream is
        # indistinguishable from a broken one.
        if status is not None:
            self.assertEqual(504, status, "a stalled upstream must read as 504")
