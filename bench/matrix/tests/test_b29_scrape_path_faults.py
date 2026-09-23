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


def incomplete_scrape_status(case, timeout):
    """Scrapes /metrics when the upstream body will fail, and returns the status.

    A scraper must never read a short exposition as complete. There are two
    honest answers. A frontend that has sent the head must break the transfer,
    and then the status is None. A frontend that buffers the response can
    still replace it with an error status. A 2xx with a clean end is the
    failure.
    """
    import requests

    try:
        response = requests.get(case.edge.url + "/metrics", timeout=timeout)
    except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError):
        return None
    case.assertNotEqual(2, response.status_code // 100, "a failed upstream body was reported as a complete scrape")
    return response.status_code


class ScrapeWithHungIntake(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_PERMANENT_DROP = True

    def test_a_hung_scrape_is_cut_at_the_deadline(self):
        import requests

        self.intake.arm("hang")
        started = time.monotonic()
        # No try/except: a closed socket with no response must fail the test.
        status = requests.get(self.edge.url + "/metrics", timeout=120).status_code
        self.assertLess(time.monotonic() - started, 45, "the scrape outlived the deadline")
        # A stall must read as 504, not 502. The watchdog closes the upstream
        # socket, and without the timed_out check that failure maps to 502.
        self.assertEqual(504, status, "a stalled upstream must read as 504")


class ScrapeWithStalledBody(MatrixCase):
    SLOW = True
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_METRICS = {"edge_upstream_timeouts_total": 1}
    EXPECT_LOGS = ["upstream.timed.out", "UpstreamTimeout"]

    def test_a_stalled_scrape_body_is_not_reported_as_complete(self):
        # Headers arrive immediately, but the body takes 80 s.
        self.intake.arm("slow_body", arg=10000, count=1)
        started = time.monotonic()
        status = incomplete_scrape_status(self, timeout=60)
        self.assertLess(time.monotonic() - started, 45, "the scrape body outlived the deadline")
        if status is not None:
            self.assertEqual(504, status, "a stalled upstream body must read as 504")


class ScrapeWithTruncatedBody(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_LOGS = ["UpstreamResponseTruncated"]

    def test_a_short_scrape_body_is_not_reported_as_complete(self):
        import requests

        self.intake.arm("truncate_after_read", count=1)
        status = incomplete_scrape_status(self, timeout=10)
        if status is not None:
            self.assertEqual(502, status, "a short upstream body must read as 502")
        self.assertEqual(202, requests.get(self.edge.url + "/metrics", timeout=10).status_code)
