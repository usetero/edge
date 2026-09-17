"""B21: the intake rejects a large batch on its head.

The early-response path answers before the body finished, so part of the
request body is still on the inbound socket. The next request on that same
connection must be served, not parsed out of the leftovers.
"""

import json

import requests

from harness import MatrixCase


class RejectEarlyStreamed(MatrixCase):
    ALLOW_PHANTOM_SUCCESS = True
    EXPECT_PERMANENT_DROP = True  # the intake rejected it, not us

    def test_the_next_request_on_the_connection_is_still_served(self):
        session = requests.Session()
        try:
            big = json.dumps([{"message": "x" * 200 * 1024}]).encode()
            self.intake.arm("reject_early", count=1)
            first = session.post(
                self.edge.url + "/api/v2/logs",
                data=big,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
            self.assertEqual(first.status_code, 400, repr(first))

            second = session.post(
                self.edge.url + "/api/v2/logs",
                json=[{"message": "after the rejection"}],
                timeout=60,
            )
            self.assertEqual(
                second.status_code,
                202,
                "the follow-up was answered %d, so leftover body bytes were "
                "parsed as a request" % second.status_code,
            )
        finally:
            session.close()
