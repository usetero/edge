"""A34: the spellings of an encoding an agent may send.

stdio maps `content-encoding` through a std enum and httpz passes the raw
string to the router, so the two can disagree about the same header. Policies
are loaded, so the decode path actually runs.
"""

import gzip
import json

from harness import MatrixCase

BATCH = json.dumps([{"message": "spelling", "ddsource": "matrix"}]).encode()


class EncodingSpellings(MatrixCase):
    # Content codings are case-insensitive (RFC 9110 §8.4.1), but
    # `std.http.Server` matches them case-sensitively, so stdio refuses
    # `GZIP` with a 400 — which the agent discards for good.
    DEFECTS = {"stdio": "refuses an uppercase content-encoding with 400"}
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "keep-all",
                "name": "keep-all",
                "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"},
            }
        ]
    }

    def test_every_gzip_spelling_reaches_the_intake(self):
        spellings = ("gzip", "GZIP", "x-gzip", "gzip ")
        if self.frontend == "httpz":
            # httpz forwards the raw string, so the case would only prove that
            # our own std-based intake refuses `GZIP`, as in a10.
            spellings = ("gzip", "x-gzip", "gzip ")
        for spelling in spellings:
            with self.subTest(spelling=spelling):
                before = self.intake.requests_seen()
                response = self.post_raw_body(
                    gzip.compress(BATCH), headers={"Content-Encoding": spelling}
                )
                self.assertEqual(
                    response.status_code,
                    202,
                    "%r answered %d" % (spelling, response.status_code),
                )
                self.assertGreater(
                    self.intake.requests_seen(),
                    before,
                    "%r never reached the intake" % spelling,
                )
