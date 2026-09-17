"""A35: a small body that expands past the decoded cap.

With policies loaded the edge must decode to evaluate, so a bomb is a memory
question. Bounded rejection is the requirement; an unbounded decode is not.
Without policies the same body must forward untouched, since nothing reads it.
"""

import gzip
import time

from harness import MatrixCase

BOMB = gzip.compress(b"[" + b'{"message":"' + b"a" * (40 * 1024 * 1024) + b'"}' + b"]")


class DecompressionBombWithPolicies(MatrixCase):
    # The agent discards a payload for good on 413 (harness/agent.py), so a
    # decode budget the sender cannot see must not end the batch. The policy
    # paths fail open instead, and this case holds that line.
    EDGE_CONFIG = {"max_body_size": 1048576, "max_decoded_bytes": 1048576}
    EDGE_POLICIES = {
        "policies": [
            {
                "id": "keep-all",
                "name": "keep-all",
                "log": {"match": [{"log_field": "body", "regex": ".*"}], "keep": "all"},
            }
        ]
    }
    ALLOW_PHANTOM_SUCCESS = True

    def test_a_bomb_is_bounded(self):
        started = time.monotonic()
        response = self.post_raw_body(BOMB, headers={"Content-Encoding": "gzip"}, timeout=60)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 30, "the decode was not bounded promptly")
        self.assertIn(
            response.status_code,
            (202, 413),
            "a bomb owes either a bounded rejection or a fail-open forward, got %d"
            % response.status_code,
        )


class DecompressionBombWithoutPolicies(MatrixCase):
    EDGE_CONFIG = {"max_body_size": 1048576, "max_decoded_bytes": 1048576}

    def test_without_policies_the_body_is_never_decoded(self):
        response = self.post_raw_body(BOMB, headers={"Content-Encoding": "gzip"}, timeout=60)
        self.assert_status(response, 202, "nothing reads the body, so it must forward")
        self.assertGreaterEqual(self.intake_saw(1), 1)
