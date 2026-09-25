"""C10: many senders give up mid-batch while others finish, with policies.

A44 to A46 each send one input. This case mixes them with complete batches.
In a ReleaseFast build, one bad request can damage memory that a later valid
request uses. So valid traffic runs on the same process and is checked after.
"""

import gzip
import random
import threading

from harness import MatrixCase

POLICIES = {
    "policies": [
        {
            "id": "drop-debug",
            "name": "drop-debug",
            "log": {"match": [{"log_field": "body", "regex": "^DEBUG"}], "keep": "none"},
        }
    ]
}


class AbandonChurn(MatrixCase):
    EDGE_POLICIES = POLICIES
    DEFECTS = {"stdio": "a partial gzip batch reaches the decoder, and the process dies"}

    def test_valid_batches_survive_a_stream_of_abandoned_ones(self):
        rng = random.Random(24)
        bodies = [gzip.compress(self.log_batch(size, level="DEBUG"), 1) for size in (2_000, 20_000, 60_000)]
        errors: list[str] = []

        def abandoner(seed: int) -> None:
            local = random.Random(seed)
            for _ in range(40):
                body = local.choice(bodies)
                try:
                    self.abandon(
                        body,
                        local.randrange(1, len(body)),
                        extra="Content-Encoding: gzip",
                        half_close=local.random() < 0.5,
                        timeout=10,
                    )
                except OSError as err:
                    errors.append("abandon: %r" % err)

        threads = [threading.Thread(target=abandoner, args=(rng.random(),)) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertTrue(self.edge.alive(), "the edge died:\n%s" % self.edge.logs())

        # Valid traffic after the churn must still decode, filter, and arrive.
        for body in bodies:
            response = self.post_raw_body(body, headers={"Content-Encoding": "gzip"}, timeout=30)
            self.assertIn(response.status_code, (200, 202), "a valid batch failed after the churn")
        self.assertEqual(errors, [], "a sender could not even connect")
