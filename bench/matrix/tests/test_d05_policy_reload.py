"""D05: the policy file changes while traffic flows.

The control plane rewrites policies in production. A reload must not fail
requests, and an invalid file must leave the previous snapshot in place rather
than disarming the edge.
"""

import json
import threading
import time

import requests

from harness import MatrixCase

KEEP_ALL = {
    "policies": [
        {
            "id": "keep-all",
            "name": "keep-all",
            "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
        }
    ]
}


class PolicyReloadUnderLoad(MatrixCase):
    SLOW = True
    EDGE_POLICIES = KEEP_ALL

    def test_a_reload_does_not_fail_requests(self):
        failures = []
        stop = threading.Event()

        def sender():
            # One connection per thread, as an agent keeps one. A connection
            # per request runs the machine out of ephemeral ports in seconds
            # at this rate, and the case then fails on the sender's local
            # address instead of on the reload.
            with requests.Session() as session:
                while not stop.is_set():
                    try:
                        if self.post_logs(timeout=20, session=session).status_code != 202:
                            failures.append("status")
                    except Exception as err:
                        failures.append(repr(err))

        traffic = [threading.Thread(target=sender, daemon=True) for _ in range(4)]
        for thread in traffic:
            thread.start()
        try:
            time.sleep(1)
            # A valid rewrite, then a broken one.
            with open(self._policy_path, "w") as handle:
                json.dump(KEEP_ALL, handle)
            time.sleep(2)
            with open(self._policy_path, "w") as handle:
                handle.write("{ this is not json")
            time.sleep(3)
        finally:
            stop.set()
            for thread in traffic:
                thread.join(timeout=30)

        self.assertEqual(
            failures[:3], [], "%d of the requests failed across the reload" % len(failures)
        )
        self.assertEqual(self.health().status_code, 200)
