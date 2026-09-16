"""The shared base every matrix case inherits.

One case is one file under `tests/`, and one class per file. The base starts a
fault-injecting intake and the edge binary under test, hands the case a set of
senders, and asserts the invariants that must hold whatever the fault was.

Class attributes a case may set:

    EDGE_CONFIG     merged into the generated edge config
    EDGE_ENV        extra environment for the edge process
    INTAKE_LATENCY  intake round trip, in milliseconds
    SLOW            true when the case waits for a 30 s deadline
    EXPECT_SHED     true when the case shed connections on purpose
"""

from __future__ import annotations

import gzip
import json
import os
import time
import unittest

from .procs import Edge, EchoIntake
from .raw import RawClient, request_head

try:
    import requests
except ImportError:  # pragma: no cover - the runner installs it
    requests = None

LOG_PAYLOAD = [{"message": "matrix case", "ddsource": "matrix", "service": "suite"}]


class MatrixCase(unittest.TestCase):
    EDGE_CONFIG: dict = {}
    EDGE_ENV: dict = {}
    INTAKE_LATENCY: int = 0
    SLOW: bool = False
    EXPECT_SHED: bool = False

    intake: EchoIntake
    edge: Edge

    @property
    def frontend(self) -> str:
        """Which frontend this run is exercising, from the runner."""
        return os.environ.get("EDGE_FRONTEND", "unknown")

    def expect_difference(self, frontend: str, reason: str) -> None:
        """Marks a case that is known to behave differently on `frontend`.

        The suite stays green where we intend the difference and stays loud
        everywhere else, instead of weakening the assertion for both.
        """
        if self.frontend == frontend:
            self.skipTest("known difference on %s: %s" % (frontend, reason))

    def setUp(self) -> None:
        if os.environ.get("MATRIX_FAST") and self.SLOW:
            self.skipTest("slow case; unset MATRIX_FAST to run it")
        self.intake = EchoIntake(latency_ms=self.INTAKE_LATENCY)
        try:
            self.edge = Edge(self.intake.url, self.EDGE_CONFIG, self.EDGE_ENV)
        except Exception:
            self.intake.stop()
            raise
        self.baseline = self.edge.metrics()

    def tearDown(self) -> None:
        try:
            self.assert_invariants()
        finally:
            self.edge.stop()
            self.intake.stop()

    # ---------------------------------------------------------------- senders

    def post_logs(self, body=None, path: str = "/api/v2/logs", headers=None, timeout: float = 60.0):
        """A well-formed request, the way an agent sends one."""
        self.assertIsNotNone(requests, "run through bench/matrix/run.py, which supplies requests")
        payload = json.dumps(LOG_PAYLOAD if body is None else body).encode()
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        return requests.post(self.edge.url + path, data=payload, headers=merged, timeout=timeout)

    def post_raw_body(self, body: bytes, path: str = "/api/v2/logs", headers=None, timeout: float = 60.0):
        self.assertIsNotNone(requests, "run through bench/matrix/run.py, which supplies requests")
        merged = {"Content-Type": "application/json"}
        merged.update(headers or {})
        return requests.post(self.edge.url + path, data=body, headers=merged, timeout=timeout)

    def gzipped(self, body=None) -> bytes:
        return gzip.compress(json.dumps(LOG_PAYLOAD if body is None else body).encode())

    def raw(self, timeout: float = 60.0) -> RawClient:
        return RawClient(self.edge.port, timeout=timeout)

    def head(self, path: str = "/api/v2/logs", body_len: int | None = None, extra: str = "") -> bytes:
        return request_head(path, body_len, extra)

    def health(self, timeout: float = 10.0):
        self.assertIsNotNone(requests, "run through bench/matrix/run.py, which supplies requests")
        return requests.get(self.edge.url + "/_health", timeout=timeout)

    # --------------------------------------------------------------- asserts

    def assert_status(self, response, expected: int, why: str = "") -> None:
        got = getattr(response, "status", None)
        if got is None:
            got = getattr(response, "status_code", None)
        self.assertEqual(got, expected, "%s (response: %r)" % (why or "wrong status", response))

    def assert_logged(self, needle: str, why: str = "") -> None:
        logs = self.edge.logs()
        self.assertIn(needle, logs, "%s\n--- edge log ---\n%s" % (why or "missing log line", logs))

    def assert_not_logged(self, needle: str) -> None:
        self.assertNotIn(needle, self.edge.logs())

    def metric_delta(self, name: str) -> float:
        """How much a counter moved since the case started."""
        return self.edge.metric(name) - self.baseline.get(name, 0.0)

    def wait_for_metric(self, name: str, at_least: float, timeout: float = 10.0) -> float:
        deadline = time.monotonic() + timeout
        value = self.metric_delta(name)
        while value < at_least and time.monotonic() < deadline:
            time.sleep(0.2)
            value = self.metric_delta(name)
        self.assertGreaterEqual(value, at_least, "%s never reached %s" % (name, at_least))
        return value

    def intake_saw(self, at_least: int, timeout: float = 10.0) -> int:
        deadline = time.monotonic() + timeout
        seen = self.intake.requests_seen()
        while seen < at_least and time.monotonic() < deadline:
            time.sleep(0.1)
            seen = self.intake.requests_seen()
        return seen

    # ------------------------------------------------------------ invariants

    def assert_invariants(self) -> None:
        """Holds in every cell, whatever the fault was."""
        self.assertTrue(self.edge.alive(), "the edge process died:\n%s" % self.edge.logs())

        # It must still serve after the fault.
        health = self.health()
        self.assertEqual(health.status_code, 200, "health broke after the case")

        # Connection accounting must return to its baseline. stdio only: httpz
        # cannot report this without a patch to the dependency. The scrape
        # itself holds a slot, and the health probe above may still be on its
        # way out, so the floor is the baseline plus one.
        metrics = self.edge.metrics()
        if "edge_connections_active" in metrics:
            ceiling = max(1.0, self.baseline.get("edge_connections_active", 1.0)) + 1
            deadline = time.monotonic() + 5
            active = metrics["edge_connections_active"]
            while active > ceiling and time.monotonic() < deadline:
                time.sleep(0.25)
                metrics = self.edge.metrics()
                active = metrics["edge_connections_active"]
            self.assertLessEqual(
                active,
                ceiling,
                "connection slots leaked (%s open):\n%s" % (active, self.edge.logs()),
            )

        if not self.EXPECT_SHED:
            shed = sum(v for k, v in metrics.items() if k.startswith("edge_connections_shed_total"))
            base = sum(v for k, v in self.baseline.items() if k.startswith("edge_connections_shed_total"))
            self.assertEqual(shed, base, "connections were shed unexpectedly")

        # Every 5xx the edge produced itself must have a log line naming it.
        logs = self.edge.logs()
        errors = sum(
            v for k, v in metrics.items() if k.startswith("edge_responses_total") and 's5xx' in k
        )
        base_errors = sum(
            v for k, v in self.baseline.items() if k.startswith("edge_responses_total") and 's5xx' in k
        )
        if errors > base_errors:
            self.assertTrue(
                "request.failed" in logs or "upstream" in logs,
                "a 5xx was answered with nothing in the log:\n%s" % logs,
            )
