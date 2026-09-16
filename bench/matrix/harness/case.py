"""The shared base every matrix case inherits.

One case is one file under `tests/`, and one class per file. The base starts a
fault-injecting intake and the edge binary under test, hands the case a set of
senders, and asserts the invariants that must hold whatever the fault was.

Every case asserts what a customer needs, not what either frontend happens to
do. Neither frontend is the oracle: both are judged against the expectation,
and either can fail.

A defect we have already found and recorded is declared with `DEFECTS`, keyed
by the frontend it affects. The case still runs, and the runner reports it as
`xfail` with the note, so the defect stays counted and visible rather than
skipped. If the case starts passing, the runner reports `XPASS`, which means
the defect is fixed and the note must go.

Class attributes a case may set:

    EDGE_CONFIG     merged into the generated edge config
    EDGE_ENV        extra environment for the edge process
    EDGE_POLICIES   policy document to load, so the decode path runs
    INTAKE_LATENCY  intake round trip, in milliseconds
    SLOW            true when the case waits for a 30 s deadline
    EXPECT_SHED     true when the case shed connections on purpose
    DEFECTS         {frontend: note} for behaviour we know is wrong today

Telemetry is part of the expectation, not an afterthought. A fault an operator
cannot see is still a fault, so declare it:

    EXPECT_METRICS      {series: minimum delta} for both frontends
    EXPECT_METRICS_FOR  {frontend: {series: minimum delta}} where a series is
                        frontend specific, such as the connection gauges
    EXPECT_LOGS         substrings that must appear in the edge log
    EXPECT_LOGS_FOR     {frontend: [substrings]}
    FORBID_LOGS         substrings that must NOT appear. This is the half that
                        earns its keep: it is how a sender-side fault is kept
                        from ever reading as an intake fault.
"""

from __future__ import annotations

import gzip
import json
import os
import tempfile
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
    EDGE_POLICIES: dict | None = None
    INTAKE_LATENCY: int = 0
    SLOW: bool = False
    EXPECT_SHED: bool = False
    DEFECTS: dict = {}
    EXPECT_METRICS: dict = {}
    EXPECT_METRICS_FOR: dict = {}
    EXPECT_LOGS: list = []
    EXPECT_LOGS_FOR: dict = {}
    FORBID_LOGS: list = []

    # A counter that moved must be explainable from the log. Checked in every
    # case, so a case that declares nothing still cannot pass with silent
    # telemetry.
    METRIC_NEEDS_LOG = (
        (("edge_request_errors_total", 'class="uncaught"'), "request.failed"),
        (("edge_request_errors_total", 'class="module"'), "policy.failed.open"),
        (("edge_upstream_timeouts_total",), "upstream.timed.out"),
        (("edge_upstream_retries_total",), "upstream.retried"),
        (("edge_connections_shed_total",), "connection.shed"),
        (("edge_requests_invalid_total",), "request.rejected"),
    )

    intake: EchoIntake
    edge: Edge

    @property
    def frontend(self) -> str:
        """Which frontend this run is exercising, from the runner."""
        return os.environ.get("EDGE_FRONTEND", "unknown")

    def run(self, result=None):
        """Turns a declared defect into a reported expected failure.

        The assertion stays exactly as strict as it is for the other frontend,
        so the defect keeps failing until somebody fixes it, and the day it
        passes the runner says so.
        """
        note = self.DEFECTS.get(self.frontend)
        if result is None or not note:
            return super().run(result)

        inner = unittest.TestResult()
        super().run(inner)
        result.startTest(self)
        try:
            if inner.skipped:
                result.addSkip(self, inner.skipped[0][1])
            elif inner.failures or inner.errors:
                detail = (inner.failures + inner.errors)[0][1].strip().splitlines()[-1]
                error = AssertionError("known defect on %s: %s [%s]" % (self.frontend, note, detail))
                result.addExpectedFailure(self, (AssertionError, error, None))
            else:
                result.addUnexpectedSuccess(self)
        finally:
            result.stopTest(self)
        return result

    def setUp(self) -> None:
        if os.environ.get("MATRIX_FAST") and self.SLOW:
            self.skipTest("slow case; unset MATRIX_FAST to run it")
        self.intake = EchoIntake(latency_ms=self.INTAKE_LATENCY)
        config = dict(self.EDGE_CONFIG)
        if self.EDGE_POLICIES is not None:
            handle = tempfile.NamedTemporaryFile("w", suffix=".policies.json", delete=False)
            json.dump(self.EDGE_POLICIES, handle)
            handle.close()
            self._policy_path = handle.name
            config["policy_providers"] = [{"id": "file", "type": "file", "path": handle.name}]
        try:
            self.edge = Edge(self.intake.url, config, self.EDGE_ENV)
        except Exception:
            self.intake.stop()
            raise
        # A stdio build without --prefix overwrites the httpz binary, which
        # would silently test one frontend twice. The edge reports its own
        # frontend, so trust that, not the path.
        running = self.edge.frontend()
        if running is not None and self.frontend in ("stdio", "httpz"):
            self.assertEqual(
                running,
                self.frontend,
                "EDGE_BIN carries the %s frontend, not %s; rebuild with "
                "--prefix zig-out-stdio" % (running, self.frontend),
            )
        self.baseline = self.edge.metrics()
        # Expectations are about what this case produced, so the startup lines
        # (which name the configured upstream) must not count. Diff by line,
        # because stdout and stderr are flushed independently.
        self.log_snapshot = set(self.edge.logs().splitlines())

    def tearDown(self) -> None:
        try:
            self.assert_telemetry()
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

    def case_logs(self) -> str:
        """Only the lines this case produced."""
        return "\n".join(
            line for line in self.edge.logs().splitlines() if line not in self.log_snapshot
        )

    def wait_for_log(self, needle: str, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.case_logs():
                return True
            time.sleep(0.2)
        return False

    def assert_logged(self, needle: str, why: str = "") -> None:
        if self.wait_for_log(needle):
            return
        logs = self.case_logs()
        self.assertIn(needle, logs, "%s\n--- edge log ---\n%s" % (why or "missing log line", logs))

    def assert_not_logged(self, needle: str) -> None:
        self.assertNotIn(needle, self.case_logs())

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

    # ------------------------------------------------------------- telemetry

    def assert_telemetry(self) -> None:
        """The declared metrics and logs, plus the universal pairing rule."""
        expected = dict(self.EXPECT_METRICS)
        expected.update(self.EXPECT_METRICS_FOR.get(self.frontend, {}))
        for series, minimum in expected.items():
            self.wait_for_metric(series, minimum, timeout=8)

        wanted = list(self.EXPECT_LOGS) + list(self.EXPECT_LOGS_FOR.get(self.frontend, []))
        for needle in wanted:
            self.assertTrue(
                self.wait_for_log(needle),
                "missing %r in the edge log:\n%s" % (needle, self.case_logs()),
            )

        # A forbidden line may still be on its way, so settle before looking.
        time.sleep(1.5)
        logs = self.case_logs()
        for needle in self.FORBID_LOGS:
            self.assertNotIn(
                needle,
                logs,
                "%r must not appear for this fault; it points at the wrong "
                "subsystem:\n%s" % (needle, logs),
            )

        metrics = self.edge.metrics()
        for parts, needle in self.METRIC_NEEDS_LOG:
            def matches(name: str, parts=parts) -> bool:
                return all(part in name for part in parts)

            moved = sum(v for k, v in metrics.items() if matches(k))
            base = sum(v for k, v in self.baseline.items() if matches(k))
            if moved > base:
                self.assertTrue(
                    self.wait_for_log(needle),
                    "%s moved but %r never appeared, so the event is "
                    "unexplainable from the log:\n%s"
                    % ("+".join(parts), needle, self.case_logs()),
                )

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
            ceiling = max(1.0, self.baseline.get("edge_connections_active", 1.0)) + 2
            deadline = time.monotonic() + 8
            active = metrics["edge_connections_active"]
            while active > ceiling and time.monotonic() < deadline:
                time.sleep(1.0)
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

        # A 5xx relayed from the intake is not our failure and owes no log
        # line; b06 asserts that relay. The errors we produce ourselves are
        # covered by METRIC_NEEDS_LOG in assert_telemetry.
