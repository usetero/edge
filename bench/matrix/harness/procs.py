"""Process control for the two servers every case needs.

`EchoIntake` is the real `zig-out/bin/echo-server`, which carries the fault
modes the matrix drives (`POST /fault?mode=...`). `Edge` is the real edge
binary under test. Both write their logs to files the case can read, because
half the assertions are about what we logged, not only what we answered.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(url: str, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.read().decode("utf-8", "replace")


class EchoIntake:
    """The fake Datadog intake: `src/bench/echo_server.zig`."""

    BINARY = os.path.join(REPO_ROOT, "zig-out", "bin", "echo-server")

    def __init__(self, latency_ms: int = 0):
        self.port = free_port()
        self.log_path = tempfile.mktemp(suffix=".echo.log")
        env = dict(os.environ)
        env["ECHO_LATENCY_MS"] = str(latency_ms)
        self._log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(
            [self.BINARY, str(self.port), tempfile.gettempdir()],
            stdout=self._log,
            stderr=self._log,
            env=env,
        )
        self._wait_ready()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self.port

    def _wait_ready(self, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.stats()
                return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise RuntimeError("echo server never became ready: %s" % self.log_path)

    def stats(self) -> dict:
        return json.loads(_get("%s/stats" % self.url))

    def reset(self) -> None:
        urllib.request.urlopen("%s/reset" % self.url, data=b"", timeout=5).read()

    def arm(self, mode: str, arg: int = 0, count: int | None = None) -> None:
        """Injects an intake fault. `count` limits it to the next N requests."""
        query = "mode=%s&arg=%d" % (mode, arg)
        if count is not None:
            query += "&count=%d" % count
        urllib.request.urlopen("%s/fault?%s" % (self.url, query), data=b"", timeout=5).read()

    def faults_applied(self) -> int:
        return int(self.stats().get("fault_applied", 0))

    def requests_seen(self) -> int:
        return int(self.stats().get("total_requests", 0))

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._log.close()


class Edge:
    """The edge binary under test, with a config written for this case."""

    def __init__(self, upstream_url: str, config: dict | None = None, env: dict | None = None):
        self.port = free_port()
        self.binary = os.environ.get("EDGE_BIN", os.path.join(REPO_ROOT, "zig-out", "bin", "edge"))
        merged = {
            "listen_address": "127.0.0.1",
            "listen_port": self.port,
            "upstream_url": upstream_url,
            "log_level": "info",
            "max_body_size": 1048576,
        }
        merged.update(config or {})
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(merged, handle)
        handle.close()
        self.config_path = handle.name
        self.config = merged

        self.out_path = tempfile.mktemp(suffix=".edge.out.log")
        self.err_path = tempfile.mktemp(suffix=".edge.err.log")
        self._out = open(self.out_path, "wb")
        self._err = open(self.err_path, "wb")
        process_env = dict(os.environ)
        process_env.update(env or {})
        self.proc = subprocess.Popen(
            [self.binary, self.config_path],
            stdout=self._out,
            stderr=self._err,
            env=process_env,
        )
        self._wait_ready()

    @property
    def url(self) -> str:
        return "http://127.0.0.1:%d" % self.port

    def _wait_ready(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("edge exited early:\n%s" % self.logs())
            try:
                if _get("%s/_health" % self.url, timeout=1.0):
                    return
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        raise RuntimeError("edge never answered /_health:\n%s" % self.logs())

    def alive(self) -> bool:
        return self.proc.poll() is None

    def logs(self) -> str:
        """Both streams. INFO and WARN land on stdout, ERROR on stderr."""
        self._out.flush()
        self._err.flush()
        parts = []
        for path in (self.out_path, self.err_path):
            with open(path, "r", errors="replace") as handle:
                parts.append(handle.read())
        return "".join(parts)

    def metrics(self) -> dict[str, float]:
        """The Prometheus scrape as a flat {series: value} map, labels kept."""
        out: dict[str, float] = {}
        try:
            text = _get("%s/_edge/metrics" % self.url, timeout=10)
        except (OSError, urllib.error.URLError):
            return out
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            name, _, value = line.rpartition(" ")
            try:
                out[name.strip()] = float(value)
            except ValueError:
                continue
        return out

    def metric(self, name: str, default: float = 0.0) -> float:
        return self.metrics().get(name, default)

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._out.close()
        self._err.close()
        try:
            os.unlink(self.config_path)
        except OSError:
            pass
