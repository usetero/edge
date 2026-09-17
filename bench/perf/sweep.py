#!/usr/bin/env python3
"""Throughput, latency and memory across the shapes and settings that matter.

Drives `oha` against the real edge binary with the real echo server behind it,
for both frontends, and prints one table per axis. Each axis varies one thing
and holds the rest at the baseline, so a row is readable on its own and two
runs on the same host are comparable.

    ./bin/uv run --python ./bin/python3 --with requests bench/perf/sweep.py
    ./bin/uv run --python ./bin/python3 --with requests bench/perf/sweep.py --axes policies,latency
    ./bin/uv run --python ./bin/python3 --with requests bench/perf/sweep.py --seconds 20 --frontend stdio

Baseline: the small Datadog payload, 64 connections, one policy loaded, an
intake that answers immediately, and the shipped thread-pool and connection
limits.

Axes:

    payload    small (228 B), boundary (64 KiB, where a body stops being held
               resident), large (the 1.4 MB Datadog payload), gzip
    conns      concurrent senders
    policies   how many rules are loaded. Most do not match, which is the
               shape a real policy set has
    latency    what the intake costs per request, in milliseconds
    threads    `thread_pool_count`. httpz sizes its handler pool from this;
               stdio runs a task per connection and ignores it, which is worth
               showing rather than assuming
    maxconn    `max_connections`, which sizes the connection slab on stdio and
               the per-worker connection table on httpz
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

sys.stdout.reconfigure(line_buffering=True)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "bench", "matrix"))

from harness import Edge, EchoIntake  # noqa: E402

BINARIES = {
    "httpz": os.path.join(REPO_ROOT, "zig-out", "bin", "edge"),
    "stdio": os.path.join(REPO_ROOT, "zig-out-stdio", "bin", "edge"),
}

PAYLOAD_DIR = os.path.join(REPO_ROOT, "bench", "perf", "payloads")

#: One row of settings. The axes below each change a single field.
BASELINE = {
    "payload": "small",
    "conns": 64,
    "policies": 1,
    "latency": 0,
    "threads": None,   # None means the shipped default
    "maxconn": None,
}

AXES = {
    "payload": ["small", "boundary", "large", "gzip"],
    "conns": [16, 64, 256],
    "policies": [0, 1, 10, 50],
    "latency": [0, 5, 50, 200],
    "threads": [8, 32, 128],
    "maxconn": [64, 256, 1024],
}


def payload(name: str) -> tuple[bytes, dict]:
    if name == "small":
        with open(os.path.join(PAYLOAD_DIR, "datadog-small.json"), "rb") as handle:
            return handle.read(), {}
    if name == "large":
        with open(os.path.join(PAYLOAD_DIR, "datadog-1mb.json"), "rb") as handle:
            return handle.read(), {}
    if name == "boundary":
        body = json.dumps([{"message": "x" * 64 * 1024, "ddsource": "bench"}]).encode()
        return body, {}
    if name == "gzip":
        with open(os.path.join(PAYLOAD_DIR, "datadog-1mb.json"), "rb") as handle:
            return gzip.compress(handle.read()), {"Content-Encoding": "gzip"}
    raise SystemExit("unknown payload %r" % name)


def policy_document(count: int) -> dict:
    """`count` rules, all but one non-matching.

    A real policy set is mostly rules that do not fire, and every one of them
    is still evaluated per record. `.+` rather than `.*`, because Hyperscan
    refuses a pattern that can match an empty buffer and the rule would
    silently do nothing.
    """
    policies = []
    for i in range(max(0, count - 1)):
        policies.append({
            "id": "miss-%d" % i,
            "name": "miss-%d" % i,
            "log": {"match": [{"log_field": "body", "regex": "needle-%d-absent" % i}], "keep": "all"},
        })
    if count > 0:
        policies.append({
            "id": "keep-all",
            "name": "keep-all",
            "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
        })
    return {"policies": policies}


def peak_rss_mb(pid: int, stop_after: float) -> float:
    peak = 0.0
    deadline = time.monotonic() + stop_after
    while time.monotonic() < deadline:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
        try:
            peak = max(peak, int(out.stdout.strip()) / 1024)
        except ValueError:
            break
        time.sleep(0.5)
    return peak


def run_oha(url: str, body: bytes, headers: dict, connections: int, seconds: int) -> dict:
    body_file = tempfile.NamedTemporaryFile("wb", suffix=".bin", delete=False)
    body_file.write(body)
    body_file.close()
    out_file = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False)
    out_file.close()

    command = [
        "oha", "-z", "%ds" % seconds, "-c", str(connections), "-m", "POST",
        "-H", "Content-Type: application/json",
    ]
    for name, value in headers.items():
        command += ["-H", "%s: %s" % (name, value)]
    command += ["-D", body_file.name, "--no-tui", "--output-format", "json", "-o", out_file.name, url]
    subprocess.run(command, check=True, capture_output=True)

    with open(out_file.name) as handle:
        report = json.load(handle)
    os.unlink(body_file.name)
    os.unlink(out_file.name)
    return report


def measure(frontend: str, settings: dict, seconds: int) -> dict:
    body, headers = payload(settings["payload"])
    os.environ["EDGE_BIN"] = BINARIES[frontend]

    intake = EchoIntake(latency_ms=settings["latency"])
    config = {"max_body_size": 4 * 1024 * 1024}
    if settings["threads"] is not None:
        config["thread_pool_count"] = settings["threads"]
    if settings["maxconn"] is not None:
        config["max_connections"] = settings["maxconn"]
    if settings["policies"] > 0:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(policy_document(settings["policies"]), handle)
        handle.close()
        config["policy_providers"] = [{"id": "file", "type": "file", "path": handle.name}]

    edge = Edge(intake.url, config)
    running = edge.frontend()
    if running is not None and running != frontend:
        raise SystemExit("%s carries the %s frontend; rebuild with --prefix" % (BINARIES[frontend], running))
    try:
        rss = {"peak": 0.0}
        watcher = threading.Thread(
            target=lambda: rss.update(peak=peak_rss_mb(edge.pid, seconds + 2)), daemon=True
        )
        watcher.start()
        report = run_oha(edge.url + "/api/v2/logs", body, headers, settings["conns"], seconds)
        watcher.join(timeout=seconds + 10)
        rejected = edge.metric("edge_policies_rejected")
    finally:
        edge.stop()
        intake.stop()

    if rejected:
        raise SystemExit("%d policies were rejected; the run measured the wrong path" % rejected)

    summary = report["summary"]
    percentiles = report["latencyPercentiles"]
    codes = report["statusCodeDistribution"]
    return {
        "frontend": frontend,
        **settings,
        "rps": summary["requestsPerSec"],
        "p50": percentiles["p50"] * 1000,
        "p99": percentiles["p99"] * 1000,
        "p99.9": percentiles["p99.9"] * 1000,
        "max": summary["slowest"] * 1000,
        "rss": rss["peak"],
        "codes": codes,
    }


HEADER = "%-7s %-10s %9s %8s %8s %9s %9s %8s  %s"
ROW = "%-7s %-10s %9.0f %8.1f %8.1f %9.1f %9.1f %8.1f  %s"


def print_row(axis: str, row: dict) -> None:
    other = ",".join(
        "%s=%s" % (k, row[k]) for k in ("payload", "conns", "policies", "latency", "threads", "maxconn")
        if k != axis and row[k] != BASELINE[k]
    )
    non_2xx = {k: v for k, v in row["codes"].items() if not k.startswith("2")}
    note = ("shed %s" % non_2xx) if non_2xx else other
    print(ROW % (
        row["frontend"], str(row[axis]), row["rps"], row["p50"], row["p99"],
        row["p99.9"], row["max"], row["rss"], note))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=12)
    parser.add_argument("--frontend", choices=("stdio", "httpz", "both"), default="both")
    parser.add_argument("--axes", default=",".join(AXES))
    parser.add_argument("--out", default="/tmp/edge-perf-sweep.json")
    args = parser.parse_args()

    if not shutil.which("oha"):
        raise SystemExit("oha is required (brew install oha)")

    frontends = ["httpz", "stdio"] if args.frontend == "both" else [args.frontend]
    results = []

    for axis in args.axes.split(","):
        if axis not in AXES:
            raise SystemExit("unknown axis %r; choose from %s" % (axis, ",".join(AXES)))
        print("\n== %s (everything else at the baseline) ==" % axis)
        print(HEADER % ("front", axis, "rps", "p50 ms", "p99 ms", "p99.9 ms", "max ms", "rss MB", "notes"))
        print("-" * 104)
        for value in AXES[axis]:
            settings = dict(BASELINE)
            settings[axis] = value
            for frontend in frontends:
                row = measure(frontend, settings, args.seconds)
                row["axis"] = axis
                results.append(row)
                print_row(axis, row)

    with open(args.out, "w") as handle:
        json.dump(results, handle, indent=1)
    print("\n%d rows written to %s" % (len(results), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
