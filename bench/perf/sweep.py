#!/usr/bin/env python3
"""Throughput, latency and memory across the shapes a customer actually sends.

Drives `oha` against the real edge binary with the real echo server behind it,
for both frontends, and prints one table. Use it to compare a branch against a
recorded baseline: the shapes are fixed, so the numbers are comparable run to
run on the same host.

    ./bin/uv run --python ./bin/python3 --with requests bench/perf/sweep.py
    ./bin/uv run --python ./bin/python3 --with requests bench/perf/sweep.py --seconds 10

Shapes:

    small      one short record, the ordinary agent flush
    boundary   64 KiB, which is where a body stops being held resident
    large      1 MB, a full agent batch
    gzip       a compressed batch, so the decode path runs

Each shape runs with policies off and on, because an active policy changes the
path completely: the body is made resident and evaluated per record.
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
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "bench", "matrix"))

from harness import Edge, EchoIntake  # noqa: E402

# `.+`, not `.*`: Hyperscan refuses a pattern that can match an empty buffer.
KEEP_ALL = {
    "policies": [
        {
            "id": "keep-all",
            "name": "keep-all",
            "log": {"match": [{"log_field": "body", "regex": ".+"}], "keep": "all"},
        }
    ]
}

BINARIES = {
    "httpz": os.path.join(REPO_ROOT, "zig-out", "bin", "edge"),
    "stdio": os.path.join(REPO_ROOT, "zig-out-stdio", "bin", "edge"),
}


def record(size: int) -> bytes:
    return json.dumps([{"message": "x" * size, "ddsource": "bench", "service": "sweep"}]).encode()


def payloads() -> dict[str, tuple[bytes, dict]]:
    small = record(200)
    boundary = record(64 * 1024)
    large = record(1024 * 1024 - 512)
    return {
        "small": (small, {}),
        "boundary": (boundary, {}),
        "large": (large, {}),
        "gzip": (gzip.compress(large), {"Content-Encoding": "gzip"}),
    }


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


def measure(frontend: str, shape: str, body: bytes, headers: dict, connections: int,
            policies: bool, seconds: int) -> dict:
    os.environ["EDGE_BIN"] = BINARIES[frontend]
    intake = EchoIntake()
    config = {"max_body_size": 4 * 1024 * 1024}
    if policies:
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(KEEP_ALL, handle)
        handle.close()
        config["policy_providers"] = [{"id": "file", "type": "file", "path": handle.name}]

    edge = Edge(intake.url, config)
    running = edge.frontend()
    if running is not None and running != frontend:
        raise SystemExit("%s carries the %s frontend; rebuild with --prefix" % (BINARIES[frontend], running))
    try:
        import threading

        rss = {"peak": 0.0}
        watcher = threading.Thread(
            target=lambda: rss.update(peak=peak_rss_mb(edge.pid, seconds + 2)), daemon=True
        )
        watcher.start()
        report = run_oha(edge.url + "/api/v2/logs", body, headers, connections, seconds)
        watcher.join(timeout=seconds + 10)
    finally:
        edge.stop()
        intake.stop()

    summary = report["summary"]
    percentiles = report["latencyPercentiles"]
    codes = report["statusCodeDistribution"]
    accepted = sum(v for k, v in codes.items() if k.startswith("2"))
    return {
        "frontend": frontend,
        "shape": shape,
        "connections": connections,
        "policies": policies,
        "rps": summary["requestsPerSec"],
        "p50": percentiles["p50"] * 1000,
        "p99": percentiles["p99"] * 1000,
        "p99.9": percentiles["p99.9"] * 1000,
        "max": summary["slowest"] * 1000,
        "rss": rss["peak"],
        "ok": accepted,
        "codes": codes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=int, default=12)
    parser.add_argument("--frontend", choices=("stdio", "httpz", "both"), default="both")
    parser.add_argument("--shapes", default="small,boundary,large,gzip")
    parser.add_argument("--connections", default="64,256")
    args = parser.parse_args()

    if not shutil.which("oha"):
        raise SystemExit("oha is required (brew install oha)")

    frontends = ["httpz", "stdio"] if args.frontend == "both" else [args.frontend]
    shapes = args.shapes.split(",")
    connection_counts = [int(c) for c in args.connections.split(",")]
    all_payloads = payloads()

    print("%-7s %-9s %5s %-8s %9s %8s %8s %9s %9s %9s" % (
        "front", "shape", "conns", "policies", "rps", "p50 ms", "p99 ms", "p99.9 ms", "max ms", "rss MB"))
    print("-" * 96)

    results = []
    for shape in shapes:
        body, headers = all_payloads[shape]
        for connections in connection_counts:
            for policies in (False, True):
                for frontend in frontends:
                    row = measure(frontend, shape, body, headers, connections, policies, args.seconds)
                    results.append(row)
                    print("%-7s %-9s %5d %-8s %9.0f %8.1f %8.1f %9.1f %9.1f %9.1f" % (
                        row["frontend"], row["shape"], row["connections"],
                        "on" if row["policies"] else "off",
                        row["rps"], row["p50"], row["p99"], row["p99.9"], row["max"], row["rss"]))
                    if any(not k.startswith("2") for k in row["codes"]):
                        print("        non-2xx answers: %s" % row["codes"])

    with open("/tmp/edge-perf-sweep.json", "w") as handle:
        json.dump(results, handle, indent=1)
    print("\\nrows written to /tmp/edge-perf-sweep.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
