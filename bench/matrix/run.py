#!/usr/bin/env python3
"""Runs the fault matrix against both frontends and prints where they differ.

    ./bin/uv run --with requests bench/matrix/run.py
    ./bin/uv run --with requests bench/matrix/run.py --fast
    ./bin/uv run --with requests bench/matrix/run.py --frontend stdio -k b05

httpz is the oracle: for most cases the right answer is "stdio does what httpz
does". A case that must differ calls `expect_difference`, which reports as
`diff` rather than a failure.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

BINARIES = {
    "httpz": os.path.join(REPO_ROOT, "zig-out", "bin", "edge"),
    "stdio": os.path.join(REPO_ROOT, "zig-out-stdio", "bin", "edge"),
}


def build(frontends: list[str]) -> None:
    zig = os.path.join(REPO_ROOT, "bin", "zig")
    print("building: echo server with fault injection")
    subprocess.run([zig, "build", "echo-server", "-Doptimize=ReleaseFast"], cwd=REPO_ROOT, check=True)
    if "httpz" in frontends:
        print("building: httpz frontend")
        subprocess.run([zig, "build", "-Doptimize=ReleaseFast"], cwd=REPO_ROOT, check=True)
    if "stdio" in frontends:
        print("building: stdio frontend")
        subprocess.run(
            [zig, "build", "-Dfrontend=stdio", "-Doptimize=ReleaseFast", "--prefix", "zig-out-stdio"],
            cwd=REPO_ROOT,
            check=True,
        )


def load_suite(pattern: str | None) -> unittest.TestSuite:
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(HERE, "tests"), top_level_dir=HERE)
    if not pattern:
        return suite
    picked = unittest.TestSuite()
    for case in iterate(suite):
        if pattern in case.id():
            picked.addTest(case)
    return picked


def iterate(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from iterate(item)
        else:
            yield item


def short_id(case_id: str) -> str:
    """tests.test_b05_reject_early.RejectEarly.test_x -> b05 reject_early.test_x"""
    parts = case_id.split(".")
    module = parts[1] if len(parts) > 1 else parts[0]
    name = module.replace("test_", "", 1)
    return "%s.%s" % (name, parts[-1])


def first_cause(trace: str) -> str:
    """The assertion line, not the log dump an assertion message carries."""
    for line in trace.strip().splitlines():
        stripped = line.strip()
        if stripped.startswith(("AssertionError", "Error", "RuntimeError", "self.fail")):
            return stripped[:200]
        if "Error:" in stripped and not stripped.startswith("File "):
            return stripped[:200]
    return trace.strip().splitlines()[-1][:200]


def run_one(frontend: str, pattern: str | None, fast: bool) -> dict[str, tuple[str, str]]:
    os.environ["EDGE_BIN"] = BINARIES[frontend]
    os.environ["EDGE_FRONTEND"] = frontend
    if fast:
        os.environ["MATRIX_FAST"] = "1"
    else:
        os.environ.pop("MATRIX_FAST", None)

    suite = load_suite(pattern)
    # unittest drops its references to the cases as it runs them, so the
    # names have to be collected first.
    names = [short_id(case.id()) for case in iterate(suite)]

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=0)
    started = time.monotonic()
    result = runner.run(suite)
    elapsed = time.monotonic() - started

    outcomes: dict[str, tuple[str, str]] = {name: ("pass", "") for name in names}
    for case, trace in result.failures + result.errors:
        outcomes[short_id(case.id())] = ("FAIL", first_cause(trace))
    for case, reason in result.skipped:
        label = "diff" if reason.startswith("known difference") else "skip"
        outcomes[short_id(case.id())] = (label, reason[:160])

    print("  %s: %d cases in %.0f s" % (frontend, len(outcomes), elapsed))
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", choices=("stdio", "httpz", "both"), default="both")
    parser.add_argument("--fast", action="store_true", help="skip the cases that wait for a 30 s deadline")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("-k", dest="pattern", help="substring filter on the case id")
    args = parser.parse_args()

    frontends = ["stdio", "httpz"] if args.frontend == "both" else [args.frontend]
    if not args.skip_build:
        build(frontends)

    results = {frontend: run_one(frontend, args.pattern, args.fast) for frontend in frontends}

    names = sorted({name for outcomes in results.values() for name in outcomes})
    width = max((len(n) for n in names), default=10)
    print("\n%-*s  %s" % (width, "case", "  ".join("%-8s" % f for f in frontends)))
    print("-" * (width + 2 + 10 * len(frontends)))
    failures: list[tuple[str, str, str]] = []
    for name in names:
        cells = []
        for frontend in frontends:
            status, detail = results[frontend].get(name, ("n/a", ""))
            cells.append("%-8s" % status)
            if status == "FAIL":
                failures.append((name, frontend, detail))
        print("%-*s  %s" % (width, name, "  ".join(cells)))

    if failures:
        print("\nfailures:")
        for name, frontend, detail in failures:
            print("  %s [%s]\n    %s" % (name, frontend, detail))

    print("\n%d case(s), %d failure(s)" % (len(names), len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
