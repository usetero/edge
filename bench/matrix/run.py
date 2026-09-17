#!/usr/bin/env python3
"""Runs the fault matrix against both frontends and prints where they differ.

    ./bin/uv run --with requests bench/matrix/run.py
    ./bin/uv run --with requests bench/matrix/run.py --fast
    ./bin/uv run --with requests bench/matrix/run.py --frontend stdio -k b05

Every case asserts what a customer needs. Neither frontend is the oracle, and
either can fail. A case may declare `DEFECTS = {frontend: note}` for behaviour
we have already found and recorded: it then reports as `xfail` with the note,
so the defect stays counted, and as `XPASS` on the day it is fixed.
"""

from __future__ import annotations

import argparse
import io
import os
import subprocess
import sys
import time
import unittest

sys.stdout.reconfigure(line_buffering=True)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)

#: One prefix per frontend, and each build names its frontend. Neither
#: binary comes from the default, so a change of default cannot make the suite
#: test one frontend twice — which it silently did once.
BINARIES = {
    "httpz": os.path.join(REPO_ROOT, "zig-out-httpz", "bin", "edge"),
    "stdio": os.path.join(REPO_ROOT, "zig-out-stdio", "bin", "edge"),
}


def build(frontends: list[str]) -> None:
    zig = os.path.join(REPO_ROOT, "bin", "zig")
    print("building: echo server with fault injection")
    subprocess.run([zig, "build", "echo-server", "-Doptimize=ReleaseFast"], cwd=REPO_ROOT, check=True)
    for frontend in frontends:
        print("building: %s frontend" % frontend)
        subprocess.run(
            [zig, "build", "-Dfrontend=%s" % frontend, "-Doptimize=ReleaseFast",
             "--prefix", "zig-out-%s" % frontend],
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


class Progress(unittest.TextTestResult):
    """Prints each case as it finishes, so a slow sweep shows its progress."""

    def __init__(self, frontend, *args):
        super().__init__(*args)
        self.frontend = frontend
        self.started_at = 0.0

    def startTest(self, test):
        self.started_at = time.monotonic()
        super().startTest(test)

    def _note(self, test, status):
        print("  %-6s %-6s %.0fs  %s" % (
            self.frontend, status, time.monotonic() - self.started_at, short_id(test.id())))

    def addSuccess(self, test):
        super().addSuccess(test)
        self._note(test, "pass")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._note(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._note(test, "ERROR")

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._note(test, "skip")

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._note(test, "xfail")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._note(test, "XPASS")


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
    runner = unittest.TextTestRunner(
        stream=stream,
        verbosity=0,
        resultclass=lambda *args: Progress(frontend, *args),
    )
    started = time.monotonic()
    result = runner.run(suite)
    elapsed = time.monotonic() - started

    outcomes: dict[str, tuple[str, str]] = {name: ("pass", "") for name in names}
    for case, trace in result.failures + result.errors:
        outcomes[short_id(case.id())] = ("FAIL", first_cause(trace))
    for case, reason in result.skipped:
        outcomes[short_id(case.id())] = ("skip", reason[:200])
    for case, note in result.expectedFailures:
        outcomes[short_id(case.id())] = ("xfail", first_cause(note))
    for case in result.unexpectedSuccesses:
        outcomes[short_id(case.id())] = ("XPASS", "the declared defect no longer reproduces; drop the DEFECTS note")

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

    known = [
        (name, frontend, results[frontend][name][1])
        for name in names
        for frontend in frontends
        if results[frontend].get(name, ("", ""))[0] == "xfail"
    ]
    if known:
        print("\nknown defects that reproduced:")
        for name, frontend, detail in known:
            print("  %s [%s]\n    %s" % (name, frontend, detail))

    fixed = [
        (name, frontend)
        for name in names
        for frontend in frontends
        if results[frontend].get(name, ("", ""))[0] == "XPASS"
    ]
    if fixed:
        print("\nno longer failing (remove the DEFECTS note):")
        for name, frontend in fixed:
            print("  %s [%s]" % (name, frontend))

    print("\n%d case(s), %d failure(s), %d known defect(s)" % (len(names), len(failures), len(known)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
