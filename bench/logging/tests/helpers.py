from __future__ import annotations

import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Callable


class TailProcess:
    def __init__(self, cmd: list[str], stderr_path: Path, capture_stdout: bool = False):
        self.cmd = cmd
        self.stderr_path = stderr_path
        self.stderr_file = stderr_path.open("w")
        stdout = subprocess.PIPE if capture_stdout else subprocess.DEVNULL
        self.proc = subprocess.Popen(
            cmd, stdout=stdout, stderr=self.stderr_file, text=True
        )

    def stop(self) -> None:
        if self.proc.poll() is not None:
            self.stderr_file.close()
            return
        self.proc.terminate()
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=2.0)
        finally:
            self.stderr_file.close()

    def assert_running(self) -> None:
        if self.proc.poll() is None:
            return
        stderr = self.stderr_path.read_text() if self.stderr_path.exists() else ""
        raise AssertionError(
            f"edge-tail exited early (code={self.proc.returncode})\n{stderr}"
        )


def start_tail(
    edge_tail_bin: Path,
    stderr_path: Path,
    args: list[str],
    capture_stdout: bool = False,
) -> TailProcess:
    return TailProcess([str(edge_tail_bin), *args], stderr_path, capture_stdout)


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.rstrip("\n") for line in path.read_text().splitlines()]


def wait_for(
    predicate: Callable[[], bool], timeout_s: float = 3.0, poll_s: float = 0.05
) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(poll_s)
    raise AssertionError("timed out waiting for predicate")


def wait_for_line_counts(
    path: Path, expected_counts: dict[str, int], timeout_s: float = 4.0
) -> None:
    def predicate() -> bool:
        counts = Counter(read_lines(path))
        for line, count in expected_counts.items():
            if counts[line] < count:
                return False
        return True

    wait_for(predicate, timeout_s=timeout_s)


def wait_for_process_exit(proc: subprocess.Popen[str], timeout_s: float = 2.0) -> int:
    try:
        return proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait(timeout=timeout_s)
        raise AssertionError("process did not exit in time") from exc
