import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for


def test_perf_guard_burst_latency(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "perf-burst.log"
    out_path = tmp_path / "perf-burst.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "perf-burst.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "20",
            "--flush-interval-ms",
            "50",
            "--flush-lines",
            "128",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        t0 = time.monotonic()
        with in_path.open("a") as f:
            for i in range(400):
                f.write(f"line-{i}\n")
        wait_for(lambda: len(read_lines(out_path)) >= 400, timeout_s=8.0)
        elapsed = time.monotonic() - t0
    finally:
        proc.stop()

    # Guardrail only: keep end-to-end under a forgiving threshold in CI/local.
    assert elapsed < 4.0


def test_perf_guard_multi_file_throughput(edge_tail_bin: Path, tmp_path: Path) -> None:
    out_path = tmp_path / "perf-many.out"
    files = [tmp_path / f"mf-{i}.log" for i in range(16)]
    for f in files:
        f.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "perf-many.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "20",
            "--flush-interval-ms",
            "50",
            "--flush-lines",
            "128",
            *[str(f) for f in files],
        ],
    )
    try:
        time.sleep(0.2)
        t0 = time.monotonic()
        for i, f in enumerate(files):
            with f.open("a") as w:
                for j in range(80):
                    w.write(f"f{i}-{j}\n")
        wait_for(lambda: len(read_lines(out_path)) >= 16 * 80, timeout_s=10.0)
        elapsed = time.monotonic() - t0
    finally:
        proc.stop()

    assert elapsed < 6.0
