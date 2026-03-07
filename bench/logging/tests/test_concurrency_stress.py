import threading
import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for, wait_for_line_counts


def test_many_files_concurrent_appends(edge_tail_bin: Path, tmp_path: Path) -> None:
    file_count = 20
    files = [tmp_path / f"mf-{i}.log" for i in range(file_count)]
    out_path = tmp_path / "many.out"
    for f in files:
        f.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "many.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "25"]
        + [str(f) for f in files],
    )
    try:
        time.sleep(0.2)
        threads: list[threading.Thread] = []

        def append_line(path: Path, line: str) -> None:
            with path.open("a") as f:
                f.write(line)

        for i, f in enumerate(files):
            t = threading.Thread(target=append_line, args=(f, f"v{i}\n"))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        wait_for(lambda: len(read_lines(out_path)) >= file_count, timeout_s=8.0)
    finally:
        proc.stop()

    lines = set(read_lines(out_path))
    for i in range(file_count):
        assert f"v{i}" in lines


def test_burst_idle_burst(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "burst.log"
    out_path = tmp_path / "burst.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "burst.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "25", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            for i in range(20):
                f.write(f"a{i}\n")
        wait_for(lambda: len(read_lines(out_path)) >= 20)

        time.sleep(0.4)
        with in_path.open("a") as f:
            for i in range(20):
                f.write(f"b{i}\n")
        wait_for(lambda: len(read_lines(out_path)) >= 40)
    finally:
        proc.stop()

    lines = read_lines(out_path)
    assert len(lines) == 40
    assert lines[0] == "a0"
    assert lines[-1] == "b19"


def test_high_frequency_tiny_writes(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "tiny.log"
    out_path = tmp_path / "tiny.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "tiny.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "20", str(in_path)],
    )
    try:
        time.sleep(0.2)
        for i in range(60):
            with in_path.open("a") as f:
                f.write(f"x{i}\n")
            time.sleep(0.004)
        wait_for(lambda: len(read_lines(out_path)) >= 60, timeout_s=8.0)
    finally:
        proc.stop()

    assert len(read_lines(out_path)) == 60


def test_short_soak_with_periodic_rotation(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "soak.log"
    out_path = tmp_path / "soak.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "soak.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "25",
            "--rotate-wait-ms",
            "100",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        for i in range(6):
            with in_path.open("a") as f:
                f.write(f"s{i}\n")
            old = tmp_path / f"soak.log.{i}"
            in_path.rename(old)
            in_path.write_text("")
            with in_path.open("a") as f:
                f.write(f"n{i}\n")
            time.sleep(0.08)

        wait_for_line_counts(out_path, {"s0": 1, "n5": 1}, timeout_s=8.0)
    finally:
        proc.stop()
