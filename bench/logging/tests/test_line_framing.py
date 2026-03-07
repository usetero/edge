import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for, wait_for_line_counts


def test_partial_line_waits_for_newline(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "partial.log"
    out_path = tmp_path / "partial.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "partial.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("par")
        time.sleep(0.2)
        assert read_lines(out_path) == []

        with in_path.open("a") as f:
            f.write("tial\n")
        wait_for_line_counts(out_path, {"partial": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["partial"]


def test_empty_lines_preserved(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "empty.log"
    out_path = tmp_path / "empty.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "empty.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("\n\nx\n")
        wait_for(lambda: len(read_lines(out_path)) >= 3)
    finally:
        proc.stop()

    assert read_lines(out_path) == ["", "", "x"]


def test_max_line_boundary_exact(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "boundary.log"
    out_path = tmp_path / "boundary.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "boundary.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--max-line",
            "4",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("1234\n")
        wait_for_line_counts(out_path, {"1234": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["1234"]


def test_over_limit_line_is_truncated(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "trunc.log"
    out_path = tmp_path / "trunc.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "trunc.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--max-line",
            "4",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("123456\n")
        wait_for_line_counts(out_path, {"1234": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["1234"]
