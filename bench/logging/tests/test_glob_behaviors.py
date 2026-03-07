import time
from collections import Counter
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_overlap_patterns_do_not_duplicate_output(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "dup.log"
    out_path = tmp_path / "dup.out"
    in_path.write_text("")

    pattern = str(tmp_path / "*.log")
    proc = start_tail(
        edge_tail_bin,
        tmp_path / "dup.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            pattern,
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("once\n")
        wait_for_line_counts(out_path, {"once": 1})
    finally:
        proc.stop()

    counts = Counter(read_lines(out_path))
    assert counts["once"] == 1


def test_glob_discovers_new_matching_file(edge_tail_bin: Path, tmp_path: Path) -> None:
    out_path = tmp_path / "discover.out"
    pattern = str(tmp_path / "*.log")
    new_file = tmp_path / "new.log"

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "discover.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--glob-interval-ms",
            "80",
            pattern,
        ],
    )
    try:
        time.sleep(0.2)
        new_file.write_text("first\n")
        wait_for_line_counts(out_path, {"first": 1})
    finally:
        proc.stop()


def test_file_stops_matching_and_readded_with_same_name(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    out_path = tmp_path / "match.out"
    pattern = str(tmp_path / "*.log")
    tracked = tmp_path / "x.log"
    renamed = tmp_path / "x.txt"

    tracked.write_text("")
    proc = start_tail(
        edge_tail_bin,
        tmp_path / "match.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--glob-interval-ms",
            "80",
            "--removed-expire-ms",
            "150",
            pattern,
        ],
    )
    try:
        time.sleep(0.2)
        with tracked.open("a") as f:
            f.write("first\n")
        wait_for_line_counts(out_path, {"first": 1})

        tracked.rename(renamed)
        time.sleep(0.30)
        tracked.write_text("second\n")
        wait_for_line_counts(out_path, {"second": 1})
    finally:
        proc.stop()


def test_large_directory_many_non_matching_files(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    for i in range(120):
        (tmp_path / f"ignore-{i}.txt").write_text("x\n")

    out_path = tmp_path / "large.out"
    pattern = str(tmp_path / "*.log")
    hit = tmp_path / "hit.log"
    hit.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "large.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--glob-interval-ms",
            "100",
            pattern,
        ],
    )
    try:
        time.sleep(0.2)
        with hit.open("a") as f:
            f.write("yes\n")
        wait_for_line_counts(out_path, {"yes": 1})
    finally:
        proc.stop()
