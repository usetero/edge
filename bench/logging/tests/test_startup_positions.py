import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_read_from_head_reads_existing_and_new(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "head.log"
    out_path = tmp_path / "head.out"
    in_path.write_text("seed\n")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "head.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        wait_for_line_counts(out_path, {"seed": 1})
        with in_path.open("a") as f:
            f.write("next\n")
        wait_for_line_counts(out_path, {"seed": 1, "next": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["seed", "next"]


def test_read_from_tail_skips_existing_reads_new(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "tail.log"
    out_path = tmp_path / "tail.out"
    in_path.write_text("seed\n")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "tail.err",
        ["-o", str(out_path), "--read-from", "tail", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("next\n")
        wait_for_line_counts(out_path, {"next": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["next"]


def test_read_from_checkpoint_without_state_starts_at_beginning(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "cp.log"
    out_path = tmp_path / "cp.out"
    state_dir = tmp_path / "state"
    in_path.write_text("seed\n")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "cp.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "checkpoint",
            "--poll-ms",
            "40",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    try:
        wait_for_line_counts(out_path, {"seed": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["seed"]
