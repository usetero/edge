import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_checkpoint_resume(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "cp.log"
    out1 = tmp_path / "cp1.out"
    out2 = tmp_path / "cp2.out"
    state_dir = tmp_path / "state"
    in_path.write_text("")

    proc1 = start_tail(
        edge_tail_bin,
        tmp_path / "cp1.err",
        [
            "-o",
            str(out1),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--checkpoint-interval-ms",
            "40",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("one\ntwo\n")
        wait_for_line_counts(out1, {"one": 1, "two": 1})
    finally:
        proc1.stop()

    proc2 = start_tail(
        edge_tail_bin,
        tmp_path / "cp2.err",
        [
            "-o",
            str(out2),
            "--read-from",
            "checkpoint",
            "--poll-ms",
            "40",
            "--checkpoint-interval-ms",
            "40",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("three\n")
        wait_for_line_counts(out2, {"three": 1})
    finally:
        proc2.stop()

    assert read_lines(out1) == ["one", "two"]
    assert read_lines(out2) == ["three"]
