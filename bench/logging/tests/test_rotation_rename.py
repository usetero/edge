import time
from collections import Counter
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_rename_create_rotation(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "rot.log"
    old_path = tmp_path / "rot.log.1"
    out_path = tmp_path / "rot.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "rename.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--rotate-wait-ms",
            "250",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("before\n")
        time.sleep(0.15)

        in_path.rename(old_path)
        in_path.write_text("")
        with old_path.open("a") as f:
            f.write("old-drain\n")
        with in_path.open("a") as f:
            f.write("new\n")

        wait_for_line_counts(out_path, {"before": 1, "old-drain": 1, "new": 1})
    finally:
        proc.stop()

    counts = Counter(read_lines(out_path))
    assert counts["before"] == 1
    assert counts["old-drain"] == 1
    assert counts["new"] == 1
