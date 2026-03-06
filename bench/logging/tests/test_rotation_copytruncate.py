import time
from collections import Counter
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_copytruncate(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "ct.log"
    out_path = tmp_path / "ct.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "copytruncate.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("first\n")
        time.sleep(0.15)

        in_path.write_text("")
        time.sleep(0.08)
        with in_path.open("a") as f:
            f.write("second\n")

        wait_for_line_counts(out_path, {"first": 1, "second": 1})
    finally:
        proc.stop()

    counts = Counter(read_lines(out_path))
    assert counts["first"] == 1
    assert counts["second"] == 1
