import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_file_append(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "file.log"
    out_path = tmp_path / "file.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "append.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("line1\nline2\n")
        wait_for_line_counts(out_path, {"line1": 1, "line2": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["line1", "line2"]
