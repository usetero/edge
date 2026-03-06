import time
from collections import Counter
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_glob_discovery_and_expiry(edge_tail_bin: Path, tmp_path: Path) -> None:
    pattern = tmp_path / "log-*.log"
    out_path = tmp_path / "glob.out"
    log_file = tmp_path / "log-a.log"

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "glob.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--glob-interval-ms",
            "100",
            "--removed-expire-ms",
            "200",
            str(pattern),
        ],
    )
    try:
        time.sleep(0.2)
        log_file.write_text("first\n")
        wait_for_line_counts(out_path, {"first": 1})

        log_file.unlink()
        time.sleep(0.30)
        log_file.write_text("second\n")
        wait_for_line_counts(out_path, {"second": 1})
    finally:
        proc.stop()

    counts = Counter(read_lines(out_path))
    assert counts["first"] == 1
    assert counts["second"] == 1
