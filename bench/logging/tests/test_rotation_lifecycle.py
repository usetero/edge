import time
from collections import Counter
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_rapid_rename_create_rotations(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "rapid.log"
    out_path = tmp_path / "rapid.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "rapid.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "30",
            "--rotate-wait-ms",
            "120",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        for idx in range(3):
            with in_path.open("a") as f:
                f.write(f"before-{idx}\n")
            time.sleep(0.08)
            old = tmp_path / f"rapid.log.{idx + 1}"
            in_path.rename(old)
            in_path.write_text("")
            with old.open("a") as f:
                f.write(f"drain-{idx}\n")
            with in_path.open("a") as f:
                f.write(f"after-{idx}\n")
            time.sleep(0.2)

        wait_for_line_counts(
            out_path,
            {
                "before-0": 1,
                "drain-0": 1,
                "after-0": 1,
                "before-1": 1,
                "drain-1": 1,
                "after-1": 1,
                "before-2": 1,
                "drain-2": 1,
                "after-2": 1,
            },
            timeout_s=6.0,
        )
    finally:
        proc.stop()


def test_rotation_drains_old_fd_within_grace(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "drain.log"
    old_path = tmp_path / "drain.log.1"
    out_path = tmp_path / "drain.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "drain.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--rotate-wait-ms",
            "300",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("before\n")
        time.sleep(0.12)

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


def test_copytruncate_with_immediate_append(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "cti.log"
    out_path = tmp_path / "cti.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "cti.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("first\n")
        time.sleep(0.1)
        in_path.write_text("")
        with in_path.open("a") as f:
            f.write("second\n")
        wait_for_line_counts(out_path, {"first": 1, "second": 1})
    finally:
        proc.stop()


def test_delete_and_recreate_same_path(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "reuse.log"
    out_path = tmp_path / "reuse.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "reuse.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--rotate-wait-ms",
            "120",
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("first\n")
        wait_for_line_counts(out_path, {"first": 1})
        in_path.unlink()
        time.sleep(0.25)
        in_path.write_text("second\n")
        wait_for_line_counts(out_path, {"second": 1})
    finally:
        proc.stop()


def test_path_missing_then_reappears(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "later.log"
    out_path = tmp_path / "later.out"

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "later.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        in_path.write_text("arrived\n")
        wait_for_line_counts(out_path, {"arrived": 1})
    finally:
        proc.stop()
