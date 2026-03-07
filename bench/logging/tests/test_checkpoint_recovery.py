import signal
import subprocess
import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for_line_counts


def test_clean_shutdown_resume_from_checkpoint(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "clean.log"
    out1 = tmp_path / "clean-1.out"
    out2 = tmp_path / "clean-2.out"
    state_dir = tmp_path / "state-clean"
    in_path.write_text("")

    proc1 = start_tail(
        edge_tail_bin,
        tmp_path / "clean-1.err",
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
        tmp_path / "clean-2.err",
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


def test_sigkill_recovery_is_at_least_once(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "kill.log"
    out1 = tmp_path / "kill-1.out"
    out2 = tmp_path / "kill-2.out"
    state_dir = tmp_path / "state-kill"
    in_path.write_text("")

    proc1 = start_tail(
        edge_tail_bin,
        tmp_path / "kill-1.err",
        [
            "-o",
            str(out1),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--checkpoint-interval-ms",
            "80",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    time.sleep(0.2)
    with in_path.open("a") as f:
        f.write("a\nb\n")
    wait_for_line_counts(out1, {"a": 1, "b": 1})
    proc1.proc.send_signal(signal.SIGKILL)
    proc1.proc.wait(timeout=2.0)
    proc1.stderr_file.close()

    proc2 = start_tail(
        edge_tail_bin,
        tmp_path / "kill-2.err",
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
            f.write("c\n")
        wait_for_line_counts(out2, {"c": 1})
    finally:
        proc2.stop()

    lines = read_lines(out2)
    assert "c" in lines


def test_wal_tail_corruption_is_tolerated(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "wal.log"
    out1 = tmp_path / "wal-1.out"
    out2 = tmp_path / "wal-2.out"
    state_dir = tmp_path / "state-wal"
    in_path.write_text("")

    proc1 = start_tail(
        edge_tail_bin,
        tmp_path / "wal-1.err",
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
            f.write("one\n")
        wait_for_line_counts(out1, {"one": 1})
    finally:
        proc1.stop()

    wal = state_dir / "checkpoint.wal"
    if wal.exists() and wal.stat().st_size > 24:
        with wal.open("r+b") as f:
            f.truncate(wal.stat().st_size - 8)

    proc2 = start_tail(
        edge_tail_bin,
        tmp_path / "wal-2.err",
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
            f.write("two\n")
        wait_for_line_counts(out2, {"two": 1})
    finally:
        proc2.stop()


def test_checkpoint_ttl_eviction_allows_replay(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "ttl.log"
    out1 = tmp_path / "ttl-1.out"
    out2 = tmp_path / "ttl-2.out"
    state_dir = tmp_path / "state-ttl"
    in_path.write_text("")

    proc1 = start_tail(
        edge_tail_bin,
        tmp_path / "ttl-1.err",
        [
            "-o",
            str(out1),
            "--read-from",
            "head",
            "--poll-ms",
            "30",
            "--checkpoint-interval-ms",
            "40",
            "--checkpoint-ttl-ms",
            "120",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("seed\n")
        wait_for_line_counts(out1, {"seed": 1})
        time.sleep(0.35)
    finally:
        proc1.stop()

    proc2 = start_tail(
        edge_tail_bin,
        tmp_path / "ttl-2.err",
        [
            "-o",
            str(out2),
            "--read-from",
            "checkpoint",
            "--poll-ms",
            "40",
            "--checkpoint-interval-ms",
            "40",
            "--checkpoint-ttl-ms",
            "120",
            "--state-dir",
            str(state_dir),
            str(in_path),
        ],
    )
    try:
        wait_for_line_counts(out2, {"seed": 1})
    finally:
        proc2.stop()


def test_checkpoint_slot_exhaustion_does_not_stop_tailing(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    a = tmp_path / "slot-a.log"
    b = tmp_path / "slot-b.log"
    out_path = tmp_path / "slot.out"
    state_dir = tmp_path / "state-slot"
    a.write_text("")
    b.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "slot.err",
        [
            "-o",
            str(out_path),
            "--read-from",
            "head",
            "--poll-ms",
            "40",
            "--checkpoint-max-slots",
            "1",
            "--checkpoint-interval-ms",
            "30",
            "--state-dir",
            str(state_dir),
            str(a),
            str(b),
        ],
    )
    try:
        time.sleep(0.2)
        with a.open("a") as f:
            f.write("a1\n")
        with b.open("a") as f:
            f.write("b1\n")
        wait_for_line_counts(out_path, {"a1": 1, "b1": 1})
    finally:
        proc.stop()
