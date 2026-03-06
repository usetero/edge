import time
from pathlib import Path

from .helpers import read_lines, start_tail, wait_for, wait_for_line_counts


def test_single_file_ordering_is_preserved(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "ordered.log"
    out_path = tmp_path / "ordered.out"
    in_path.write_text("")

    expected = [f"l{i}" for i in range(12)]
    proc = start_tail(
        edge_tail_bin,
        tmp_path / "ordered.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("".join(f"{line}\n" for line in expected))
        wait_for(lambda: len(read_lines(out_path)) >= len(expected))
    finally:
        proc.stop()

    assert read_lines(out_path) == expected


def test_per_file_ordering_with_interleaved_inputs(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    out_path = tmp_path / "interleave.out"
    a.write_text("")
    b.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "interleave.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(a), str(b)],
    )
    try:
        time.sleep(0.2)
        with a.open("a") as fa:
            fa.write("a1\na2\n")
        with b.open("a") as fb:
            fb.write("b1\nb2\n")
        wait_for_line_counts(out_path, {"a1": 1, "a2": 1, "b1": 1, "b2": 1})
    finally:
        proc.stop()

    lines = read_lines(out_path)
    a_lines = [line for line in lines if line.startswith("a")]
    b_lines = [line for line in lines if line.startswith("b")]
    assert a_lines == ["a1", "a2"]
    assert b_lines == ["b1", "b2"]


def test_output_file_is_recreated_on_restart(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "recreate.log"
    out_path = tmp_path / "recreate.out"
    in_path.write_text("")
    out_path.write_text("old\n")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "recreate.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "40", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("new\n")
        wait_for_line_counts(out_path, {"new": 1})
    finally:
        proc.stop()

    assert read_lines(out_path) == ["new"]


def test_events_are_flushed_while_process_is_running(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "flush.log"
    out_path = tmp_path / "flush.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "flush.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("tick\n")
        wait_for_line_counts(out_path, {"tick": 1})
        proc.assert_running()
    finally:
        proc.stop()
