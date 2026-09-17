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


def test_output_file_appends_on_restart(edge_tail_bin: Path, tmp_path: Path) -> None:
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

    assert read_lines(out_path) == ["old", "new"]


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


def test_output_file_external_truncation_preserves_post_truncation_lines(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    # An operator truncates the `-o` file in place (copytruncate-style) while
    # edge-tail is running. Under true O_APPEND, the next flush must land at
    # the new (zero) EOF and the post-truncation payload must be preserved with
    # no leading NUL hole. The pre-fix code captured stat().size once at
    # startup and wrote at that stale offset via pwritev, producing a run of
    # NUL bytes equal to the original file size followed by the new lines.
    in_path = tmp_path / "trunc.log"
    out_path = tmp_path / "trunc.out"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "trunc.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(in_path)],
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("line1\nline2\nline3\n")
        wait_for_line_counts(out_path, {"line3": 1})

        # External truncation of the output file in place (same inode).
        out_path.write_text("")

        with in_path.open("a") as f:
            f.write("line4\nline5\nline6\n")
        wait_for_line_counts(out_path, {"line6": 1})
    finally:
        proc.stop()

    raw = out_path.read_bytes()
    assert b"\x00" not in raw, f"unexpected NUL bytes in output: {raw!r}"
    assert read_lines(out_path) == ["line4", "line5", "line6"]


def test_output_file_external_append_is_not_overwritten(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    # A sibling process appends to the `-o` file after edge-tail has opened it
    # but before edge-tail's next flush. Under true O_APPEND both writers' bytes
    # survive. The pre-fix code wrote at the stale offset captured at startup,
    # overwriting the externally appended bytes.
    in_path = tmp_path / "ext.log"
    out_path = tmp_path / "ext.out"
    in_path.write_text("")
    out_path.write_text("PRE\n")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "ext.err",
        ["-o", str(out_path), "--read-from", "head", "--poll-ms", "30", str(in_path)],
    )
    try:
        time.sleep(0.2)
        # Sibling append before edge-tail flushes anything of its own.
        with out_path.open("a") as f:
            f.write("EXT\n")
        with in_path.open("a") as f:
            f.write("new\n")
        wait_for_line_counts(out_path, {"new": 1})
    finally:
        proc.stop()

    lines = read_lines(out_path)
    assert lines == ["PRE", "EXT", "new"]
