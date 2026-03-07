import subprocess
import time
from pathlib import Path

from .helpers import read_lines, start_tail


def test_stdin_to_stdout(edge_tail_bin: Path) -> None:
    res = subprocess.run(
        [str(edge_tail_bin), "-o", "-"],
        input="a\nb\n",
        capture_output=True,
        text=True,
        check=True,
    )
    assert res.stdout == "a\nb\n"
    assert res.stderr == ""


def test_stdin_to_file(edge_tail_bin: Path, tmp_path: Path) -> None:
    out = tmp_path / "stdin.out"
    subprocess.run(
        [str(edge_tail_bin), "-o", str(out)],
        input="x\ny\n",
        text=True,
        check=True,
    )
    assert read_lines(out) == ["x", "y"]


def test_file_to_stdout(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "stream.log"
    in_path.write_text("")

    proc = start_tail(
        edge_tail_bin,
        tmp_path / "stdout.err",
        ["-o", "-", "--read-from", "head", "--poll-ms", "40", str(in_path)],
        capture_stdout=True,
    )
    try:
        time.sleep(0.2)
        with in_path.open("a") as f:
            f.write("line1\nline2\n")
        time.sleep(0.3)
    finally:
        proc.stop()

    stdout = proc.proc.stdout.read() if proc.proc.stdout is not None else ""
    assert stdout == "line1\nline2\n"
