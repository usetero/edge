import subprocess
from pathlib import Path

from .helpers import read_lines


def test_stdin_pipe(edge_tail_bin: Path, tmp_path: Path) -> None:
    out = tmp_path / "stdin.out"
    subprocess.run(
        [str(edge_tail_bin), "-o", str(out)],
        input="a\nb\n",
        text=True,
        check=True,
    )
    assert read_lines(out) == ["a", "b"]
