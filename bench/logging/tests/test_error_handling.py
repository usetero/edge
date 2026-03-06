import stat
import subprocess
from pathlib import Path


def test_unreadable_input_file_fails(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "no-read.log"
    in_path.write_text("x\n")
    in_path.chmod(0)
    try:
        res = subprocess.run(
            [str(edge_tail_bin), "-o", str(tmp_path / "out.log"), str(in_path)],
            capture_output=True,
            text=True,
        )
    finally:
        in_path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    assert res.returncode != 0


def test_unwritable_output_path_fails(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "in.log"
    in_path.write_text("x\n")
    locked_dir = tmp_path / "locked"
    locked_dir.mkdir()
    locked_dir.chmod(0)
    out_path = locked_dir / "out.log"

    try:
        res = subprocess.run(
            [str(edge_tail_bin), "-o", str(out_path), str(in_path)],
            capture_output=True,
            text=True,
        )
    finally:
        locked_dir.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    assert res.returncode != 0


def test_invalid_read_from_value_fails(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "in.log"
    in_path.write_text("")
    res = subprocess.run(
        [str(edge_tail_bin), "--read-from", "bogus", str(in_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0


def test_invalid_numeric_value_fails(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "in.log"
    in_path.write_text("")
    res = subprocess.run(
        [str(edge_tail_bin), "--poll-ms", "0", str(in_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0


def test_invalid_negative_numeric_fails(edge_tail_bin: Path, tmp_path: Path) -> None:
    in_path = tmp_path / "in.log"
    in_path.write_text("")
    res = subprocess.run(
        [str(edge_tail_bin), "--checkpoint-interval-ms", "-1", str(in_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0


def test_invalid_stdin_and_files_combination_fails(
    edge_tail_bin: Path, tmp_path: Path
) -> None:
    in_path = tmp_path / "x.log"
    in_path.write_text("")
    res = subprocess.run(
        [str(edge_tail_bin), "-", str(in_path)],
        capture_output=True,
        text=True,
    )
    assert res.returncode != 0
