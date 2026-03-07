from pathlib import Path
import subprocess

import pytest


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def edge_tail_bin(project_root: Path) -> Path:
    subprocess.run(["zig", "build", "tail"], cwd=project_root, check=True)
    binary = project_root / "zig-out" / "bin" / "edge-tail"
    if not binary.exists():
        raise RuntimeError(f"edge-tail binary missing at {binary}")
    return binary
