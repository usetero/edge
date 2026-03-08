import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="session")
def edge_tail_bin(project_root: Path) -> Path:
    env_bin = os.getenv("EDGE_TAIL_BIN", "").strip()
    if env_bin:
        binary = Path(env_bin).expanduser()
        if not binary.is_absolute():
            binary = (project_root / binary).resolve()
        if not binary.exists():
            raise RuntimeError(f"EDGE_TAIL_BIN points to missing binary: {binary}")
        return binary

    subprocess.run(["zig", "build", "tail"], cwd=project_root, check=True)
    binary = project_root / "zig-out" / "bin" / "edge-tail"
    if not binary.exists():
        raise RuntimeError(f"edge-tail binary missing at {binary}")
    return binary
