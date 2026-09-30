"""The edge's failure capture directory, as a case sees it.

A case that sets `CAPTURE_MAX_DUMPS` gets a fresh directory and the edge gets
`TERO_FAILURE_CAPTURE_DIR` pointing at it. See src/frontend/failure_capture.zig
for what a dump holds.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass


@dataclass
class Dump:
    """One dump: the `.json` metadata and the `.body` it names."""

    name: str
    meta: dict
    body: bytes
    raw_meta: str


class CaptureDir:
    def __init__(self, max_dumps: int, seed: dict | None = None):
        self.path = tempfile.mkdtemp(suffix=".failure-capture")
        # Open to everyone, the way a Kubernetes emptyDir starts, so every
        # case also checks that the edge narrows the directory.
        os.chmod(self.path, 0o777)
        self.max_dumps = max_dumps
        for name, data in (seed or {}).items():
            with open(os.path.join(self.path, name), "wb") as handle:
                handle.write(data)

    def env(self) -> dict:
        return {
            "TERO_FAILURE_CAPTURE_DIR": self.path,
            "TERO_FAILURE_CAPTURE_MAX_DUMPS": str(self.max_dumps),
        }

    def names(self) -> list[str]:
        return sorted(os.listdir(self.path))

    def clear(self) -> None:
        for name in os.listdir(self.path):
            os.unlink(os.path.join(self.path, name))

    def dumps(self) -> list[Dump]:
        """Every whole dump, oldest first. A `.body` without its `.json` is
        still being written and is not a dump yet."""
        out = []
        for name in sorted(os.listdir(self.path)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(self.path, name), "r") as handle:
                raw = handle.read()
            meta = json.loads(raw)
            with open(os.path.join(self.path, meta["body"]["file"]), "rb") as handle:
                body = handle.read()
            out.append(Dump(name=name, meta=meta, body=body, raw_meta=raw))
        return out

    def wait_for(self, count: int, timeout: float = 10.0) -> list[Dump]:
        """The dumps once there are at least `count`. A 408 is relayed before
        its dump is written, so the sender can see the answer first."""
        deadline = time.monotonic() + timeout
        dumps = self.dumps()
        while len(dumps) < count and time.monotonic() < deadline:
            time.sleep(0.1)
            dumps = self.dumps()
        return dumps

    def remove(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)
