"""`oha` wrapper, for the cases that need real load rather than one request."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile


def available() -> bool:
    return shutil.which("oha") is not None


def run(url: str, payload: bytes, connections: int, seconds: float, method: str = "POST") -> dict:
    """Drives `oha` and returns its summary. Raises when oha is missing."""
    if not available():
        raise RuntimeError("oha is not installed (brew install oha)")
    body = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
    body.write(payload)
    body.close()
    out = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False)
    out.close()
    subprocess.run(
        [
            "oha", "-z", "%ds" % int(seconds), "-c", str(connections), "-m", method,
            "-H", "Content-Type: application/json", "-D", body.name,
            "--no-tui", "--output-format", "json", "-o", out.name, url,
        ],
        check=True,
        capture_output=True,
    )
    with open(out.name) as handle:
        report = json.load(handle)
    return {
        "rps": report["summary"]["requestsPerSec"],
        "p50": report["latencyPercentiles"]["p50"],
        "p99": report["latencyPercentiles"]["p99"],
        "p99.9": report["latencyPercentiles"]["p99.9"],
        "max": report["summary"]["slowest"],
        "codes": report["statusCodeDistribution"],
    }
