"""B28: TLS flushing must deliver every declared body byte.

Exercises the production upstream clients shared by both frontends, directly:
the driver trusts the fixture certificate without changing OS trust or adding
a test-only certificate setting to the edge server. No frontend is involved.
"""

from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest

from harness.procs import REPO_ROOT
from harness.tls import tls_intake


class TlsBodyIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="edge-matrix-tls-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.cert, cls.key = directory / "cert.pem", directory / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, capture_output=True)
        cls.binary = directory / "upstream-tls"
        subprocess.run([
            str(Path(REPO_ROOT) / "bin/zig"), "build-exe", "-lc", "-O", "ReleaseSafe",
            "--dep", "upstream", "-Mroot=src/bench/upstream_tls_harness.zig",
            "-Mupstream=src/frontend/upstream.zig", f"-femit-bin={cls.binary}",
        ], cwd=REPO_ROOT, check=True)

    def check_bodies(self, version):
        with tls_intake(version, self.cert, self.key) as (url, failures):
            result = subprocess.run(
                [str(self.binary), url, str(self.cert)], capture_output=True, text=True, timeout=60,
            )
        self.assertEqual([], failures, f"{version.name}: intake received a truncated or altered body")
        self.assertEqual(0, result.returncode, result.stderr)

    def test_tls12_preserves_buffered_and_streamed_bodies(self):
        self.check_bodies(ssl.TLSVersion.TLSv1_2)

    def test_tls13_preserves_buffered_and_streamed_bodies(self):
        self.check_bodies(ssl.TLSVersion.TLSv1_3)
