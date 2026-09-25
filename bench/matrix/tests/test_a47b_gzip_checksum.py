"""A47b: a gzip batch that decodes, but whose CRC32 does not match its data.

gzip carries a CRC32 of the data so a receiver can detect damage. The batch
here is stored (level 0), and one letter inside a message is changed, so the
JSON stays valid and the stream decodes to the end.

A policy drops one record, so the edge writes a new gzip stream. If the edge
does not check the CRC, the new stream carries a fresh, valid CRC, and the
damaged data reaches the intake as if it were sound. The edge must not hide
damage it received: it forwards the bytes as sent, and the intake rejects them
on the CRC.
"""

import gzip
import json

from harness import MatrixCase
from tests.test_a44_abandoned_gzip_body import POLICIES


class GzipChecksum(MatrixCase):
    EDGE_POLICIES = POLICIES

    def test_a_batch_with_a_bad_crc_is_forwarded_as_sent(self):
        records = [
            {"message": "DEBUG drop me", "ddsource": "matrix"},
            {"message": "INFO keep me", "ddsource": "matrix"},
        ]
        sound = gzip.compress(json.dumps(records).encode(), 0)
        marker = sound.index(b"keep me")
        damaged = sound[:marker] + b"kEep me" + sound[marker + len(b"keep me"):]
        with self.assertRaises(gzip.BadGzipFile):
            gzip.decompress(damaged)

        self.intake.capture_start("a47b")
        self.post_raw_body(damaged, headers={"Content-Encoding": "gzip"}, timeout=30)
        bodies = self.intake.capture_stop()

        self.assertEqual(len(bodies), 1, "expected one forwarded batch")
        self.assertEqual(
            bodies[0],
            damaged,
            "the edge re-encoded a batch whose CRC did not match, so the damage "
            "reached the intake behind a valid CRC",
        )
