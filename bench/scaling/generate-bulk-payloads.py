#!/usr/bin/env python3
"""Generate a gzipped Datadog logs batch that matches production agent traffic.

The checked-in payloads are 1-4 KB and uncompressed, so a benchmark using them
never exercises the decompression path and never approaches max_body_size. A
real Datadog agent ships gzipped batches: roughly 1 MB on the wire that expands
to about 4 MB once decoded.

Plain replicated JSON compresses far past 4:1, so the record template carries
randomized high-entropy fields (trace ids, span ids, request ids, a token
blob). Those are what real logs contain, and they let the generator hit a
requested compression ratio instead of whatever the template happens to give.
The entropy width is bisected until the gzipped size lands near the target.
"""

import argparse
import gzip
import json
import os
import random
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOADS_DIR = os.path.join(SCRIPT_DIR, "payloads")

HEX = "0123456789abcdef"


def build_batch(template, decoded_bytes, entropy_chars, rng):
    """Emit records until the encoded array reaches decoded_bytes."""
    records = []
    size = 2  # the enclosing [] brackets
    i = 0
    while size < decoded_bytes:
        record = dict(template[i % len(template)])
        i += 1
        # Fields a real agent varies per record. These dominate the compressed
        # size; everything else in the template is near-free after the first
        # occurrence.
        record["trace_id"] = "".join(rng.choices(HEX, k=32))
        record["span_id"] = "".join(rng.choices(HEX, k=16))
        record["timestamp"] = 1700000000000 + i
        if entropy_chars > 0:
            record["request_context"] = "".join(rng.choices(HEX, k=entropy_chars))
        records.append(record)
        size += len(json.dumps(record, separators=(",", ":"))) + 1
    return records


def encode(records):
    raw = json.dumps(records, separators=(",", ":")).encode()
    return raw, gzip.compress(raw, compresslevel=6)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--decoded-bytes", type=int, default=4 * 1024 * 1024)
    ap.add_argument("--compressed-bytes", type=int, default=1024 * 1024)
    ap.add_argument("--template", default=os.path.join(PAYLOADS_DIR, "datadog-logs.json"))
    ap.add_argument("--out", default=os.path.join(PAYLOADS_DIR, "datadog-logs-bulk.json.gz"))
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    with open(args.template) as f:
        template = json.load(f)

    # Bisect the per-record entropy width until the gzipped size lands within
    # 3% of the target. More entropy compresses worse, so size is monotonic
    # in entropy_chars and a plain bisection converges.
    lo, hi = 0, 4096
    best = None
    for _ in range(14):
        mid = (lo + hi) // 2
        records = build_batch(template, args.decoded_bytes, mid, random.Random(args.seed))
        raw, packed = encode(records)
        best = (raw, packed, mid)
        if abs(len(packed) - args.compressed_bytes) <= args.compressed_bytes * 0.03:
            break
        if len(packed) < args.compressed_bytes:
            lo = mid + 1
        else:
            hi = mid - 1
        if lo > hi:
            break

    raw, packed, entropy = best
    with open(args.out, "wb") as f:
        f.write(packed)

    ratio = len(raw) / len(packed)
    print(
        f"Generated {args.out}: {len(packed):,} bytes gzipped, "
        f"{len(raw):,} bytes decoded ({ratio:.1f}:1, {len(json.loads(raw)):,} records)"
    )
    if abs(len(packed) - args.compressed_bytes) > args.compressed_bytes * 0.10:
        print(
            f"warning: compressed size is more than 10% off the {args.compressed_bytes:,} "
            f"byte target (entropy width bottomed out at {entropy})",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
