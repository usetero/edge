#!/usr/bin/env python3
"""Generate Datadog intake payloads for each record shape the parser handles.

Shapes map 1:1 to code paths in src/signals/datadog/log.zig:
  plain    known fields only (the original datadog-2mb shape)
  extras   + unknown scalar fields   -> extra map (dupe + asAny scalars)
  nested   + nested object/array     -> asAny + stringifyAnyValue + extra_raw_json
  wrapped  message is stringified JSON (GCP/Cloud Run forwarder shape)
           -> ensureUnwrapped / flattenValue / bodyForMatch DFS

Each payload is a JSON array ~TARGET_BYTES decoded (must stay under the
config's max_decoded_bytes, 2 MiB in bench configs), written as .json.zst for
oha -D. Pass --json to also keep the uncompressed file. Deterministic output.

Usage: python3 bench/perf/generate_payloads.py [--json]
"""

import json
import pathlib
import subprocess
import sys

TARGET_BYTES = 1_800_000  # decoded; leaves headroom under the 2 MiB cap
OUT_DIR = pathlib.Path(__file__).parent / "payloads"

HOSTS = ["web-01", "web-02", "api-03", "worker-04", "cron-05"]


def base(i):
    return {
        "message": (
            f"Log entry {i}: User authentication request completed "
            "successfully with MFA verification for request processing on server"
        ),
        "service": "auth-service",
        "hostname": f"{HOSTS[i % len(HOSTS)]}.us-east-1.prod.example.com",
        "ddsource": "nodejs",
        "ddtags": f"env:prod,version:1.2.3,team:platform,entry:{i}",
        "status": "info",
        "timestamp": 1733946000000 + i,
    }


def plain(i):
    return base(i)


def extras(i):
    r = base(i)
    r.update(
        {
            "trace_id": "abc123-def456",
            "span_id": f"span-{i:08x}",
            "request_id": f"req-{i:012d}",
            "usr.id": f"user-{i % 1000}",
            "duration_ms": (i * 7) % 500,
            "success": i % 10 != 0,
        }
    )
    return r


def nested(i):
    r = extras(i)
    r.update(
        {
            "http": {
                "method": "POST" if i % 3 else "GET",
                "status_code": 200 if i % 20 else 503,
                "url": f"/api/v1/orders/{i}",
                "useragent": "Mozilla/5.0 (compatible; svc/1.2)",
            },
            "error": {"kind": "", "stack": ""},
            "tags": ["region:us-east-1", "tier:web", f"shard:{i % 16}"],
        }
    )
    return r


def wrapped(i):
    inner = {
        "data": {
            "jsonPayload": {
                "event_type": "RequestCompleted",
                "account_name": f"account-{i % 100}",
                "message": (
                    f"request {i} completed with MFA verification "
                    "for downstream processing"
                ),
                "modules": ["auth", "mfa"],
            }
        },
        "severity": "INFO",
    }
    r = base(i)
    r["message"] = json.dumps(inner, separators=(",", ":"))
    r["ddsource"] = "gcp"
    return r


SHAPES = {"plain": plain, "extras": extras, "nested": nested, "wrapped": wrapped}


def build(shape_fn):
    records, size, i = [], 2, 0  # 2 for the surrounding []
    while size < TARGET_BYTES:
        rec = json.dumps(shape_fn(i), separators=(",", ":"))
        records.append(rec)
        size += len(rec) + 1
        i += 1
    return "[" + ",".join(records) + "]"


def main():
    keep_json = "--json" in sys.argv
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, fn in SHAPES.items():
        body = build(fn)
        json_path = OUT_DIR / f"datadog-2mb-{name}.json"
        json_path.write_text(body)
        subprocess.run(
            ["zstd", "-f", "-q", str(json_path), "-o", str(json_path) + ".zst"],
            check=True,
        )
        n = body.count('"message"')
        print(f"{name}: {len(body):,} bytes decoded, {n} records -> {json_path}.zst")
        if not keep_json:
            json_path.unlink()


if __name__ == "__main__":
    main()
