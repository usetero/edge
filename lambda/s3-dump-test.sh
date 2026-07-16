#!/bin/bash
# Drive the local RIE s3-dump test: invoke a few times (the extension flushes
# at each invoke boundary), then list the MinIO bucket.
#
# Bring the stack up first:
#   docker compose -f docker-compose.yml -f docker-compose.s3-dump.yml up -d
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.s3-dump.yml)

echo "== invoking the function 5x (each POSTs a Datadog log through the extension) =="
for i in $(seq 1 5); do
  curl -sS -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" \
    -H "Content-Type: application/json" \
    -d "{\"n\":$i}" >/dev/null && echo "  invoke $i ok"
  sleep 1
done

echo "== giving the invoke-boundary flush a moment =="
sleep 2

echo "== objects in s3://tero-edge-dump/dump/ =="
"${COMPOSE[@]}" run --rm --entrypoint /bin/sh createbuckets -c \
  "mc alias set local http://minio:9000 minioadmin minioadmin >/dev/null && mc ls --recursive local/tero-edge-dump/ && echo '---' && mc cat \$(mc ls --recursive local/tero-edge-dump/ | head -1 | awk '{print \"local/tero-edge-dump/\"\$NF}') 2>/dev/null | head -c 400 || echo '(no objects yet)'"
