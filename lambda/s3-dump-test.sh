#!/bin/bash
# Drive the local RIE s3-dump test: invoke a few times (the extension flushes
# at each invoke boundary), then list the RustFS bucket.
#
# Bring the stack up first:
#   docker compose -f docker-compose.yml -f docker-compose.s3-dump.yml up -d
set -euo pipefail

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
S3=(curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user rustfsadmin:rustfsadmin)
BUCKET_URL=http://localhost:9002/tero-edge-dump
keys=$("${S3[@]}" "$BUCKET_URL?list-type=2&prefix=dump/" | grep -o '<Key>[^<]*' | sed 's/<Key>//' || true)
if [ -z "$keys" ]; then
  echo '(no objects yet)'
  exit 0
fi
echo "$keys"
echo '---'
"${S3[@]}" "$BUCKET_URL/$(echo "$keys" | head -1)" | head -c 400
