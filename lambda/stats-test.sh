#!/bin/bash
# Verify the final policy-stats flush to the control plane on shutdown.
# Invoke N times (accumulating policy hits), then SIGTERM the RIE container to
# trigger SHUTDOWN → loader.close() → a final sync. The stub prints every sync;
# the last one must carry policyStatuses with non-zero matchHits.
set -euo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.stats-test.yml)

echo "== invoking 6x (each handler log matches count-all → hits accumulate) =="
for i in $(seq 1 6); do
  curl -sS -XPOST "http://localhost:9000/2015-03-31/functions/function/invocations" -d "{\"n\":$i}" >/dev/null && echo "  invoke $i"
  sleep 0.5
done
sleep 1

echo
echo "== syncs recorded BEFORE shutdown (expect startup sync, matchHits=0) =="
"${COMPOSE[@]}" logs control-plane 2>&1 | grep "SYNC #" || echo "(none yet)"

echo
echo "== SIGTERM lambda-test → SHUTDOWN → close() final sync =="
"${COMPOSE[@]}" stop -t 15 lambda-test >/dev/null 2>&1
sleep 1

echo
echo "== extension shutdown + sync debug logs =="
"${COMPOSE[@]}" logs lambda-test 2>&1 | grep -iE "extension.shutdown|http.sync.request|http.sync.status|final policy stats|LambdaExtensionError" | tail -15

echo
echo "== ALL syncs recorded by the stub (the LAST should carry matchHits>0) =="
"${COMPOSE[@]}" logs control-plane 2>&1 | grep "SYNC #"
