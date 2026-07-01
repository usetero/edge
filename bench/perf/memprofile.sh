#!/usr/bin/env bash
# Faithful memory recreation: 2 MiB decoded zstd DD-logs traffic through the
# filter path, captured with sample + heap (malloc-attributed) + vmmap.
# Usage: bench/perf/memprofile.sh [connections=4] [warmup_secs=18] [load=45s]
# ponytail: single-knob (concurrency). Run it per -c value for the sweep.
set -euo pipefail
cd "$(dirname "$0")/../.."

CONN=${1:-4}; WARM=${2:-18}; DUR=${3:-45s}
CFG=bench/perf/configs/datadog-2mb-rules.json
PAY=bench/perf/payloads/datadog-2mb.json.zst
OUT=bench/perf/debug/mem; mkdir -p "$OUT"

./zig-out/bin/echo-server 9999 >/dev/null 2>&1 & ECHO=$!
# MallocStackLogging: makes `heap` print alloc backtraces so every big node is
# attributed to its call stack — the whole point of this capture.
MallocStackLogging=1 ./zig-out/bin/edge-datadog "$CFG" >"$OUT/proxy.log" 2>&1 & PROXY=$!
trap 'kill $ECHO $PROXY 2>/dev/null || true' EXIT
until curl -sf -o /dev/null http://127.0.0.1:8080/_health; do sleep 0.2; done

oha -z "$DUR" -c "$CONN" -m POST \
  -H "Content-Type: application/json" -H "Content-Encoding: zstd" \
  -D "$PAY" http://127.0.0.1:8080/api/v2/logs >"$OUT/oha-c$CONN.log" 2>&1 & LOAD=$!

sleep "$WARM"   # reach steady state + spread requests across all pool threads
echo "capturing at c=$CONN (pid $PROXY)…"
sample "$PROXY" 4 -f "$OUT/sample-c$CONN.txt" >/dev/null 2>&1 || true
heap   "$PROXY" >"$OUT/heap-c$CONN.txt" 2>&1 || true
vmmap  "$PROXY" >"$OUT/vmmap-c$CONN.txt" 2>&1 || true
grep -iE "physical footprint" "$OUT/heap-c$CONN.txt" | head -2
wait "$LOAD" >/dev/null 2>&1 || true
echo "artifacts: $OUT/{sample,heap,vmmap}-c$CONN.txt"
