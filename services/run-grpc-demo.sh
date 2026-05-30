#!/usr/bin/env bash
# Polyglot demo: start the Python gRPC detection engine, then run the Go collector
# against it (Go collector -> gRPC -> Python engine). See docs/adr/0002 and 0003.
#
# Usage:  bash services/run-grpc-demo.sh [logs.jsonl] [min_proximity]
set -euo pipefail
cd "$(dirname "$0")/.."

LOGS="${1:-sample_data/corpus/enterprise_day.jsonl}"
MINPROX="${2:-0.9}"
PORT="${FS_GRPC_PORT:-50051}"
LOG=/tmp/fs_grpc_demo.log

echo ">> starting Python gRPC engine on :$PORT"
uv run --extra grpc python services/engine_grpc/server.py "$PORT" > "$LOG" 2>&1 &
SV=$!
# clean up the whole server (uv parent + python child): kill the pid AND whatever holds the port
cleanup() { kill "$SV" 2>/dev/null || true; lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true; }
trap cleanup EXIT

for _ in $(seq 1 60); do
  grep -q "gRPC detection engine on" "$LOG" 2>/dev/null && break
  sleep 0.5
done
cat "$LOG"

echo ">> running Go collector against $LOGS"
( cd services/collector-go && FS_ENGINE_ADDR="localhost:$PORT" go run . "../../$LOGS" "$MINPROX" )
