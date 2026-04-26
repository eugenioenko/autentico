#!/bin/bash
set -e

BINARY="$(pwd)/autentico"
K6_IMG="grafana/k6"
SCRIPTS="$(pwd)/stress"
TEST_SCRIPT=/scripts/load-1m-50vu-nosleep.js
RESULTS_FILE="$(pwd)/wal_vertical_raw.txt"

> "$RESULTS_FILE"

run_k6() {
  docker run --rm -i --network=host \
    -v "$SCRIPTS:/scripts" \
    -e BASE_URL=http://localhost:9999 \
    -e USERNAME=admin -e PASSWORD=asdf123 \
    -e CLIENT_ID=stress-test \
    -e REDIRECT_URI=http://localhost:8080/stress/callback \
    "$K6_IMG" run "$TEST_SCRIPT" 2>&1 | grep -E "iterations|login_latency|token_latency|refresh_latency|authorize_latency|introspect_latency|flow_errors|flow_success|http_req_failed"
}

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 2
}

run_test() {
  local label="$1" maxprocs="$2"
  PIDS=()

  env AUTENTICO_MAX_PROCS=$maxprocs AUTENTICO_VERIFICO_ENABLED=false \
    "$BINARY" start &>/tmp/autentico-wal.log &
  PIDS+=($!)
  sleep 2

  echo ""
  echo "=== $label ==="
  echo "=== $label ===" >> "$RESULTS_FILE"
  local output
  output=$(run_k6)
  echo "$output"
  echo "$output" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"
  cleanup
}

echo "WAL Mode Vertical Scaling — $(date)"
echo "WAL Mode Vertical Scaling — $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

run_test "WAL Vertical: 1 core"  1
run_test "WAL Vertical: 2 cores" 2
run_test "WAL Vertical: 4 cores" 4
run_test "WAL Vertical: 6 cores" 6

echo ""
echo "=== ALL DONE ==="
