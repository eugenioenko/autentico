#!/bin/bash
set -e

BINARY=/home/enko/Documents/autentico/autentico
SECRET=benchmarksecret123
K6_IMG="grafana/k6"
SCRIPTS=/home/enko/Documents/autentico/stress
TEST_SCRIPT=/scripts/load-30s-200vu-nosleep.js
RESULTS_FILE=/home/enko/Documents/autentico/horizontal_200vu_results.txt

> "$RESULTS_FILE"

run_k6() {
  docker run --rm -i --network=host \
    -v "$SCRIPTS:/scripts" \
    -e BASE_URL=http://localhost:9999 \
    -e USERNAME=lisa.mitchell1 -e PASSWORD=asdf123 \
    -e CLIENT_ID=stress-test \
    -e REDIRECT_URI=http://localhost:8080/stress/callback \
    "$K6_IMG" run "$TEST_SCRIPT" 2>&1 | grep -E "iterations|login_latency|token_latency|refresh_latency|authorize_latency|introspect_latency|flow_errors|flow_success|http_req_failed"
}

start_worker() {
  local port=$1 maxprocs=$2
  env AUTENTICO_VERIFICO_SECRET=$SECRET AUTENTICO_VERIFICO_URL=http://0.0.0.0:$port AUTENTICO_MAX_PROCS=$maxprocs \
    "$BINARY" verifico start --port "$port" &>/tmp/verifico-$port.log &
  PIDS+=($!)
}

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  PIDS=()
  sleep 2
}

run_test() {
  local label="$1"
  local num_workers="$2"
  PIDS=()

  local workers_env=""
  for i in $(seq 1 "$num_workers"); do
    local port=$((5049 + i))
    start_worker "$port" 1
    if [ -n "$workers_env" ]; then
      workers_env="$workers_env,localhost:$port"
    else
      workers_env="localhost:$port"
    fi
  done
  sleep 1

  if [ -n "$workers_env" ]; then
    env AUTENTICO_MAX_PROCS=2 AUTENTICO_VERIFICO_WORKERS=$workers_env \
      "$BINARY" start &>/tmp/autentico-hz.log &
  else
    env AUTENTICO_MAX_PROCS=2 \
      "$BINARY" start &>/tmp/autentico-hz.log &
  fi
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

# 2 total cores: 2A + 0W (baseline, no verifico)
run_test "2c: 2A + 0W (baseline)" 0

# 4 total cores: 2A + 2W
run_test "4c: 2A + 2W" 2

# 6 total cores: 2A + 4W
run_test "6c: 2A + 4W" 4

# 8 total cores: 2A + 6W
run_test "8c: 2A + 6W" 6

# 16 total cores: 2A + 14W
run_test "16c: 2A + 14W" 14

echo ""
echo "=== ALL DONE ==="
echo "Results saved to $RESULTS_FILE"
