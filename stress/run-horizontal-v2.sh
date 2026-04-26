#!/bin/bash
set -e

BINARY=/home/enko/Documents/autentico/autentico
SECRET=benchmarksecret123
K6_IMG="grafana/k6"
SCRIPTS=/home/enko/Documents/autentico/stress
TEST_SCRIPT=/scripts/load-1m-50vu-nosleep.js
RESULTS_FILE=/home/enko/Documents/autentico/horizontal_raw.txt

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
  local a_maxprocs="$2"
  local worker_maxprocs="$3"
  shift 3
  PIDS=()

  # Remaining args are port numbers for workers
  local workers_env=""
  for port in "$@"; do
    start_worker "$port" "$worker_maxprocs"
    if [ -n "$workers_env" ]; then
      workers_env="$workers_env,localhost:$port"
    else
      workers_env="localhost:$port"
    fi
  done
  sleep 1

  # Start Autentico
  env AUTENTICO_MAX_PROCS=$a_maxprocs AUTENTICO_VERIFICO_WORKERS=$workers_env \
    "$BINARY" start &>/tmp/autentico-hz.log &
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

# Test 1: 2 cores — 1A(1) + 1W(1)
run_test "2c: 1A(1) + 1W(1)" 1 1 5050

# Test 2: 4 cores — 1A(1) + 3W(1)
run_test "4c: 1A(1) + 3W(1)" 1 1 5050 5051 5052

# Test 3: 4 cores — 2A(2) + 2W(1)
run_test "4c: 2A(2) + 2W(1)" 2 1 5050 5051

# Test 4: 6 cores — 2A(2) + 4W(1)
run_test "6c: 2A(2) + 4W(1)" 2 1 5050 5051 5052 5053

# Test 5: 6 cores — 1A(1) + 5W(1)
run_test "6c: 1A(1) + 5W(1)" 1 1 5050 5051 5052 5053 5054

# Test 6: 8 cores — 4A(4) + 4W(1)
run_test "8c: 4A(4) + 4W(1)" 4 1 5050 5051 5052 5053

# Test 7: 8 cores — 2A(2) + 6W(1)
run_test "8c: 2A(2) + 6W(1)" 2 1 5050 5051 5052 5053 5054 5055

# Test 8: 8 cores — 2A(2) + 3W(2)
run_test "8c: 2A(2) + 3W(2)" 2 2 5050 5051 5052

# Test 9: 8 cores — 4A(4) + 2W(2)
run_test "8c: 4A(4) + 2W(2)" 4 2 5050 5051

echo ""
echo "=== ALL DONE ==="
echo "Results saved to $RESULTS_FILE"
