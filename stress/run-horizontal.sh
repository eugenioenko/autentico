#!/bin/bash
set -e

BINARY=/home/enko/Documents/autentico/autentico
SECRET=benchmarksecret123
K6_IMG="grafana/k6"
SCRIPTS=/home/enko/Documents/autentico/stress
TEST_SCRIPT=/scripts/load-1m-50vu-nosleep.js

run_k6() {
  docker run --rm -i --network=host \
    -v "$SCRIPTS:/scripts" \
    -e BASE_URL=http://localhost:9999 \
    -e USERNAME=admin -e PASSWORD=asdf123 \
    -e CLIENT_ID=stress-test \
    -e REDIRECT_URI=http://localhost:8080/stress/callback \
    "$K6_IMG" run "$TEST_SCRIPT" 2>&1 | grep -E "login_latency\.|iterations\.\."
}

start_worker() {
  local core=$1 port=$2
  taskset -c "$core" env AUTENTICO_VERIFICO_SECRET=$SECRET AUTENTICO_VERIFICO_URL=http://0.0.0.0:$port AUTENTICO_MAX_PROCS=1 \
    "$BINARY" verifico start --port "$port" &>/tmp/verifico-$port.log &
  PIDS+=($!)
}

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  PIDS=()
  sleep 1
}

run_test() {
  local label="$1" a_cores="$2" a_maxprocs="$3" workers_env="$4"
  shift 4
  PIDS=()

  # Start workers (remaining args are core:port pairs)
  for wp in "$@"; do
    local core="${wp%%:*}" port="${wp##*:}"
    start_worker "$core" "$port"
  done
  sleep 1

  # Start Autentico
  taskset -c "$a_cores" env AUTENTICO_MAX_PROCS=$a_maxprocs AUTENTICO_VERIFICO_WORKERS=$workers_env \
    "$BINARY" start &>/tmp/autentico-hz.log &
  PIDS+=($!)
  sleep 2

  echo "=== $label ==="
  run_k6
  cleanup
}

# Test 1: 2 cores — 1A + 1W
run_test "2 cores: 1A + 1W" "0" "1" "localhost:5050" "1:5050"

# Test 2: 4 cores — 1A + 3W
run_test "4 cores: 1A + 3W" "0" "1" "localhost:5050,localhost:5051,localhost:5052" "1:5050" "2:5051" "3:5052"

# Test 3: 4 cores — 2A + 2W
run_test "4 cores: 2A + 2W" "0-1" "2" "localhost:5050,localhost:5051" "2:5050" "3:5051"

# Test 4: 6 cores — 2A + 4W
run_test "6 cores: 2A + 4W" "0-1" "2" "localhost:5050,localhost:5051,localhost:5052,localhost:5053" "2:5050" "3:5051" "4:5052" "5:5053"

# Test 5: 6 cores — 1A + 5W
run_test "6 cores: 1A + 5W" "0" "1" "localhost:5050,localhost:5051,localhost:5052,localhost:5053,localhost:5054" "1:5050" "2:5051" "3:5052" "4:5053" "5:5054"

# Test 6: 8 cores — 2A + 6W
run_test "8 cores: 2A + 6W" "0-1" "2" "localhost:5050,localhost:5051,localhost:5052,localhost:5053,localhost:5054,localhost:5055" "2:5050" "3:5051" "4:5052" "5:5053" "6:5054" "7:5055"

# Test 7: 8 cores — 4A + 4W
run_test "8 cores: 4A + 4W" "0-3" "4" "localhost:5050,localhost:5051,localhost:5052,localhost:5053" "4:5050" "5:5051" "6:5052" "7:5053"

echo "=== ALL DONE ==="
