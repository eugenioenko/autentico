#!/bin/bash
set -e

BINARY="$(pwd)/autentico"
SECRET=benchmarksecret123
K6_IMG="grafana/k6"
SCRIPTS="$(pwd)/stress"
TEST_SCRIPT=/scripts/load-1m-50vu-nosleep.js
RESULTS_FILE="$(pwd)/verifico_results_32core.txt"

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

  # Start Autentico (with or without verifico)
  if [ -n "$workers_env" ]; then
    env AUTENTICO_MAX_PROCS=$a_maxprocs AUTENTICO_VERIFICO_WORKERS=$workers_env \
      "$BINARY" start &>/tmp/autentico-hz.log &
  else
    env AUTENTICO_MAX_PROCS=$a_maxprocs AUTENTICO_VERIFICO_ENABLED=false \
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

echo "Verifico K8s Scaling Benchmark — $(date)"
echo "Verifico K8s Scaling Benchmark — $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# ── Part 1: Vertical baseline (no verifico) ────────────────────────────────
echo "--- Part 1: Vertical Scaling Baseline ---"
echo "--- Part 1: Vertical Scaling Baseline ---" >> "$RESULTS_FILE"

run_test "Vertical: 2 cores"  2 0
run_test "Vertical: 4 cores"  4 0
run_test "Vertical: 8 cores"  8 0
run_test "Vertical: 16 cores" 16 0
run_test "Vertical: 32 cores" 32 0

# ── Part 2: K8s simulation — 2-core Autentico + N worker nodes ─────────────
# Each worker simulates a 2-core k8s node.
echo "--- Part 2: K8s Scaling (2A + N worker nodes, 2 cores each) ---"
echo "--- Part 2: K8s Scaling (2A + N worker nodes, 2 cores each) ---" >> "$RESULTS_FILE"

run_test "K8s: 2A(2) + 1W(2)" 2 2  5050
run_test "K8s: 2A(2) + 2W(2)" 2 2  5050 5051
run_test "K8s: 2A(2) + 3W(2)" 2 2  5050 5051 5052
run_test "K8s: 2A(2) + 4W(2)" 2 2  5050 5051 5052 5053
run_test "K8s: 2A(2) + 6W(2)" 2 2  5050 5051 5052 5053 5054 5055
run_test "K8s: 2A(2) + 8W(2)" 2 2  5050 5051 5052 5053 5054 5055 5056 5057

# ── Part 3: Best configs from laptop retested on 32 cores ──────────────────
echo "--- Part 3: Best Configs Retest ---"
echo "--- Part 3: Best Configs Retest ---" >> "$RESULTS_FILE"

run_test "Retest: 1A(1) + 3W(1)" 1 1  5050 5051 5052
run_test "Retest: 2A(2) + 4W(1)" 2 1  5050 5051 5052 5053
run_test "Retest: 4A(4) + 2W(2)" 4 2  5050 5051

echo ""
echo "=== ALL DONE ==="
echo "Results saved to $RESULTS_FILE"
