#!/bin/bash
set -e

BINARY="$(pwd)/autentico"
TEST_SCRIPT="$(pwd)/stress/load-10s-200vu-nosleep.js"
RESULTS_FILE="$(pwd)/wal_bench_results.txt"
DB_DIR="$(pwd)/data"
DB_FILE="$DB_DIR/bench.db"
PORT=9999
BASE_URL="http://localhost:$PORT"
USERNAME="admin"
PASSWORD="BenchTest123!"

> "$RESULTS_FILE"

setup_fresh_db() {
  rm -rf "$DB_DIR"
  mkdir -p "$DB_DIR"

  # Onboard creates DB, runs migrations, seeds admin client with ROPC
  AUTENTICO_DB_FILE_PATH="$DB_FILE" \
  AUTENTICO_CSRF_SECURE_COOKIE=false \
  AUTENTICO_IDP_SESSION_SECURE=false \
    "$BINARY" onboard --username "$USERNAME" --password "$PASSWORD" --enable-admin-password-grant

  # Start server briefly to configure via admin API
  AUTENTICO_DB_FILE_PATH="$DB_FILE" \
  AUTENTICO_CSRF_SECURE_COOKIE=false \
  AUTENTICO_IDP_SESSION_SECURE=false \
  AUTENTICO_RATE_LIMIT_RPS=0 \
  AUTENTICO_RATE_LIMIT_RPM=0 \
    "$BINARY" start &>/tmp/autentico-bench.log &
  SERVER_PID=$!
  sleep 2

  # Get admin token via ROPC
  local token_resp
  token_resp=$(curl -sf -X POST "$BASE_URL/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&username=$USERNAME&password=$PASSWORD&client_id=autentico-admin")
  ADMIN_TOKEN=$(echo "$token_resp" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

  if [ -z "$ADMIN_TOKEN" ]; then
    echo "FATAL: failed to get admin token"
    kill "$SERVER_PID" 2>/dev/null || true
    exit 1
  fi

  # Create public stress-test client
  curl -sf -X POST "$BASE_URL/admin/api/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "client_id": "stress-test",
      "client_name": "Stress Test Client",
      "client_type": "public",
      "redirect_uris": ["http://localhost:8080/stress/callback"],
      "grant_types": ["authorization_code", "refresh_token"],
      "response_types": ["code"],
      "scopes": "openid profile email offline_access",
      "token_endpoint_auth_method": "none"
    }' >/dev/null

  # Disable lockout and SSO idle timeout
  curl -sf -X PUT "$BASE_URL/admin/api/settings" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"account_lockout_max_attempts": "0", "sso_session_idle_timeout": "0"}' >/dev/null

  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  sleep 1
}

run_k6() {
  k6 run \
    -e BASE_URL="$BASE_URL" \
    -e USERNAME="$USERNAME" \
    -e PASSWORD="$PASSWORD" \
    -e CLIENT_ID=stress-test \
    -e REDIRECT_URI=http://localhost:8080/stress/callback \
    "$TEST_SCRIPT" 2>&1 | grep -E "iterations|login_latency|token_latency|refresh_latency|authorize_latency|introspect_latency|flow_errors|flow_success|http_req_failed"
}

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
  sleep 1
}

run_test() {
  local label="$1" cores="$2"

  echo ""
  echo "=== $label ==="

  AUTENTICO_DB_FILE_PATH="$DB_FILE" \
  AUTENTICO_CSRF_SECURE_COOKIE=false \
  AUTENTICO_IDP_SESSION_SECURE=false \
  AUTENTICO_RATE_LIMIT_RPS=0 \
  AUTENTICO_RATE_LIMIT_RPM=0 \
  GOMAXPROCS="$cores" \
    "$BINARY" start &>/tmp/autentico-bench.log &
  SERVER_PID=$!
  sleep 2

  echo "=== $label ===" >> "$RESULTS_FILE"
  local output
  output=$(run_k6)
  echo "$output"
  echo "$output" >> "$RESULTS_FILE"
  echo "" >> "$RESULTS_FILE"

  cleanup
}

echo "WAL Mode Benchmark (10s, 200 VU) — $(date)"
echo "WAL Mode Benchmark (10s, 200 VU) — $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

setup_fresh_db

run_test "WAL: 1 core"    1
run_test "WAL: 2 cores"   2
run_test "WAL: 4 cores"   4
run_test "WAL: 6 cores"   6
run_test "WAL: 8 cores"   8
run_test "WAL: unlimited" "$(nproc)"

echo ""
echo "=== ALL DONE ==="
echo "Results saved to $RESULTS_FILE"
