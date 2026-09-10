#!/usr/bin/env bash
#
# Property-based fuzzing of the Autentico HTTP API with Schemathesis.
#
# Spins up a throwaway server (temp DB, rate limiting off) and drives it from the
# live OpenAPI spec at /swagger/doc.json. Two profiles:
#
#   public  unauthenticated; every path except /admin/* and /account/*
#   admin   authenticated with a clean ROPC bearer token; /admin/api/* only.
#           /admin/api/settings* is excluded so the fuzzer cannot disable its
#           own auth or CORS mid-run.
#
# Requires Docker. Linux only (uses --network=host).
#
# Usage:
#   make schemathesis                     # both profiles
#   PROFILE=public schemathesis/run.sh
#   PROFILE=admin  schemathesis/run.sh
#
# Env overrides:
#   PROFILE        public | admin | both          (default: both)
#   PORT           server port                    (default: 19998)
#   MAX_EXAMPLES   generated cases per operation   (default: 50)
#   MAX_FAILURES   stop after N failures           (default: 50)
#   ST_IMAGE       schemathesis docker image       (default: pinned below)
#   ST_ARGS        extra args for `schemathesis run`
#   AUTENTICO_BIN  path to the server binary       (default: <repo>/autentico)
#   KEEP_SERVER    set to 1 to leave the server running on exit

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-both}"
PORT="${PORT:-19998}"
BASE_URL="http://localhost:${PORT}"
MAX_EXAMPLES="${MAX_EXAMPLES:-50}"
MAX_FAILURES="${MAX_FAILURES:-50}"
ST_IMAGE="${ST_IMAGE:-schemathesis/schemathesis:4.26.1}"
AUTENTICO_BIN="${AUTENTICO_BIN:-$ROOT/autentico}"
REPORT_DIR="$ROOT/schemathesis/report"

ADMIN_USER=admin
ADMIN_PASS='Password123!'

workdir="$(mktemp -d)"
server_pid=""

cleanup() {
  if [ -n "$server_pid" ] && [ -z "${KEEP_SERVER:-}" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$workdir"
}
trap cleanup EXIT

command -v docker >/dev/null || { echo "docker is required"; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }

if [ ! -x "$AUTENTICO_BIN" ]; then
  echo ">> building server binary"
  make -C "$ROOT" build-go
fi

mkdir -p "$REPORT_DIR"

export AUTENTICO_DB_FILE_PATH="$workdir/autentico.db"
cd "$workdir"   # keep the generated .env and cwd state out of the repo

echo ">> init + onboard"
"$AUTENTICO_BIN" init --url "$BASE_URL" >/dev/null
"$AUTENTICO_BIN" onboard --username "$ADMIN_USER" --password "$ADMIN_PASS" \
  --email admin@test.com --enable-admin-password-grant >/dev/null

echo ">> starting server on $BASE_URL"
AUTENTICO_CSRF_SECURE_COOKIE=false \
AUTENTICO_IDP_SESSION_SECURE=false \
AUTENTICO_REFRESH_TOKEN_SECURE=false \
AUTENTICO_RATE_LIMIT_RPS=0 \
AUTENTICO_RATE_LIMIT_RPM=0 \
  "$AUTENTICO_BIN" start >"$workdir/server.log" 2>&1 &
server_pid=$!

for i in $(seq 1 100); do
  if curl -sf "$BASE_URL/healthz" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "server exited early:"; cat "$workdir/server.log"; exit 1
  fi
  sleep 0.2
  if [ "$i" = 100 ]; then
    echo "server did not become ready"; cat "$workdir/server.log"; exit 1
  fi
done

SPEC_URL="$BASE_URL/swagger/doc.json"
rc=0

st() {
  docker run --rm --network=host \
    --user "$(id -u):$(id -g)" \
    -v "$REPORT_DIR:/report" \
    "$ST_IMAGE" run "$SPEC_URL" \
    --url "$BASE_URL" \
    --checks all \
    --max-examples "$MAX_EXAMPLES" \
    --max-failures "$MAX_FAILURES" \
    --request-timeout 10 \
    ${ST_ARGS:-} \
    "$@"
}

run_public() {
  echo; echo "=== PROFILE: public ==="
  st --exclude-path-regex '^/(admin|account)/' \
     --report junit --report-junit-path /report/junit-public.xml || rc=$?
}

run_admin() {
  echo; echo "=== PROFILE: admin ==="
  local token
  token="$(curl -sf "$BASE_URL/oauth2/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d "grant_type=password&username=${ADMIN_USER}&password=${ADMIN_PASS}&client_id=autentico-admin&scope=openid profile email" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
  if [ -z "$token" ]; then echo "failed to obtain admin token"; rc=1; return; fi
  st --include-path-regex '^/admin/' \
     --exclude-path-regex '^/admin/api/settings' \
     -H "Authorization: Bearer $token" \
     --report junit --report-junit-path /report/junit-admin.xml || rc=$?
}

case "$PROFILE" in
  public) run_public ;;
  admin)  run_admin ;;
  both)   run_public; run_admin ;;
  *) echo "unknown PROFILE: $PROFILE (want public|admin|both)"; exit 2 ;;
esac

echo
echo ">> JUnit reports written to schemathesis/report/"
exit $rc
