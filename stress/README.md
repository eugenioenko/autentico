# Stress Tests

Load and stress tests for Autentico using [k6](https://k6.io).

## Prerequisites

- Docker (used by the Makefile targets — no k6 install required), **or** [k6](https://k6.io/docs/get-started/installation/) installed directly
- A running Autentico instance started **with rate limiting disabled** (see below)
- A registered public OAuth2 client and a test user (see setup below)

## Setup

### 1. Start the server without rate limiting

The default per-IP rate limiter (20 RPM) will throttle requests long before any load test
produces meaningful results. Use the dedicated make target:

```bash
make stress-server
# equivalent to:
AUTENTICO_RATE_LIMIT_RPS=0 AUTENTICO_RATE_LIMIT_RPM=0 ./autentico start
```

> **Do not run with rate limiting disabled in production.**

### 2. Configure runtime settings for load testing

Two runtime settings must be adjusted before running multi-VU tests. With defaults, all
500 VUs share one test user — the account lockout kicks in after 5 failed attempts and
blocks all subsequent logins for 15 minutes.

```bash
curl -X PUT http://localhost:9999/admin/api/settings \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_lockout_max_attempts": "0", "sso_session_idle_timeout": "0"}'
```

- `account_lockout_max_attempts=0` — disables lockout so a single locked account can't
  block the entire test
- `sso_session_idle_timeout=0` — disables IdP SSO sessions; without this, after the first
  successful login each VU carries a session cookie and `/oauth2/authorize` redirects
  directly to the callback instead of showing the login form, breaking the flow

The `flow.js` helper also clears the cookie jar at the start of every iteration as a
belt-and-suspenders measure.

> Restore both settings to their defaults after testing.

### 3. Register the stress-test client

In the Admin UI (`/admin/`) or via the API, create a client with:

| Field        | Value                                   |
|--------------|-----------------------------------------|
| Client ID    | `stress-test`                           |
| Client Type  | `public`                                |
| Grant Types  | `authorization_code`, `refresh_token`   |
| Scopes       | `openid profile email offline_access`   |
| Redirect URI | `http://localhost:8080/stress/callback` |
| Auth Method  | `none`                                  |

### 4. Create a test user

Create (or use an existing) user whose credentials you will pass as `USERNAME` / `PASSWORD`.

## Running

All make targets accept `USERNAME`, `PASSWORD`, `BASE_URL`, and other variables as overrides:

```bash
make stress-smoke   USERNAME=admin PASSWORD=secret
make stress-load    USERNAME=admin PASSWORD=secret
make stress-spike   USERNAME=admin PASSWORD=secret
make stress-ceiling USERNAME=admin PASSWORD=secret
make stress-ratelimit
make stress-debug   USERNAME=admin PASSWORD=secret   # single iteration, verbose output
```

Or run directly with Docker:

```bash
docker run --rm -i --network=host \
  -v $(pwd)/stress:/scripts \
  -e BASE_URL=http://localhost:9999 \
  -e USERNAME=admin \
  -e PASSWORD=secret \
  -e CLIENT_ID=stress-test \
  -e REDIRECT_URI=http://localhost:8080/stress/callback \
  grafana/k6 run /scripts/smoke.js
```

Or with k6 installed locally:

```bash
k6 run \
  -e BASE_URL=http://localhost:9999 \
  -e USERNAME=admin \
  -e PASSWORD=secret \
  stress/smoke.js
```

## Configuration

| Variable       | Default                                 | Description              |
|----------------|-----------------------------------------|--------------------------|
| `BASE_URL`     | `http://localhost:8080`                 | Server base URL          |
| `USERNAME`     | `admin`                                 | Test user username       |
| `PASSWORD`     | `password`                              | Test user password       |
| `CLIENT_ID`    | `stress-test`                           | Registered client ID     |
| `REDIRECT_URI` | `http://localhost:8080/stress/callback` | Registered redirect URI  |
| `OAUTH_PATH`   | `/oauth2`                               | OAuth2 path prefix       |

## What each test covers

### `smoke.js` — sanity check
1 VU, 30 seconds. Runs a single virtual user through the full PKCE auth code flow end to end:
`authorize → login → token exchange → introspect → refresh`

Run this first after any deployment or config change to confirm the flow works before
running heavier tests.

### `load.js` — baseline performance
20 concurrent VUs for 3 minutes. Establishes steady-state p95/p99 latency numbers for each
step. SQLite's single-writer lock shows up here as latency on write-heavy steps (login, token
exchange, refresh).

### `spike.js` — burst resilience
Ramps from 0 to 100 VUs over 30 seconds, sustains for 1 minute, then ramps back down.
Confirms the server absorbs sudden traffic bursts without errors. Thresholds allow up to 5%
error rate and 3s login p95.

### `ceiling.js` — capacity limit
Ramps from 0 to 500 VUs in stages (50 → 100 → 200 → 300 → 500), sustains at 500 for
1 minute, then ramps down. Use this to find where latency becomes user-unacceptable and
where errors first appear.

### `rate_limit.js` — rate limiter verification
Fires 50 req/s at the login endpoint to confirm:
- The rate limiter blocks excess requests with HTTP 429
- `Retry-After` header is present on blocked responses
- The error body matches the expected OAuth error format

Note: run this against a server started **with** rate limiting enabled (normal `./autentico start`).

### `debug.js` — single-iteration inspector
Runs one iteration and prints the authorize page status, CSRF token snippet, login redirect
location, and response body. Use this to diagnose flow failures before running load tests.

## Capacity characterization

The following results were measured on a developer laptop (16 cores, single process, SQLite WAL
mode with read/write connection pool), 60s sustained load, running the full PKCE auth code flow
including bcrypt password verification, token issuance, introspection, and refresh.

| Concurrency | Error rate | Login p95 | Token p95 | Assessment |
|-------------|-----------|-----------|-----------|------------|
| 20 VUs      | 0%        | 248ms     | 300ms     | **Comfortable** — imperceptible to users |
| 100 VUs     | 0%        | 1.19s     | 1.56s     | **Sustained load** — fully functional |
| 200 VUs     | 0%        | 2.37s     | 2.94s     | **Moderate pressure** — noticeable but acceptable |
| 500 VUs     | 0%        | 5.76s     | 7.34s     | **Stress ceiling** — degraded experience |

**Bottleneck:** SQLite's single-writer connection. All write operations (login, token exchange,
refresh) serialize through one connection. Reads (authorize, introspect) run concurrently via
the read pool. The failure mode is graceful — requests queue and eventually succeed rather than
returning errors. No `SQLITE_BUSY` errors were observed at any load level tested.

**Practical limits:**
- Up to **~50 concurrent logins**: sub-300ms everywhere, imperceptible to users
- Up to **100 concurrent logins**: under 1.5s p95, all requests succeed — recommended
  production ceiling for a single SQLite-backed instance
- Beyond **200+ concurrent logins**: login p95 exceeds 2 seconds; consider horizontal
  scaling or reducing bcrypt cost if this load is expected

## Custom metrics

Each step is tracked independently so you can pinpoint exactly where slowdowns occur:

| Metric               | Description                         |
|----------------------|-------------------------------------|
| `authorize_latency`  | GET /oauth2/authorize               |
| `login_latency`      | POST /oauth2/login (includes bcrypt)|
| `token_latency`      | POST /oauth2/token (code exchange)  |
| `introspect_latency` | POST /oauth2/introspect             |
| `refresh_latency`    | POST /oauth2/token (refresh)        |
| `flow_errors`        | Count of failed flow iterations     |
| `flow_success_rate`  | Rate of fully successful flows      |
