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

### 2. Register the stress-test client

In the Admin UI (`/admin/`) or via the API, create a client with:

| Field        | Value                                   |
|--------------|-----------------------------------------|
| Client ID    | `stress-test`                           |
| Client Type  | `public`                                |
| Grant Types  | `authorization_code`, `refresh_token`   |
| Scopes       | `openid profile email offline_access`   |
| Redirect URI | `http://localhost:8080/stress/callback` |
| Auth Method  | `none`                                  |

### 3. Create a test user

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

The following results were measured on a developer laptop (single process, SQLite backend)
running the full PKCE auth code flow including bcrypt password verification, token issuance,
introspection, and refresh. Results on server hardware will differ.

| Concurrency | Error rate | Login p95 | Token p95 | Assessment |
|-------------|------------|-----------|-----------|------------|
| 20 VUs      | 0%         | 86ms      | 54ms      | **Comfortable** — all steps well under 100ms |
| 100 VUs     | 0%         | 611ms     | 647ms     | **Supported** — noticeable but fully functional |
| 500 VUs     | 0%         | 3.36s     | 3.89s     | **Degraded** — users feel the wait at login |

**Bottleneck:** SQLite's single-writer lock. All write operations (login, token exchange,
refresh) serialize through one connection. The failure mode is graceful — requests queue and
eventually succeed rather than returning errors. No `SQLITE_BUSY` errors were observed at any
load level tested.

**Practical limits:**
- Up to **~50 concurrent logins**: sub-200ms everywhere, imperceptible to users
- Up to **100 concurrent logins**: under 700ms p95, all requests succeed — recommended
  production ceiling for a single SQLite-backed instance
- Beyond **200+ concurrent logins**: login p95 exceeds 1–2 seconds; consider horizontal
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
