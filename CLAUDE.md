# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Autentico is a self-contained OAuth 2.0 / OpenID Connect (OIDC) Identity Provider built with Go and SQLite. It implements the full authentication lifecycle: Authorization Code + PKCE, ROPC, Refresh Token grants, MFA (TOTP + email OTP), WebAuthn/passkeys, SSO sessions, trusted devices, token introspection/revocation, dynamic client registration, and an embedded React admin UI.

## Common Commands

```bash
# Build
make build                    # Build everything (admin UI + Go binary, statically linked)
make build-go                 # Build Go binary only (uses pre-built admin UI in pkg/admin/dist)
go build -o autentico main.go

# Run
make run                      # go run main.go start

# Test
make test                     # go test -p 1 -v ./...
go test ./pkg/token/...       # Run tests for a specific package
go test -run TestCreateUser ./pkg/user/...  # Run a single test

# Lint and format
make lint                     # Requires golangci-lint
make fmt                      # Format code with gofmt
go vet ./...                  # Static analysis

# Bootstrap a new .env (RSA key, TOTP encryption key, CSRF secret, token signing secrets)
./autentico init              # or: ./autentico init --url https://auth.example.com

# Admin UI (frontend only, copies built assets into pkg/admin/dist)
make admin-ui-build

# Swagger documentation
make docs                     # Serves Swagger UI at localhost:8888
make generate-docs            # Regenerate swagger files from handler annotations
```

## Headless Onboarding & Admin Token (CI / Testing)

```bash
# 1. Remove existing DB for a clean start (if needed)
rm -f autentico.db

# 2. Start the server (auto-generates .env if missing)
./autentico start --auto-setup &
sleep 2

# 3. Create admin account with ROPC grant enabled (must run BEFORE start seeds the admin client,
#    or on a fresh DB — seedAdminClient skips if autentico-admin already exists)
./autentico onboard --username admin --password secret --email admin@test.com --enable-admin-password-grant

# 4. Get an admin bearer token via ROPC
TOKEN=$(curl -s http://localhost:9999/oauth2/token -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=secret&client_id=autentico-admin&scope=openid profile email" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

# 5. Use the token for admin API calls
curl -s http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN"
```

**Important:** `onboard` must run before the first `start` seeds the admin client, or on a fresh DB. The `--enable-admin-password-grant` flag adds the `password` grant type to `autentico-admin`. If the client already exists without it, delete the DB and re-onboard.

## Playwright MCP (Browser Testing)

The Playwright MCP server provides browser automation tools (`mcp__playwright__*`) for testing UI flows.

**Setup:** The MCP server expects Chrome at `/opt/google/chrome/chrome`. If not installed, symlink the Playwright-managed Chromium:

```bash
# Install Playwright browsers (if not already cached)
npx playwright install chromium

# Symlink to the expected path (requires sudo)
sudo mkdir -p /opt/google/chrome
sudo ln -sf ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome /opt/google/chrome/chrome
```

**Debug UI as test client:** The `debug-ui/` directory contains a Vite+React app that acts as an OAuth2 client for manual testing. It runs on `http://localhost:5174` and uses client_id `autentico-debug`.

```bash
# Register the debug client (with consent_required for consent screen testing)
curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"autentico-debug","client_name":"Debug UI","redirect_uris":["http://localhost:5174/callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"],"response_types":["code"],"scopes":"openid profile email offline_access","client_type":"public","token_endpoint_auth_method":"none","consent_required":true}'

# Add CORS origin for the debug UI
curl -s -X PUT http://localhost:9999/admin/api/settings \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"cors_allowed_origins": "http://localhost:5174"}'

# Start the debug UI dev server
cd debug-ui && pnpm dev
```

## Feature Development Workflow

When implementing new features, follow the checklist in `WORKFLOW.md`. Key points:

1. **Spec first** — read the relevant RFC/spec sections before writing code
2. **RFC annotations** — every return path and validation check must have an inline comment referencing the spec section
3. **Tests** — always add both positive and negative tests. Four layers exist:
   - **Unit** (`pkg/*/…_test.go`) — always required
   - **E2E** (`tests/e2e/`) — when the feature spans multiple endpoints
   - **Functional** (`tests/functional/`) — black-box HTTP tests against a running server
   - **Browser** (`tests/browser/`) — when the feature has a UI component (Playwright)
4. **Config** — new bootstrap env vars go in `BootstrapConfig` + `InitBootstrap()` + `pkg/cli/init.go`; runtime settings go in `Config` + `appsettings`
5. **RFC compliance** — update MUST/SHOULD/MAY tables in `rfc/rfc.md`, verify discovery document
6. **UI** — new settings need admin-ui updates; user-facing features need account-ui updates
7. **Docs** — update README.md, docs-web, CLAUDE.md, and run `make generate-docs` for Swagger changes

See `WORKFLOW.md` for the full checklist.

## OIDC Conformance Testing

The OpenID Foundation conformance suite runs locally via Docker. Specs and review plan are in `rfc/`.

### Setup

1. **Start the conformance suite** (docker-compose in `/tmp/conformance-suite`):
   ```bash
   cd /tmp/conformance-suite && docker compose -f docker-compose-local.yml up -d
   ```
   Suite UI at **https://localhost:8444** (callbacks use port 8443 — both are exposed by docker-compose)

2. **Start Autentico in conformance mode** (in a terminal — must stay running):
   ```bash
   make conformance-server
   ```
   Overrides `APP_URL=http://172.17.0.1:9999`, disables secure cookies and rate limiting.

3. **Stop the suite:**
   ```bash
   cd /tmp/conformance-suite && docker compose -f docker-compose-local.yml down
   ```

### Notes

- Access the admin UI at **http://localhost:9999/admin** (not `172.17.0.1` — browser blocks `Crypto.subtle` on non-localhost HTTP)
- `AUTENTICO_APP_URL` in `.env` should stay as `http://localhost:9999`; `make conformance-server` overrides it for the conformance suite
- If the admin client has wrong redirect URIs (after URL change), delete the DB and restart: `rm -rf data && make conformance-server`
- Conformance clients must be recreated after wiping the DB (see below)

### Conformance Clients

Create these 3 clients via the admin API after onboarding. Get a Bearer token from the admin UI first.

```bash
TOKEN="<admin bearer token>"

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid1","client_name":"Conformance Client 1","client_secret":"openid1secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_basic"}'

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid2","client_name":"Conformance Client 2 (secret_post)","client_secret":"openid2secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_post"}'

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid3","client_name":"Conformance Client 3","client_secret":"openid3secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_basic"}'
```

| Role | client_id | client_secret | auth method |
|---|---|---|---|
| client | `openid1` | `openid1secret` | `client_secret_basic` |
| client_secret_post | `openid2` | `openid2secret` | `client_secret_post` |
| client2 | `openid3` | `openid3secret` | `client_secret_basic` |

Redirect URI for all clients: `https://localhost.emobix.co.uk:8443/test/*/callback` (wildcard — the suite uses a dynamic run ID in the path, which changes per test run).

### Test Plans Run

| Plan | Status |
|---|---|
| `oidcc-basic-certification-test-plan` | ✅ Passed (2026-03-24) — issues documented in `openid.md` |

## Architecture

### CLI Entry Points

`main.go` delegates to `pkg/cli/`. Subcommands:
- `autentico init` — generates a `.env` with fresh RSA key (base64 PEM), TOTP encryption key, CSRF secret, and token signing secrets; on an existing `.env`, adds only a missing TOTP key and preserves other settings and secrets
- `autentico start` — loads config, initializes DB, auto-applies routine pending migrations (refuses existing databases with pending major migrations), seeds `autentico-admin` and `autentico-account` clients, registers all routes, starts background cleanup, listens on `AppListenPort`; accepts `--no-auto-migrate` to skip automatic migrations, `--auto-setup` to generate `.env` if missing
- `autentico migrate` — interactive CLI to apply pending database schema migrations; requires a persistent `AUTENTICO_TOTP_ENCRYPTION_KEY` and prompts for the target schema number (currently `17`); `--approve-major=15,17` permits unattended pre-v3 upgrades (`--approve-major=17` from schema 15/16) with a verified backup and rollback on failure
- `autentico onboard` — headless alternative to the `/onboard` web wizard; creates the first admin account with `--username`, `--password`, `--email`; `--enable-admin-password-grant` adds ROPC grant to the admin client for CI/testing

### Package Structure

Each feature package in `pkg/` follows a consistent pattern:
- `model.go` — Data structs, request/response types, validation using `ozzo-validation`
- `handler.go` — HTTP handlers with Swagger annotations
- `create.go`, `read.go`, `update.go`, `delete.go` — Database CRUD operations
- `service.go` — Business logic helpers

### All Packages

| Package | Purpose |
|---------|---------|
| `pkg/account` | Account UI API — profile, password change, TOTP setup, passkey management, session listing, applications list |
| `pkg/admin` | Serves embedded React admin UI (from `pkg/admin/dist`) and `/admin/api/stats` |
| `pkg/api` | API utilities shared across admin and account APIs |
| `pkg/appsettings` | Settings CRUD — persists runtime config to `settings` table, checks onboarding status |
| `pkg/audit` | Audit log recording and querying (`audit_logs` table) |
| `pkg/auth_code` | Authorization code model (PKCE, nonce, single-use flag) |
| `pkg/authorize` | `/oauth2/authorize` — validates client + redirect URI, renders login page |
| `pkg/authzsig` | HMAC signatures and shared parameter extraction; signatures prove integrity, and signup, email verification, magic-link and passkey handlers also require `client.ValidateAuthorization` |
| `pkg/bearer` | Bearer token extraction utilities |
| `pkg/cleanup` | Background goroutine purging expired tokens, sessions, MFA challenges, etc. |
| `pkg/cli` | `init`, `start`, `migrate`, and `onboard` subcommand implementations |
| `pkg/client` | OAuth2 client registration, CRUD, and authentication (`/oauth2/register`) |
| `pkg/config` | Bootstrap config (env vars, immutable) and runtime config (DB, hot-reloadable) |
| `pkg/consent` | OAuth2 consent screen — per-client `consent_required`, scope display, consent persistence |
| `pkg/db` | SQLite initialization, schema DDL |
| `pkg/db/migrations` | Migration system — `SchemaVersion` constant, `Migration` struct, `Check()` and `Run()` functions, ordered migrations slice |
| `pkg/deletion` | Account deletion requests — user-initiated, admin-reviewed |
| `pkg/email` | Email sending (SMTP) — OTP codes, password reset, email verification |
| `pkg/emailverification` | Email verification flow — send verification link, confirm token |
| `pkg/federation` | Federated/social login providers; validate current client, redirect, scopes and PKCE at begin, callback and code issuance through `client.ValidateAuthorization` |
| `pkg/group` | User groups — CRUD, membership management |
| `pkg/health` | Health check endpoint (`/health`) |
| `pkg/idpsession` | IdP-level SSO sessions — cross-request browser sessions, idle timeout enforcement |
| `pkg/introspect` | `/oauth2/introspect` — token introspection (RFC 7662) |
| `pkg/jwtutil` | JWT parsing, `AccessTokenClaims`, audience validation |
| `pkg/key` | RSA key loading (from `AUTENTICO_PRIVATE_KEY` env var) or ephemeral fallback, JWK generation |
| `pkg/login` | `/oauth2/login` — credential validation, MFA challenge creation, auth code issuance |
| `pkg/mfa` | MFA challenge management (TOTP enrollment, TOTP/email OTP verification) |
| `pkg/middleware` | CORS, CSRF, logging, admin bearer-token auth, audience validation, rate limiting |
| `pkg/model` | Shared response types: `ApiResponse[T]`, `ApiError`, `AuthErrorResponse`, JWK/JWKS, WellKnownConfig |
| `pkg/onboarding` | First-run admin account creation wizard |
| `pkg/passkey` | WebAuthn registration + authentication ceremonies (`go-webauthn/webauthn v0.15.0`) |
| `pkg/passwordreset` | Password reset flow — forgot password, reset token, new password |
| `pkg/ratelimit` | Per-IP rate limiting for auth endpoints (token bucket) |
| `pkg/reqid` | Request ID generation and context propagation |
| `pkg/revoke` | `/oauth2/revoke` — token revocation (RFC 7009) |
| `pkg/session` | OAuth session lifecycle (create, read, deactivate, logout) |
| `pkg/signup` | Self-service user registration (enabled via `allow_self_signup` setting) |
| `pkg/token` | `/oauth2/token` — code exchange, refresh token grant, ROPC, client credentials |
| `pkg/trusteddevice` | Trusted device tokens — MFA bypass cookie management |
| `pkg/user` | User CRUD, bcrypt password hashing, account lockout, TOTP secret storage |
| `pkg/userclaim` | Custom per-user claims — admin CRUD + merge into tokens/UserInfo when `custom_claims` scope granted |
| `pkg/userinfo` | `/oauth2/userinfo` endpoint |
| `pkg/utils` | Shared helpers: response writers, bearer token extraction, redirect URI validation, SHA-256 hashing, client IP |
| `pkg/wellknown` | `/.well-known/openid-configuration` and `/oauth2/.well-known/jwks.json` |

### OAuth2 / Auth Flow

1. Client redirects to `/oauth2/authorize` → validates client, renders `view/login.html`
2. Depending on `auth_mode`: user submits password to `/oauth2/login`, or initiates passkey ceremony at `/oauth2/passkey/login/begin` + `/oauth2/passkey/login/finish`
3. If MFA is enabled (`require_mfa` or user has TOTP enrolled): user is redirected to `/oauth2/mfa` for TOTP/email OTP verification (unless on a trusted device). When `mfa_method` is `both` and user has TOTP enrolled, TOTP is preferred with an option to switch to email.
4. If client has `consent_required`: user is redirected to `/oauth2/consent` to approve requested scopes. Consent is remembered per user+client+scopes — subsequent logins skip this step unless scopes change.
5. Auth code is issued, client redirects back with `code`
6. Client exchanges code at `/oauth2/token` → access token + id token + refresh token (RS256 JWTs)
7. Tokens are signed with the RSA key from `AUTENTICO_PRIVATE_KEY` (base64-encoded PEM env var); if unset, an ephemeral key is used (tokens invalidated on restart)

### View Templates

HTML templates in `view/` rendered server-side for all interactive flows:
`layout.html`, `login.html`, `signup.html`, `onboard.html`, `mfa.html`, `mfa_enroll.html`, `consent.html`, `forgot_password.html`, `reset_password.html`, `verify_email.html`, `logout_success.html`, `error.html`

### Configuration (3 layers)

**Bootstrap** (`pkg/config`, env vars / `.env`, immutable until restart)

Key fields:
- `AUTENTICO_APP_URL` — base URL (derives issuer, domain, port)
- `AUTENTICO_APP_OAUTH_PATH` — override OAuth path (default: `/oauth2`)
- `AUTENTICO_LISTEN_PORT` — override listen port independent of `APP_URL` (for reverse proxy setups)
- `AUTENTICO_DB_FILE_PATH` — SQLite file path (default: `./autentico.db`)
- `AUTENTICO_DB_READ_POOL_SIZE` — SQLite read connection pool (default: `min(CPUs, 4)`)
- `AUTENTICO_PRIVATE_KEY` — base64-encoded RSA private key PEM
- `AUTENTICO_ACCESS_TOKEN_SECRET`, `AUTENTICO_REFRESH_TOKEN_SECRET`, `AUTENTICO_CSRF_SECRET_KEY`
- `AUTENTICO_CSRF_SECURE_COOKIE`, `AUTENTICO_REFRESH_TOKEN_SECURE`, `AUTENTICO_IDP_SESSION_SECURE`
- `AUTENTICO_JWK_CERT_KEY_ID` (default: `autentico-key-1`)
- `AUTENTICO_RATE_LIMIT_RPS`, `AUTENTICO_RATE_LIMIT_BURST`, `AUTENTICO_RATE_LIMIT_RPM`, `AUTENTICO_RATE_LIMIT_RPM_BURST` — per-IP rate limiting
- `AUTENTICO_ANTI_TIMING_MIN_MS`, `AUTENTICO_ANTI_TIMING_MAX_MS` — anti-timing delay for auth responses

Access via `config.GetBootstrap()`.

**Runtime** (`pkg/config`, persisted in `settings` table, hot-reloadable via admin API)

Key fields: token expiration durations, `auth_mode`, `require_mfa`, `mfa_method`, `allow_self_signup`, `sso_session_idle_timeout`, account lockout, passkey RP name, trusted device settings, cleanup intervals, SMTP settings (host, port, username, password, from), CORS (`cors_allowed_origins`), theme (CSS, logo, title, tagline, footer links), profile field visibility, email verification, password reset, account deletion permissions, validation rules.

Access via `config.Get()`. Updated via `appsettings.LoadIntoConfig()`.

**Per-client overrides** (stored on `clients` table, nullable — unset means "use global")

Overridable: token expiration times, `allowed_audiences`, `allow_self_signup`, `sso_session_idle_timeout`, `trust_device_enabled`, `trust_device_expiration`, `consent_required`.

### Database

Initialized by `db.InitDB()`. Schema defined in `pkg/db/migrations/`. 22 tables listed below (SchemaVersion 16):

| Table | Purpose |
|-------|---------|
| `users` | Accounts — password hash, TOTP secret, persistent last-used TOTP timestep, email, lockout fields, soft delete |
| `tokens` | SHA-256 access/refresh token hashes with explicit client ID and ACR metadata; revocation support |
| `sessions` | SHA-256 access/refresh token hashes (refresh lookup indexed); OAuth sessions — device info, `last_activity_at`, `deactivated_at`, `idp_session_id` (FK into `idp_sessions`, nullable for non-browser grants like ROPC / client_credentials) |
| `auth_codes` | Single-use authorization codes (PKCE, nonce, `idp_session_id` carried from `/authorize` to `/oauth2/token`) |
| `idp_sessions` | SSO browser sessions — one row per browser/device; parent of OAuth sessions via `sessions.idp_session_id`. `idpsession.DeactivateWithCascade` revokes the row + every child OAuth session + their tokens in one transaction. |
| `mfa_challenges` | Pending TOTP/email OTP challenges |
| `trusted_devices` | Trusted device tokens (MFA bypass) |
| `passkey_challenges` | Pending WebAuthn ceremony state |
| `passkey_credentials` | Registered WebAuthn credentials (JSON blob) |
| `clients` | OAuth2 clients with per-client config overrides (including `consent_required`) and account dashboard metadata (`show_in_account`, `client_uri`, `logo_uri`, `description`) |
| `settings` | Key-value runtime config |
| `device_codes` | Pending OAuth device authorization grants (migration 008) |
| `magic_link_tokens` | Pending passwordless email login grants (migration 009) |
| `federation_providers` | External IdP configurations for federated/social login |
| `federated_identities` | Links between local users and external IdP accounts |
| `deletion_requests` | User-initiated account deletion requests (admin-reviewed) |
| `password_reset_tokens` | Time-limited tokens for password reset flow (migration 002) |
| `audit_logs` | Security event audit trail (migration 003) |
| `groups` | User groups (migration 004) |
| `user_groups` | Group membership join table (migration 004) |
| `user_consents` | Stored OAuth2 consent decisions per user+client+scopes (migration 007) |
| `user_claims` | Custom per-user claims — one row per `(user_id, claim_name)` (migration 011) |

**SQLite driver:** `modernc.org/sqlite` (NOT `mattn/go-sqlite3`). Scanning SQL NULL into a plain `string` causes an error — always use `*string` or provide explicit `""` in test fixtures for nullable string columns.

### Database Migrations

Schema versioning uses SQLite's built-in `PRAGMA user_version`. The current expected version is defined as `SchemaVersion` in `pkg/db/migrations/migrations.go`.

- `InitDB()` runs all migrations on fresh, empty databases; existing databases retain their current version until migration
- `autentico start` checks `migrations.CheckAuto()` before applying routine migrations. Existing databases with pending `Major: true` upgrades are refused before any migration runs
- `autentico start --no-auto-migrate` calls `migrations.Check()` instead — refuses to start if the DB is behind, printing a message to run `autentico migrate`
- `autentico migrate` shows versions and requires typing the target schema number. Schema 15 explicitly warns that tokens, OAuth/SSO sessions, and pending login grants are discarded; accounts and enrollment remain
- Unattended Docker deployments must stop the service, prepare a persistent `AUTENTICO_TOTP_ENCRYPTION_KEY`, run `autentico migrate --approve-major=15,17` (`--approve-major=17` from schema 15/16), then start it. Approval is schema-specific and never approves a later major migration; later routine upgrades stay noninteractive
- Major migrations hold an exclusive OS lock, checkpoint WAL, close SQLite, create and verify a protected snapshot, and persist a recovery record before writes. Failed or interrupted upgrades restore the snapshot before retry. Startup refuses pending recovery
- The persistent `.lock` file is never unlinked; Unix root-run migrations preserve database ownership on the lock so the service user can restart. `.migration.json` tracks recovery; protected backups retain old bearer tokens and need secure retention
- SQLite file URIs use `pkg/sqliteutil` to handle Windows drives and reserved characters; CI runs the real database and CLI migration tests on Windows

Migrations are the single source of truth for the schema. `001_initial_schema.go` creates all tables and is the baseline. Fresh databases run all migrations from scratch; existing databases run only pending ones.

**Adding a new migration:**
1. Increment `SchemaVersion` in `pkg/db/migrations/migrations.go`
2. Create `pkg/db/migrations/NNN_description.go` (same package) with the SQL as a named constant, e.g. `const migration002 = \`ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''\``
3. Append `{Version: N, SQL: migrationNNN}` to the `migrations` slice in `migrations.go`; use `Major: true` for upgrades requiring explicit approval and protected recovery

TOTP verification uses the shared per-enrollment `totp_last_used_step` watermark (RFC 6238 §5.2). Browser login, password grants, account actions, and enrollment confirmation consume accepted timesteps atomically. Six-digit SHA-1 codes retain ±1 timestep clock tolerance; already accepted or older steps are rejected. Schema 16 adds this field as a routine migration and preserves existing enrollments and sessions. `mfa.VerifyEnrolledTotp` also enforces the persistent account-level five-attempt budget for browser MFA, password grants and TOTP removal. The old password-grant helper delegates to it. Lock duration uses `account_lockout_duration`, with a 15-minute fallback when nonpositive; fresh challenges and password success do not clear it. Removal checks the password before verifying/counting TOTP.

### Testing

Test helpers in `tests/utils/`:
- `WithTestDB(t)` — in-memory SQLite, auto-cleanup
- `WithConfigOverride(t, fn)` — override config values with auto-restore
- `MockJSONRequest(t, body, method, url, handler)` — test handler with JSON body
- `MockApiRequestWithAuth(t, body, method, url, handler, token)` — with Bearer token
- `MockFormRequest(t, formData, method, url, handler)` — form-encoded POST

E2E tests in `tests/e2e/` use a real test server instance.

Tests run with `-p 1` (sequential) to avoid SQLite conflicts.

### Response Patterns

- Success: `utils.SuccessResponse(w, data)` or `utils.WriteApiResponse(w, data, statusCode)`
- API errors: `utils.ErrorResponse(w, message, statusCode, errorCode)`
- OAuth errors: `utils.WriteErrorResponse(w, statusCode, "error_type", "description")`
- Wrapped type: `model.ApiResponse[T]`; OAuth error type: `model.AuthErrorResponse`

## Passkey signup policy

Public passkey registration checks current self-signup policy (including client overrides) and passkey auth mode at begin and finish. A five-minute HttpOnly cookie binds pending registration to its browser. Required email verification gates registration and both passkey login modes before session/code issuance. The internal `/oauth2/verify-email/pending` page resumes the existing resend flow without exposing the email token. Registration routes share the authentication rate limiter. Named and discoverable login recheck that the auth mode allows passkeys at begin, finish, and final session/code issuance.

## Trusted proxy client IPs

`AUTENTICO_TRUSTED_PROXIES` is a bootstrap list of IPv4/IPv6 CIDRs, empty by default. `InitBootstrap` returns an error for invalid entries; CLI callers must propagate it. `utils.GetClientIP` uses the network peer unless trusted, then walks all `X-Forwarded-For` fields from right to left until the first untrusted hop. Rate limits, audit logs and session records use this same resolver. Forwarding values before that boundary, `X-Real-IP`, and `Forwarded` do not establish identity.

## TOTP encryption and schema 17

`pkg/totpsecret` uses AES-256-GCM with a fresh nonce and authenticated user ID/version. `AUTENTICO_TOTP_ENCRYPTION_KEY` is a required persistent base64-encoded 32-byte bootstrap key. Fresh `init`/auto-setup include it; re-running `init` on an existing regular `.env` only adds a missing key and preserves existing settings and secrets. Startup and migration reject missing/invalid keys; startup and up-to-date migration validate stored enrollments against the key. There is no plaintext or ephemeral-key fallback.

Schema 17 is a major offline transformation with backup/recovery and explicit approval. It encrypts all nonempty active, pending and deactivated TOTP seeds in place, preserving enrollment flags, replay state and lockout. It does not discard sessions. Schema 15 still discards old bearer credentials. Pre-v3 unattended upgrades approve `15,17`; schema 15/16 upgrades approve `17`. Keep the original encryption key for all restarts and database restores.

## Refresh client binding

Refresh requests require a registered client, using the shared authentication and active/grant checks. Confidential clients supply their secret; public clients identify themselves with `client_id`. The refresh JWT, stored token and session must agree on client/user binding. Historical tokens with no client binding are rejected rather than reassigned; no migration is required.

## Atomic token issuance

`token.storeGrantTokens` claims authorization codes, approved device codes or refresh tokens through a conditional update and inserts the replacement token/session pair in one writer transaction. A failed insert or commit rolls back consumption; no refresh cookie or successful response precedes commit. Expiry is checked again inside the transaction. Code-replay revocation follows the existing browser IdP-session linkage through refresh rotation; codes without linkage conservatively revoke code/refresh grants for that user/client. Refresh replay keeps the existing account-wide revocation policy. No schema migration is required.

## Atomic password resets and MFA challenges

`passwordreset.resetPassword` hashes outside the writer lock, then conditionally consumes one unused reset token, updates the active user's password, and deactivates OAuth/IdP sessions in one transaction. Expiry is rechecked after obtaining the writer. Failed writes or commits leave the token, password and sessions unchanged; success and its audit event follow commit.

`mfa.ConsumeMfaChallenge` conditionally consumes the verified snapshot (user, method, code and login state), rejecting reused, exhausted, changed or expired challenges. The browser handler must commit consumption before success audit, trusted-device cookies, authenticated sessions, consent or authorization-code issuance. Both paths explicitly clean up SQLite transactions after failed commits. No schema migration is required.

## Introspection token lifetimes

`introspect.tokenExpiration` selects access or refresh expiry from the hash that matched the stored pair. Both `IntrospectToken` and the response's `exp` use this helper; expiry at the current second is inactive, matching signed JWT `exp` precision. The shared token record keeps its original access and refresh timestamps for UserInfo and session lookup.

## Callback query encoding

Password login, SSO, consent approval/denial, authorization errors, browser MFA and RP-initiated logout parse registered callback URLs and add response values with `url.Values.Set`/`Encode`, preserving existing query values and round-tripping opaque state. MFA parses the restored callback before issuing authenticated state. Malformed registered logout URLs render the signed-out page without redirection. Passkey, federation and email-verification callbacks already use encoded query construction.

## Verification resend privacy

`emailverification.HandleResendVerification` keeps authorization signature/client/redirect/scope/PKCE validation before account lookup. Accepted requests use one randomized-delay policy and one deferred generic sent-page response for unknown, inactive, verified, email-less or eligible accounts, including token-storage errors. Eligible tokens are stored before asynchronous email dispatch. Missing SMTP configuration and delivery failures are logged privately; the background sender captures only recipient, URL and request ID. The private handler takes a sender function for deterministic blocked-delivery tests.
