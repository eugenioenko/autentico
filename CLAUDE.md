# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Autentico is a self-contained OpenID Connect (OIDC) Identity Provider built with Go and SQLite. It implements the full authentication lifecycle: Authorization Code + PKCE, ROPC, Refresh Token grants, MFA (TOTP + email OTP), WebAuthn/passkeys, SSO sessions, trusted devices, token introspection/revocation, and an embedded React admin UI.

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

# Bootstrap a new .env (RSA key, CSRF secret, token signing secrets)
./autentico init              # or: ./autentico init --url https://auth.example.com

# Admin UI (frontend only, copies built assets into pkg/admin/dist)
make admin-ui-build

# Swagger documentation
make docs                     # Serves Swagger UI at localhost:8888
make generate-docs            # Regenerate swagger files from handler annotations
```

## Architecture

### CLI Entry Points

`main.go` delegates to `pkg/cli/`. Two subcommands:
- `autentico init` — generates a `.env` with fresh RSA key (base64 PEM), CSRF secret, and token signing secrets
- `autentico start` — loads config, initializes DB, seeds `autentico-admin` client, registers all routes, starts background cleanup, listens on `AppListenPort`

### Package Structure

Each feature package in `pkg/` follows a consistent pattern:
- `model.go` — Data structs, request/response types, validation using `ozzo-validation`
- `handler.go` — HTTP handlers with Swagger annotations
- `create.go`, `read.go`, `update.go`, `delete.go` — Database CRUD operations
- `service.go` — Business logic helpers

### All Packages

| Package | Purpose |
|---------|---------|
| `pkg/admin` | Serves embedded React admin UI (from `pkg/admin/dist`) and `/admin/api/stats` |
| `pkg/appsettings` | Settings CRUD — persists runtime config to `settings` table, checks onboarding status |
| `pkg/auth_code` | Authorization code model (PKCE, nonce, single-use flag) |
| `pkg/authorize` | `/oauth2/authorize` — validates client + redirect URI, renders login page |
| `pkg/cleanup` | Background goroutine purging expired tokens, sessions, MFA challenges, etc. |
| `pkg/cli` | `init` and `start` subcommand implementations |
| `pkg/client` | OAuth2 client registration, CRUD, and authentication (`/oauth2/register`) |
| `pkg/config` | Bootstrap config (env vars, immutable) and runtime config (DB, hot-reloadable) |
| `pkg/db` | SQLite initialization, schema DDL, incremental migrations |
| `pkg/idpsession` | IdP-level SSO sessions — cross-request browser sessions, idle timeout enforcement |
| `pkg/introspect` | `/oauth2/introspect` — token introspection (RFC 7662) |
| `pkg/jwtutil` | JWT parsing, `AccessTokenClaims`, audience validation |
| `pkg/key` | RSA key loading (from `AUTENTICO_PRIVATE_KEY` env var) or ephemeral fallback, JWK generation |
| `pkg/login` | `/oauth2/login` — credential validation, MFA challenge creation, auth code issuance |
| `pkg/mfa` | MFA challenge management (TOTP enrollment, TOTP/email OTP verification) |
| `pkg/middleware` | CORS, CSRF, logging, admin bearer-token auth, audience validation |
| `pkg/model` | Shared response types: `ApiResponse[T]`, `ApiError`, `AuthErrorResponse`, JWK/JWKS, WellKnownConfig |
| `pkg/onboarding` | First-run admin account creation wizard |
| `pkg/passkey` | WebAuthn registration + authentication ceremonies (`go-webauthn/webauthn v0.15.0`) |
| `pkg/session` | OAuth session lifecycle (create, read, deactivate, logout) |
| `pkg/signup` | Self-service user registration (enabled via `allow_self_signup` setting) |
| `pkg/token` | `/oauth2/token` — code exchange, refresh token grant, ROPC, revocation |
| `pkg/trusteddevice` | Trusted device tokens — MFA bypass cookie management |
| `pkg/user` | User CRUD, bcrypt password hashing, account lockout, TOTP secret storage |
| `pkg/userinfo` | `/oauth2/userinfo` endpoint |
| `pkg/utils` | Shared helpers: response writers, bearer token extraction, redirect URI validation, SHA-256 hashing, client IP |
| `pkg/wellknown` | `/.well-known/openid-configuration` and `/.well-known/jwks.json` |

### OAuth2 / Auth Flow

1. Client redirects to `/oauth2/authorize` → validates client, renders `view/login.html`
2. Depending on `auth_mode`: user submits password to `/oauth2/login`, or initiates passkey ceremony at `/oauth2/passkey/login/begin` + `/oauth2/passkey/login/finish`
3. If MFA is enabled: user is redirected to `/oauth2/mfa` for TOTP/email OTP verification (unless on a trusted device)
4. Auth code is issued, client redirects back with `code`
5. Client exchanges code at `/oauth2/token` → access token + id token + refresh token (RS256 JWTs)
6. Tokens are signed with the RSA key from `AUTENTICO_PRIVATE_KEY` (base64-encoded PEM env var); if unset, an ephemeral key is used (tokens invalidated on restart)

### View Templates

HTML templates in `view/` rendered server-side for all interactive flows:
`layout.html`, `login.html`, `signup.html`, `onboard.html`, `mfa.html`, `mfa_enroll.html`, `error.html`

### Configuration (3 layers)

**Bootstrap** (`pkg/config`, env vars / `.env`, immutable until restart)

Key fields:
- `AUTENTICO_APP_URL` — base URL (derives issuer, domain, port)
- `AUTENTICO_DB_FILE_PATH` — SQLite file path (default: `./db/autentico.db`)
- `AUTENTICO_PRIVATE_KEY` — base64-encoded RSA private key PEM
- `AUTENTICO_ACCESS_TOKEN_SECRET`, `AUTENTICO_REFRESH_TOKEN_SECRET`, `AUTENTICO_CSRF_SECRET_KEY`
- `AUTENTICO_CSRF_SECURE_COOKIE`, `AUTENTICO_REFRESH_TOKEN_SECURE`, `AUTENTICO_IDP_SESSION_SECURE`
- `AUTENTICO_JWK_CERT_KEY_ID` (default: `autentico-key-1`)

Access via `config.GetBootstrap()`.

**Runtime** (`pkg/config`, persisted in `settings` table, hot-reloadable via admin API)

Key fields: token expiration durations, `auth_mode`, `mfa_enabled`, `mfa_method`, `allow_self_signup`, `sso_session_idle_timeout`, account lockout, passkey RP name, trusted device settings, cleanup intervals, SMTP settings, theme (CSS, logo, title), validation rules.

Access via `config.Get()`. Updated via `appsettings.LoadIntoConfig()`.

**Per-client overrides** (stored on `clients` table, nullable — unset means "use global")

Overridable: token expiration times, `allowed_audiences`, `allow_self_signup`, `sso_session_idle_timeout`, `trust_device_enabled`, `trust_device_expiration`.

### Database

Initialized by `db.InitDB()`. Schema in `pkg/db/db.go`. 11 tables:

| Table | Purpose |
|-------|---------|
| `users` | Accounts — password hash, TOTP secret, email, lockout fields, soft delete |
| `tokens` | Access + refresh token pairs, revocation support |
| `sessions` | OAuth sessions — device info, `last_activity_at`, `deactivated_at` |
| `auth_codes` | Single-use authorization codes (PKCE, nonce) |
| `idp_sessions` | SSO browser sessions for idle timeout and auto-login |
| `mfa_challenges` | Pending TOTP/email OTP challenges |
| `trusted_devices` | Trusted device tokens (MFA bypass) |
| `passkey_challenges` | Pending WebAuthn ceremony state |
| `passkey_credentials` | Registered WebAuthn credentials (JSON blob) |
| `clients` | OAuth2 clients with per-client config overrides |
| `settings` | Key-value runtime config |

**SQLite driver:** `modernc.org/sqlite` (NOT `mattn/go-sqlite3`). Scanning SQL NULL into a plain `string` causes an error — always use `*string` or provide explicit `""` in test fixtures for nullable string columns.

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
