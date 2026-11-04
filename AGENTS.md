# AGENTS.md

Guidance for coding agents working in this repository. Keep this file short and durable: describe conventions and where to look, not version numbers, counts or per-fix details. Security design notes live in `rfc/security-invariants.md`.

## Project Overview

Autentico is a self-contained OAuth 2.0 / OpenID Connect Identity Provider built with Go and SQLite. It covers Authorization Code + PKCE, refresh tokens, ROPC, client credentials, device codes, MFA (TOTP + email OTP), passkeys, magic links, federated login, SSO sessions, trusted devices, introspection/revocation, dynamic client registration, ForwardAuth for protected apps, and embedded React admin and account UIs.

## Common Commands

```bash
make build                    # Admin UI + account UI + Go binary
make build-go                 # Go binary only (uses pre-built UI assets)
make run                      # go run main.go start
make test                     # go test -p 1 -v ./...  (sequential: SQLite)
go test ./pkg/token/...       # One package
go test -run TestName ./pkg/user/...
make test-functional          # Black-box HTTP tests against a built binary
make lint                     # golangci-lint
make fmt
make generate-docs            # Regenerate Swagger from handler annotations
```

Run `grep -E '^[a-zA-Z_-]+:' Makefile` for the full target list (stress tests, conformance, Docker).

The full Go suite runs in CI. Locally, focus on the changed packages plus any integration tests relevant to the change.

## CLI

`main.go` delegates to `pkg/cli/`. Run `./autentico <cmd> --help` for current flags.

- `init`: writes a `.env` with fresh keys and secrets. On an existing `.env` it only adds a missing TOTP encryption key and preserves everything else.
- `start`: loads config, opens the DB, applies routine migrations (refuses pending major ones), seeds the `autentico-admin` and `autentico-account` clients, and serves.
- `migrate`: interactive schema upgrade; `--approve-major=<versions>` for unattended major upgrades.
- `onboard`: headless first-admin creation.

## Headless Onboarding & Admin Token (CI / Testing)

```bash
# Fresh database; make sure no server is running before deleting it
rm -f autentico.db
./autentico init
./autentico onboard --username admin --password secret --email admin@test.com --enable-admin-password-grant
./autentico start &
sleep 2

TOKEN=$(curl -s http://localhost:9999/oauth2/token -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&username=admin&password=secret&client_id=autentico-admin&scope=openid profile email" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s http://localhost:9999/admin/api/clients -H "Authorization: Bearer $TOKEN"
```

Run `onboard` before the first `start`: both seed `autentico-admin`, and seeding skips an existing client, so `--enable-admin-password-grant` only takes effect if `onboard` creates it. If the client already exists without the `password` grant, stop the server, delete the DB and onboard again.

## Feature Development Workflow

Follow `WORKFLOW.md`. In short:

1. **Spec first.** Read the relevant RFC/spec in `rfc/` before writing code.
2. **RFC annotations.** Every return path and validation check gets an inline comment citing the spec section.
3. **Tests.** Add positive and negative tests. Unit tests are always required; add E2E (`tests/e2e/`), functional (`tests/functional/`) or browser (`tests/browser/`) tests when the feature spans endpoints, needs black-box coverage or has UI.
4. **Config.** Bootstrap env vars go in `BootstrapConfig` + `InitBootstrap()` + `pkg/cli/init.go`. Runtime settings go in `Config` + `appsettings`. Per-client overrides go in `ClientOverrides` + `GetForClient()`.
5. **RFC compliance.** Update the MUST/SHOULD/MAY tables in `rfc/rfc.md` and check the discovery document.
6. **UI.** New settings need admin-ui changes; user-facing features need account-ui changes.
7. **Docs.** Update README.md, docs-web and Swagger. Record security-sensitive rules in `rfc/security-invariants.md` (or a dedicated `rfc/<feature>.md`), not here.

## Architecture

### Package conventions

Each feature package in `pkg/` follows the same layout:
- `model.go`: structs, request/response types, `ozzo-validation` rules
- `handler.go`: HTTP handlers with Swagger annotations
- `create.go`, `read.go`, `update.go`, `delete.go`: database access
- `service.go`: business logic

Package names match their feature (`pkg/token`, `pkg/passkey`, `pkg/forwardauth`, ...). Browse `pkg/` rather than relying on a list here. Some packages worth knowing up front:

| Package | Role |
|---|---|
| `pkg/cli` | Subcommands; `start.go` wires all routes and middleware |
| `pkg/config` | Bootstrap config (env, immutable) and runtime config (DB, hot-reloadable) |
| `pkg/db`, `pkg/db/migrations` | SQLite setup and the migration system |
| `pkg/client` | Client registration, authentication and shared authorization validation |
| `pkg/authzsig` | HMAC-signed authorization parameters carried across browser steps |
| `pkg/mfa` | MFA challenges and `FinishLogin`, the shared browser-login finalizer |
| `pkg/idpsession` | SSO browser sessions and freshness checks |
| `pkg/token` | `/oauth2/token` grants and atomic token issuance |
| `pkg/utils` | Response writers, client IP resolution, redirect URI validation |
| `pkg/model` | Shared response types (`ApiResponse[T]`, `AuthErrorResponse`, JWKS, discovery) |

### Browser auth flow

1. `/oauth2/authorize` validates the client, redirect URI, response type and PKCE, then either completes SSO or renders `view/login.html`.
2. The user authenticates with a primary method: password, passkey, magic link, federation, signup or email verification.
3. Every primary method ends in `mfa.FinishLogin`, which revalidates client and user, applies MFA and trusted-device policy, creates the browser session, enforces consent, and issues the code.
4. The client exchanges the code at `/oauth2/token` for RS256 access, ID and refresh tokens.

Server-rendered pages live in `view/`; the admin and account SPAs are embedded from `admin-ui/` and `account-ui/` builds.

### Configuration layers

- **Bootstrap**: `AUTENTICO_*` env vars / `.env`, read via `config.GetBootstrap()`. Immutable until restart. `pkg/config/config.go` and `pkg/cli/init.go` are the source of truth for available vars.
- **Runtime**: the `settings` table, read via `config.Get()`, reloaded with `appsettings.LoadIntoConfig()`. Editable from the admin UI/API.
- **Per-client overrides**: nullable columns on `clients`; resolve with `config.GetForClient(...)` for the current request's client instead of using global values.

### Database

- Driver is `modernc.org/sqlite`, not `mattn/go-sqlite3`. Scanning SQL NULL into a plain `string` errors: use `*string`/`sql.Null*`, and insert explicit `""` in test fixtures for nullable string columns.
- The schema is defined only by migrations in `pkg/db/migrations/`. The current version is the `SchemaVersion` variable in `migrations.go`; the DB stores it in `PRAGMA user_version`.
- Fresh databases run every migration. `start` auto-applies routine migrations and refuses pending `Major: true` ones, which need `autentico migrate` (they take a verified backup and support recovery).

**Adding a migration:**
1. Increment `SchemaVersion`.
2. Add `pkg/db/migrations/NNN_description.go` with the SQL as a named constant.
3. Append `{Version: N, SQL: migrationNNN}` to the `migrations` slice. Use `Major: true` only when the upgrade discards data or transforms it offline and needs explicit approval.

Prefer changes that need no migration, or a routine one. Never discard tokens, sessions or TOTP enrollments without calling it out in the PR.

### Response helpers

- Success: `utils.SuccessResponse(w, data)` or `utils.WriteApiResponse(w, data, status)`
- API errors: `utils.ErrorResponse(w, message, status, code)`
- OAuth errors: `utils.WriteErrorResponse(w, status, "error_type", "description")`
- 401 challenges: `utils.WriteBasicUnauthorized` / `utils.WriteBearerUnauthorized`

## Security Conventions

These rules apply across the codebase. `rfc/security-invariants.md` has the detailed reasoning per area; read the relevant section before changing that area.

- **Revalidate at every step.** Browser flows carry signed parameters (`pkg/authzsig`), but each step must still call `client.ValidateAuthorization` for the current client, redirect, scope, grant and PKCE policy. Fail closed when the client is missing, inactive or changed.
- **Single browser-login exit.** New primary login methods must finish through `mfa.FinishLogin`; don't issue sessions or codes directly.
- **Atomic consumption.** Single-use credentials (codes, refresh tokens, reset tokens, MFA challenges, magic links) are claimed with a conditional update inside one writer transaction together with the resulting writes. Recheck expiry after acquiring the writer, explicitly roll back after a failed COMMIT, and only emit cookies, audit events or responses after commit.
- **Federation state** is the exception: it is consumed and committed on its own before upstream discovery and token exchange, so the SQLite writer is never held across network I/O and replays are rejected immediately.
- **Client authentication.** Use `client.AuthenticateClientFromRequest`; don't parse Basic or form credentials by hand.
- **Client IP.** Use `utils.GetClientIP`, which honors `AUTENTICO_TRUSTED_PROXIES`. Never trust `X-Forwarded-For` or `X-Real-IP` directly.
- **Callback URLs.** Build redirect query strings with `url.Values` (`Set`/`Encode`) on the parsed registered URL; never concatenate strings.
- **Cookies.** Use names from bootstrap config (`config.HostCookieName` for `__Host-` bindings); never hard-code cookie names.
- **Secrets at rest.** Store tokens, cookies and codes as SHA-256 hashes. TOTP seeds are AES-GCM encrypted with `AUTENTICO_TOTP_ENCRYPTION_KEY`; there is no plaintext fallback.
- **Privacy.** Endpoints that look up accounts by email or username (such as verification resend) must not reveal whether the account exists. Logs and audit events never contain secrets, codes or claim values.
- **Federation network access.** Outbound federation calls use the restricted HTTP client that blocks private addresses.

## Testing

Helpers in `tests/utils/`:
- `WithTestDB(t)`: in-memory SQLite with cleanup
- `WithConfigOverride(t, fn)`: override config with automatic restore
- `MockJSONRequest`, `MockApiRequestWithAuth`, `MockFormRequest`, `MockFormRequestWithBasicAuth`: drive handlers directly

E2E tests in `tests/e2e/` use a real in-process test server. Other suites:
- `tests/functional/`: Vitest against a running binary
- `tests/browser/`: Playwright
- `tests/proxy/`: real Caddy/nginx/Traefik ForwardAuth harness (`python3 tests/proxy/run.py --binary ./autentico`)
- `tests/migrations/`: migration and cross-feature tests against the built binary

Tests run with `-p 1` because of SQLite.

## Playwright MCP (Browser Testing)

The Playwright MCP server expects Chrome at `/opt/google/chrome/chrome`. If it's missing, symlink Playwright's Chromium:

```bash
npx playwright install chromium
sudo mkdir -p /opt/google/chrome
sudo ln -sf ~/.cache/ms-playwright/chromium-*/chrome-linux64/chrome /opt/google/chrome/chrome
```

## OIDC Conformance Testing

The OpenID Foundation conformance suite runs locally via Docker; results and notes are in `openid.md` and `audits/`.

1. Start the suite: `cd /tmp/conformance-suite && docker compose -f docker-compose-local.yml up -d`. UI at https://localhost:8444 (callbacks use 8443).
2. Start Autentico in conformance mode and keep it running: `make conformance-server`. This overrides `AUTENTICO_APP_URL=http://172.17.0.1:9999` and disables secure cookies and rate limiting.
3. Stop the suite: `cd /tmp/conformance-suite && docker compose -f docker-compose-local.yml down`.

Notes:
- Open the admin UI at http://localhost:9999/admin, not `172.17.0.1` (browsers block `crypto.subtle` on non-localhost HTTP).
- Keep `AUTENTICO_APP_URL=http://localhost:9999` in `.env`; the make target overrides it.
- If the admin client has wrong redirect URIs after a URL change: `rm -rf data && make conformance-server`, then recreate the clients below.

### Conformance clients

Create these after onboarding, using an admin bearer token:

```bash
TOKEN="<admin bearer token>"

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid1","client_name":"Conformance Client 1","client_secret":"openid1secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/a/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_basic"}'

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid2","client_name":"Conformance Client 2 (secret_post)","client_secret":"openid2secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/a/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_post"}'

curl -s -X POST http://localhost:9999/admin/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id":"openid3","client_name":"Conformance Client 3","client_secret":"openid3secret","redirect_uris":["https://localhost.emobix.co.uk:8443/test/a/*/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scopes":"openid profile email offline_access address phone","client_type":"confidential","token_endpoint_auth_method":"client_secret_basic"}'
```

| Role | client_id | client_secret | auth method |
|---|---|---|---|
| client | `openid1` | `openid1secret` | `client_secret_basic` |
| client_secret_post | `openid2` | `openid2secret` | `client_secret_post` |
| client2 | `openid3` | `openid3secret` | `client_secret_basic` |

The `*` in the redirect URI matches exactly one path segment (the test alias). Register the exact alias URL when it is fixed.
