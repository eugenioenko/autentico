# Config Refactor Session Context

## Branch
`feat/env-config-settings-table` → PR #40

## What Was Done

### Overview
Replaced `autentico.json` with a three-layer configuration system:
1. **Bootstrap** (`AUTENTICO_*` env vars / `.env`) — immutable secrets and infra, loaded once at startup
2. **Settings** (SQLite `settings` table) — runtime-editable global defaults, reloaded on write
3. **Per-client** (nullable columns on `clients` table) — per-OAuth2-client overrides

---

## Files Changed

### New Files
- `pkg/appsettings/crud.go` — `GetSetting`, `SetSetting`, `GetAllSettings`
- `pkg/appsettings/load.go` — `EnsureDefaults()`, `LoadIntoConfig()`, `IsOnboarded()`
- `pkg/appsettings/handler.go` — `GET /admin/api/onboarding`, `GET|PUT /admin/api/settings`

### Deleted Files
- `autentico.json` — replaced by `.env` + settings DB table

### Major Rewrites
- `pkg/config/config.go` — added `BootstrapConfig` struct, `InitBootstrap()`, `GetForClient()`, `ClientOverrides`; kept `Config` struct for soft settings
- `pkg/key/key.go` — load from `AUTENTICO_PRIVATE_KEY` (base64 PEM) or generate ephemeral RSA key with `slog.Warn`
- `pkg/cli/init.go` — generates `.env` with secrets + RSA key; removed `--email`/`--password` flags
- `pkg/cli/start.go` — calls `InitBootstrap()`, `EnsureDefaults()`, `LoadIntoConfig()`, seeds admin client

### Modified Files
- `pkg/db/db.go` — added `settings` table; added nullable columns to `clients` via `addColumnIfNotExists`
- `pkg/client/model.go` — added nullable override fields (`*string`, `*bool`) for per-client config
- `pkg/client/read.go` — updated SELECT + scan to include new nullable columns; added `scanClient()` helper
- `pkg/token/generate.go` — added `cfg *config.Config` third argument; callers use `config.GetForClient()`
- `pkg/token/handler.go` — resolves per-client config before calling `GenerateTokens`
- `pkg/signup/handler.go` — first user granted admin role, sets `onboarded=true`
- `pkg/user/read.go` — added `CountUsers() (int, error)`
- `pkg/login/handler.go` — fixed `cfg.AppOAuthPath` → `config.GetBootstrap().AppOAuthPath`
- `pkg/idpsession/cookie.go` — reads cookie name/secure from `Bootstrap`
- `pkg/wellknown/handler.go` — uses `GetBootstrap().AppAuthIssuer`
- `admin-ui/src/pages/LoginPage.tsx` — checks `/admin/api/onboarding` before OIDC flow
- `main.go` — updated init flags (`--url` only)
- `go.mod` / `go.sum` — added `github.com/joho/godotenv`

### Test Files Updated
All test files updated to use `config.Bootstrap.*` / `config.GetBootstrap().*` instead of the moved fields:
- `pkg/config/config_test.go` — rewritten; added `TestInitBootstrap_*`, `TestGetForClient_*`
- `pkg/key/key_test.go` — simplified; removed `AuthPrivateKeyFile` references
- `pkg/utils/redirect_uri_test.go` — removed `AuthAllowedRedirectURIs`; tests syntactic validation only
- `pkg/jwtutil/validate_test.go` — uses `config.Bootstrap.AppAuthIssuer`, `config.Bootstrap.AuthJwkCertKeyID`
- `pkg/idpsession/cookie_test.go` — uses `config.Bootstrap.AuthIdpSessionCookieName`
- `pkg/wellknown/handler_test.go` — added `init()` to set Bootstrap fields
- `pkg/authorize/handler_test.go` — replaced allowlist test with syntactic invalid URI test
- `pkg/login/handler_test.go` — same; updated Bootstrap references
- `pkg/token/handler_test.go` — Bootstrap refs; `GenerateTokens` 3-arg calls
- `pkg/token/generate_test.go` — Bootstrap refs; 3-arg calls
- `tests/auth/auth_test.go` — Bootstrap refs; 3-arg calls
- `tests/e2e/test_server_test.go` — all `config.Values.App*` → `config.Bootstrap.*`
- `tests/e2e/test_helpers_test.go` — `AuthDefaultClientID` → `""`
- `tests/e2e/session_test.go` — `AuthIdpSessionCookieName` → Bootstrap
- `tests/utils/config_override.go` — saves/restores both `config.Values` AND `config.Bootstrap`
- Multiple middleware/user/userinfo/introspect/passkey test files — `AppAuthIssuer`, `AuthJwkCertKeyID` → Bootstrap

---

## Key Design Decisions

### Bootstrap defaults in `var Bootstrap = BootstrapConfig{...}`
Added sensible defaults to the `Bootstrap` declaration so unit tests work without calling `InitBootstrap()`. Tests that override specific Bootstrap fields use `WithConfigOverride` for cleanup.

### `ValidateAudience` semantics
Empty `requiredAudiences` means no restriction — any token is accepted. Tests that want to verify rejection must explicitly configure `config.Values.AuthAccessTokenAudience`.

### `LoadIntoConfig` merge strategy
Starts from `config.Values` (not `config.GetOriginal()`) so DB settings merge into the current state, preserving test overrides for keys not in the DB.

### `WithConfigOverride` updated
Now saves and restores both `config.Values` and `config.Bootstrap` so tests that modify Bootstrap fields are properly cleaned up.

### RSA key priority
1. `AUTENTICO_PRIVATE_KEY` env var (base64 PEM) → decode and use
2. Not set → generate ephemeral RSA 2048-bit key + log `slog.Warn`

No file-based PEM loading. `autentico init` generates the key and writes it to `.env`.

### Per-client config
`config.GetForClient(ClientOverrides)` returns a copy of `config.Values` with non-nil client fields applied. `GenerateTokens` now takes `*config.Config` so per-client expirations and audiences are used for token generation.

---

## Env Vars Reference

| Var | Default | Notes |
|-----|---------|-------|
| `AUTENTICO_APP_URL` | `http://localhost:9999` | Domain/host/port/issuer derived from this |
| `AUTENTICO_APP_OAUTH_PATH` | `/oauth2` | OAuth2 path prefix |
| `AUTENTICO_APP_ENABLE_CORS` | `true` | |
| `AUTENTICO_DB_FILE_PATH` | `./db/autentico.db` | |
| `AUTENTICO_PRIVATE_KEY` | *(ephemeral)* | Base64 RSA PEM; generate with `autentico init` |
| `AUTENTICO_JWK_CERT_KEY_ID` | `autentico-key-1` | |
| `AUTENTICO_ACCESS_TOKEN_SECRET` | `your-secret-here` | |
| `AUTENTICO_REFRESH_TOKEN_SECRET` | `your-secret-here` | |
| `AUTENTICO_CSRF_SECRET_KEY` | `your-secret-here` | |
| `AUTENTICO_CSRF_SECURE_COOKIE` | `false` | |
| `AUTENTICO_REFRESH_TOKEN_COOKIE_NAME` | `autentico_refresh_token` | |
| `AUTENTICO_REFRESH_TOKEN_SECURE` | `false` | |
| `AUTENTICO_IDP_SESSION_COOKIE_NAME` | `autentico_idp_session` | |
| `AUTENTICO_IDP_SESSION_SECURE` | `false` | |
| `AUTENTICO_SWAGGER_PORT` | `8888` | |

---

## Removed Fields / Breaking Changes

| Removed | Replacement |
|---------|-------------|
| `config.Config.AuthAllowedRedirectURIs` | Per-client allowlist; syntactic validation only at global level |
| `config.Config.AuthDefaultClientID` | `client_id` always from request |
| `config.Config.AuthPrivateKeyFile` | `Bootstrap.PrivateKeyBase64` / ephemeral |
| `config.Config.AppOAuthPath` | `Bootstrap.AppOAuthPath` |
| `config.Config.AppURL` / `AppHost` / `AppDomain` | `Bootstrap.*` equivalents |
| `config.Config.AppAuthIssuer` | `Bootstrap.AppAuthIssuer` |
| `config.Config.AuthJwkCertKeyID` | `Bootstrap.AuthJwkCertKeyID` |
| `config.Config.AuthCSRFProtectionSecretKey` | `Bootstrap.AuthCSRFProtectionSecretKey` |
| `config.Config.AuthIdpSessionCookieName` | `Bootstrap.AuthIdpSessionCookieName` |
| `config.Config.AuthRefreshTokenAsSecureCookie` | `Bootstrap.AuthRefreshTokenAsSecureCookie` |
| `config.InitConfig(path)` | `config.InitBootstrap()` |
| `token.GenerateTokens(user, clientID)` | `token.GenerateTokens(user, clientID, cfg)` |
| `autentico.json` | `.env` + settings DB |
