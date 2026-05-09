# Autentico Documentation Content Catalog

Generated from all `.mdx` files in `docs-web/src/content/docs/`.

---

## Landing Page

### `index.mdx` — "Autentico"

**Feature claims:**
- Self-hosted OAuth 2.0 / OpenID Connect Identity Provider built with Go
- Single binary backed by SQLite
- Authorization Code Flow with PKCE, Refresh Tokens, ROPC, Token Introspection (RFC 7662), Token Revocation (RFC 7009), Dynamic Client Registration (RFC 7591), full OIDC Discovery document
- WebAuthn/FIDO2 passkey authentication, TOTP with in-browser QR enrollment, Email OTP, trusted device recognition
- Built-in React dashboard for managing users, clients, sessions
- Self-service account portal: profile, change password, enroll TOTP, register passkeys
- Single Go binary with embedded SQLite, no Postgres, no Redis, no sidecars
- ~40MB idle, ~100MB under heavy load
- Immutable bootstrap settings from `.env`, runtime settings in database (hot-reloadable), per-client overrides
- RS256 JWT signing, CSRF protection, bcrypt password hashing, account lockout, rate limiting, configurable session timeouts
- Passes OpenID Foundation Basic OP certification test

**CLI commands:** `./autentico start --auto-setup`

**External links:**
- `https://demo.autentico.top/launch` (live demo)
- `https://github.com/eugenioenko/autentico` (GitHub)
- `https://github.com/eugenioenko/autentico/releases` (releases)

---

## Getting Started

### `getting-started/installation.mdx` — "Installation"

**CLI commands/flags:**
- `autentico init` — generate `.env` with fresh secrets. Flags: `--url`, `--dev`
- `autentico start` — start server, applies pending migrations automatically
- `autentico start --auto-setup` — generate `.env` if missing, then start
- `autentico start --no-auto-migrate` — skip auto migrations, refuses to start if schema behind
- `autentico migrate` — interactively apply pending database migrations
- `autentico onboard` — create first admin account headlessly (for CI/CD). Flags: `--username`, `--password`, `--email`
- `autentico onboard --enable-admin-password-grant` — also seeds `autentico-admin` client with `password` (ROPC) grant. Also settable via `AUTENTICO_ENABLE_ADMIN_PASSWORD_GRANT=true`
- `autentico version` — print version and exit

**Config keys:** `AUTENTICO_APP_URL`, `AUTENTICO_ENABLE_ADMIN_PASSWORD_GRANT`

**Code examples:**
- Binary download URLs for Linux amd64/arm64, macOS amd64/arm64, Windows amd64
- Docker run command: `docker run -p 9999:9999 -v autentico-data:/app/data ghcr.io/eugenioenko/autentico:latest start --auto-setup`
- Docker run with custom URL via `-e AUTENTICO_APP_URL=https://auth.example.com`
- Build from source: `make build` (requires Go 1.22+ and Node.js 22+)

**Feature claims:**
- Single self-contained binary with no runtime dependencies
- Docker image: `ghcr.io/eugenioenko/autentico:latest`
- `--auto-setup` generates `.env` with fresh secrets on first run, reuses on restarts
- Volume at `/app/data` persists database and generated configuration
- `--dev` flag on init disables secure cookie flags
- Changing `AUTENTICO_APP_URL` after first run leaves admin client with old callback URL

**External links:**
- `https://github.com/eugenioenko/autentico/releases/latest` (download)
- `https://github.com/eugenioenko/autentico.git` (source)

---

### `getting-started/quickstart.mdx` — "Quickstart"

**CLI commands/flags:**
- `./autentico start --auto-setup`
- `./autentico onboard --username admin --password yourpassword --email admin@example.com`

**Config keys:** `AUTENTICO_ADMIN_USERNAME`, `AUTENTICO_ADMIN_PASSWORD`, `AUTENTICO_ADMIN_EMAIL`, `AUTENTICO_APP_URL`

**Endpoints mentioned:**
- `http://localhost:9999/onboard` — browser onboarding

**Feature claims:**
- `--auto-setup` generates `.env` with fresh secrets (RSA key, CSRF, token signing) on first run
- Onboard credentials can be passed via environment variables
- For production, set `AUTENTICO_APP_URL` to public HTTPS URL
- Secure cookies require HTTPS; `--dev` only for local HTTP development

---

## Deployment

### `deployment/binary.mdx` — "Binary Deployment"

**Config keys:** `AUTENTICO_DB_FILE_PATH`, `AUTENTICO_PRIVATE_KEY`

**Feature claims:**
- No runtime dependencies beyond the binary itself
- One executable and one SQLite file
- RSA private key is passed as `AUTENTICO_PRIVATE_KEY` env var (base64-encoded PEM), not written to disk
- Recommends `sqlite3 .backup` for hot backup

**Code examples:**
- systemd service file at `/etc/systemd/system/autentico.service` with `EnvironmentFile=/opt/autentico/.env`
- systemd commands: `systemctl daemon-reload`, `systemctl enable --now autentico`

---

### `deployment/docker.mdx` — "Docker"

**Config keys:** `AUTENTICO_APP_URL`, `AUTENTICO_DB_FILE_PATH`, `AUTENTICO_LISTEN_PORT`, `AUTENTICO_PRIVATE_KEY`, `AUTENTICO_CSRF_SECRET_KEY`, `AUTENTICO_ACCESS_TOKEN_SECRET`, `AUTENTICO_REFRESH_TOKEN_SECRET`

**Endpoints mentioned:**
- `http://localhost:9999/healthz` — health check endpoint (in HEALTHCHECK directive)

**Feature claims:**
- Image: `ghcr.io/eugenioenko/autentico:latest`
- Minimal Linux container with just the `autentico` binary
- Entrypoint is `./autentico`, default command is `start`
- `--auto-setup` generates `.env` with fresh secrets on first run
- Volume at `/app/data` for persistence
- `AUTENTICO_APP_URL` defaults to `http://localhost:9999`
- `AUTENTICO_DB_FILE_PATH` defaults to `./autentico.db`
- `AUTENTICO_LISTEN_PORT` defaults to port in `AUTENTICO_APP_URL`
- Logs structured HTTP access logs to stdout

**Code examples:**
- Docker run with volume, port mapping, `--auto-setup`
- Docker run with custom URL
- Docker run with pre-generated `.env` via `--env-file`
- HEALTHCHECK directive using `wget -qO- http://localhost:9999/healthz`

---

### `deployment/docker-compose.mdx` — "Docker Compose"

**Feature claims:**
- Same as Docker page re: `--auto-setup` behavior
- Caddy reverse proxy with automatic HTTPS via Let's Encrypt

**Code examples:**
- Minimal docker-compose.yml with autentico service
- Production docker-compose.yml with `--url https://auth.example.com` and `127.0.0.1:9999:9999`
- docker-compose.yml with pre-generated `.env` via `env_file:`
- docker-compose.yml with Caddy reverse proxy service
- Caddyfile: `auth.example.com { reverse_proxy autentico:9999 }`
- Upgrade: `docker compose pull && docker compose up -d`

---

### `deployment/key-generation.mdx` — "Key Generation"

**Config keys:** `AUTENTICO_PRIVATE_KEY`, `AUTENTICO_CSRF_SECRET_KEY`, `AUTENTICO_ACCESS_TOKEN_SECRET`, `AUTENTICO_REFRESH_TOKEN_SECRET`

**Endpoints mentioned:**
- `/oauth2/.well-known/jwks.json` — public key for token verification

**Feature claims:**
- Four secrets required: `AUTENTICO_PRIVATE_KEY` (RSA, base64 PEM, RS256 JWT signing), `AUTENTICO_CSRF_SECRET_KEY` (HMAC for CSRF token signing), `AUTENTICO_ACCESS_TOKEN_SECRET` (opaque access token identifier generation), `AUTENTICO_REFRESH_TOKEN_SECRET` (opaque refresh token identifier generation)
- If `AUTENTICO_PRIVATE_KEY` unset, ephemeral key generated on startup, all tokens invalidated on restart
- `autentico init` will error if `.env` already exists

**CLI commands/flags:**
- `./autentico init --url https://auth.example.com`
- Docker variant: `docker run --rm -v "$(pwd)":/output ghcr.io/eugenioenko/autentico:latest init --url https://auth.example.com --output /output`

**Code examples:**
- Manual RSA key generation: `openssl genrsa 4096 | base64 -w 0`
- Manual random secret: `openssl rand -base64 32`

---

### `deployment/migrations.mdx` — "Database Migrations"

**Feature claims:**
- Uses SQLite's `PRAGMA user_version` to track schema version
- Migrations applied automatically on startup by default
- Fresh databases stamped with current version on first start
- Migrations are irreversible
- `autentico migrate` is interactive: shows current/target versions, warns about irreversibility, requires typing target version number to confirm

**CLI commands/flags:**
- `autentico start` — applies pending migrations automatically
- `autentico start --no-auto-migrate` — server refuses to start if DB behind
- `autentico migrate` — interactive migration

---

### `deployment/production-checklist.mdx` — "Production Checklist"

**Config keys mentioned:**
- `AUTENTICO_APP_URL`
- `AUTENTICO_COOKIE_SECRET` — **NOTE: this key does not exist in bootstrap settings; may be incorrect**
- `AUTENTICO_ADMIN_TOKEN` — **NOTE: this key does not exist in bootstrap settings; may be incorrect**
- `AUTENTICO_PRIVATE_KEY`
- `mfa_enabled` — **NOTE: runtime setting name in docs is `require_mfa` per runtime-settings page**
- `mfa_method`
- `lockout_max_attempts` — **NOTE: runtime setting name is `account_lockout_max_attempts` per runtime-settings page**
- `lockout_duration` — **NOTE: runtime setting name is `account_lockout_duration` per runtime-settings page**
- `sso_session_idle_timeout`
- `sso_session_max_age`
- `access_token_expiration`
- `refresh_token_expiration`
- `allow_self_signup`

**Endpoints mentioned:**
- `GET /.well-known/openid-configuration` — health check

**Feature claims:**
- Background cleanup starts automatically; check logs for `[cleanup]` entries
- Logs to stdout

---

### `deployment/reverse-proxy.mdx` — "Reverse Proxy"

**Config keys:** `AUTENTICO_APP_URL`, `cors_allowed_origins`, `AUTENTICO_LISTEN_PORT`

**Endpoints mentioned:**
- `PUT /admin/api/settings` — update CORS settings

**Feature claims:**
- Autentico listens on plain HTTP
- Issuer claim and OIDC discovery document derived from `AUTENTICO_APP_URL`
- `X-Forwarded-For` and `X-Real-IP` headers logged with each request
- CORS: specific origins in production, `*` for dev only, empty to disable

**Code examples:**
- Caddy config (standalone and Docker Compose)
- nginx config with TLS, proxy headers
- Traefik Docker labels
- curl to update CORS via `PUT /admin/api/settings`

---

## Configuration

### `configuration/overview.mdx` — "Configuration Overview"

**Feature claims:**
- Three-layer configuration: bootstrap (.env), runtime (settings DB table), per-client (clients DB table)
- Bootstrap loaded once at startup, immutable
- Runtime hot-reloadable via Admin UI or `PUT /admin/api/settings`
- Per-client overrides applied per-request, unset fields fall through to runtime defaults
- Precedence: runtime settings → per-client overrides → bootstrap always available
- `onboarded` and `private_key` settings keys are protected (cannot be set via API)

**Endpoints mentioned:**
- `PUT /admin/api/settings`

---

### `configuration/bootstrap.mdx` — "Bootstrap Settings (.env)"

**Config keys (all):**

Application:
- `AUTENTICO_APP_URL` (default: `http://localhost:9999`)
- `AUTENTICO_APP_OAUTH_PATH` (default: `/oauth2`)
- `AUTENTICO_DB_FILE_PATH` (default: `./autentico.db`)

Cryptographic secrets:
- `AUTENTICO_PRIVATE_KEY` — base64-encoded RSA 2048 private key PEM, RS256
- `AUTENTICO_ACCESS_TOKEN_SECRET` — HMAC secret for access token signing
- `AUTENTICO_REFRESH_TOKEN_SECRET` — HMAC secret for refresh token signing
- `AUTENTICO_CSRF_SECRET_KEY` — 32-byte secret for CSRF token generation (`gorilla/csrf`)

Cookies:
- `AUTENTICO_CSRF_SECURE_COOKIE` (default: `true`)
- `AUTENTICO_IDP_SESSION_COOKIE_NAME` (default: `autentico_idp_session`)
- `AUTENTICO_IDP_SESSION_SECURE` (default: `true`)
- `AUTENTICO_REFRESH_TOKEN_COOKIE_NAME` (default: `autentico_refresh_token`)
- `AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY` (default: `false`) — opt-in: refresh token as HttpOnly cookie instead of JSON body

Rate limiting:
- `AUTENTICO_RATE_LIMIT_RPS` (default: `5`)
- `AUTENTICO_RATE_LIMIT_BURST` (default: `10`)
- `AUTENTICO_RATE_LIMIT_RPM` (default: `20`)
- `AUTENTICO_RATE_LIMIT_RPM_BURST` (default: `20`)

Anti-timing delay:
- `AUTENTICO_ANTI_TIMING_MIN_MS` (default: `50`)
- `AUTENTICO_ANTI_TIMING_MAX_MS` (default: `150`)

Performance:
- `GOMAXPROCS` (standard Go env var)
- `AUTENTICO_DB_READ_POOL_SIZE` (default: `0` = auto: min(CPUs, 4), minimum 2)

Token signing:
- `AUTENTICO_JWK_CERT_KEY_ID` (default: `autentico-key-1`)

Networking (derived from `AUTENTICO_APP_URL`):
- `AUTENTICO_LISTEN_PORT` — **NOTE: listed in Docker page but NOT in this bootstrap reference table** (only derived values shown)

**Feature claims:**
- Rate limiting applies to: `/oauth2/login`, `/oauth2/mfa`, `/oauth2/token`, `/oauth2/passkey/login/finish`
- Two-tier rate limiting: per-second and per-minute, request must pass both
- Set `AUTENTICO_RATE_LIMIT_RPS=0` to disable both limiters
- Anti-timing delay on: `/oauth2/login`, `/oauth2/passkey/login`, `/oauth2/forgot-password`, `/oauth2/resend-verification`
- `AppDomain`, `AppHost`, `AppPort`, `AppAuthIssuer` all derived from `AUTENTICO_APP_URL`

**NOTE:** `AUTENTICO_LISTEN_PORT` is documented in the Docker page but not present in the bootstrap settings reference table. The bootstrap page only shows derived values.

---

### `configuration/runtime-settings.mdx` — "Runtime Settings"

**Endpoints mentioned:**
- `GET /admin/api/settings` — read all settings
- `PUT /admin/api/settings` — update settings

**Config keys (runtime, all):**

Token lifetimes:
- `access_token_expiration` (default: `15m`)
- `refresh_token_expiration` (default: `720h`)
- `authorization_code_expiration` (default: `10m`)

Authentication:
- `auth_mode` (default: `password`; values: `password`, `password_and_passkey`, `passkey_only`)
- `allow_self_signup` (default: `false`)
- `allow_username_change` (default: `false`)
- `allow_email_change` (default: `false`)
- `allow_self_service_deletion` (default: `false`)
- `access_token_audience` (default: `[]`)

Email verification:
- `require_email_verification` (default: `false`)
- `email_verification_expiration` (default: `24h`)
- `password_reset_expiration` (default: `1h`)

SSO sessions:
- `sso_enabled` (default: `true`)
- `sso_session_idle_timeout` (default: `4h`)
- `sso_session_max_age` (default: `720h`)

Account security:
- `account_lockout_max_attempts` (default: `5`)
- `account_lockout_duration` (default: `15m`)

CORS:
- `cors_allowed_origins` (default: empty)

Security:
- `pkce_enforce_s256` (default: `true`)

MFA:
- `require_mfa` (default: `false`)
- `mfa_method` (default: `totp`; values: `totp`, `email`, `both`)

SMTP:
- `smtp_host` (default: empty)
- `smtp_port` (default: `587`)
- `smtp_username` (default: empty)
- `smtp_password` (default: empty; not returned by GET)
- `smtp_from` (default: empty)

Trusted devices:
- `trust_device_enabled` (default: `false`)
- `trust_device_expiration` (default: `720h`)

Passkeys:
- `passkey_rp_name` (default: `Autentico`)

Input validation:
- `validation_min_username_length` (default: `4`)
- `validation_max_username_length` (default: `64`)
- `validation_min_password_length` (default: `6`)
- `validation_max_password_length` (default: `64`)
- `validation_username_is_email` (default: `false`)
- `validation_email_required` (default: `false`)

Profile fields (values: `hidden`, `optional`, `required`; default: `hidden`):
- `profile_field_email` — also accepts `is_username`
- `profile_field_given_name`
- `profile_field_family_name`
- `profile_field_middle_name`
- `profile_field_nickname`
- `profile_field_website`
- `profile_field_profile`
- `profile_field_gender`
- `profile_field_birthdate`
- `profile_field_phone`
- `profile_field_picture`
- `profile_field_locale`
- `profile_field_address` — controls all address sub-fields as a group
- `signup_show_optional_fields` (default: `false`)

Cleanup:
- `cleanup_interval` (default: `6h`)
- `cleanup_retention` (default: `24h`)

Audit log:
- `audit_log_retention` (default: `0`; `0` disables, `-1` keeps forever, duration enables with auto-purge)

Theming:
- `theme_title` (default: `Autentico`)
- `theme_logo_url` (default: empty)
- `theme_css_inline` (default: empty)
- `theme_css_file` (default: empty)
- `theme_brand_color` (default: `#ff7b00`)
- `theme_tagline` (default: empty)
- `email_footer_text` (default: empty)
- `footer_links` (default: `[]`; JSON array of `{label, url}`)

**Feature claims:**
- All values stored as strings
- Durations use Go duration format
- `onboarded` and `private_key` keys are protected
- `smtp_password` not returned by settings GET endpoint

---

### `configuration/per-client-overrides.mdx` — "Per-Client Overrides"

**Endpoints mentioned:**
- `POST /oauth2/register` — set overrides at registration
- `PUT /oauth2/register/YOUR_CLIENT_ID` — update overrides on existing client

**Config keys (per-client overrides, all):**
- `access_token_expiration`
- `refresh_token_expiration`
- `authorization_code_expiration`
- `allowed_audiences` — string array of `aud` values; extends global `access_token_audience`; include `"autentico-admin"` for admin API access
- `allow_self_signup`
- `sso_session_idle_timeout`
- `trust_device_enabled`
- `trust_device_expiration`

**Feature claims:**
- Unset overrides (null) fall through to runtime defaults
- Duration strings use Go `time.Duration` format
- `"0"` means no idle expiration for `sso_session_idle_timeout`

---

## Authentication

### `authentication/overview.mdx` — "Authentication Overview"

**Config keys:** `auth_mode`

**Endpoints mentioned:**
- `PUT /admin/api/settings` — change auth_mode

**Feature claims:**
- Three auth modes: `password` (default), `password_and_passkey`, `passkey_only`
- Mode changeable at runtime without restart
- `password`: standard username+password, MFA on top if `mfa_enabled` true
- `password_and_passkey`: either password or registered passkey; password logins include MFA, passkey logins do not
- `passkey_only`: password disabled, users walked through passkey registration on initial login
- **NOTE: mermaid diagram and table reference `mfa_enabled` but runtime settings page uses `require_mfa`**

**Code examples:**
- CSS variables for login page theming (light + dark mode)
- curl to update `auth_mode` via PUT

---

### `authentication/password.mdx` — "Password Authentication"

**Endpoints mentioned:**
- `GET /oauth2/authorize` — start flow
- `POST /oauth2/login` — credential submission

**Config keys:** `validation_min_username_length`, `validation_max_username_length`, `validation_min_password_length`, `validation_max_password_length`, `validation_username_is_email`, `validation_email_required`

**Feature claims:**
- Default `auth_mode`
- Passwords hashed with bcrypt, never stored in plaintext
- Account lockout after configurable failed attempts
- Validation rules enforced at registration

---

### `authentication/mfa.mdx` — "Multi-Factor Authentication"

**Endpoints mentioned:**
- `POST /oauth2/login` — triggers MFA challenge
- `GET /oauth2/mfa?challenge_id=X` — render MFA page
- `POST /oauth2/mfa` — submit OTP code

**Config keys:** `mfa_enabled` (**NOTE: runtime settings page uses `require_mfa`**), `mfa_method`, `smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_from`, `theme_title`

**Feature claims:**
- MFA challenge is short-lived (5 minutes), single-use
- If challenge expires, user redirected to login page
- TOTP compatible with RFC 6238 apps (Google Authenticator, Authy, 1Password, Bitwarden)
- TOTP enrollment automatic on first login after MFA enabled (QR code shown)
- TOTP secret stored per-user in database, QR code generated server-side
- TOTP issuer name from `theme_title` setting
- Email OTP: sends one-time code to registered email, no enrollment needed
- MFA applied to password auth only; passkey auth skips MFA
- Trusted devices allow skipping MFA after successful verification

**Code examples:**
- curl to enable MFA via `PUT /admin/api/settings` with `mfa_enabled` and `mfa_method`

---

### `authentication/passkeys.mdx` — "Passkeys (WebAuthn)"

**Endpoints mentioned:**
- `GET /oauth2/passkey/login/begin?username=...&client_id=...` — start authentication
- `POST /oauth2/passkey/login/finish?challenge_id=X` — finish authentication
- `POST /oauth2/passkey/register/finish?challenge_id=X` — finish first-login registration

**Config keys:** `passkey_rp_name`, `auth_mode`, `AUTENTICO_APP_URL`

**Feature claims:**
- Uses `go-webauthn/webauthn` library
- Supports platform authenticators (Face ID, Touch ID, Windows Hello) and hardware security keys (YubiKey)
- Challenges short-lived (5 minutes) and single-use, stored in `passkey_challenges` table
- In `passkey_only` mode, users without credentials are walked through registration on first login
- Registered credentials stored in `passkey_credentials` table
- Relying party ID derived from `AUTENTICO_APP_URL` hostname
- Changing `AUTENTICO_APP_URL` breaks existing passkey credentials

**Architecture claims:**
- Tables: `passkey_challenges`, `passkey_credentials`

---

### `authentication/sso-sessions.mdx` — "SSO Sessions"

**Config keys:** `sso_enabled` (default: `true`), `sso_session_idle_timeout` (default: `4h`), `sso_session_max_age` (default: `720h`)

**Endpoints mentioned:**
- `GET /oauth2/authorize` — checks session cookie
- `GET /oauth2/logout` — deactivates SSO session

**Feature claims:**
- Session cookie scoped to Autentico domain
- On new authorization request: read cookie → check session → if valid, issue auth code without login page
- Session cookie `Expires` set to `sso_session_max_age` at login time
- Changing setting doesn't retroactively update existing cookies
- Idle timeout overridable per-client
- `GET /oauth2/logout` scoped to current End-User session per OpenID Connect RP-Initiated Logout 1.0 section 2
- Logout cascade-revokes IdP session + every OAuth session born from it + their tokens, clears cookie
- Other devices keep their sessions (matches Keycloak, Auth0, Google behavior)
- "Sign out everywhere" is separate from RP-Initiated Logout

**Architecture claims:**
- Sessions table fields: `id`, `user_id`, `user_agent`, `ip_address`, `last_activity_at`, `created_at`, `expires_at`, `deactivated_at`
- **NOTE: describes `sessions` table but the actual DB table for SSO sessions is `idp_sessions`**

**External links:**
- `https://openid.net/specs/openid-connect-rpinitiated-1_0.html` (RP-Initiated Logout)

---

### `authentication/trusted-devices.mdx` — "Trusted Devices"

**Config keys:** `trust_device_enabled` (default: `false`), `trust_device_expiration` (default: `720h`)

**Endpoints mentioned:**
- `PUT /admin/api/settings` — enable trusted devices

**Feature claims:**
- After successful MFA, user checks "Trust this device" checkbox
- Autentico creates `trusted_devices` record and sets signed token cookie
- On subsequent logins, cookie found → bypass MFA
- Table fields: `id`, `user_id`, `device_name`, `created_at`, `last_used_at`, `expires_at`
- Both settings overridable per-client
- Devices cleared when: record expires, user logs out, admin deactivates sessions, cleanup job runs
- Cookies are HttpOnly and Secure

**Architecture claims:**
- Table: `trusted_devices`

---

## Protocol Reference

### `protocol/overview.mdx` — "Protocol Overview"

**Endpoints mentioned:**
- `/.well-known/openid-configuration`
- `/oauth2/.well-known/jwks.json`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/userinfo`
- `/oauth2/introspect`
- `/oauth2/revoke`
- `/oauth2/logout`
- `/oauth2/protocol/openid-connect/token` (Keycloak-compatible alias)
- `/oauth2/protocol/openid-connect/userinfo` (Keycloak-compatible alias)

**Config keys:** `AUTENTICO_APP_OAUTH_PATH`

**Feature claims:**
- Supported grant types: `authorization_code` + PKCE, `refresh_token`, `password` (ROPC), `client_credentials`
- Keycloak-compatible aliases for token and userinfo endpoints
- `/oauth2` path prefix configurable via `AUTENTICO_APP_OAUTH_PATH`

**External links:**
- OAuth 2.0 (RFC 6749)
- OpenID Connect Core 1.0

---

### `protocol/authorization-code.mdx` — "Authorization Code Flow + PKCE"

**Endpoints mentioned:**
- `GET /oauth2/authorize` — authorization endpoint
- `POST /oauth2/login` — credential submission
- `POST /oauth2/token` — token exchange
- `POST /oauth2/protocol/openid-connect/token` — Keycloak-compatible

**Feature claims:**
- PKCE (RFC 7636) required for public clients, recommended for all
- Authorization request parameters: `response_type` (required, `code`), `client_id` (required), `redirect_uri` (required, exact match), `scope` (required, includes `openid` for OIDC), `state` (recommended, CSRF), `nonce` (recommended, replay), `code_challenge` (required for public), `code_challenge_method` (required with challenge, `S256` or `plain`)
- Auth code default lifetime: 10 minutes, single-use
- Token response includes `access_token`, `token_type`, `expires_in`, `refresh_token`, `id_token`
- `redirect_uri` in token exchange must exactly match authorization request

**Code examples:**
- JavaScript PKCE code_verifier and code_challenge generation
- curl for public client (PKCE), confidential client (Basic Auth), confidential client (POST body)

---

### `protocol/introspection-revocation.mdx` — "Introspection & Revocation"

**Endpoints mentioned:**
- `POST /oauth2/introspect` — token introspection (RFC 7662)
- `POST /oauth2/revoke` — token revocation (RFC 7009)
- `GET /oauth2/logout` — implicit revocation

**Feature claims:**
- Introspection protected by admin bearer token (`Authorization: Bearer $ADMIN_TOKEN`)
- Active response: `{ active: true, sub, username, exp, iat, iss, aud }`
- Inactive response: `{ active: false }`
- Revocation always returns 200 OK with empty body (per RFC 7009)
- Both access tokens and refresh tokens can be revoked
- Revocation request params: `token`, `client_id`
- Implicit revocation: on logout, admin session deactivation, cleanup job

---

### `protocol/oidc-discovery.mdx` — "OIDC Discovery"

**Endpoints mentioned:**
- `GET /.well-known/openid-configuration`
- `GET /oauth2/.well-known/openid-configuration` (same document)
- `GET /oauth2/.well-known/jwks.json`

**Config keys:** `AUTENTICO_AUTH_JWK_CERT_KEY_ID` (**NOTE: bootstrap page uses `AUTENTICO_JWK_CERT_KEY_ID`; this is a different name**)

**Feature claims:**
- Both paths return same discovery document
- Discovery document claims:
  - `issuer`: `https://auth.example.com/oauth2`
  - `authorization_endpoint`: `https://auth.example.com/oauth2/authorize`
  - `token_endpoint`: `https://auth.example.com/oauth2/token`
  - `userinfo_endpoint`: `https://auth.example.com/oauth2/userinfo`
  - `registration_endpoint`: `https://auth.example.com/oauth2/register`
  - `end_session_endpoint`: `https://auth.example.com/oauth2/logout`
  - `jwks_uri`: `https://auth.example.com/oauth2/.well-known/jwks.json`
  - `response_types_supported`: `["code", "token", "id_token", "code token", "code id_token"]`
  - `subject_types_supported`: `["public"]`
  - `id_token_signing_alg_values_supported`: `["RS256"]`
  - `scopes_supported`: `["openid", "profile", "email"]`
  - `token_endpoint_auth_methods_supported`: `["client_secret_basic", "client_secret_post"]`
  - `claims_supported`: `["sub", "iss", "aud", "exp", "iat", "name", "email"]`
- JWKS `kid` configurable via `AUTENTICO_AUTH_JWK_CERT_KEY_ID` (default: `autentico-key`)
- **NOTE: default `kid` value listed here is `autentico-key` but bootstrap page says `autentico-key-1`**

---

### `protocol/refresh-tokens.mdx` — "Refresh Tokens"

**Endpoints mentioned:**
- `POST /oauth2/token` — refresh token grant (`grant_type=refresh_token`)

**Config keys:** `refresh_token_expiration`

**Feature claims:**
- Default refresh token lifetime: 30 days (`720h`)
- New refresh token issued with each refresh; old one invalidated (rotation)
- Refresh request params: `grant_type=refresh_token`, `refresh_token`, `client_id`

---

### `protocol/ropc.mdx` — "Resource Owner Password Credentials"

**Endpoints mentioned:**
- `POST /oauth2/token` — ROPC grant (`grant_type=password`)
- `POST /oauth2/register` — register client with `password` grant type

**Feature claims:**
- Legacy grant type; requires client to handle credentials directly
- Cannot support MFA, passkeys, or SSO sessions
- Request params: `grant_type=password`, `username`, `password`, `client_id`, `scope`
- Response includes: `access_token`, `id_token`, `refresh_token`, `token_type`, `expires_in`, `scope`
- Client must have `password` in `grant_types`
- Limitations: MFA not enforced (bypasses MFA), passkey not available, no SSO session created, account lockout still applies

---

### `protocol/scopes.mdx` — "Scopes"

**Feature claims:**
- Supported scopes and claims:
  - `openid`: `sub`, `iss`, `aud`, `exp`, `iat`; triggers ID token issuance
  - `profile`: `name`, `preferred_username`, `given_name`, `family_name` (empty values omitted)
  - `email`: `email`, `email_verified`
- Default client scopes if omitted at registration: `openid profile email`
- Scopes recorded on authorization code and propagated to token response

**Endpoints mentioned:**
- `GET /oauth2/authorize` — pass scopes in request
- `GET /oauth2/userinfo` — returns claims based on scopes

---

### `protocol/token-structure.mdx` — "Token Structure & Claims"

**Endpoints mentioned:**
- `GET /oauth2/.well-known/jwks.json` — public keys for verification
- `GET /.well-known/openid-configuration` — discovery

**Config keys:** `AUTENTICO_APP_URL`, `AUTENTICO_APP_OAUTH_PATH`, `access_token_audience`, `allowed_audiences`, `AUTENTICO_REFRESH_TOKEN_SECRET`

**Feature claims:**
- Three token types: ID tokens, access tokens, refresh tokens — all JWTs
- ID token: RS256, JWT header includes `kid` = `autentico-key-1`
  - Claims: `iss`, `sub`, `aud` (client_id), `exp`, `iat`, `nonce`
- Access token: RS256
  - Claims: `iss`, `sub`, `aud` (always includes issuer and client_id; extended by `access_token_audience`/`allowed_audiences`; admin API requires `autentico-admin`), `exp`, `iat`, `sid` (session ID), `scope`
- Refresh token: HMAC-SHA256 with `AUTENTICO_REFRESH_TOKEN_SECRET`
  - Claims: `sub`, `sid`, `iat`, `exp`
  - Opaque to relying parties

---

## Clients

### `clients/overview.mdx` — "Clients Overview"

**Endpoints mentioned:**
- `POST /oauth2/register` — create client via API
- `GET/PUT /admin/api/clients/{id}` — manage client via admin API

**Feature claims:**
- Client types: `confidential` (has secret), `public` (no secret, PKCE)
- `autentico-admin` client seeded automatically on first startup

---

### `clients/client-types.mdx` — "Client Types"

**Endpoints mentioned:**
- `POST /oauth2/token` — token exchange examples

**Feature claims:**
- Confidential: `client_type: confidential`, auth via `client_secret_basic` or `client_secret_post`
- Public: `client_type: public`, `token_endpoint_auth_method: none`, must use PKCE
- No `client_secret` issued for public clients
- Summary table: Confidential has secret + PKCE recommended; Public no secret + PKCE required

---

### `clients/registering.mdx` — "Registering a Client"

**Endpoints mentioned:**
- `POST /oauth2/register` — register client

**Feature claims:**
- Admin UI generates `client_id` and `client_secret` automatically
- `client_secret` shown once at registration
- Fields:
  - `client_name` (required)
  - `client_id` (auto-generated UUID if omitted, must be unique)
  - `client_type` (default: `confidential`)
  - `redirect_uris` (required, exact match, no wildcards, max 10 URIs)
  - `grant_types` (default: `["authorization_code", "refresh_token"]`; values: `authorization_code`, `refresh_token`, `client_credentials`, `password`)
  - `response_types` (default: `["code"]`; also `token`, `id_token` for implicit/hybrid)
  - `scopes` (default: `openid profile email`; space-separated; includes `address`, `phone`, `offline_access`, custom scopes)
  - `token_endpoint_auth_method` (default: `client_secret_basic`; values: `client_secret_basic`, `client_secret_post`, `none`)

**Code examples:**
- curl for public client (SPA/mobile) registration
- curl for confidential client (server-side) registration
- Example registration response JSON

---

### `clients/per-client-configuration.mdx` — "Per-Client Configuration"

**Feature claims:**
- Points to per-client overrides reference
- Use cases: long-lived tokens for mobile, stricter session timeout for banking, trusted devices disabled for high-security, self-signup for one client only

---

## Users

### `users/overview.mdx` — "Users Overview"

**Feature claims:**
- Users have username, optional email, bcrypt-hashed password, MFA state
- Two roles: `user` (standard) and `admin` (admin API + admin UI access)
- Role assigned at creation or updated by admin
- Role not included in tokens by default — internal to Autentico

---

### `users/managing-users.mdx` — "Managing Users"

**Endpoints mentioned:**
- `POST /admin/api/users` — create user
- `GET /admin/api/users` — list users (paginated)
- `PUT /admin/api/users/USER_ID` — update user
- `POST /admin/api/users/unlock` — unlock locked account (body: `{ "user_id": "USER_ID" }`)
- `DELETE /admin/api/users/USER_ID` — delete user

**Feature claims:**
- Create: username, password, optionally email and role
- List: paginated, without password hashes or TOTP secrets
- Update: all fields optional; updatable fields: `username`, `password`, `email`, `role`, `is_email_verified`, `totp_verified`
- Reset MFA: set `totp_verified: false` → user re-enrolls on next login
- Unlock: resets `failed_login_attempts` and clears `locked_until`
- Delete: permanent, removes user and associated data (sessions, tokens, passkeys, trusted devices)

---

### `users/user-model.mdx` — "User Model"

**Feature claims:**
- Core fields: `id` (UUID, `sub` claim), `username` (unique), `password` (bcrypt), `email` (optional, unique if set), `role` (`user`/`admin`), `created_at`, `failed_login_attempts`, `locked_until`, `totp_secret` (base32), `totp_verified`, `is_email_verified`, `deactivated_at`
- OIDC profile fields: `given_name`, `family_name`, `middle_name`, `nickname`, `phone_number`, `phone_number_verified`, `picture`, `website`, `profile`, `gender`, `birthdate`, `locale`, `zoneinfo`, `address_street`, `address_locality`, `address_region`, `address_postal_code`, `address_country`
- All OIDC fields default to empty string, omitted from API responses when blank
- Admin API excludes password hash and TOTP secret
- User `id` = `sub` claim; `username` maps to `name`; `email` maps to `email` (with `email` scope)

---

### `users/self-signup.mdx` — "Self-Signup"

**Config keys:** `allow_self_signup`

**Endpoints mentioned:**
- `PUT /admin/api/settings` — enable self-signup
- `/oauth2/authorize?prompt=create` — signup link target

**Feature claims:**
- Default: closed system (only admins create accounts)
- When enabled, "Create account" link appears on login page
- Per-client control via per-client `allow_self_signup` override
- Signup flow: click link → fill form → validate → create account → redirect to login
- Same validation rules as admin-created accounts
- Recommends pairing with email verification

---

### `users/account-lockout.mdx` — "Account Lockout"

**Config keys:** `lockout_max_attempts` (default: `5`), `lockout_duration` (default: `15m`)
**NOTE: runtime settings page uses `account_lockout_max_attempts` and `account_lockout_duration`**

**Endpoints mentioned:**
- `PUT /admin/api/settings` — update lockout settings
- `POST /admin/api/users/unlock` — unlock account

**Feature claims:**
- Each failed password attempt increments `failed_login_attempts`
- At threshold, `locked_until = now + lockout_duration`
- Login attempts while locked return error immediately (no password check)
- Counter resets to 0 on successful login
- Locked accounts unlock automatically when `locked_until` passes
- Unlock resets `failed_login_attempts` to 0 and clears `locked_until`
- Lockout applies to ROPC token requests too

---

## Admin UI

### `admin-ui/overview.mdx` — "Admin UI Overview"

**Endpoints mentioned:**
- `/admin/` — Admin UI path
- `/onboard` — initial admin account creation
- `/api-docs/` — Redoc API documentation
- `/swagger/index.html` — interactive Swagger UI

**Feature claims:**
- React SPA embedded in binary, served at `/admin/`
- Authenticates via OAuth2 using `autentico-admin` client
- Sections: Dashboard, Users, Clients, Sessions, Settings
- Links to API docs at `/api-docs/` (Redoc) and `/swagger/index.html`

---

### `admin-ui/dashboard.mdx` — "Dashboard"

**Endpoints mentioned:**
- `GET /admin/api/stats` — fetch summary statistics

**Feature claims:**
- Shows total users, total clients, active sessions
- Updates on each page load

---

### `admin-ui/clients.mdx` — "Clients"

**Feature claims:**
- Client list shows: name, ID, type, active status, grant types
- Create: client name, redirect URIs, client type, grant types, auth method
- `client_id` auto-generated; `client_secret` shown once for confidential clients
- Can update all fields except `client_id`
- Clients can be deactivated and reactivated
- Per-client overrides section in detail form

---

### `admin-ui/sessions.mdx` — "Sessions"

**Feature claims:**
- Lists all SSO sessions: active and recently expired
- Session fields: User, IP address, User agent, Status (`active`/`expired`/`deactivated`), Created at, Last activity, Expires at
- Can revoke sessions to force re-authentication
- Expired/deactivated sessions removed by background cleanup job

---

### `admin-ui/settings.mdx` — "Settings"

**Endpoints mentioned:**
- `GET /admin/api/settings` — get all settings
- `PUT /admin/api/settings` — update settings

**Config keys listed by category:**
- Authentication: `auth_mode`, `mfa_enabled` (**NOTE: should be `require_mfa`?**), `mfa_method`
- Token lifetimes: `access_token_expiration`, `refresh_token_expiration`
- SSO sessions: `sso_enabled`, `sso_session_idle_timeout`, `sso_session_max_age`
- Account security: `lockout_max_attempts`, `lockout_duration`
- SMTP: `smtp_host`, `smtp_port`, `smtp_username`, `smtp_from`
- Trusted devices: `trust_device_enabled`, `trust_device_expiration`
- Passkeys: `passkey_rp_name`
- Validation: `validation_min_username_length`, `validation_email_required`
- Theming: `theme_title`, `theme_logo_url`, `theme_brand_color`, `theme_tagline`, `theme_css_inline`, `email_footer_text`, `footer_links`
- Cleanup: `cleanup_interval`, `cleanup_retention`

**Feature claims:**
- Settings hot-reloaded without restart
- Changes take effect on next request

---

### `admin-ui/users.mdx` — "Users"

**Endpoints mentioned:**
- `POST /admin/api/users` — bulk user creation via scripted API calls

**Feature claims:**
- User list shows: username, email, role, account status (active/locked/deactivated), TOTP enrollment status, creation date
- Search box filters by username or email
- Actions: New User, Edit, Unlock, Reset TOTP, Delete
- Deactivated users (`deactivated_at` set) cannot log in; can be reactivated by clearing `deactivated_at` via API

---

## Integrate

### `integrate/connecting.mdx` — "Connecting an OIDC Client"

**Endpoints mentioned:**
- `GET /oauth2/.well-known/openid-configuration` — discovery URL
- `POST /oauth2/register` — register client
- `/oauth2/protocol/openid-connect/token` — Keycloak alias
- `/oauth2/protocol/openid-connect/userinfo` — Keycloak alias

**Feature claims:**
- Any OIDC-compliant library/framework works
- Most libraries accept discovery URL and auto-configure
- Verify `iss` claim matches configured issuer
- Scopes to request: `openid profile email`

---

### `integrate/client-libraries.mdx` — "Client Libraries"

**Feature claims:**
- Works with any OIDC-compliant client library
- Examples provided for:
  - `oidc-client-ts` (SPA) — authority-based config
  - `next-auth` (Next.js) — OIDC provider with issuer
  - `arctic` (lightweight) — `createOIDCClient`
  - `coreos/go-oidc` (Go) — `oidc.NewProvider` + `oauth2.Config`
  - `authlib` (Python) — `OAuth2Session` with `fetch_server_metadata`
- All libraries auto-discover endpoints from issuer URL
- Use PKCE (S256) for public clients
- Keycloak aliases mentioned

---

### `integrate/pkce-walkthrough.mdx` — "PKCE Flow Walkthrough"

**Endpoints mentioned:**
- `GET /oauth2/authorize` — authorization request
- `POST /oauth2/token` — code exchange and refresh token grant
- `GET /oauth2/.well-known/jwks.json` — JWKS for verification

**Feature claims:**
- Complete raw HTTP walkthrough of PKCE flow
- Steps: generate PKCE params → build auth URL → user authenticates → exchange code → verify ID token → refresh
- Old refresh token invalidated on each refresh

**Code examples:**
- JavaScript PKCE generation
- Authorization URL construction
- curl for token exchange (public client PKCE)
- curl for refresh token

---

### `integrate/test-fixture.mdx` — "Use as a Test Fixture"

**Endpoints mentioned:**
- `POST /oauth2/token` — get admin token via ROPC
- `POST /admin/api/clients` — register test client
- `POST /admin/api/users` — create test user
- `PUT /admin/api/settings` — configure CORS and SSO
- `GET /.well-known/openid-configuration` — health check

**Config keys:** `AUTENTICO_RATE_LIMIT_RPS`, `AUTENTICO_RATE_LIMIT_RPM`, `AUTENTICO_ANTI_TIMING_MIN_MS`, `AUTENTICO_ANTI_TIMING_MAX_MS`, `AUTENTICO_CSRF_SECURE_COOKIE`, `AUTENTICO_IDP_SESSION_SECURE`

**CLI commands:**
- `autentico onboard --username admin --password ... --email ... --enable-admin-password-grant`
- `autentico start`
- `autentico init --url http://localhost:9999`

**Feature claims:**
- ~375ms startup (DB init + admin creation + client registration + CORS config)
- Full per-test lifecycle: ~400ms
- 15 browser E2E tests: ~18s
- 15 tests x 100 runs (1,500 lifecycles): ~30 min
- 0% flakiness from IdP layer
- Per-test: clean DB, onboard, start, seed, test, stop

**Code examples:**
- Complete Playwright global-setup.ts
- Complete Playwright per-test fixture (autentico.fixture.ts)
- Playwright config
- Test example

---

### `integrate/verifying-tokens.mdx` — "Verifying Tokens"

**Endpoints mentioned:**
- `GET /oauth2/.well-known/jwks.json` — JWKS endpoint
- `GET /.well-known/openid-configuration` — discovery

**Feature claims:**
- RS256 (RSA + SHA-256) signing for all tokens
- Local verification: fetch JWKS once at startup, cache, refresh on unknown `kid`
- Verification steps: decode JWT header → find key by `kid` → verify RS256 signature → check `exp`, `iss`, `aud`
- Alternative: introspection endpoint for revocation-aware validation

**Code examples:**
- Node.js `jose` library example
- Node.js `jsonwebtoken` + `jwks-rsa` example

---

## Security

### `security/overview.mdx` — "Hardening"

**Config keys:**
- `AUTENTICO_COOKIE_SECRET` — **NOTE: does not exist in bootstrap settings; likely incorrect**
- `AUTENTICO_ADMIN_TOKEN` — **NOTE: does not exist in bootstrap settings; likely incorrect**
- `AUTENTICO_PRIVATE_KEY`
- `mfa_enabled` — **NOTE: runtime settings uses `require_mfa`**
- `validation_min_password_length`
- `lockout_max_attempts` — **NOTE: runtime settings uses `account_lockout_max_attempts`**
- `lockout_duration` — **NOTE: runtime settings uses `account_lockout_duration`**
- `AUTENTICO_RATE_LIMIT_RPS` (default: 5), `AUTENTICO_RATE_LIMIT_BURST` (default: 10), `AUTENTICO_RATE_LIMIT_RPM` (default: 20), `AUTENTICO_RATE_LIMIT_RPM_BURST` (default: 20)
- `AUTENTICO_LISTEN_PORT`
- `cors_allowed_origins`
- `allowed_audiences`

**Feature claims:**
- Rate limiter on: `/oauth2/login`, `/oauth2/mfa`, `/oauth2/token`, `/oauth2/passkey/login/finish`
- Two-tier: per-second + per-minute, request must pass both
- Per source IP via `X-Forwarded-For`
- `AUTENTICO_RATE_LIMIT_RPS=0` to disable
- Admin API (`/admin/api/*`) requires bearer token with `admin` role AND `autentico-admin` in `aud` claim
- `autentico-admin` client tokens satisfy admin API requirement automatically
- Other clients need `"autentico-admin"` in `allowed_audiences`
- Headless admin tokens: `--enable-admin-password-grant` on `autentico onboard` or `AUTENTICO_ENABLE_ADMIN_PASSWORD_GRANT=true`
- Secrets rotation: rotating `AUTENTICO_COOKIE_SECRET` invalidates all SSO session cookies (**NOTE: should this be CSRF secret key?**); rotating RSA key invalidates all tokens
- Database file permissions: `chmod 600`
- RSA key is 2048-bit (**NOTE: key-generation page says `openssl genrsa 4096`**)

---

### `security/incident-response.mdx` — "Incident Response"

**Config keys:** `AUTENTICO_ADMIN_TOKEN` (**NOTE: does not exist**), `AUTENTICO_PRIVATE_KEY`, `AUTENTICO_JWK_CERT_KEY_ID`

**Feature claims:**
- Account compromise: revoke sessions, reset password, reset MFA, revoke passkeys, notify user
- Admin token compromise: rotate token, review admin API logs, check for new admin users, check for unexpected clients
- Private key compromise: generate new key (`openssl genrsa 4096 | base64 -w 0`), replace, restart; all existing tokens invalid; update `AUTENTICO_JWK_CERT_KEY_ID`
- Database breach: passwords bcrypt-hashed (safe), TOTP secrets exposed (re-enroll), session/refresh tokens compromised (revoke all, consider key rotation)
- **CONTRADICTION:** "Autentico does not have built-in rate limiting beyond account lockout" — but hardening page and bootstrap page document built-in per-IP rate limiting

---

## API Reference

### `api-reference/endpoints.mdx` — "API Endpoints"

**Feature claims:**
- Full interactive API reference at `https://api.autentico.top`
- Single short page pointing to external API docs

**External links:**
- `https://api.autentico.top` — interactive API reference

---

## Architecture

### `architecture/database-schema.mdx` — "Database Schema"

**Architecture claims — Tables documented:**

1. `users` — columns: `id` (TEXT PK), `username` (TEXT UNIQUE), `email` (TEXT UNIQUE), `password` (TEXT), `role` (TEXT), `totp_secret` (TEXT), `totp_verified` (BOOLEAN), `failed_login_attempts` (INTEGER), `locked_until` (DATETIME), `is_email_verified` (BOOLEAN), `deactivated_at` (DATETIME), `created_at` (DATETIME)
   - **NOTE: missing OIDC profile columns (given_name, family_name, etc.) documented in user-model page**

2. `clients` — columns: `id` (TEXT PK), `client_id` (TEXT UNIQUE), `client_secret` (TEXT), `client_name` (TEXT), `client_type` (TEXT), `redirect_uris` (TEXT JSON), `grant_types` (TEXT JSON), `response_types` (TEXT JSON), `scopes` (TEXT), `token_endpoint_auth_method` (TEXT), `is_active` (BOOLEAN), `access_token_expiration` (TEXT), `refresh_token_expiration` (TEXT), `authorization_code_expiration` (TEXT), `allowed_audiences` (TEXT JSON), `allow_self_signup` (INTEGER), `sso_session_idle_timeout` (TEXT), `trust_device_enabled` (INTEGER), `trust_device_expiration` (TEXT)
   - **NOTE: missing `consent_required` column documented in CLAUDE.md**
   - **NOTE: missing `post_logout_redirect_uris` column used in test-fixture.mdx**

3. `tokens` — columns: `id`, `user_id` (FK → users), `access_token`, `refresh_token`, `access_token_type` (`Bearer`), `access_token_expires_at`, `refresh_token_expires_at`, `scope`, `grant_type`, `revoked_at`

4. `idp_sessions` — columns: `id` (TEXT PK), `user_id` (FK → users), `user_agent`, `ip_address`, `last_activity_at`, `created_at`, `deactivated_at`
   - **NOTE: missing `expires_at` column that SSO sessions page lists**

5. `auth_codes` — columns: `code` (TEXT PK), `user_id` (FK), `client_id`, `redirect_uri`, `scope`, `nonce`, `code_challenge`, `code_challenge_method`, `expires_at`, `used`
   - **NOTE: missing `idp_session_id` column documented in CLAUDE.md**

6. `mfa_challenges` — columns: `id`, `user_id`, `method` (`totp`/`email`), `code`, `login_state` (JSON), `expires_at` (5 min), `used`

7. `trusted_devices` — columns: `id`, `user_id`, `device_name`, `last_used_at`, `expires_at`
   - **NOTE: missing `created_at` column documented in trusted-devices page**

8. `passkey_challenges` — columns: `id`, `user_id`, `challenge_data` (JSON), `type` (`authentication`/`registration`), `login_state` (JSON), `expires_at` (5 min), `used`

9. `passkey_credentials` — columns: `id`, `user_id`, `name`, `credential` (JSON), `last_used_at`

10. `settings` — columns: `key`, `value`, `updated_at`

**Missing tables (documented in CLAUDE.md but not in schema page):**
- `sessions` — OAuth sessions (separate from `idp_sessions`)
- `federation_providers` — external IdP configurations
- `federated_identities` — links between local users and external IdP accounts
- `deletion_requests` — user-initiated account deletion requests
- `password_reset_tokens` — time-limited tokens for password reset (migration 002)
- `audit_logs` — security event audit trail (migration 003)
- `groups` — user groups (migration 004)
- `user_groups` — group membership join table (migration 004)
- `user_consents` — stored OAuth2 consent decisions (migration 007)

**Feature claims:**
- Single SQLite database file
- All tables created on startup if they don't exist
- Schema migrations applied automatically via `ALTER TABLE ... ADD COLUMN` (idempotent)
- **NOTE: CLAUDE.md says migrations are the single source of truth; this page says "all tables created on startup if they don't exist" which may be outdated**

---

### `architecture/design-decisions.mdx` — "Design Decisions"

**Feature claims:**
- Central goal: operational simplicity
- SQLite via `modernc.org/sqlite` (pure Go, no CGo)
- Can't run multiple instances pointing at same SQLite file
- RS256 for token signing (asymmetric); 2048-bit RSA key
- Three-layer configuration rationale
- JWT generation with standard library + minimal JWT library; no third-party OAuth2 framework
- Background cleanup goroutine for expired records (no TTL in SQLite)
- React admin UI and Swagger docs embedded via `//go:embed`
- SQLite handles concurrent reads well, serializes writes safely
- Scales to tens of thousands of users and hundreds of authentications per second

**External links:**
- None (references internal packages/paths only)

---

### `architecture/package-structure.mdx` — "Package Structure"

**Architecture claims — Packages listed:**
- `pkg/admin/` — Dashboard stats handler; Admin UI embedded FS
- `pkg/appsettings/` — Settings DB CRUD + hot-reload
- `pkg/auth_code/` — Authorization code create/read/mark-used
- `pkg/authorize/` — `GET /oauth2/authorize`
- `pkg/cleanup/` — Background goroutine to purge expired records
- `pkg/client/` — OAuth2 client registration, auth, CRUD
- `pkg/config/` — Bootstrap (env) + Values (runtime) config structs
- `pkg/db/` — SQLite init, schema, migrations
- `pkg/introspect/` — `POST /oauth2/introspect`
- `pkg/jwtutil/` — JWT validation helpers
- `pkg/key/` — RSA key loading, JWK generation
- `pkg/login/` — `POST /oauth2/login`
- `pkg/mfa/` — MFA challenge create/validate (TOTP + email OTP)
- `pkg/middleware/` — CSRF, CORS, logging, admin auth middleware
- `pkg/model/` — Shared response types
- `pkg/onboarding/` — First-run admin account creation
- `pkg/passkey/` — WebAuthn registration and authentication
- `pkg/session/` — SSO session create/read/deactivate + admin API
- `pkg/signup/` — Self-signup handler
- `pkg/token/` — `POST /oauth2/token` — all grant types
- `pkg/trusteddevice/` — Trusted device create/read/validate
- `pkg/user/` — User CRUD, authentication, lockout
- `pkg/userinfo/` — `GET /oauth2/userinfo`
- `pkg/wellknown/` — `GET /.well-known/openid-configuration`, `GET /oauth2/.well-known/jwks.json`

**Missing packages (in CLAUDE.md but not in this page):**
- `pkg/account` — Account UI API
- `pkg/api` — API utilities shared across admin and account APIs
- `pkg/audit` — Audit log recording
- `pkg/authzsig` — HMAC signatures for authorize-to-login integrity
- `pkg/bearer` — Bearer token extraction utilities
- `pkg/cli` — CLI subcommand implementations
- `pkg/consent` — OAuth2 consent screen
- `pkg/deletion` — Account deletion requests
- `pkg/email` — Email sending (SMTP)
- `pkg/emailverification` — Email verification flow
- `pkg/federation` — Federated/social login providers
- `pkg/group` — User groups
- `pkg/idpsession` — IdP-level SSO sessions
- `pkg/passwordreset` — Password reset flow
- `pkg/ratelimit` — Per-IP rate limiting
- `pkg/reqid` — Request ID generation
- `pkg/revoke` — Token revocation
- `pkg/utils` — Shared helpers

**Feature claims:**
- Feature-based package structure
- Consistent file layout: `model.go`, `handler.go`, `create.go`, `read.go`, `update.go`, `delete.go`, `service.go`
- Config package: `config.Bootstrap`, `config.Values`, `config.Get()`, `config.GetBootstrap()`, `config.GetForClient(overrides)`
- Entry point: `pkg/cli/start.go` → `RunStart()` initializes DB, loads settings, registers routes, starts cleanup, starts HTTP server

**Other paths mentioned:**
- `view/` — server-side HTML templates
- `admin-ui/` — React SPA source
- `docs/` — Swagger-generated API documentation
- `docs-web/` — Starlight documentation site

---

### `architecture/performance.mdx` — "Performance & Capacity"

**Endpoints mentioned (in test sequence):**
- `GET /oauth2/authorize`
- `POST /oauth2/login`
- `POST /oauth2/token`
- `POST /oauth2/introspect`

**Feature claims:**
- Full PKCE auth code flow measured end to end
- bcrypt password verification: ~60ms on modern hardware
- 20 VUs: 0% errors, login p95 86ms, token p95 54ms, introspect p95 17ms
- 100 VUs: 0% errors, login p95 611ms, token p95 647ms, introspect p95 271ms
- 500 VUs: 0% errors, login p95 3.36s, token p95 3.89s, introspect p95 1.60s
- Bottlenecks: bcrypt (intentionally slow) and SQLite single-writer lock
- Failure mode: graceful degradation (latency climbs, zero errors)
- No `SQLITE_BUSY` errors at any concurrency up to 500
- Daily user estimates: ~10k (sub-100ms), ~20k (under 500ms), ~50k (1-2s at peak), >50k (3s+)
- Recommended ceiling: 100 concurrent logins (~10k-20k daily active users)
- SSO sessions mean most return users skip login entirely
- Options for scaling: reduce bcrypt cost factor, enable WAL mode, sticky-session LB, replace persistence layer

**Code examples:**
- `make stress-server`, `make stress-smoke`, `make stress-load`, `make stress-spike`, `make stress-ceiling`

**External links:**
- `https://github.com/eugenioenko/autentico/tree/main/stress` (k6 scripts)
- `https://github.com/eugenioenko/autentico/blob/main/stress/README.md`

---

## Summary of Potential Discrepancies Found

### Config key naming inconsistencies across docs pages

| Used in some pages | Used in other pages | Correct (per runtime-settings.mdx) |
|---|---|---|
| `mfa_enabled` | `require_mfa` | `require_mfa` |
| `lockout_max_attempts` | `account_lockout_max_attempts` | `account_lockout_max_attempts` |
| `lockout_duration` | `account_lockout_duration` | `account_lockout_duration` |
| `AUTENTICO_AUTH_JWK_CERT_KEY_ID` | `AUTENTICO_JWK_CERT_KEY_ID` | `AUTENTICO_JWK_CERT_KEY_ID` |

### Config keys referenced but may not exist

- `AUTENTICO_COOKIE_SECRET` — referenced in production-checklist and security/overview; not in bootstrap settings
- `AUTENTICO_ADMIN_TOKEN` — referenced in production-checklist, security/overview, incident-response; not in bootstrap settings. Admin API uses bearer tokens from OAuth2, not a static token.

### Default value discrepancies

- `kid` default: `autentico-key` (oidc-discovery.mdx) vs `autentico-key-1` (bootstrap.mdx, token-structure.mdx)

### Contradictions

- `security/incident-response.mdx` says "Autentico does not have built-in rate limiting beyond account lockout" but `security/overview.mdx`, `configuration/bootstrap.mdx`, and other pages document built-in per-IP rate limiting

### Key generation size

- `architecture/design-decisions.mdx` says "2048-bit" RSA key
- `deployment/key-generation.mdx` manual generation example uses `openssl genrsa 4096`
- `configuration/bootstrap.mdx` says "RSA 2048 private key"

### Incomplete schema documentation

- `architecture/database-schema.mdx` documents 10 tables; CLAUDE.md lists 20 tables (SchemaVersion 7). Missing: `sessions`, `federation_providers`, `federated_identities`, `deletion_requests`, `password_reset_tokens`, `audit_logs`, `groups`, `user_groups`, `user_consents`
- Schema page claims "All tables created on startup if they don't exist" which may be outdated (migrations are now the source of truth per CLAUDE.md)

### Incomplete package documentation

- `architecture/package-structure.mdx` lists ~23 packages; CLAUDE.md lists ~37 packages. Missing from docs: `account`, `api`, `audit`, `authzsig`, `bearer`, `cli`, `consent`, `deletion`, `email`, `emailverification`, `federation`, `group`, `idpsession`, `passwordreset`, `ratelimit`, `reqid`, `revoke`, `utils`

### SSO sessions page

- Describes session fields as if from `sessions` table but the SSO session table is `idp_sessions`; OAuth sessions are in a separate `sessions` table

### Health check endpoint

- Docker page uses `/healthz` in HEALTHCHECK directive
- Production checklist recommends `GET /.well-known/openid-configuration` as health check
- There may be a dedicated `/healthz` or `/health` endpoint (CLAUDE.md lists `pkg/health` for `/health`)

### Docker init `--output` flag

- `deployment/key-generation.mdx` shows `autentico init --url ... --output /output` flag — may not exist

### Missing `AUTENTICO_LISTEN_PORT` in bootstrap reference

- Referenced in Docker page and security/overview but not listed as its own row in `configuration/bootstrap.mdx` table (only appears as derived value note)

### `consent_required` feature

- Documented in CLAUDE.md (per-client field, consent screen, `user_consents` table) but not mentioned in any docs-web page

### Federation / social login

- Documented in CLAUDE.md (`pkg/federation`, `federation_providers`, `federated_identities`) but not mentioned in docs-web

### Account deletion

- `allow_self_service_deletion` runtime setting documented but no page explaining the deletion feature/flow
- `deletion_requests` table not in schema docs

### Email verification / password reset

- Runtime settings `require_email_verification`, `email_verification_expiration`, `password_reset_expiration` documented
- `pkg/emailverification` and `pkg/passwordreset` packages exist per CLAUDE.md
- View templates `verify_email.html`, `forgot_password.html`, `reset_password.html` listed in CLAUDE.md
- No dedicated docs page for these flows

### Audit logging

- `audit_log_retention` runtime setting documented
- `audit_logs` table exists (per CLAUDE.md)
- No dedicated docs page for audit logging

### Groups

- `pkg/group` and tables `groups`/`user_groups` exist (per CLAUDE.md)
- No docs page for groups feature
