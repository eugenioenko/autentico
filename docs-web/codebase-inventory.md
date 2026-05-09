# Autentico Codebase Ground Truth Audit

Generated from source code on 2026-05-09. Version: v1.6.2. Schema version: 7.

---

## 1. All HTTP Endpoints

Source: `pkg/cli/start.go` route registrations.

### 1.1 Infrastructure

| Method | Path | Handler Package | Rate Limited | Auth |
|--------|------|----------------|-------------|------|
| GET | `/healthz` | `health` | No | None |
| GET | `/swagger/` | `httpSwagger` | No | None |
| GET | `/api-docs/` | `admin` | No | None |
| GET | `/api-docs` | `admin` | No | None |

### 1.2 OIDC Discovery (Public, No Auth)

| Method | Path | Handler Package | Rate Limited | Auth |
|--------|------|----------------|-------------|------|
| GET | `/.well-known/openid-configuration` | `wellknown` | No | None |
| GET | `{oauth}/.well-known/openid-configuration` | `wellknown` | No | None |
| GET | `{oauth}/.well-known/jwks.json` | `wellknown` | No | None |

Note: `{oauth}` defaults to `/oauth2` (configurable via `AUTENTICO_APP_OAUTH_PATH`).

### 1.3 OAuth2 / OIDC Protocol Endpoints

| Method | Path | Handler Package | Rate Limited | Auth |
|--------|------|----------------|-------------|------|
| GET | `{oauth}/authorize` | `authorize` | No | CSRF |
| POST | `{oauth}/authorize` | `authorize` | No | None (form POST) |
| POST | `{oauth}/login` | `login` | Yes | CSRF |
| GET, POST | `{oauth}/consent` | `consent` | No | CSRF |
| GET, POST | `{oauth}/mfa` | `mfa` | Yes | CSRF |
| GET, POST | `{oauth}/mfa/` | `mfa` | Yes | CSRF |
| GET | `{oauth}/passkey/login/begin` | `passkey` | Yes | None |
| POST | `{oauth}/passkey/login/finish` | `passkey` | Yes | None |
| GET | `{oauth}/passkey/register/begin` | `passkey` | No | None |
| POST | `{oauth}/passkey/register/finish` | `passkey` | No | None |
| GET | `{oauth}/verify-email` | `emailverification` | No | CSRF |
| POST | `{oauth}/resend-verification` | `emailverification` | No | CSRF |
| GET, POST | `{oauth}/forgot-password` | `passwordreset` | Yes | CSRF |
| GET, POST | `{oauth}/reset-password` | `passwordreset` | Yes | CSRF |
| GET | `{oauth}/federation/{id}` | `federation` | No | None |
| GET | `{oauth}/federation/{id}/callback` | `federation` | No | None |
| GET, POST | `{oauth}/signup` | `signup` | No | CSRF |
| GET, POST | `{oauth}/signup/` | `signup` | No | CSRF |
| POST | `{oauth}/token` | `token` | Yes | Client auth (Basic/form) |
| POST | `{oauth}/protocol/openid-connect/token` | `token` | Yes | Client auth (Basic/form) |
| POST | `{oauth}/revoke` | `revoke` | No | Client auth (Basic/form) |
| POST | `{oauth}/introspect` | `introspect` | No | Client auth (Basic/bearer) |
| GET, POST | `{oauth}/userinfo` | `userinfo` | No | Bearer token |
| GET, POST | `{oauth}/protocol/openid-connect/userinfo` | `userinfo` | No | Bearer token |
| POST | `{oauth}/logout` | `session` | No | None (form/id_token_hint) |
| GET | `{oauth}/logout` | `session` | No | None (query/id_token_hint) |
| POST | `{oauth}/register` | `client` | No | Admin bearer |
| GET | `{oauth}/register/{client_id}` | `client` | No | Admin bearer |
| PUT | `{oauth}/register/{client_id}` | `client` | No | Admin bearer |
| DELETE | `{oauth}/register/{client_id}` | `client` | No | Admin bearer |

### 1.4 Admin API Endpoints (Admin Bearer Auth Required)

#### Users

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/users` | `user.HandleListUsers` |
| POST | `/admin/api/users` | `user.HandleCreateUser` |
| GET | `/admin/api/users/{id}` | `user.HandleGetUser` |
| PUT | `/admin/api/users/{id}` | `user.HandleUpdateUser` |
| DELETE | `/admin/api/users/{id}` | `user.HandleDeleteUser` |
| POST | `/admin/api/users/{id}/deactivate` | `user.HandleDeactivateUser` |
| POST | `/admin/api/users/{id}/reactivate` | `user.HandleReactivateUser` |
| POST | `/admin/api/users/{id}/unlock` | `user.HandleUnlockUser` |
| POST | `/admin/api/users/{id}/revoke-sessions` | `user.HandleRevokeUserSessions` |

#### Clients

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/clients` | `client.HandleAdminListClients` |
| POST | `/admin/api/clients` | `client.HandleRegister` |
| GET | `/admin/api/clients/{client_id}` | `client.HandleGetClient` |
| PUT | `/admin/api/clients/{client_id}` | `client.HandleUpdateClient` |
| DELETE | `/admin/api/clients/{client_id}` | `client.HandleDeleteClient` |

#### Sessions

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/sessions` | `session.HandleListSessions` |
| DELETE | `/admin/api/sessions/{id}` | `session.HandleDeactivateSession` |

#### IdP Sessions

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/idp-sessions` | `idpsession.HandleListIdpSessions` |
| GET | `/admin/api/users/{id}/idp-sessions` | `idpsession.HandleListUserIdpSessions` |
| GET | `/admin/api/idp-sessions/{id}/sessions` | `session.HandleListIdpSessionSessions` |
| DELETE | `/admin/api/idp-sessions/{id}` | `idpsession.HandleForceLogoutIdpSession` |

#### Federation Providers

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/federation` | `federation.HandleListProviders` |
| POST | `/admin/api/federation` | `federation.HandleCreateProvider` |
| GET | `/admin/api/federation/{id}` | `federation.HandleGetProvider` |
| PUT | `/admin/api/federation/{id}` | `federation.HandleUpdateProvider` |
| DELETE | `/admin/api/federation/{id}` | `federation.HandleDeleteProvider` |

#### Groups

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/groups` | `group.HandleListGroups` |
| POST | `/admin/api/groups` | `group.HandleCreateGroup` |
| GET | `/admin/api/groups/{id}` | `group.HandleGetGroup` |
| PUT | `/admin/api/groups/{id}` | `group.HandleUpdateGroup` |
| DELETE | `/admin/api/groups/{id}` | `group.HandleDeleteGroup` |
| GET | `/admin/api/groups/{id}/members` | `group.HandleListMembers` |
| POST | `/admin/api/groups/{id}/members` | `group.HandleAddMember` |
| DELETE | `/admin/api/groups/{id}/members/{user_id}` | `group.HandleRemoveMember` |
| GET | `/admin/api/users/{id}/groups` | `group.HandleGetUserGroups` |

#### Tokens

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/tokens` | `token.HandleListTokens` |
| DELETE | `/admin/api/tokens/{id}` | `token.HandleRevokeToken` |

#### Settings

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/stats` | `admin.HandleStats` |
| GET | `/admin/api/settings` | `appsettings.HandleGetSettings` |
| PUT | `/admin/api/settings` | `appsettings.HandlePutSettings` |
| POST | `/admin/api/settings/test-smtp` | `appsettings.HandleTestSmtp` |
| GET | `/admin/api/settings/export` | `appsettings.HandleExportSettings` |
| POST | `/admin/api/settings/import/preview` | `appsettings.HandleImportPreview` |
| POST | `/admin/api/settings/import/apply` | `appsettings.HandleImportApply` |

#### Audit Logs

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/audit-logs` | `audit.HandleListAuditLogs` |

#### Deletion Requests

| Method | Path | Handler |
|--------|------|---------|
| GET | `/admin/api/deletion-requests` | `deletion.HandleListDeletionRequests` |
| POST | `/admin/api/deletion-requests/{id}/approve` | `deletion.HandleApproveDeletionRequest` |
| DELETE | `/admin/api/deletion-requests/{id}` | `deletion.HandleAdminCancelDeletionRequest` |

### 1.5 Account Self-Service API (Account Bearer Auth Required)

Auth middleware: `AccountAuthMiddleware` (accepts audience `autentico-account` or `autentico-admin`).

| Method | Path | Handler | Rate Limited |
|--------|------|---------|-------------|
| GET | `/account/api/profile` | `account.HandleGetProfile` | No |
| PUT | `/account/api/profile` | `account.HandleUpdateProfile` | No |
| POST | `/account/api/password` | `account.HandleUpdatePassword` | Yes |
| GET | `/account/api/sessions` | `account.HandleListSessions` | No |
| DELETE | `/account/api/sessions/{id}` | `account.HandleRevokeSession` | No |
| POST | `/account/api/sessions/revoke-others` | `account.HandleRevokeOtherSessions` | No |
| GET | `/account/api/passkeys` | `account.HandleListPasskeys` | No |
| DELETE | `/account/api/passkeys/{id}` | `account.HandleDeletePasskey` | No |
| PATCH | `/account/api/passkeys/{id}` | `account.HandleRenamePasskey` | No |
| POST | `/account/api/passkeys/register/begin` | `account.HandleAddPasskeyBegin` | No |
| POST | `/account/api/passkeys/register/finish` | `account.HandleAddPasskeyFinish` | No |
| GET | `/account/api/mfa` | `account.HandleGetMfaStatus` | No |
| POST | `/account/api/mfa/totp/setup` | `account.HandleSetupTotp` | No |
| POST | `/account/api/mfa/totp/verify` | `account.HandleVerifyTotp` | No |
| DELETE | `/account/api/mfa/totp` | `account.HandleDeleteMfa` | Yes |
| GET | `/account/api/trusted-devices` | `account.HandleListTrustedDevices` | No |
| DELETE | `/account/api/trusted-devices/{id}` | `account.HandleRevokeTrustedDevice` | No |
| GET | `/account/api/connected-providers` | `account.HandleListConnectedProviders` | No |
| DELETE | `/account/api/connected-providers/{id}` | `account.HandleDisconnectProvider` | No |
| GET | `/account/api/settings` | `account.HandleGetSettings` | No (public) |
| GET | `/account/api/deletion-request` | `deletion.HandleGetDeletionRequest` | No |
| POST | `/account/api/deletion-request` | `deletion.HandleRequestDeletion` | No |
| DELETE | `/account/api/deletion-request` | `deletion.HandleCancelDeletionRequest` | No |

### 1.6 Embedded UIs & Static Assets

| Method | Path | Handler |
|--------|------|---------|
| * | `/admin/` | `admin.Handler()` (embedded React SPA) |
| * | `/account/` | `account.Handler()` (embedded React SPA) |
| GET | `{oauth}/static/theme.css` | `view.ThemeCSSHandler()` |
| GET | `{oauth}/federation/{id}/icon.svg` | `federation.HandleFederationIcon` |
| * | `{oauth}/static/` | `view.StaticHandler()` (static file server) |

### 1.7 Onboarding & Root

| Method | Path | Handler |
|--------|------|---------|
| GET, POST | `/onboard` | `onboarding.HandleOnboardDirect` (CSRF) |
| GET, POST | `/onboard/` | `onboarding.HandleOnboardDirect` (CSRF) |
| GET | `/` | Root redirect to `/account/` |

### 1.8 Global Middleware (Applied to All Routes)

Applied in order via `CombineMiddlewares`:
1. `reqid.Middleware` -- Request ID generation
2. `middleware.SecurityHeadersMiddleware` -- Security headers
3. `middleware.LoggingMiddleware` -- Access logging
4. `middleware.CORSMiddleware` -- CORS handling

---

## 2. All Configuration Keys

### 2.1 Bootstrap Configuration (Environment Variables)

Source: `pkg/config/config.go` `InitBootstrap()` function.

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `AUTENTICO_DB_FILE_PATH` | `./autentico.db` | Path to SQLite database file |
| `AUTENTICO_APP_URL` | `http://localhost:9999` | Public base URL (derives issuer, domain, port) |
| `AUTENTICO_APP_OAUTH_PATH` | `/oauth2` | URL path prefix for OAuth2/OIDC endpoints |
| `AUTENTICO_LISTEN_PORT` | (derived from APP_URL port) | Override listen port for reverse proxy setups |
| `AUTENTICO_ACCESS_TOKEN_SECRET` | `""` (required) | HMAC secret for access token signing |
| `AUTENTICO_REFRESH_TOKEN_SECRET` | `""` (required) | HMAC secret for refresh token signing |
| `AUTENTICO_CSRF_SECRET_KEY` | `""` (required) | CSRF protection secret |
| `AUTENTICO_CSRF_SECURE_COOKIE` | `true` | Require HTTPS for CSRF cookie |
| `AUTENTICO_PRIVATE_KEY` | `""` | Base64-encoded RSA private key PEM for JWT signing (RS256). Ephemeral if unset. |
| `AUTENTICO_JWK_CERT_KEY_ID` | `autentico-key-1` | Key ID in JWK Set |
| `AUTENTICO_REFRESH_TOKEN_COOKIE_NAME` | `autentico_refresh_token` | Name of the refresh token cookie |
| `AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY` | `false` | When true, refresh token is sent as HttpOnly cookie only (stripped from JSON response) |
| `AUTENTICO_IDP_SESSION_COOKIE_NAME` | `autentico_idp_session` | Name of the IdP SSO session cookie |
| `AUTENTICO_IDP_SESSION_SECURE` | `true` | Require HTTPS for IdP session cookie |
| `AUTENTICO_RATE_LIMIT_RPS` | `5` | Per-IP sustained requests per second (0 disables) |
| `AUTENTICO_RATE_LIMIT_BURST` | `10` | Maximum burst above RPS limit |
| `AUTENTICO_RATE_LIMIT_RPM` | `20` | Per-IP sustained requests per minute (0 disables) |
| `AUTENTICO_RATE_LIMIT_RPM_BURST` | `20` | Maximum burst above RPM limit |
| `AUTENTICO_ANTI_TIMING_MIN_MS` | `50` | Minimum anti-timing delay (ms) for auth responses |
| `AUTENTICO_ANTI_TIMING_MAX_MS` | `150` | Maximum anti-timing delay (ms) for auth responses |
| `AUTENTICO_DB_READ_POOL_SIZE` | `0` (auto: min(CPUs, 4)) | Number of SQLite read connections |

**Derived fields (not from env vars):**
- `AppDomain` -- hostname from `APP_URL`
- `AppHost` -- host:port from `APP_URL`
- `AppPort` -- port from `APP_URL`
- `AppAuthIssuer` -- `APP_URL` + `APP_OAUTH_PATH`
- `AppListenPort` -- defaults to `AppPort`, overridden by `AUTENTICO_LISTEN_PORT`

### 2.2 Runtime Configuration (Settings Table, Hot-Reloadable)

Source: `pkg/appsettings/load.go` `defaults` map and `LoadIntoConfig()` function.

#### Token Expiration

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `access_token_expiration` | `15m` | Duration | Access token lifetime |
| `refresh_token_expiration` | `720h` | Duration | Refresh token lifetime (30 days) |
| `authorization_code_expiration` | `10m` | Duration | Authorization code lifetime |
| `access_token_audience` | `[]` | JSON array | Default audiences for access tokens |

#### Authentication

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `auth_mode` | `password` | String | Authentication mode (password, passkey, both) |
| `allow_self_signup` | `false` | Bool | Allow users to self-register |
| `signup_show_optional_fields` | `false` | Bool | Show optional profile fields on signup form |
| `pkce_enforce_s256` | `true` | Bool | Enforce S256 PKCE method |

#### SSO Sessions

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `sso_enabled` | `true` | Bool | Enable SSO sessions |
| `sso_session_idle_timeout` | `4h` | Duration | IdP session idle timeout |
| `sso_session_max_age` | `720h` | Duration | Maximum age of IdP session (30 days) |

#### MFA

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `require_mfa` | `false` | Bool | Require MFA for all users |
| `mfa_method` | `totp` | String | MFA method (totp, email, both) |

#### Account Security

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `account_lockout_max_attempts` | `5` | Int | Failed login attempts before lockout |
| `account_lockout_duration` | `15m` | Duration | Account lockout duration |
| `passkey_rp_name` | `Autentico` | String | WebAuthn Relying Party display name |

#### Trusted Devices

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `trust_device_enabled` | `false` | Bool | Enable trusted device MFA bypass |
| `trust_device_expiration` | `720h` | Duration | Trusted device cookie lifetime (30 days) |

#### Email / SMTP

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `smtp_host` | `""` | String | SMTP server hostname |
| `smtp_port` | `587` | String | SMTP server port |
| `smtp_username` | `""` | String | SMTP authentication username |
| `smtp_password` | `""` | String | SMTP authentication password (sensitive, hidden from GET) |
| `smtp_from` | `""` | String | Sender email address |
| `require_email_verification` | `false` | Bool | Require email verification before login |
| `email_verification_expiration` | `24h` | Duration | Email verification token lifetime |
| `password_reset_expiration` | `1h` | Duration | Password reset token lifetime |

#### Validation Rules

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `validation_min_username_length` | `4` | Int | Minimum username length |
| `validation_max_username_length` | `64` | Int | Maximum username length |
| `validation_min_password_length` | `6` | Int | Minimum password length |
| `validation_max_password_length` | `64` | Int | Maximum password length |

#### Theme / Branding

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `theme_title` | `Autentico` | String | Application title (shown in UI) |
| `theme_logo_url` | `""` | String | Logo URL |
| `theme_css_inline` | `""` | String | Inline CSS for theme customization |
| `theme_css_file` | `""` | String | Path to external CSS file |
| `theme_brand_color` | `#ff7b00` | String | Brand color |
| `theme_tagline` | `""` | String | Tagline shown on login page |
| `email_footer_text` | `""` | String | Footer text in emails |
| `footer_links` | `[]` | JSON array | Footer links on login/signup pages (label+URL pairs) |

#### Profile Field Visibility

Values: `hidden`, `optional`, `required`. Email also accepts `is_username`.

| Setting Key | Default | Description |
|------------|---------|-------------|
| `profile_field_email` | `optional` | Email field visibility |
| `profile_field_given_name` | `optional` | Given name field visibility |
| `profile_field_family_name` | `optional` | Family name field visibility |
| `profile_field_middle_name` | `hidden` | Middle name field visibility |
| `profile_field_nickname` | `hidden` | Nickname field visibility |
| `profile_field_phone` | `optional` | Phone number field visibility |
| `profile_field_picture` | `optional` | Picture URL field visibility |
| `profile_field_website` | `hidden` | Website field visibility |
| `profile_field_gender` | `hidden` | Gender field visibility |
| `profile_field_birthdate` | `hidden` | Birthdate field visibility |
| `profile_field_profile` | `hidden` | Profile URL field visibility |
| `profile_field_locale` | `hidden` | Locale field visibility |
| `profile_field_address` | `optional` | Address field visibility |

#### Account Management

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `allow_self_service_deletion` | `false` | Bool | Users can delete their own account immediately (no admin approval) |
| `allow_username_change` | `false` | Bool | Users can change their own username |
| `allow_email_change` | `false` | Bool | Users can change their own email |

#### Maintenance

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `cleanup_interval` | `6h` | Duration | Background cleanup job interval |
| `cleanup_retention` | `24h` | Duration | Retention period for expired records |
| `audit_log_retention` | `720h` | Duration | Audit log retention (0 or -1 = keep forever) |

#### CORS

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `cors_allowed_origins` | `""` | Comma-separated | Allowed CORS origins (`*` for all) |

#### Internal

| Setting Key | Default | Type | Description |
|------------|---------|------|-------------|
| `onboarded` | `false` | Bool | Whether initial onboarding is complete (protected, cannot be set via API) |

### 2.3 Per-Client Configuration Overrides

Source: `pkg/client/model.go` Client struct and `pkg/config/config.go` `ClientOverrides`.

Each field is nullable -- `nil` means "use global setting".

| Client Field | JSON Key | Type | Overrides |
|-------------|----------|------|-----------|
| `access_token_expiration` | `access_token_expiration` | `*string` (duration) | `access_token_expiration` |
| `refresh_token_expiration` | `refresh_token_expiration` | `*string` (duration) | `refresh_token_expiration` |
| `authorization_code_expiration` | `authorization_code_expiration` | `*string` (duration) | `authorization_code_expiration` |
| `allowed_audiences` | `allowed_audiences` | `[]string` (JSON) | Appended to global `access_token_audience` |
| `allow_self_signup` | `allow_self_signup` | `*bool` | `allow_self_signup` |
| `sso_session_idle_timeout` | `sso_session_idle_timeout` | `*string` (duration) | `sso_session_idle_timeout` |
| `trust_device_enabled` | `trust_device_enabled` | `*bool` | `trust_device_enabled` |
| `trust_device_expiration` | `trust_device_expiration` | `*string` (duration) | `trust_device_expiration` |
| `consent_required` | `consent_required` | `*bool` | Per-client only (no global equivalent) |

---

## 3. CLI Commands & Flags

Source: `main.go` CLI definition.

### `autentico init`

Generate a `.env` configuration file with secure defaults.

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--url` | String | `http://localhost:9999` | No | Application URL |
| `--dev` | Bool | `false` | No | Disable secure cookie flags for local HTTP development |
| `--output` | String | `.` | No | Directory to write the .env file into |

### `autentico start`

Start the HTTP server.

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--no-auto-migrate` | Bool | `false` | No | Do not automatically apply pending database migrations on startup |
| `--auto-setup` | Bool | `false` | No | Generate a .env file with secure defaults if one does not exist |
| `--url` | String | `""` | No | Application URL for --auto-setup |
| `--dev` | Bool | `false` | No | With --auto-setup, disable secure cookie flags for local HTTP development |

### `autentico migrate`

Apply pending database schema migrations. Interactive -- prompts user to type target version number to confirm.

No flags.

### `autentico onboard`

Create the first admin account (headless alternative to `/onboard`).

| Flag | Type | Default | Required | Env Var | Description |
|------|------|---------|----------|---------|-------------|
| `--username` | String | - | Yes | `AUTENTICO_ADMIN_USERNAME` | Admin username |
| `--password` | String | - | Yes | `AUTENTICO_ADMIN_PASSWORD` | Admin password |
| `--email` | String | `""` | No | `AUTENTICO_ADMIN_EMAIL` | Admin email address |
| `--enable-admin-password-grant` | Bool | `false` | No | `AUTENTICO_ENABLE_ADMIN_PASSWORD_GRANT` | Add ROPC grant to autentico-admin client for headless token acquisition |

### `autentico version`

Print the version and exit. No flags.

---

## 4. Features

### 4.1 Authentication Modes

Source: `pkg/config/config.go` `AuthMode` field, `pkg/authorize/handler.go`.

- **password** -- Username/password login (default)
- **passkey** -- WebAuthn/passkey login only
- **both** -- Password + passkey options available

### 4.2 MFA (Multi-Factor Authentication)

Source: `pkg/mfa/`, `pkg/account/mfa.go`.

- **TOTP** -- Time-based One-Time Password (RFC 6238). Enrollment via account API (setup + verify). Secret stored on user record.
- **Email OTP** -- One-time code sent via SMTP. Requires SMTP configuration.
- **MFA Method options** (`mfa_method`): `totp`, `email`, `both`. When `both` and user has TOTP enrolled, TOTP is preferred with option to switch to email.
- **Force MFA** (`require_mfa`): when enabled, all users must complete MFA. If user has not enrolled TOTP, they are redirected to enrollment.
- **MFA on ROPC**: when `require_mfa` or user has TOTP enrolled, the `totp_code` field is required on password grant.
- **MFA Disable**: requires current password + valid TOTP code.

### 4.3 WebAuthn / Passkeys

Source: `pkg/passkey/`, `pkg/account/passkey.go`.

- Registration ceremony (begin/finish)
- Authentication ceremony (begin/finish)
- Account-level passkey management: list, add, rename, delete
- Uses `go-webauthn/webauthn` v0.15.0

### 4.4 SSO Sessions (IdP Sessions)

Source: `pkg/idpsession/`.

- One IdP session per browser/device
- Idle timeout enforcement (`sso_session_idle_timeout`)
- Maximum age (`sso_session_max_age`)
- Cascade revocation: `DeactivateWithCascade` revokes IdP session + all child OAuth sessions + their tokens
- Cookie-based (`autentico_idp_session`)

### 4.5 Trusted Devices

Source: `pkg/trusteddevice/`, `pkg/account/trusted_devices.go`.

- MFA bypass for trusted devices
- Cookie-based trust token
- Configurable expiration (`trust_device_expiration`)
- Account-level management: list, revoke

### 4.6 OAuth2 Consent Screen

Source: `pkg/consent/`.

- Per-client `consent_required` flag
- Scope display on consent page
- Consent persistence (`user_consents` table): remembered per user+client+scopes
- Subsequent logins skip consent unless scopes change

### 4.7 Federation / Social Login

Source: `pkg/federation/`.

- External OIDC identity provider integration
- Provider management via admin API (CRUD)
- SVG icon support per provider
- Sort order control
- Enable/disable per provider
- User account linking (`federated_identities` table)
- Account-level connected provider management: list, disconnect

### 4.8 Email Verification

Source: `pkg/emailverification/`.

- Verification link sent via SMTP
- Token with configurable expiration (`email_verification_expiration`)
- Resend verification support
- Optional requirement (`require_email_verification`)

### 4.9 Password Reset

Source: `pkg/passwordreset/`.

- Forgot password flow (email link)
- Reset token with configurable expiration (`password_reset_expiration`)
- Stored in `password_reset_tokens` table with hashed tokens

### 4.10 Self-Service Signup

Source: `pkg/signup/`.

- Configurable via `allow_self_signup` (global and per-client override)
- Optional profile fields toggle (`signup_show_optional_fields`)
- Profile field visibility controls which fields appear

### 4.11 Account Deletion

Source: `pkg/deletion/`.

- User-initiated deletion request with optional reason
- Two modes:
  - **Admin-reviewed**: request is queued, admin approves/cancels
  - **Self-service**: when `allow_self_service_deletion` is true, account is deleted immediately
- Admin API: list, approve, cancel deletion requests
- Hard delete implementation (`HardDeleteUser`)

### 4.12 Groups

Source: `pkg/group/`.

- Group CRUD (name, description)
- Membership management (add/remove users)
- User group listing
- Groups included in token claims and userinfo (`groups` scope)

### 4.13 Audit Logging

Source: `pkg/audit/`.

31 distinct audit event types:

| Event | Description |
|-------|-------------|
| `login_success` | Successful login |
| `login_failed` | Failed login |
| `mfa_success` | MFA verification succeeded |
| `mfa_failed` | MFA verification failed |
| `passkey_login_success` | Passkey login succeeded |
| `passkey_login_failed` | Passkey login failed |
| `password_changed` | Password changed |
| `password_reset_requested` | Password reset requested |
| `password_reset_completed` | Password reset completed |
| `user_created` | User account created |
| `user_updated` | User account updated |
| `user_deactivated` | User deactivated |
| `user_reactivated` | User reactivated |
| `user_deleted` | User deleted |
| `user_unlocked` | User unlocked |
| `mfa_enrolled` | MFA enrolled |
| `mfa_disabled` | MFA disabled |
| `passkey_added` | Passkey added |
| `passkey_removed` | Passkey removed |
| `logout` | User logged out |
| `session_revoked` | Session revoked |
| `client_created` | Client created |
| `client_updated` | Client updated |
| `client_deleted` | Client deleted |
| `settings_updated` | Settings updated |
| `settings_imported` | Settings imported |
| `federation_created` | Federation provider created |
| `federation_updated` | Federation provider updated |
| `federation_deleted` | Federation provider deleted |
| `all_user_sessions_revoked` | All user sessions revoked |
| `other_sessions_revoked` | Other sessions revoked (self-service) |
| `token_revoked` | Token revoked |
| `deletion_approved` | Deletion request approved |

Audit target types: `user`, `client`, `session`, `token`, `settings`, `federation`.

### 4.14 Rate Limiting

Source: `pkg/ratelimit/`, `pkg/middleware/rate_limit.go`.

- Per-IP token bucket rate limiting
- Two tiers: per-second (RPS/burst) and per-minute (RPM/burst)
- Applied to auth endpoints: login, MFA, passkey login, forgot/reset password, token, password change, TOTP disable
- Configurable via env vars (RPS=0 disables)

### 4.15 Anti-Timing Delay

Source: `pkg/config/config.go` `AntiTimingMinMs`/`AntiTimingMaxMs`.

- Random delay added to authentication responses to prevent user enumeration
- Configurable range (default 50-150ms)
- Both set to 0 disables

### 4.16 Token Management

- Access tokens: RS256-signed JWTs
- Refresh tokens: HMAC-signed JWTs
- ID tokens: RS256-signed JWTs (only with `openid` scope)
- Refresh token rotation (revoke old, issue new per RFC 6819 / OAuth 2.1)
- Replay detection on revoked refresh tokens
- Cookie-only refresh token mode (`AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY`)

### 4.17 Dynamic Client Registration

Source: `pkg/client/handler.go`.

- RFC 7591-compliant client registration at `{oauth}/register`
- Admin-authenticated
- Supported client types: `confidential`, `public`
- Supported auth methods: `client_secret_basic`, `client_secret_post`, `none`
- Supported grant types: `authorization_code`, `refresh_token`, `client_credentials`, `password`
- Supported response types: `code`, `token`, `id_token`

### 4.18 Settings Import/Export

Source: `pkg/appsettings/handler.go`.

- Export all settings as JSON (sensitive values excluded)
- Import preview: diff current vs incoming
- Import apply: apply incoming settings (skips unknown keys and protected fields)

### 4.19 SMTP Test

Source: `pkg/appsettings/handler.go`.

- Send test email to admin's registered email

### 4.20 Background Cleanup

Source: `pkg/cleanup/`.

- Periodic cleanup of expired tokens, sessions, MFA challenges, etc.
- Configurable interval and retention period
- Also cleans up rate limiter entries (10-minute stale threshold)

### 4.21 Onboarding

Source: `pkg/onboarding/`.

- First-run wizard (`/onboard`) when no users exist
- Creates first admin account
- CLI alternative: `autentico onboard`

### 4.22 View Templates

Source: `view/` directory.

12 HTML templates rendered server-side:
- `layout.html` -- Base layout
- `login.html` -- Login page
- `signup.html` -- Self-registration
- `onboard.html` -- First-run admin setup
- `mfa.html` -- MFA challenge
- `mfa_enroll.html` -- MFA enrollment
- `consent.html` -- OAuth2 consent screen
- `forgot_password.html` -- Forgot password form
- `reset_password.html` -- Reset password form
- `verify_email.html` -- Email verification
- `logout_success.html` -- Logout confirmation
- `error.html` -- Error page

---

## 5. Database Schema

### Schema Version: 7

Source: `pkg/db/migrations/` (7 migration files).

### 5.1 Tables

#### `users` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key (UUID) |
| `username` | TEXT | No | - | Unique username |
| `email` | TEXT | Yes | - | Unique email |
| `password` | TEXT | Yes | - | Bcrypt hash (NULL for passkey-only) |
| `role` | TEXT | No | `'user'` | Role (user, admin) |
| `two_factor_enabled` | BOOLEAN | Yes | `FALSE` | Legacy 2FA flag |
| `totp_secret` | TEXT | No | `''` | Base32-encoded TOTP secret |
| `totp_verified` | BOOLEAN | Yes | `FALSE` | TOTP enrollment verified |
| `last_login` | DATETIME | Yes | - | Last successful login |
| `failed_login_attempts` | INTEGER | Yes | `0` | Failed login counter |
| `locked_until` | DATETIME | Yes | - | Account lock expiry |
| `password_last_changed` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Password last updated |
| `is_email_verified` | BOOLEAN | Yes | `FALSE` | Email verified flag |
| `email_verification_token` | TEXT | Yes | - | Verification token |
| `email_verification_expires_at` | DATETIME | Yes | - | Token expiry |
| `deactivated_at` | DATETIME | Yes | - | Deactivation timestamp |
| `registered_at` | DATETIME | Yes | - | Registration timestamp |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation timestamp |
| `updated_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last update timestamp |
| `given_name` | TEXT | No | `''` | OIDC: given name |
| `family_name` | TEXT | No | `''` | OIDC: family name |
| `middle_name` | TEXT | No | `''` | OIDC: middle name |
| `nickname` | TEXT | No | `''` | OIDC: nickname |
| `website` | TEXT | No | `''` | OIDC: website |
| `gender` | TEXT | No | `''` | OIDC: gender |
| `birthdate` | TEXT | No | `''` | OIDC: birthdate |
| `profile` | TEXT | No | `''` | OIDC: profile URL |
| `phone_number` | TEXT | No | `''` | OIDC: phone number |
| `phone_number_verified` | BOOLEAN | Yes | `FALSE` | OIDC: phone verified |
| `picture` | TEXT | No | `''` | OIDC: picture URL |
| `locale` | TEXT | No | `''` | OIDC: locale |
| `zoneinfo` | TEXT | No | `''` | OIDC: timezone |
| `address_street` | TEXT | No | `''` | OIDC: street address |
| `address_locality` | TEXT | No | `''` | OIDC: city |
| `address_region` | TEXT | No | `''` | OIDC: state/region |
| `address_postal_code` | TEXT | No | `''` | OIDC: postal code |
| `address_country` | TEXT | No | `''` | OIDC: country |

Constraints: `UNIQUE(username)`, `UNIQUE(email)`.

#### `tokens` (Migration 001, rebuilt in Migration 005)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | Yes | - | FK to users (NULL for client_credentials) |
| `access_token` | TEXT | No | - | JWT access token |
| `refresh_token` | TEXT | No | - | JWT refresh token |
| `access_token_type` | TEXT | No | - | Token type (Bearer) |
| `refresh_token_expires_at` | DATETIME | No | - | Refresh token expiry |
| `refresh_token_last_used_at` | DATETIME | Yes | - | Last refresh usage |
| `access_token_expires_at` | DATETIME | No | - | Access token expiry |
| `issued_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Issue timestamp |
| `scope` | TEXT | No | - | Granted scopes |
| `grant_type` | TEXT | No | - | Grant type used |
| `revoked_at` | DATETIME | Yes | - | Revocation timestamp |

Indexes: `idx_tokens_refresh_token`, `idx_tokens_access_token`.

#### `sessions` (Migration 001, altered in Migration 006)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | Yes | - | FK to users |
| `access_token` | TEXT | Yes | - | Associated access token |
| `refresh_token` | TEXT | Yes | - | Associated refresh token |
| `user_agent` | TEXT | Yes | - | Browser/device info |
| `ip_address` | TEXT | Yes | - | Client IP |
| `device_id` | TEXT | Yes | - | Device identifier |
| `location` | TEXT | Yes | - | Session location |
| `last_activity_at` | DATETIME | Yes | - | Last activity |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `expires_at` | DATETIME | Yes | - | Expiration time |
| `deactivated_at` | DATETIME | Yes | - | Deactivation time |
| `idp_session_id` | TEXT | Yes | - | FK to idp_sessions (Migration 006) |

Indexes: `idx_sessions_access_token`, `idx_sessions_user_id`, `idx_sessions_idp_session_id`.

#### `auth_codes` (Migration 001, altered in Migration 006)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `code` | TEXT | No | - | Primary key (the authorization code) |
| `user_id` | TEXT | No | - | FK to users |
| `client_id` | TEXT | Yes | - | Requesting client |
| `redirect_uri` | TEXT | No | - | Must match initial request |
| `scope` | TEXT | Yes | - | Associated scopes |
| `nonce` | TEXT | No | `''` | OIDC nonce |
| `code_challenge` | TEXT | No | `''` | PKCE challenge |
| `code_challenge_method` | TEXT | No | `''` | PKCE method |
| `expires_at` | DATETIME | No | - | Code expiry |
| `used` | BOOLEAN | Yes | `FALSE` | Single-use flag |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `idp_session_id` | TEXT | Yes | - | FK to idp_sessions (Migration 006) |

Index: `idx_auth_codes_idp_session_id`.

#### `idp_sessions` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users |
| `user_agent` | TEXT | Yes | - | Browser/device info |
| `ip_address` | TEXT | Yes | - | Client IP |
| `last_activity_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last activity |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `deactivated_at` | DATETIME | Yes | - | Deactivation time |

Index: `idx_idp_sessions_user_id`.

#### `mfa_challenges` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users |
| `method` | TEXT | No | - | MFA method (totp/email) |
| `code` | TEXT | No | `''` | OTP code (for email method) |
| `login_state` | TEXT | No | - | Serialized login state |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `expires_at` | DATETIME | No | - | Expiry time |
| `used` | BOOLEAN | Yes | `FALSE` | Used flag |
| `failed_attempts` | INTEGER | No | `0` | Failed verification attempts |
| `otp_sent_at` | DATETIME | Yes | - | When OTP was sent |

#### `trusted_devices` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users |
| `device_name` | TEXT | No | `''` | Device name |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `last_used_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last usage |
| `expires_at` | DATETIME | No | - | Expiry time |

#### `passkey_challenges` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users (ON DELETE CASCADE) |
| `challenge_data` | TEXT | No | - | Serialized WebAuthn challenge |
| `type` | TEXT | No | - | Challenge type |
| `login_state` | TEXT | No | `''` | Serialized login state |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `expires_at` | DATETIME | No | - | Expiry time |
| `used` | BOOLEAN | Yes | `FALSE` | Used flag |

#### `passkey_credentials` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users (ON DELETE CASCADE) |
| `name` | TEXT | No | `''` | Credential display name |
| `credential` | TEXT | No | - | Serialized WebAuthn credential (JSON) |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `last_used_at` | DATETIME | Yes | - | Last usage |

Index: `idx_passkey_credentials_user_id`.

#### `clients` (Migration 001, altered in Migration 007)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Internal unique ID |
| `client_id` | TEXT | No | - | Public client identifier (UNIQUE) |
| `client_secret` | TEXT | Yes | - | Hashed secret (NULL for public) |
| `client_name` | TEXT | No | - | Display name |
| `client_type` | TEXT | No | `'confidential'` | Client type |
| `redirect_uris` | TEXT | No | - | JSON array of redirect URIs |
| `grant_types` | TEXT | No | `'["authorization_code"]'` | JSON array of grant types |
| `response_types` | TEXT | No | `'["code"]'` | JSON array of response types |
| `scopes` | TEXT | No | `'openid profile email'` | Space-separated scopes |
| `token_endpoint_auth_method` | TEXT | No | `'client_secret_basic'` | Auth method |
| `is_active` | BOOLEAN | Yes | `TRUE` | Active flag |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `updated_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last update |
| `access_token_expiration` | TEXT | Yes | - | Per-client override |
| `refresh_token_expiration` | TEXT | Yes | - | Per-client override |
| `authorization_code_expiration` | TEXT | Yes | - | Per-client override |
| `allowed_audiences` | TEXT | Yes | - | Per-client override (JSON array) |
| `allow_self_signup` | INTEGER | Yes | - | Per-client override |
| `sso_session_idle_timeout` | TEXT | Yes | - | Per-client override |
| `trust_device_enabled` | INTEGER | Yes | - | Per-client override |
| `trust_device_expiration` | TEXT | Yes | - | Per-client override |
| `post_logout_redirect_uris` | TEXT | Yes | `'[]'` | JSON array of post-logout URIs |
| `consent_required` | INTEGER | Yes | `0` | Per-client consent flag (Migration 007) |

#### `settings` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `key` | TEXT | No | - | Primary key |
| `value` | TEXT | No | - | Setting value |
| `updated_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last update |

#### `federation_providers` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `name` | TEXT | No | - | Provider name |
| `issuer` | TEXT | No | - | OIDC issuer URL |
| `client_id` | TEXT | No | - | OAuth2 client ID |
| `client_secret` | TEXT | No | - | OAuth2 client secret |
| `icon_svg` | TEXT | Yes | - | SVG icon markup |
| `enabled` | BOOLEAN | No | `TRUE` | Enabled flag |
| `sort_order` | INTEGER | No | `0` | Display order |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |

#### `federated_identities` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `provider_id` | TEXT | No | - | FK to federation_providers |
| `provider_user_id` | TEXT | No | - | Subject ID at provider |
| `user_id` | TEXT | No | - | FK to users |
| `email` | TEXT | Yes | - | Email from provider |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |

Constraint: `UNIQUE(provider_id, provider_user_id)`. Index: `idx_federated_identities_user_id`.

#### `deletion_requests` (Migration 001)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users |
| `reason` | TEXT | Yes | - | Deletion reason |
| `requested_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Request time |

Index: `idx_deletion_requests_user_id`.

#### `password_reset_tokens` (Migration 002)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | FK to users |
| `token_hash` | TEXT | No | - | SHA-256 hash of token (UNIQUE) |
| `expires_at` | DATETIME | No | - | Token expiry |
| `used_at` | DATETIME | Yes | - | Usage timestamp |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |

Indexes: `idx_password_reset_tokens_hash`, `idx_password_reset_tokens_user`.

#### `audit_logs` (Migration 003)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `event` | TEXT | No | - | Event type |
| `actor_id` | TEXT | Yes | - | User who performed action |
| `actor_username` | TEXT | No | `''` | Actor's username |
| `target_type` | TEXT | No | `''` | Target entity type |
| `target_id` | TEXT | No | `''` | Target entity ID |
| `detail` | TEXT | No | `''` | JSON detail payload |
| `ip_address` | TEXT | No | `''` | Client IP |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Event time |

Indexes: `idx_audit_logs_created_at`, `idx_audit_logs_actor_id`, `idx_audit_logs_event`.

#### `groups` (Migration 004)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `name` | TEXT | No | - | Group name (UNIQUE) |
| `description` | TEXT | No | `''` | Description |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Creation time |
| `updated_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Last update |

#### `user_groups` (Migration 004)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `user_id` | TEXT | No | - | FK to users (ON DELETE CASCADE) |
| `group_id` | TEXT | No | - | FK to groups (ON DELETE CASCADE) |
| `created_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Membership creation |

Primary key: `(user_id, group_id)`. Indexes: `idx_user_groups_user_id`, `idx_user_groups_group_id`.

#### `user_consents` (Migration 007)

| Column | Type | Nullable | Default | Description |
|--------|------|----------|---------|-------------|
| `id` | TEXT | No | - | Primary key |
| `user_id` | TEXT | No | - | User who granted consent |
| `client_id` | TEXT | No | - | Client that received consent |
| `scopes` | TEXT | No | - | Consented scopes |
| `granted_at` | DATETIME | Yes | `CURRENT_TIMESTAMP` | Grant time |

Constraint: `UNIQUE(user_id, client_id)`. Index: `idx_user_consents_user_client`.

### 5.2 Migration History

| Version | File | Description |
|---------|------|-------------|
| 1 | `001_initial_schema.go` | All initial tables: users, tokens, sessions, auth_codes, idp_sessions, mfa_challenges, trusted_devices, passkey_challenges, passkey_credentials, clients, settings, federation_providers, federated_identities, deletion_requests + indexes |
| 2 | `002_password_reset_tokens.go` | Add `password_reset_tokens` table |
| 3 | `003_audit_logs.go` | Add `audit_logs` table |
| 4 | `004_groups.go` | Add `groups` and `user_groups` tables |
| 5 | `005_nullable_token_user_id.go` | Rebuild `tokens` table to make `user_id` nullable (for client_credentials grant) |
| 6 | `006_idp_session_linkage.go` | Add `idp_session_id` column to `auth_codes` and `sessions` tables |
| 7 | `007_user_consents.go` | Add `consent_required` column to `clients`, create `user_consents` table |

**Total tables: 20**

---

## 6. OAuth2/OIDC Grants & Flows

### 6.1 Supported Grant Types

Source: `pkg/token/handler.go`, `pkg/client/model.go`, `pkg/wellknown/handler.go`.

| Grant Type | Description | Client Auth Required | User Required |
|-----------|-------------|---------------------|---------------|
| `authorization_code` | Authorization Code + PKCE | Yes (Basic/form or public) | Yes |
| `refresh_token` | Refresh Token | Yes | Yes (validated against stored token) |
| `password` | Resource Owner Password Credentials (ROPC) | Yes | Yes (username/password) |
| `client_credentials` | Client Credentials | Yes (confidential only) | No (NULL user_id) |

### 6.2 Supported Response Types

| Response Type | Description |
|--------------|-------------|
| `code` | Authorization Code flow (the only flow fully implemented) |

Discovery also validates `token` and `id_token` in client registration, but only `code` is advertised in well-known config.

### 6.3 Token Endpoint Authentication Methods

| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic Auth (client_id:client_secret) |
| `client_secret_post` | Form body (client_id + client_secret fields) |
| `none` | No authentication (public clients) |

### 6.4 PKCE Support

- Code challenge methods: `S256` only (advertised in discovery)
- `pkce_enforce_s256` setting (default: true)

### 6.5 Supported Scopes

| Scope | Description |
|-------|-------------|
| `openid` | Triggers ID token issuance |
| `profile` | Standard OIDC profile claims |
| `email` | Email + email_verified claims |
| `address` | Structured address claim |
| `phone` | Phone number claims |
| `offline_access` | Enables refresh token |
| `groups` | User group membership |

### 6.6 Supported Claims

From well-known configuration:

`sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `sid`, `acr`, `name`, `preferred_username`, `given_name`, `family_name`, `middle_name`, `nickname`, `profile`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `updated_at`, `email`, `email_verified`, `phone_number`, `address`, `groups`

### 6.7 Prompt Values Supported

| Prompt | Description |
|--------|-------------|
| `none` | No interactive UI (SSO auto-login or error) |
| `login` | Force re-authentication |
| `create` | Direct to signup page |

### 6.8 Subject Types

- `public` (single subject identifier per user)

### 6.9 ID Token Signing

- Algorithm: `RS256`
- Key: RSA private key from `AUTENTICO_PRIVATE_KEY` (or ephemeral)

### 6.10 RP-Initiated Logout

Source: `pkg/session/logout.go`.

- Both GET and POST methods supported
- Parameters: `id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`
- Validates post_logout_redirect_uri against registered URIs
- Cascade revocation of IdP session + child sessions/tokens
- Renders logout success page if no valid redirect

### 6.11 Token Introspection

Source: `pkg/introspect/`.

- RFC 7662 compliant
- Requires client authentication (client_secret_basic or client_secret_post) or bearer token
- Returns `{"active": false}` for invalid/expired tokens

### 6.12 Token Revocation

Source: `pkg/revoke/`.

- RFC 7009 compliant
- POST only
- Requires client authentication
- Accepts access or refresh tokens

### 6.13 Keycloak-Compatible Endpoints

Aliases for interoperability:
- `{oauth}/protocol/openid-connect/token` -> same as `{oauth}/token`
- `{oauth}/protocol/openid-connect/userinfo` -> same as `{oauth}/userinfo`

---

## 7. Admin API Endpoints (Complete)

All admin API endpoints require `AdminAuthMiddleware`: valid Bearer token with `admin` role and `autentico-admin` audience.

### Users (9 endpoints)
- `GET /admin/api/users` -- List users (paginated)
- `POST /admin/api/users` -- Create user
- `GET /admin/api/users/{id}` -- Get user by ID
- `PUT /admin/api/users/{id}` -- Update user
- `DELETE /admin/api/users/{id}` -- Delete user
- `POST /admin/api/users/{id}/deactivate` -- Deactivate user
- `POST /admin/api/users/{id}/reactivate` -- Reactivate user
- `POST /admin/api/users/{id}/unlock` -- Unlock locked user
- `POST /admin/api/users/{id}/revoke-sessions` -- Revoke all user sessions

### Clients (5 endpoints)
- `GET /admin/api/clients` -- List clients
- `POST /admin/api/clients` -- Register client
- `GET /admin/api/clients/{client_id}` -- Get client
- `PUT /admin/api/clients/{client_id}` -- Update client
- `DELETE /admin/api/clients/{client_id}` -- Delete client

### OAuth Sessions (2 endpoints)
- `GET /admin/api/sessions` -- List sessions (optional `?user_id=` filter)
- `DELETE /admin/api/sessions/{id}` -- Deactivate session

### IdP Sessions (4 endpoints)
- `GET /admin/api/idp-sessions` -- List all IdP sessions
- `GET /admin/api/users/{id}/idp-sessions` -- List IdP sessions for a user
- `GET /admin/api/idp-sessions/{id}/sessions` -- List OAuth sessions under an IdP session
- `DELETE /admin/api/idp-sessions/{id}` -- Force logout IdP session (cascade)

### Federation (5 endpoints)
- `GET /admin/api/federation` -- List providers
- `POST /admin/api/federation` -- Create provider
- `GET /admin/api/federation/{id}` -- Get provider
- `PUT /admin/api/federation/{id}` -- Update provider
- `DELETE /admin/api/federation/{id}` -- Delete provider

### Groups (8 endpoints)
- `GET /admin/api/groups` -- List groups
- `POST /admin/api/groups` -- Create group
- `GET /admin/api/groups/{id}` -- Get group
- `PUT /admin/api/groups/{id}` -- Update group
- `DELETE /admin/api/groups/{id}` -- Delete group
- `GET /admin/api/groups/{id}/members` -- List group members
- `POST /admin/api/groups/{id}/members` -- Add member
- `DELETE /admin/api/groups/{id}/members/{user_id}` -- Remove member
- `GET /admin/api/users/{id}/groups` -- Get user's groups

### Tokens (2 endpoints)
- `GET /admin/api/tokens` -- List tokens
- `DELETE /admin/api/tokens/{id}` -- Revoke token

### Settings (6 endpoints)
- `GET /admin/api/settings` -- Get all settings
- `PUT /admin/api/settings` -- Update settings
- `POST /admin/api/settings/test-smtp` -- Test SMTP configuration
- `GET /admin/api/settings/export` -- Export settings
- `POST /admin/api/settings/import/preview` -- Preview settings import
- `POST /admin/api/settings/import/apply` -- Apply settings import

### Stats (1 endpoint)
- `GET /admin/api/stats` -- Get system statistics

### Audit Logs (1 endpoint)
- `GET /admin/api/audit-logs` -- List audit logs

### Deletion Requests (3 endpoints)
- `GET /admin/api/deletion-requests` -- List deletion requests
- `POST /admin/api/deletion-requests/{id}/approve` -- Approve deletion
- `DELETE /admin/api/deletion-requests/{id}` -- Cancel deletion request

### Dynamic Client Registration (RFC 7591) (4 endpoints)
- `POST {oauth}/register` -- Register client
- `GET {oauth}/register/{client_id}` -- Get client
- `PUT {oauth}/register/{client_id}` -- Update client
- `DELETE {oauth}/register/{client_id}` -- Delete client

**Total admin API endpoints: 50** (46 at `/admin/api/*` + 4 at `{oauth}/register`)

---

## 8. Account API Endpoints (Complete)

All account API endpoints require `AccountAuthMiddleware`: valid Bearer token with audience `autentico-account` or `autentico-admin`.

Exception: `GET /account/api/settings` is public (no auth).

### Profile (2 endpoints)
- `GET /account/api/profile` -- Get current user profile
- `PUT /account/api/profile` -- Update profile (respects `allow_username_change`, `allow_email_change`)

### Password (1 endpoint)
- `POST /account/api/password` -- Change password (rate limited)

### Sessions (3 endpoints)
- `GET /account/api/sessions` -- List active devices (IdP sessions) with active app count and current flag
- `DELETE /account/api/sessions/{id}` -- Revoke specific session
- `POST /account/api/sessions/revoke-others` -- Revoke all other sessions

### Passkeys (5 endpoints)
- `GET /account/api/passkeys` -- List passkeys
- `DELETE /account/api/passkeys/{id}` -- Delete passkey
- `PATCH /account/api/passkeys/{id}` -- Rename passkey
- `POST /account/api/passkeys/register/begin` -- Begin passkey registration
- `POST /account/api/passkeys/register/finish` -- Complete passkey registration

### MFA (4 endpoints)
- `GET /account/api/mfa` -- Get MFA status (totp_enabled)
- `POST /account/api/mfa/totp/setup` -- Begin TOTP setup (generates secret + QR)
- `POST /account/api/mfa/totp/verify` -- Verify TOTP enrollment
- `DELETE /account/api/mfa/totp` -- Disable TOTP (requires password + code, rate limited)

### Trusted Devices (2 endpoints)
- `GET /account/api/trusted-devices` -- List trusted devices
- `DELETE /account/api/trusted-devices/{id}` -- Revoke trusted device

### Connected Providers (2 endpoints)
- `GET /account/api/connected-providers` -- List connected external providers
- `DELETE /account/api/connected-providers/{id}` -- Disconnect provider

### Settings (1 endpoint)
- `GET /account/api/settings` -- Get public-facing config (theme, auth mode, profile field visibility, etc.) -- NO AUTH REQUIRED

### Deletion (3 endpoints)
- `GET /account/api/deletion-request` -- Get pending deletion request
- `POST /account/api/deletion-request` -- Request account deletion
- `DELETE /account/api/deletion-request` -- Cancel deletion request

**Total account API endpoints: 23**

---

## 9. Auto-Seeded Clients

Two clients are auto-seeded on startup:

### `autentico-admin`
- Client type: `public`
- Auth method: `none`
- Grant types: `authorization_code`, `refresh_token` (optionally `password` with `--enable-admin-password-grant`)
- Scopes: `openid profile email offline_access`
- Redirect URI: `{APP_URL}/admin/callback`

### `autentico-account`
- Client type: `public`
- Auth method: `none`
- Grant types: `authorization_code`, `refresh_token`
- Scopes: `openid profile email offline_access`
- Redirect URI: `{APP_URL}/account/callback`
- Post-logout redirect URI: `{APP_URL}/account/`
- SSO idle timeout override: `24h`

---

## 10. Summary Statistics

| Category | Count |
|----------|-------|
| Total HTTP endpoints (unique method+path) | ~110 |
| Bootstrap env vars | 20 |
| Runtime settings keys | 55 |
| Per-client override fields | 9 |
| CLI commands | 5 |
| CLI flags (total across commands) | 12 |
| Database tables | 20 |
| Database schema version | 7 |
| Supported grant types | 4 |
| Supported scopes | 7 |
| Supported claims | 28 |
| View templates | 12 |
| Audit event types | 31 |
| Admin API endpoints | 50 |
| Account API endpoints | 23 |
| Packages | 36 |
