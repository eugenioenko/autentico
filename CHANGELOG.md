# Changelog

## v2.0.0 (unreleased)

### Breaking Changes

#### Refresh token rotation enforced

Refresh tokens are now single-use. Each token exchange returns a new refresh token; reusing a previously consumed refresh token revokes all tokens for that user as a security measure. Clients must store the new refresh token from every response. (#163)

#### PKCE required for public clients

Public clients must include a `code_challenge` (S256) in authorization requests. Requests without PKCE are rejected with `invalid_request`. (#54, #162)

#### Access token audience always populated

Access tokens now include `[issuer, client_id]` in the `aud` claim. Per-client `allowed_audiences` extend (not replace) these defaults. Existing consumers that assume an empty audience will need to update their token validation. (#178)

#### Admin API requires `autentico-admin` audience

Admin API endpoints now require `autentico-admin` in the token `aud` claim, in addition to the admin role. Tokens without a matching audience are rejected with 403. (#187)

#### Account API requires audience claim

All `/account/api/*` endpoints now require `autentico-account` or `autentico-admin` in the `aud` claim. Tokens without a matching audience are rejected with 401. Ensure clients that need account API access have `autentico-account` in their `allowed_audiences` configuration. (#320)

#### `given_name` / `family_name` moved to ID token

These claims are no longer included in access tokens. They are available in ID tokens (when `profile` scope is requested) and from the `/oauth2/userinfo` endpoint. Clients that parsed these from access tokens must switch to ID tokens or UserInfo. (#222)

#### List endpoints return paginated response objects

All admin list endpoints (`/admin/api/users`, `/admin/api/groups`, `/admin/api/clients`, `/admin/api/federation`, `/admin/api/sessions`, `/admin/api/audit`, `/admin/api/tokens`, `/admin/api/deletions`) now return `{ "items": [...], "total": N }` instead of raw arrays. Server-side sorting, filtering, search, and pagination are supported via query parameters. (#254)

#### Bearer token logout removed

`POST /oauth2/logout` no longer accepts Bearer tokens. Only RP-Initiated Logout (OIDC RP-Initiated Logout 1.0) with form-encoded `id_token_hint` and `post_logout_redirect_uri` parameters is supported. `GET /oauth2/logout` is also supported per spec. (#107, #134)

#### JWKS endpoint moved

The JWKS endpoint moved from `/.well-known/jwks.json` to `/oauth2/.well-known/jwks.json`. The discovery document reflects the new location. (#105)

#### CORS configuration changed

The `AUTENTICO_APP_ENABLE_CORS` environment variable has been removed. CORS allowed origins are now configured at runtime via the `cors_allowed_origins` setting in the admin API. (#161)

#### Cross-client token isolation

Token introspection and revocation endpoints now enforce client isolation. A client can only introspect or revoke tokens it issued. Tokens from other clients return `active: false` (introspect) or succeed silently (revoke) per RFC. (#189)

#### Signed authorize parameters

The authorization flow now uses HMAC-signed parameters to prevent form tampering. Direct `POST` to `/oauth2/login` without going through `/oauth2/authorize` will fail. (#191)

### New Features

#### OAuth2 / OIDC Protocol

- **Device Authorization Grant (RFC 8628)** — new `/oauth2/device/authorize` and `/oauth2/device/token` endpoints with user verification flow in the account UI (#344)
- **Client Credentials Grant (RFC 6749 section 4.4)** — machine-to-machine authentication without user involvement (#152)
- **OAuth2 Consent Screen** — per-client `consent_required` setting with scope approval UI; consent decisions are remembered per user+client+scopes (#290, #311)
- **`prompt=create` support** — OIDC-compliant signup redirect via the authorization endpoint (#148)
- **`at_hash` claim** in ID tokens per OIDC Core 3.1.3.6 (#169)
- **Email claims in ID token** when `email` scope is requested (#221)
- **Configurable OAuth path** — `AUTENTICO_APP_OAUTH_PATH` env var to override the default `/oauth2` prefix (#339)

#### Authentication & Security

- **MFA method switching** — users with TOTP enrolled can switch to email OTP during MFA verification; configurable via `mfa_method` setting (`totp`, `email`, `both`) (#310, #311)
- **Federation / social login** — external IdP integration with OIDC discovery, user linking, and admin management (#59)
- **Email verification flow** — configurable email verification with token-based confirmation (#89)
- **Password reset via email** — forgot password flow with time-limited reset tokens (#123)
- **WebAuthn/passkey improvements** — auto-generated credential names, stale re-registration fixes (#118, #86)
- **Configurable anti-timing delay** — randomized response delay on auth endpoints to prevent timing attacks (#164)
- **CSP nonces** — replaced `unsafe-inline` with per-request nonces for inline scripts (#340)
- **Rate limiting on all sensitive endpoints** — extended rate limiting beyond login to cover password reset, email verification, MFA, and device authorization (#55, #327)
- **Scope validation** on the authorize endpoint (#328)
- **Stored XSS fix** in auth views via federation icon and theme CSS (#219)
- **SSRF prevention** on federation OIDC discovery (#181)
- **Password oracle fix** on TOTP disable and password change endpoints (#319)

#### Admin UI

- **Dark mode toggle** with Ant Design 6 and Vite 8 (#274)
- **Server-side pagination, sorting, filtering, and search** across all list pages — users, groups, clients, sessions, federation, audit, tokens, deletions (#254, #257, #260, #262, #266, #267, #270)
- **Per-device IdP sessions** page with cascade revocation (#237, #242)
- **Tokens listing** with revoke capability (#286)
- **Revoke all sessions** button for account and admin (#288)
- **Failed logins and locked accounts** stats on admin dashboard (#289)
- **Active/inactive toggle** on client edit form (#278)
- **Audit log overhaul** with date range filters (#262)
- **Deletion requests** moved into Users page tab (#269, #270)
- **Settings page reorganization** with improved tab grouping (#287)
- **Settings export/import** with preview (#122)
- **Configurable footer links** for login/signup pages (#284)

#### Account UI

- **Account deletion requests** — user-initiated, admin-reviewed (#84)
- **Session listing** with revoke capability (#288)

#### User Management

- **Groups and roles** with OIDC `groups` claim (#150)
- **Self-service signup** — configurable via `allow_self_signup` setting (#148)
- **Email normalization** — case-insensitive uniqueness (#249)
- **Input trimming** — whitespace stripped from username and email (#247)

#### Sessions & Tokens

- **IdP-level SSO sessions** — cross-request browser sessions with cascade revocation (#237)
- **`sso_session_max_age`** — absolute session lifetime in addition to idle timeout (#282)
- **Idle timeout cascade** — deactivating an IdP session cascades to child OAuth sessions and tokens (#280)

#### Infrastructure & Operations

- **Database migrations system** — versioned schema with `autentico migrate` CLI command and auto-migration on startup (#85)
- **CLI `onboard` command** — headless admin account setup for CI/Docker environments (#138)
- **`--auto-setup` flag** — single-command Docker quickstart with auto-generated `.env` (#199)
- **`--enable-admin-password-grant` flag** — enables ROPC grant on admin client for headless API access (#216)
- **Audit logging** — security event trail with configurable retention, enabled by default at 30 days (#125, #261)
- **Unified email templates** with branding support (#295)
- **Theming** — CSS customization, logo, title, tagline, brand color on login buttons (#90, #92, #305, #306)

#### Performance

- **SQLite WAL mode** with read/write connection pool split — configurable via `AUTENTICO_DB_READ_POOL_SIZE` (#300, #301)

### Bug Fixes

- Fix routing errors shown as login template errors (#343)
- Fix hardcoded `/oauth2` paths — now uses configurable `AppOAuthPath` (#339)
- Validate date format and range ordering in list queries (#329)
- Log and handle previously swallowed database errors (#325)
- Validate path parameters before database lookups (#324)
- Enforce token and session revocation across all bearer endpoints (#227)
- Cascade idle IdP session deactivation to child sessions and tokens (#280)
- Always create IdP sessions; treat idle timeout 0 as infinite (#245)
- Create IdP session during email verification login flow (#244)
- Normalize emails to lowercase for case-insensitive uniqueness (#249)
- Trim whitespace from username and email inputs (#247)
- Increase MFA challenge expiration from 5 to 10 minutes (#297)
- Cap list query `MaxLimit` at 1000 to prevent unbounded queries (#268)
- Enable audit logging by default with 30-day retention (#261)
- Validate duration settings on save (#204)
- User deactivation revokes access; admin hard-delete support (#175)
- Onboarding UX — default username and password validation (#158)
- Allow Google Fonts in CSP header (#149)
- Proper error codes for admin user endpoints (#143)
- Fix Docker entrypoint and `init --output` flag (#96)
- Fix account-ui redirect loop and passkey stale re-registration (#86)
- Unify persistent data in `./data/` directory (#210)
- Load `.env` from DB directory when not found in CWD (#209)
- Generate default passkey name instead of empty string (#118)

### Documentation

- Comprehensive documentation audit — 87 findings fixed (#332)
- Updated `llms.txt` and `llms-full.txt` with complete feature set (#130, #334, #341)
- Swagger API docs overhauled with Scalar UI (#207, #208)
- README performance benchmarks for WAL mode (#302)
- Test fixture guide for using Autentico in integration tests (#313)

### Internal

- Refactor: pass validated auth state via request context (#322)
- Refactor: consolidate post-auth IdP session creation into `FinalizeLogin` helper (#248)
- Refactor: filter deactivated sessions and revoked tokens at SQL read layer (#230, #253)
- Replace `oidc-client-ts` with `oidc-js-react` in admin UI (#314)
- Frontend dependency updates — Vite 8, Ant Design 6 (#274, #323)
- OIDC Basic Certification test plan passed (#79, #102)
- Comprehensive test coverage: unit, e2e, functional, browser, security, adversarial (#128, #139, #142, #251, #252, #271, #272, #326, #330, #335)
