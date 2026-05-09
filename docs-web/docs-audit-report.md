# Documentation Audit Report

Generated: 2026-05-09
Based on: source code ground truth (`docs-audit-truth.md`) vs documentation catalog (`docs-content-catalog.md`)
Version: v1.6.2, Schema version: 7

---

## 1. Errors (things the docs say that are WRONG)

### 1.1 Wrong config key names

| # | Page(s) | Docs say | Correct (source code) | Severity |
|---|---------|----------|----------------------|----------|
| 1 | `authentication/mfa.mdx`, `authentication/overview.mdx`, `admin-ui/settings.mdx`, `security/overview.mdx`, `deployment/production-checklist.mdx` | `mfa_enabled` | `require_mfa` | :red_circle: Error |
| 2 | `users/account-lockout.mdx`, `admin-ui/settings.mdx`, `security/overview.mdx`, `deployment/production-checklist.mdx` | `lockout_max_attempts` | `account_lockout_max_attempts` | :red_circle: Error |
| 3 | `users/account-lockout.mdx`, `admin-ui/settings.mdx`, `security/overview.mdx`, `deployment/production-checklist.mdx` | `lockout_duration` | `account_lockout_duration` | :red_circle: Error |
| 4 | `protocol/oidc-discovery.mdx` | `AUTENTICO_AUTH_JWK_CERT_KEY_ID` | `AUTENTICO_JWK_CERT_KEY_ID` | :red_circle: Error |

**Fix:** Search-and-replace across all docs pages. The runtime-settings.mdx page has the correct names; all other pages must match.

### 1.2 Non-existent config keys referenced

| # | Page(s) | Key referenced | Reality | Severity |
|---|---------|---------------|---------|----------|
| 5 | `deployment/production-checklist.mdx`, `security/overview.mdx` | `AUTENTICO_COOKIE_SECRET` | Does not exist in source code. No such env var in `pkg/config/config.go`. Likely confusion with `AUTENTICO_CSRF_SECRET_KEY`. | :red_circle: Error |
| 6 | `deployment/production-checklist.mdx`, `security/overview.mdx`, `security/incident-response.mdx` | `AUTENTICO_ADMIN_TOKEN` | Does not exist. Admin API uses bearer tokens obtained via OAuth2, not a static config token. | :red_circle: Error |

**Fix:** Remove references to `AUTENTICO_COOKIE_SECRET`. Where it says "rotating AUTENTICO_COOKIE_SECRET invalidates SSO session cookies," replace with `AUTENTICO_CSRF_SECRET_KEY` (invalidates CSRF tokens) or explain that regenerating the IdP session cookie name/secure flags affects sessions. Remove `AUTENTICO_ADMIN_TOKEN` references and explain that admin tokens are obtained via OAuth2 (ROPC grant with `--enable-admin-password-grant` or browser flow).

### 1.3 Wrong auth_mode values

| # | Page(s) | Docs say | Source code uses | Severity |
|---|---------|----------|-----------------|----------|
| 7 | `configuration/runtime-settings.mdx` | `password`, `password_and_passkey`, `passkey_only` | `password`, `password_and_passkey`, `passkey_only` | Correct here |
| 8 | `docs-audit-truth.md` (ground truth file) | `password`, `passkey`, `both` | `password`, `password_and_passkey`, `passkey_only` | :red_circle: Error (in ground truth, not in docs) |

**Note:** The runtime-settings.mdx page correctly uses `password_and_passkey` and `passkey_only`. However, some other pages may describe them as "passkey" and "both" in prose -- verify all auth_mode references.

### 1.4 Wrong endpoint paths

| # | Page(s) | Docs say | Correct path | Severity |
|---|---------|----------|-------------|----------|
| 9 | `users/managing-users.mdx`, `users/account-lockout.mdx` | `POST /admin/api/users/unlock` with `{"user_id": "USER_ID"}` in body | `POST /admin/api/users/{id}/unlock` (user ID in URL path, not body) | :red_circle: Error |

**Fix:** Update curl examples to use `POST /admin/api/users/USER_ID/unlock` without a request body.

### 1.5 Wrong discovery document values

| # | Page(s) | Docs say | Source code returns | Severity |
|---|---------|----------|-------------------|----------|
| 10 | `protocol/oidc-discovery.mdx` | `"response_types_supported": ["code", "token", "id_token", "code token", "code id_token"]` | `"response_types_supported": ["code"]` | :red_circle: Error |
| 11 | `protocol/oidc-discovery.mdx` | `"scopes_supported": ["openid", "profile", "email"]` | `"scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access", "groups"]` | :red_circle: Error |
| 12 | `protocol/oidc-discovery.mdx` | `"claims_supported": ["sub", "iss", "aud", "exp", "iat", "name", "email"]` | Full list: `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `sid`, `acr`, `name`, `preferred_username`, `given_name`, `family_name`, `middle_name`, `nickname`, `profile`, `picture`, `website`, `gender`, `birthdate`, `locale`, `zoneinfo`, `updated_at`, `email`, `email_verified`, `phone_number`, `address`, `groups` | :red_circle: Error |
| 13 | `protocol/oidc-discovery.mdx` | `kid` default: `autentico-key` | Default is `autentico-key-1` (source: `pkg/config/config.go` line 228/298) | :red_circle: Error |

**Fix:** Replace the example discovery JSON in `protocol/oidc-discovery.mdx` with the actual output from the source code. The `response_types_supported` is only `["code"]` since implicit flow is not implemented.

### 1.6 ROPC MFA claim is wrong

| # | Page(s) | Docs say | Source code does | Severity |
|---|---------|----------|-----------------|----------|
| 14 | `protocol/ropc.mdx` | "MFA is not enforced -- even if `mfa_enabled` is true globally, the ROPC flow bypasses the MFA challenge" | ROPC **does** enforce MFA. `pkg/token/handler.go` checks `require_mfa` and user TOTP enrollment, requires `totp_code` form field. Returns `mfa_required` or `invalid_grant` on failure. | :red_circle: Error |

**Fix:** Rewrite the ROPC limitations section. MFA IS enforced via `totp_code` parameter. Document the `totp_code` form field in the ROPC request. Also fix `mfa_enabled` to `require_mfa`.

### 1.7 Contradictions between pages

| # | Page(s) | Contradiction | Severity |
|---|---------|--------------|----------|
| 15 | `security/incident-response.mdx` | "Autentico does not have built-in rate limiting beyond account lockout" | :red_circle: Error |
| | `security/overview.mdx`, `configuration/bootstrap.mdx` | Detailed documentation of built-in per-IP rate limiting with RPS/RPM tiers | |

**Fix:** Remove the false statement from `incident-response.mdx`. Replace with a reference to the rate limiting configuration documented in `security/overview.mdx`.

### 1.8 Wrong audit_log_retention default

| # | Page(s) | Docs say | Source code default | Severity |
|---|---------|----------|-------------------|----------|
| 16 | `configuration/runtime-settings.mdx` | `audit_log_retention` default: `0` (with "0 disables, -1 keeps forever") | Default is `720h` (`pkg/appsettings/load.go` line 40) | :red_circle: Error |

**Fix:** Update the default to `720h` (30 days). Clarify the semantics of 0 and -1 if they are still valid override values.

### 1.9 RSA key size inconsistency

| # | Page(s) | Docs say | Reality | Severity |
|---|---------|----------|---------|----------|
| 17 | `configuration/bootstrap.mdx`, `architecture/design-decisions.mdx` | "RSA 2048 private key" / "2048-bit RSA key" | `deployment/key-generation.mdx` manual example uses `openssl genrsa 4096`. `autentico init` generates 4096-bit key. | :red_circle: Error |

**Fix:** Verify the key size generated by `autentico init` and align all pages. If `init` generates 4096-bit, update bootstrap.mdx and design-decisions.mdx to say 4096.

---

## 2. Missing Documentation (features/endpoints that exist but aren't documented)

### 2.1 Missing feature pages

| # | Feature | Source code packages | Docs coverage | Severity |
|---|---------|---------------------|--------------|----------|
| 18 | OAuth2 Consent Screen | `pkg/consent/`, `user_consents` table, `consent_required` per-client field | No docs page at all. Not even mentioned in any docs-web page. | :yellow_circle: Missing |
| 19 | Federation / Social Login | `pkg/federation/`, `federation_providers` table, `federated_identities` table, 5 admin API endpoints, 2 account API endpoints | No docs page. Major feature entirely undocumented. | :yellow_circle: Missing |
| 20 | Account Deletion | `pkg/deletion/`, `deletion_requests` table, 3 admin + 3 account API endpoints, `allow_self_service_deletion` setting | No docs page explaining the flow. Setting is documented but no feature page. | :yellow_circle: Missing |
| 21 | Email Verification | `pkg/emailverification/`, 2 endpoints, `require_email_verification` + `email_verification_expiration` settings | No dedicated docs page. Settings documented but flow not explained. | :yellow_circle: Missing |
| 22 | Password Reset | `pkg/passwordreset/`, `password_reset_tokens` table, 2 endpoints, `password_reset_expiration` setting | No dedicated docs page. Setting documented but flow not explained. | :yellow_circle: Missing |
| 23 | Audit Logging | `pkg/audit/`, `audit_logs` table, 31 event types, admin API endpoint, `audit_log_retention` setting | No docs page. Major operational feature undocumented. | :yellow_circle: Missing |
| 24 | Groups | `pkg/group/`, `groups` + `user_groups` tables, 8 admin API endpoints, `groups` scope | No docs page. Feature affects token claims. | :yellow_circle: Missing |
| 25 | Client Credentials Grant | Supported in `pkg/token/handler.go`, advertised in discovery | Only mentioned in passing in `protocol/overview.mdx` and `clients/registering.mdx`. No dedicated page like ROPC has. | :yellow_circle: Missing |
| 26 | RP-Initiated Logout | `pkg/session/logout.go`, GET + POST at `{oauth}/logout`, `post_logout_redirect_uris` client field | Only mentioned briefly in SSO sessions and introspection pages. No dedicated page explaining the full flow, parameters, or behavior. | :yellow_circle: Missing |
| 27 | Settings Import/Export | `pkg/appsettings/handler.go`, 3 endpoints (export, import preview, import apply) | No docs page. | :yellow_circle: Missing |
| 28 | SMTP Test | `POST /admin/api/settings/test-smtp` | Not documented. | :yellow_circle: Missing |

### 2.2 Missing config keys from documentation

| # | Setting | Default | Page that should document it | Severity |
|---|---------|---------|----------------------------|----------|
| 29 | `AUTENTICO_LISTEN_PORT` | Derived from APP_URL | `configuration/bootstrap.mdx` lists it as a derived value but does not have its own row in the config table. It IS a distinct env var. | :yellow_circle: Missing |
| 30 | `consent_required` (per-client override) | `0` (false) | `configuration/per-client-overrides.mdx` does not list it | :yellow_circle: Missing |
| 31 | `AUTENTICO_REFRESH_TOKEN_SECURE` | Listed in CLAUDE.md bootstrap env vars but not in any code | Verify existence; if exists, add to bootstrap.mdx | :yellow_circle: Missing |
| 32 | `validation_username_is_email` and `validation_email_required` | Listed in `runtime-settings.mdx` | These do NOT exist in `pkg/appsettings/load.go`. They appear to be phantom settings. Should be removed or verified. | :red_circle: Error |

### 2.3 Missing endpoints from documentation

| # | Endpoint | Handler | Severity |
|---|---------|---------|----------|
| 33 | `POST /admin/api/users/{id}/deactivate` | `user.HandleDeactivateUser` | :yellow_circle: Missing |
| 34 | `POST /admin/api/users/{id}/reactivate` | `user.HandleReactivateUser` | :yellow_circle: Missing |
| 35 | `POST /admin/api/users/{id}/revoke-sessions` | `user.HandleRevokeUserSessions` | :yellow_circle: Missing |
| 36 | `GET /admin/api/idp-sessions` | `idpsession.HandleListIdpSessions` | :yellow_circle: Missing |
| 37 | `GET /admin/api/users/{id}/idp-sessions` | `idpsession.HandleListUserIdpSessions` | :yellow_circle: Missing |
| 38 | `GET /admin/api/idp-sessions/{id}/sessions` | `session.HandleListIdpSessionSessions` | :yellow_circle: Missing |
| 39 | `DELETE /admin/api/idp-sessions/{id}` | `idpsession.HandleForceLogoutIdpSession` | :yellow_circle: Missing |
| 40 | `GET /admin/api/tokens` | `token.HandleListTokens` | :yellow_circle: Missing |
| 41 | `DELETE /admin/api/tokens/{id}` | `token.HandleRevokeToken` | :yellow_circle: Missing |
| 42 | `GET /admin/api/settings/export` | `appsettings.HandleExportSettings` | :yellow_circle: Missing |
| 43 | `POST /admin/api/settings/import/preview` | `appsettings.HandleImportPreview` | :yellow_circle: Missing |
| 44 | `POST /admin/api/settings/import/apply` | `appsettings.HandleImportApply` | :yellow_circle: Missing |
| 45 | `POST /admin/api/settings/test-smtp` | `appsettings.HandleTestSmtp` | :yellow_circle: Missing |
| 46 | All federation admin API endpoints (5) | `federation.Handle*` | :yellow_circle: Missing |
| 47 | All group admin API endpoints (8+1) | `group.Handle*` | :yellow_circle: Missing |
| 48 | All deletion request admin API endpoints (3) | `deletion.Handle*` | :yellow_circle: Missing |
| 49 | All account API endpoints (23 total) | `account.Handle*` | :yellow_circle: Missing (no dedicated page listing all account API endpoints) |
| 50 | Dynamic client registration endpoints (4) at `{oauth}/register` | `client.Handle*` | :yellow_circle: Missing (mentioned in passing but no dedicated API reference) |

### 2.4 Missing database tables from schema page

| # | Table | Migration | Severity |
|---|-------|-----------|----------|
| 51 | `sessions` | 001 (altered in 006) | :yellow_circle: Missing |
| 52 | `federation_providers` | 001 | :yellow_circle: Missing |
| 53 | `federated_identities` | 001 | :yellow_circle: Missing |
| 54 | `deletion_requests` | 001 | :yellow_circle: Missing |
| 55 | `password_reset_tokens` | 002 | :yellow_circle: Missing |
| 56 | `audit_logs` | 003 | :yellow_circle: Missing |
| 57 | `groups` | 004 | :yellow_circle: Missing |
| 58 | `user_groups` | 004 | :yellow_circle: Missing |
| 59 | `user_consents` | 007 | :yellow_circle: Missing |

The schema page documents only 10 of 20 tables.

### 2.5 Missing packages from architecture page

| # | Severity |
|---|----------|
| 60 | `architecture/package-structure.mdx` lists 23 packages; source code has 36. Missing: `account`, `api`, `audit`, `authzsig`, `bearer`, `cli`, `consent`, `deletion`, `email`, `emailverification`, `federation`, `group`, `idpsession`, `passwordreset`, `ratelimit`, `reqid`, `revoke`, `utils` | :yellow_circle: Missing |

### 2.6 Missing CLI flags

| # | Flag | Command | Severity |
|---|------|---------|----------|
| 61 | `--output` | `autentico init` | Not documented in `getting-started/installation.mdx`. The flag exists (outputs .env to a specific directory). Documented in `deployment/key-generation.mdx` Docker example only. | :yellow_circle: Missing |
| 62 | `--url` and `--dev` | `autentico start` (for `--auto-setup`) | Not documented in installation page as flags of `start`. | :yellow_circle: Missing |

### 2.7 Missing scopes documentation

| # | Scope | Claims | Severity |
|---|-------|--------|----------|
| 63 | `address` | Structured address claim (`address_street`, `address_locality`, `address_region`, `address_postal_code`, `address_country`) | :yellow_circle: Missing from `protocol/scopes.mdx` |
| 64 | `phone` | `phone_number`, `phone_number_verified` | :yellow_circle: Missing from `protocol/scopes.mdx` |
| 65 | `offline_access` | Enables refresh token issuance | :yellow_circle: Missing from `protocol/scopes.mdx` |
| 66 | `groups` | User group membership | :yellow_circle: Missing from `protocol/scopes.mdx` |

---

## 3. Stale/Outdated Content

### 3.1 Schema page migration claims

| # | Page | Issue | Severity |
|---|------|-------|----------|
| 67 | `architecture/database-schema.mdx` | Says "All tables created on startup if they don't exist" and "Schema migrations applied automatically via `ALTER TABLE ... ADD COLUMN` (idempotent)". This is outdated. Since at least schema version 5, migrations use full table rebuilds (not just ALTER TABLE). The migration system uses `PRAGMA user_version` and runs ordered migration scripts. Fresh databases run all migrations from scratch. | :yellow_circle: Stale |

### 3.2 SSO sessions page table description

| # | Page | Issue | Severity |
|---|------|-------|----------|
| 68 | `authentication/sso-sessions.mdx` | Lists session fields (`id`, `user_id`, `user_agent`, `ip_address`, `last_activity_at`, `created_at`, `expires_at`, `deactivated_at`) as if describing `sessions` table, but SSO sessions use the `idp_sessions` table which does NOT have `expires_at`. The `idp_sessions` model has: `ID`, `UserID`, `UserAgent`, `IPAddress`, `LastActivityAt`, `CreatedAt`, `DeactivatedAt`. Max age is enforced via `sso_session_max_age` computed against `created_at`, not stored in a column. | :red_circle: Error |

### 3.3 Anti-timing delay endpoints

| # | Page | Issue | Severity |
|---|------|-------|----------|
| 69 | `configuration/bootstrap.mdx` | Lists anti-timing delay on: `/oauth2/login`, `/oauth2/passkey/login`, `/oauth2/forgot-password`, `/oauth2/resend-verification`. Source code shows `RandomDelay()` is called in `emailverification/handler.go`, `passwordreset/handler.go`, and `passkey/handler.go` -- but NOT in `login/handler.go`. Login endpoint does not use anti-timing delay. | :red_circle: Error |

**Fix:** Update the anti-timing delay endpoint list to match actual usage: `/oauth2/passkey/login`, `/oauth2/forgot-password`, `/oauth2/resend-verification`. Remove `/oauth2/login` from the list.

---

## 4. Inconsistencies Between Pages

### 4.1 Config key naming

| # | Setting | Pages using wrong name | Pages using correct name | Severity |
|---|---------|----------------------|------------------------|----------|
| 70 | `require_mfa` | `authentication/mfa.mdx` (`mfa_enabled`), `authentication/overview.mdx` (`mfa_enabled`), `admin-ui/settings.mdx` (`mfa_enabled`), `security/overview.mdx` (`mfa_enabled`), `deployment/production-checklist.mdx` (`mfa_enabled`), `protocol/ropc.mdx` (`mfa_enabled`) | `configuration/runtime-settings.mdx` (`require_mfa`) | :red_circle: |
| 71 | `account_lockout_max_attempts` | `users/account-lockout.mdx` (`lockout_max_attempts`), `admin-ui/settings.mdx` (`lockout_max_attempts`), `security/overview.mdx` (`lockout_max_attempts`), `deployment/production-checklist.mdx` (`lockout_max_attempts`) | `configuration/runtime-settings.mdx` (`account_lockout_max_attempts`) | :red_circle: |
| 72 | `account_lockout_duration` | Same pages as above with `lockout_duration` | `configuration/runtime-settings.mdx` (`account_lockout_duration`) | :red_circle: |

### 4.2 JWK key ID default

| # | Pages | Value claimed | Severity |
|---|-------|--------------|----------|
| 73 | `protocol/oidc-discovery.mdx` | `autentico-key` | :red_circle: |
| 73 | `configuration/bootstrap.mdx`, `protocol/token-structure.mdx` | `autentico-key-1` (correct) | |

### 4.3 RSA key size

| # | Pages | Value claimed | Severity |
|---|-------|--------------|----------|
| 74 | `configuration/bootstrap.mdx` | RSA 2048 | :red_circle: |
| 74 | `architecture/design-decisions.mdx` | 2048-bit | |
| 74 | `deployment/key-generation.mdx` | `openssl genrsa 4096` (implies 4096-bit) | |
| 74 | `security/overview.mdx` | 2048-bit | |

### 4.4 Health check endpoint

| # | Pages | Value claimed | Severity |
|---|-------|--------------|----------|
| 75 | `deployment/docker.mdx` | `/healthz` (correct, matches source: `GET /healthz`) | :blue_circle: |
| 75 | `deployment/production-checklist.mdx` | `GET /.well-known/openid-configuration` as health check | Functional but not the canonical health endpoint |

**Fix:** Production checklist should mention `/healthz` as the dedicated health endpoint. The well-known endpoint works but involves more processing.

### 4.5 Profile field defaults inconsistency

| # | Pages | Docs say | Source code says | Severity |
|---|-------|----------|-----------------|----------|
| 76 | `configuration/runtime-settings.mdx` | Profile fields default to `hidden` | Source: `profile_field_email`, `profile_field_given_name`, `profile_field_family_name` default to `optional`; all others default to `hidden` | :red_circle: Error |

The runtime-settings page says "(values: hidden, optional, required; default: hidden)" as a blanket statement, but 3 fields (`email`, `given_name`, `family_name`) default to `optional`, not `hidden`.

### 4.6 Rate-limited endpoints

| # | Pages | Claimed endpoints | Actual rate-limited endpoints (from `start.go`) | Severity |
|---|-------|------------------|------------------------------------------------|----------|
| 77 | `configuration/bootstrap.mdx`, `security/overview.mdx` | `/oauth2/login`, `/oauth2/mfa`, `/oauth2/token`, `/oauth2/passkey/login/finish` | `/oauth2/login`, `/oauth2/mfa`, `/oauth2/mfa/`, `/oauth2/passkey/login/begin`, `/oauth2/passkey/login/finish`, `/oauth2/forgot-password`, `/oauth2/reset-password`, `/oauth2/token`, `/oauth2/protocol/openid-connect/token`, `/account/api/password`, `/account/api/mfa/totp` (DELETE) | :yellow_circle: Missing |

**Fix:** The docs list only 4 rate-limited endpoints but the actual list is 11. Add the missing ones: forgot-password, reset-password, passkey/login/begin, the Keycloak-compatible token endpoint, and the two account API endpoints.

---

## 5. Improvement Suggestions

### 5.1 Thin/incomplete pages

| # | Page | Issue | Severity |
|---|------|-------|----------|
| 78 | `protocol/scopes.mdx` | Only documents 3 of 7 supported scopes. Missing `address`, `phone`, `offline_access`, `groups`. No examples of address claim structure or phone claims. | :blue_circle: Improvement |
| 79 | `architecture/database-schema.mdx` | Documents 10 of 20 tables. Missing 9 tables added in later features. Should be the single source of truth for the full schema. | :blue_circle: Improvement |
| 80 | `architecture/package-structure.mdx` | Documents 23 of 36 packages. Missing 13 packages for major features (account, audit, consent, deletion, email, federation, groups, etc.). | :blue_circle: Improvement |
| 81 | `api-reference/endpoints.mdx` | Single line pointing to external URL. Should at minimum list all endpoint groups with methods and paths. | :blue_circle: Improvement |
| 82 | `clients/registering.mdx` | Does not mention `consent_required` field or `post_logout_redirect_uris` field. | :blue_circle: Improvement |
| 83 | `admin-ui/sessions.mdx` | Only describes SSO sessions view. Does not explain the distinction between IdP sessions and OAuth sessions, or how cascade revocation works in the UI. | :blue_circle: Improvement |
| 84 | `protocol/introspection-revocation.mdx` | Says introspection is "protected by admin bearer token" but source code shows it accepts both client authentication (Basic/POST) and bearer tokens. | :red_circle: Error |

### 5.2 Missing code examples

| # | Topic | Severity |
|---|-------|----------|
| 85 | Client Credentials grant -- no curl example or dedicated page | :blue_circle: Improvement |
| 86 | RP-Initiated Logout -- no curl example showing all parameters (`id_token_hint`, `post_logout_redirect_uri`, `state`, `client_id`) | :blue_circle: Improvement |
| 87 | Account API usage -- no curl examples for profile update, password change, TOTP setup, passkey management | :blue_circle: Improvement |
| 88 | Groups API -- no curl examples for group CRUD or membership management | :blue_circle: Improvement |
| 89 | Audit log querying -- no curl example or explanation of filtering | :blue_circle: Improvement |
| 90 | Consent screen -- no explanation of how to enable per-client, what the user sees, or how consent is persisted | :blue_circle: Improvement |
| 91 | Federation setup -- no examples of configuring an external IdP (Google, GitHub, etc.) | :blue_circle: Improvement |

### 5.3 Missing integration guides

| # | Topic | Severity |
|---|-------|----------|
| 92 | Account self-service portal integration -- how to embed or link the `/account/` UI | :blue_circle: Improvement |
| 93 | Webhook/event integration -- no docs on audit events as a notification mechanism | :blue_circle: Improvement |
| 94 | Mobile app integration -- PKCE walkthrough focuses on web; no mobile-specific guidance (deep links, custom schemes) | :blue_circle: Improvement |

### 5.4 Cross-linking opportunities

| # | From page | Should link to | Severity |
|---|-----------|---------------|----------|
| 95 | `authentication/mfa.mdx` | Missing link to trusted devices page | :blue_circle: Improvement |
| 96 | `authentication/sso-sessions.mdx` | Missing link to admin session management | :blue_circle: Improvement |
| 97 | `protocol/ropc.mdx` | Should link to MFA docs since ROPC now supports `totp_code` | :blue_circle: Improvement |
| 98 | `clients/registering.mdx` | Should link to per-client overrides page | :blue_circle: Improvement |
| 99 | `users/self-signup.mdx` | Should link to email verification (recommended pairing) | :blue_circle: Improvement |
| 100 | `configuration/per-client-overrides.mdx` | Should mention `consent_required` field | :blue_circle: Improvement |

### 5.5 `AUTENTICO_REFRESH_TOKEN_COOKIE_ONLY` feature

| # | Issue | Severity |
|---|-------|----------|
| 101 | This bootstrap setting enables cookie-only refresh tokens (stripped from JSON response). It's listed in `configuration/bootstrap.mdx` but no docs page explains the rationale, behavior, or implications for SPAs vs server-side apps. | :blue_circle: Improvement |

### 5.6 Keycloak-compatible endpoints

| # | Issue | Severity |
|---|-------|----------|
| 102 | `{oauth}/protocol/openid-connect/token` and `{oauth}/protocol/openid-connect/userinfo` are mentioned on `protocol/overview.mdx` and `integrate/connecting.mdx` but not explained in detail. A brief section explaining when/why to use these aliases would help users migrating from Keycloak. | :blue_circle: Improvement |

---

## Summary

| Category | Count |
|----------|-------|
| :red_circle: Errors | 19 findings |
| :yellow_circle: Missing documentation | 43 findings |
| :blue_circle: Improvements | 25 findings |
| **Total** | **87 findings** |

### Priority fixes (highest impact)

1. **Config key renames** (items 1-4, 70-72): `mfa_enabled` -> `require_mfa`, `lockout_max_attempts` -> `account_lockout_max_attempts`, `lockout_duration` -> `account_lockout_duration`, `AUTENTICO_AUTH_JWK_CERT_KEY_ID` -> `AUTENTICO_JWK_CERT_KEY_ID`. Affects 10+ pages.

2. **Remove phantom config keys** (items 5-6, 32): `AUTENTICO_COOKIE_SECRET`, `AUTENTICO_ADMIN_TOKEN` do not exist. `validation_username_is_email` and `validation_email_required` are not real runtime settings.

3. **Fix OIDC discovery example** (items 10-13): `response_types_supported`, `scopes_supported`, `claims_supported`, and `kid` default are all wrong in the example JSON.

4. **Fix ROPC MFA claim** (item 14): ROPC does enforce MFA via `totp_code` parameter. The docs say the opposite.

5. **Fix unlock endpoint path** (item 9): `POST /admin/api/users/{id}/unlock` not `POST /admin/api/users/unlock`.

6. **Remove rate limiting contradiction** (item 15): Incident response page denies rate limiting exists.

7. **Add missing feature pages** (items 18-28): Consent screen, federation/social login, account deletion, email verification, password reset, audit logging, groups, client credentials grant, RP-initiated logout, settings import/export.

8. **Complete schema docs** (items 51-59): Add 9 missing database tables to the schema page.

9. **Fix anti-timing endpoints** (item 69): Login endpoint does not use anti-timing delay.

10. **Fix profile field defaults** (item 76): Three fields default to `optional`, not `hidden`.
