# TODO

## High Priority (Core OIDC Gaps)

- [x] **PKCE** — Implement `code_challenge`/`code_verifier` validation (RFC 7636). Supports S256 and plain methods.
- [x] **ID Token** — Return an `id_token` in the token response. JWT access tokens are already issued; `nonce` is captured but unused.
- [x] **Account Lockout** — Wire up lockout logic using existing `failed_login_attempts` and `locked_until` DB columns.

## Medium Priority (Security & Usability)

- [ ] **MFA/TOTP** — Implement two-factor authentication. `two_factor_enabled` column exists in the users table.
- [ ] **Email Verification** — Implement verification flow using existing `email_verification_token` and `email_verification_expires_at` DB columns.
- [ ] **Password Reset** — Add forgot-password / reset flow.
- [ ] **Consent Screen** — Show users what scopes a client is requesting before granting access.

## Lower Priority (Nice-to-Haves)

- [ ] **Client Credentials Grant** — Listed in client model validation but not implemented in the token handler. Needed for service-to-service auth.
- [ ] **`prompt` Parameter Support** — Handle `login`, `consent`, `none`, `select_account` values per OIDC spec.
- [ ] **Audit Logging** — Log security events (logins, failures, token grants).
- [ ] **Social Login / Federation** — Support external identity providers (Google, GitHub, etc.).
