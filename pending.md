# Pending work for `feat/account-ui-idp-sessions`

Issue: [#228](https://github.com/eugenioenko/autentico/issues/228) — account-ui Sessions tab backed by `idp_sessions` with cascade revocation.

## Tests still failing in full `make test`

- `TestCrossClient_RevokeIsNoOp` — passes alone and in small combos; fails only in the full suite. Root cause is config leakage from earlier tests that mutate `config.Values` without restoring. Partially fixed (AuthSsoSessionIdleTimeout, AuthAccessTokenExpiration, AuthRefreshTokenExpiration now wrapped in `t.Cleanup`) but one more leak remains. Suspects: the many `signup_test.go` mutations of `config.Values.AuthAllowSelfSignup` (none restore), `authorize_tampering_test.go:224`, `rp_initiated_logout_test.go:23`. Wrap those in `t.Cleanup` too.

## Missing from the plan

- **Functional black-box test (two-browser-context cascade):** log in with two different clients via two isolated contexts, revoke device A via `/account/api/sessions/{id}` from context A, verify context B's token still works. Should live under `tests/functional/` (Vitest) or `tests/browser/` (Playwright — use `devices[...]` so UA strings differ in the listing).
- **Swagger regen:** `make generate-docs` has not been run since the `SessionResponse` shape and handler annotations changed.
- **Docs pass:**
  - `CLAUDE.md` session-table row should mention `idp_session_id` on both `auth_codes` and `sessions`.
  - `README.md` / `docs-web` — note the logout scope change (single-device, not all-devices).
- **`rfc/rfc.md` MUST/SHOULD table** — RP-Initiated Logout row should reflect "current End-User session at this OP" scoping.

## Out of scope — file follow-ups

- Email verification handler (`pkg/emailverification/handler.go`) should create an IdP session on successful verification for parity with signup/login. Not a correctness bug — produces one OAuth session with NULL `idp_session_id` that won't show up in the Sessions list and doesn't cascade. No migration needed.
- `DELETE /admin/api/idp-sessions/{id}` for admin force-logout of a specific device — explicitly deferred per issue scope.
- "Sign out everywhere" as a separate explicit action in account-ui.

## Landed in this branch

- Migration 006: `auth_codes.idp_session_id`, `sessions.idp_session_id` (nullable, indexed).
- `idp_session_id` plumbed through `/authorize`, `/login`, `/signup`, `/mfa`, `/passkey`, `/federation`, and `/oauth2/token` (including refresh-token carry-forward).
- `idpsession.DeactivateWithCascade` + unit tests.
- `/oauth2/logout` scoped to current IdP session via cookie; spec-compliant single-device semantics.
- Cleanup sweep for idle IdP sessions (complements `/authorize`'s lazy check).
- `GET/DELETE /account/api/sessions` rewritten against IdP sessions (active_apps_count, is_current derived from access token, current-device cookie clear on delete).
- account-ui Sessions page rewritten with UA parser, active-apps count, current-device confirm → /oauth2/logout redirect.
- E2E test `TestIdpSessionCascade_FullFlow` — authorize → token → list → cascade delete → introspect shows revoked.
