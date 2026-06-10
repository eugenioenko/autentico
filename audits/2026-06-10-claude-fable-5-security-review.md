# Security Code Review — claude-fable-5

| Field | Value |
|---|---|
| Date | 2026-06-10 |
| Auditor | claude-fable-5 (Claude Code), static review with agent fan-out + manual verification of every flagged item |
| Commit audited | 961f5bf |
| Scope | 10 dimensions: credential storage, token security, SQL injection, auth code/PKCE, session/cookie security, CSRF, rate limiting/brute force, open redirect/SSRF, headers/output, secrets/randomness/enumeration |

## Findings

| Severity | Finding | Location | Status |
|---|---|---|---|
| HIGH | Refresh tokens stored in plaintext in the `tokens` table — DB leak yields usable refresh tokens for all active sessions. Contrast: password-reset and magic-link tokens are SHA-256-hashed before storage. Rotation/replay detection limits but does not eliminate the blast radius. | `pkg/token/create.go`, `pkg/token/generate.go` | Open |
| HIGH | Abandoned `dgrijalva/jwt-go` (unmaintained since 2021, CVE-2020-26160) still used in production paths alongside the maintained `golang-jwt/jwt/v5`. Migration should be finished. | `pkg/token/generate.go`, `pkg/token/decode.go`, `pkg/jwtutil/validate.go`, `pkg/session/logout.go` | Open |
| MEDIUM | TOTP secrets stored in plaintext in `users.totp_secret` — DB compromise bypasses MFA. Encrypting at rest (AES-GCM, key from env) mitigates DB-file-only leaks. | `pkg/user/update.go:182`, `pkg/db/migrations/001_initial_schema.go` | Open |
| MEDIUM | CSP `form-action *` — the inline comment justifies it by post-login redirects, but `form-action` governs form *submission* targets (always same-origin here), not redirect targets. Likely tightenable to `'self'`; verify against conformance suite. | `pkg/middleware/security_headers.go:31-39` | Open |
| LOW | `fmt.Sprintf` interpolates table names into DELETE statements. Safe today (hardcoded table list) but an injection antipattern if refactored. | `pkg/user/delete.go:85` | Open |

## False positives (investigated and disproved)

| Claim | Evidence against |
|---|---|
| "No refresh token rotation" | Rotation with replay detection implemented per RFC 6819 §5.2.2.3 — a replayed rotated token revokes all of the user's tokens. `pkg/token/refresh_token.go:80-96` (GH #163). |
| "No MFA attempt limits" | Challenges invalidated after 5 failed attempts for both TOTP and email OTP. `pkg/mfa/handler.go:195,210`. |

## What passed

- **Credential storage:** bcrypt for passwords and client secrets; dummy-hash compare + `utils.RandomDelay()` against enumeration timing (`pkg/user/authenticate.go`); account lockout configurable.
- **Token security:** RS256 strictly enforced, alg-confusion rejected (`pkg/jwtutil/validate.go:72`); auth codes single-use, reuse revokes all user tokens (`pkg/token/authorization_code.go:33-38`); PKCE verified, S256 default.
- **SQL injection:** parameterized queries throughout; list endpoints use allowlisted sort/filter fields via `BuildListQuery`; LIKE patterns parameterized.
- **Cookies:** HttpOnly + Secure + SameSite (Strict for refresh token and trusted device, Lax for IdP session).
- **CSRF:** gorilla/csrf on interactive routes, generic error messages, no suspicious exemptions.
- **SSRF:** federation `safeHTTPClient` blocks private/loopback/link-local IPs, 5-redirect limit, 10s timeout (`pkg/federation/safeclient.go`).
- **Misc:** `crypto/rand` everywhere security-relevant; `hmac.Equal` for signature comparisons; password reset / email verification / magic link tokens hashed and single-use; "email sent" responses regardless of account existence; per-request CSP nonces; ~43 audit-log call sites.

## See also

- Prior coverage to not re-test: [2026-04-08 sectool audit](2026-04-08-sectool-claude-audit.md), [2026-04-03 ZAP scan](2026-04-03-owasp-zap-scan.md)
- CVE-mapped regression tests: `tests/security/CVE_REFERENCE.md`
