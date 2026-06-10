# sectool MCP Proxy Audit

| Field | Value |
|---|---|
| Date | 2026-04-08 (approx.) |
| Auditor | sectool MCP proxy driven by Claude Code (model not recorded — predates the convention in README.md) |
| Commit audited | not recorded |
| Scope | ~2h interactive session, ~112 proxy flows — token endpoints, PKCE, introspection, refresh flow, CSRF, redirect URIs, admin API |

## Findings (5 total)

| Severity | Finding | Status |
|---|---|---|
| HIGH | Token introspection accepted unauthenticated requests, returning active token metadata | Fixed same session |
| MEDIUM | PKCE not enforced at authorization endpoint — public clients could skip `code_challenge` | Fixed (GH #162) |
| MEDIUM | Refresh tokens not rotated on use — same token worked indefinitely | Fixed (GH #163); rotation + replay detection now in `pkg/token/refresh_token.go` |
| LOW | CSRF error message leaked internal config (`AUTENTICO_CSRF_SECURE_COOKIE` env var name + value) | Fixed same session |
| LOW | XSS payload storable in `client_name` (no exploitable render — HTML-encoded on output) | Fixed same session |

## What passed (23 tests, no issues)

Redirect URI validation (6 bypass variants), JWT `alg:none` confusion, scope
escalation, admin authorization, username enumeration, SQL injection, mass
assignment, account lockout, and others.

## Techniques that worked well

- `replay_send` with mutations — capture a real auth request, twist one parameter
- `jwt_decode` — spotted empty `aud` array and algorithm differences between access/refresh tokens
- `cookie_jar` — review of session cookie security attributes
- `proxy_poll` with host/path filters to cut through browser noise
