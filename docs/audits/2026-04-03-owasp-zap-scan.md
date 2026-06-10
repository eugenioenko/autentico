# OWASP ZAP API Scan

| Field | Value |
|---|---|
| Date | 2026-04-03 (fixes merged in PR #146, commit 2786355) |
| Auditor | OWASP ZAP (authenticated + unauthenticated API scan), run by eugenioenko |
| Commit audited | parent of 2786355 |
| Scope | 169 URLs — all public OAuth/OIDC endpoints plus admin and account APIs |

## Result

- **Before fixes:** 0 FAIL, 111 PASS, 8 WARN
- **After fixes (PR #146):** 0 FAIL, 112 PASS, 4 WARN — remaining 4 WARNs are
  informational / by-design.

## Findings

| Severity | Finding | Status |
|---|---|---|
| MEDIUM | Missing OWASP security headers (X-Frame-Options, X-Content-Type-Options, CSP, Permissions-Policy, COEP, COOP) | Fixed in PR #146 — added `pkg/middleware/security_headers.go` |
| LOW | DELETE endpoints returned 500 instead of 404 for nonexistent resources | Fixed in PR #146 |

## What passed

111 ZAP checks including injection classes, cookie attributes on authenticated
flows, and information-disclosure probes across the scanned surface.

## Notes

Follow-up: PR #149 (2026-04-05) relaxed the CSP to allow Google Fonts after the
header rollout broke the hosted UIs.
