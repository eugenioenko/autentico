# OIDC Basic OP Conformance Certification

| Field | Value |
|---|---|
| Date | 2026-03-24 |
| Auditor | OpenID Foundation conformance suite (local Docker), run by eugenioenko |
| Commit audited | (pre-2786355; exact hash not recorded) |
| Scope | `oidcc-basic-certification-test-plan` — full OIDC Core Basic OP profile |

## Result

✅ **Passed.** All tests in the Basic certification plan green.

## Findings

15 issues were surfaced and resolved during the certification effort. They are
documented in detail in [`openid.md`](../openid.md) at the repo root — this file
exists to anchor the date and result in the audit index.

## What passed

The complete Basic OP profile: authorization code flow, ID token claims/signing,
discovery document correctness, userinfo, client authentication variants
(`client_secret_basic`, `client_secret_post`), and error handling per OIDC Core 1.0.

## See also

- Conformance setup instructions: `CLAUDE.md` § OIDC Conformance Testing
- Spec-compliance review phases: [`rfc/rfc.md`](../rfc/rfc.md)
