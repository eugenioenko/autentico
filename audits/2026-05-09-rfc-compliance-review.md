# RFC / OIDC Spec Compliance Review (13 phases)

| Field | Value |
|---|---|
| Date | 2026-03-28 → 2026-05-09 (13 phases; date in filename is completion of the last phase) |
| Auditor | Claude Sonnet 4.6 and Claude Opus 4.6 (1M context), Claude Code sessions directed by eugenioenko |
| Commits audited | rolling — one phase per PR; see PR list below |
| Scope | Every implemented spec, item by item: RFC 6749, 6750, 7636, 7009, 7662, 7591, 8414, 8628, 9068, RFC 6819/9700 (refresh rotation), OIDC Core / Discovery / RP-Initiated Logout 1.0 |

## Result

✅ All 13 phases complete. Each phase: read the spec sections, reviewed the code
paths against them, fixed non-compliance bugs, added positive + negative unit and
e2e tests, annotated return paths and validation checks with inline RFC-section
comments, and filled in the MUST/SHOULD/MAY compliance tables.

The phase-by-phase detail and the full MUST/SHOULD/MAY tables live in
[`rfc/rfc.md`](../rfc/rfc.md) — that file is the source of truth; this record
anchors the effort in the audit index.

## Key PRs

| PR | Phase / content |
|---|---|
| #102 | Review plan + OIDC conformance testing setup |
| #108 | Compliance bug fixes — RFC 7009, 7662, 6749, 6750, 8414 |
| #115 | Cross-cutting compliance rules added to the plan |
| #116 | 7-phase spec review with annotations, tests, and bug fixes |
| #132/#135 | Dynamic client registration audited against RFC 7591 |
| #133 | RP-Initiated Logout 1.0 form-param support |
| #136 | Authorization server metadata audited against RFC 8414 |
| #152 | client_credentials grant (RFC 6749 §4.4) |
| #163 | Refresh token rotation (RFC 6819 / RFC 9700) |
| #344 | Device Authorization Grant (RFC 8628) |

## Lasting effects

- Inline RFC-section comments on every return path and validation check (now a
  requirement for new features per `WORKFLOW.md`)
- MUST/SHOULD/MAY tables in `rfc/rfc.md` kept current as features land
- Fed directly into the OIDC Basic certification pass
  ([2026-03-24 conformance record](2026-03-24-oidc-conformance.md))
