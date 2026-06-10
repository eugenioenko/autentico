# Security Audit Records

This folder is the single place to record security audits, scans, and reviews of Autentico.
If you (human or agent) perform any security assessment — automated scan, manual pentest,
spec-compliance review, or AI code review — store the results here.

## File naming

```
YYYY-MM-DD-<auditor>-<type>.md
```

- **Date** — when the audit was performed (not when the file was written).
- **Auditor** — the tool name (`owasp-zap`, `sectool`) or, for AI agent reviews, the
  exact model that performed it (e.g. `claude-fable-5`, `claude-opus-4-8`). Never just
  "claude-code" or "ai" — the model matters for judging the review's depth later.
- **Type** — `scan`, `audit`, `security-review`, `conformance`, `pentest`.

Examples: `2026-04-03-owasp-zap-scan.md`, `2026-06-10-claude-fable-5-security-review.md`

## Required content

Every audit file must start with this header table:

| Field | Value |
|---|---|
| Date | YYYY-MM-DD |
| Auditor | tool/model + version, and who ran it |
| Commit audited | short hash of HEAD at audit time |
| Scope | what was covered (endpoints, packages, dimensions) |

Then:

1. **Findings** — a table with severity (CRITICAL/HIGH/MEDIUM/LOW), description,
   location (`file:line` for code findings), and **status** (open / fixed in PR #N / accepted risk).
2. **What passed** — list what was tested and found clean. This is as important as the
   findings: it tells the next auditor what not to re-test.
3. **False positives** (if any) — claims that were investigated and disproved, with evidence.
   Prevents the next audit from re-raising them.

## Rules for agents

- **Never delete or rewrite past audit files.** They are point-in-time records. If a finding
  is fixed later, update its **status** cell (with the PR number) — leave the finding text intact.
- **Always record the commit hash.** A finding without a commit is unverifiable later.
- Before starting a new audit, **read the existing files here** to avoid duplicating
  effort — re-test only what changed since the recorded commit, plus anything new.
- Cross-reference, don't duplicate: spec-compliance detail lives in `rfc/rfc.md`,
  OIDC conformance issues in `openid.md`, CVE-mapped regression tests in
  `tests/security/CVE_REFERENCE.md`. Link to them; summarize only.
- If a finding leads to a code fix, add a regression test under `tests/security/`
  and reference it in the finding's status.

## Index

| Date | Auditor | Type | Result |
|---|---|---|---|
| 2026-03-24 | OpenID Foundation conformance suite | conformance | ✅ Basic OP plan passed, 15 issues documented |
| 2026-04-03 | OWASP ZAP | scan | 0 FAIL / 112 PASS / 4 WARN after fixes (PR #146) |
| 2026-04-08 | sectool MCP + Claude Code | audit | 5 findings (1 HIGH), all fixed; 23 passed tests |
| 2026-04-23 | claude-opus-4-6 | cve-test-audit | 45 CVE-derived attack tests, all passed, no code changes needed (PR #252) |
| 2026-06-10 | claude-fable-5 | security-review | 4 open hardening items, 2 false positives disproved |

Keep this index updated when adding a file.
