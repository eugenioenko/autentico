# Incremental security review: gpt-6-astra

| Field | Value |
|---|---|
| Date | 2026-11-10 |
| Auditor | OpenAI gpt-6-astra (Codex), directed by eugenioenko; source review, local Go tests and govulncheck v1.1.4 |
| Commit audited | `e7280161320273a19509d6a47c8e03f88b40df71` |
| Scope | Changes since the October 22 audit (`fa45835`): ForwardAuth, configurable cookies, federation claim admission, inherited/merged group claims, selected prior fixes; build-toolchain and CSRF dependency triage |

This is an incremental source and handler-level assessment, not a full external
pentest or certification. Daybreaker was not available through the connected
tools or local executable lookup. Tests ran against an archive of the committed
source, isolated from the developer's working changes, database and server.
No application fixes were made as part of this report.

## Findings

| Severity | Finding | Location | Evidence | Status |
|---|---|---|---|---|
| MEDIUM | Build and release configuration selects Go 1.25, a release line outside the current upstream support window. The local Go 1.25.1 scan also reports known affected standard-library symbols. Builds need a supported, patched toolchain and release-artifact verification. | `Dockerfile:2`, `.github/workflows/ci.yml:12`, `.github/workflows/release.yml:9` | Configuration inspection, upstream release policy, local scanner; no released binary inspected | Open |
| LOW | CSRF middleware trusts the configured hostname irrespective of scheme: an HTTPS POST with `Origin: http://<configured host>` and a valid CSRF cookie/token pair reaches the protected handler. Removing that trusted-host exemption rejects the same request. This matches the origin-validation weakness in GO-2025-3884. | `pkg/middleware/csrf.go:42` | Reproduced handler-level probe with positive and negative controls | Open |

### Toolchain finding: scope and remediation

The local environment used `go1.25.1 linux/amd64`. `govulncheck ./...` exited 3
and reported **50 symbol-level advisories**, summarized in
[the scanner evidence](evidence/2026-11-10/govulncheck-summary.txt). Its summary
attributes these to one module and the standard library; it additionally lists
6 imported-package and 11 required-module advisories without called vulnerable
symbols. These are scanner classifications, **not 50 confirmed exploits**.
The `./...` scope includes test utility packages, and some traces are incidental
or depend on functionality/configuration not used by this server.

The Go 1.25.1 local result does not establish which patch version built a deployed
image. CI selects `1.25` and Docker selects `golang:1.25-bookworm`, so those builds
can have newer patches than the local executable. Nevertheless, both stay on
the same unsupported release line. The `go 1.25.0` language/minimum directive in
`go.mod` alone is not a pin to the local vulnerable patch.

Upstream's [release policy and history](https://go.dev/doc/devel/release) lists
Go 1.27 and 1.26 as the current two release lines. Move CI and Docker builds to a
supported patched release, rerun tests and scan the actual release binaries.
Then triage any remaining module reports individually. As one example of the
local exposure, [GO-2026-4341](https://pkg.go.dev/vuln/GO-2026-4341) describes
excessive allocation parsing many form/query parameters, fixed in Go 1.25.6;
the scanner identifies calls in logout and passkey handling. No resource
exhaustion attack was run during this assessment.

### CSRF finding: reproduction and limits

The retained [probe](evidence/2026-11-10/csrf_origin_test.go.txt) exercises the
actual `CSRFMiddleware`, with HTTPS requests, secure CSRF cookies and a synthetic
protected handler. It first obtains a valid cookie/token pair through a GET.
The [captured output](evidence/2026-11-10/csrf-probe.txt) records:

| POST origin and credentials | Observed result |
|---|---|
| HTTPS configured host, valid pair | 204 |
| HTTP configured host, valid pair | 204 — scheme downgrade accepted |
| Foreign HTTPS host, valid pair | 403 |
| HTTP configured host, missing token | 403 |
| HTTP configured host, valid pair, trusted-host exemption removed | 403 |

This confirms a failed scheme check, not theft of a victim token or a completed
browser CSRF exploit. The probe manually supplies cookies; it does not model
SameSite, HSTS, cookie injection or a network attacker. A real exploit requires
additional conditions that provide an accepted cookie/token pair and permit
browser delivery. Token validation continues to work, which is why this report
rates the demonstrated application weakness LOW rather than claiming a general
authentication bypass.

The [upstream advisory](https://pkg.go.dev/vuln/GO-2025-3884) identifies the
hostname-only `TrustedOrigins` behavior and recommends scheme-aware cross-origin
protection. Evaluate removing the redundant same-host exemption or adding
scheme-aware protection. Preserve explicit development HTTP behavior and test
TLS termination at trusted proxies. An eventual fix should add a permanent
negative regression in `tests/security/`; the archived probe intentionally
asserts the behavior observed at this commit and is not part of ordinary CI.

## What passed

Source review and existing tests supported the following boundaries:

- **ForwardAuth:** trusted network peer and exact app-origin checks; return-path
  restrictions; encrypted browser-flow cookies; state/nonce/S256 binding;
  single-use callback consumption; expiry recheck after obtaining the writer;
  current parent/account/MFA policy; unverified-email withholding; configured
  and legacy authentication-cookie stripping. Tests include concurrent callbacks,
  expiry during redemption, rollback on injected failures and policy changes.
- **Federation admission:** signed ID-token and nonce checks precede claim
  evaluation; rules use strict types; absent/null/wrong-type negative matches
  fail; current provider policy is reread after upstream I/O; rejected claims
  create no local account/session/code. The mock-upstream callback suite passed.
- **Group claims:** SQL parameters bind user input; inherited and direct claims
  resolve together; direct values override according to the documented contract;
  merged reserved names are filtered; group and user claim tests passed.
- **Prior fix regressions:** the security suite and token, revocation, logout,
  account and trusted-device packages passed. This includes existing tests for
  PKCE downgrade rejection, email-verification enforcement, privileged revocation,
  invalid logout hints, device decisions and trusted-device credential hashing.
- **Cookie configuration:** validation and middleware tests passed. The CSRF
  origin weakness above is an additional explicit probe, not contradicted by
  those existing passing tests.

Commands and results are retained in
[test-results.txt](evidence/2026-11-10/test-results.txt). The first security-suite
attempt could not compile because archived source lacks generated UI bundles.
Adding CI-style placeholder `dist/index.html` files in the isolated copy resolved
that setup error; no browser/UI result is inferred from those placeholders.

All 12 selected package/suite runs passed. Race-detector runs for ForwardAuth,
federation, user claims and group claims also passed with no reported data races.

To reproduce the independent CSRF probe from a checkout containing this report:

```bash
audit_checkout=$(mktemp -d)
git archive e7280161320273a19509d6a47c8e03f88b40df71 | tar -x -C "$audit_checkout"
cp audits/evidence/2026-11-10/csrf_origin_test.go.txt "$audit_checkout/pkg/middleware/audit_origin_test.go"
(cd "$audit_checkout" && go test -p 1 ./pkg/middleware -run TestAuditCSRFOriginDowngrade -v -count=1)
```

The broader security suite and `govulncheck ./...` reproduction also need the
generated embedded UI directories; CI uses a placeholder `index.html` in each
of `pkg/admin/dist` and `pkg/account/dist`. Run the commands in the evidence file
inside that isolated copy. Scanner results can change as its advisory database
changes, and the local Go version affects standard-library results.

## False positives and bounded conclusions

- A group-local `role` claim does not become a top-level authorization role:
  the default mode prefixes it, and merge mode explicitly filters reserved names.
- A negative federation rule does not admit a missing or mistyped claim: the
  evaluator rejects these before negating a comparison, and callback tests pass.
- Scanner call-graph reachability does not prove exploitable TLS/server behavior,
  affected deployment versions, or that every diagnostic is reachable by an
  unauthenticated attacker. Those questions need advisory-specific analysis.
- The HTTP-origin CSRF probe is not a tokenless bypass; the missing-token
  control is rejected.

## Coverage limits and follow-up

No new authorization bypass was confirmed in the reviewed ForwardAuth,
federation admission or group-claim code. This is a bounded result, not proof
that those features have no vulnerabilities.

Not run: Daybreaker, a fresh ZAP scan, OIDF conformance, the full Go suite,
real Caddy/nginx/Traefik browser tests, real React UI tests, a live Kubernetes
deployment, TLS/network interception attacks, long-duration load, or a scan of
published binaries/container layers. Proxy fixture configurations were read,
but their runtime behavior was not independently revalidated. Existing security
tests were rerun; the CSRF matrix is the new independent probe in this review.

The October 22 report's pre-account-takeover and admin recovery findings are
not closed by this assessment. Older audit status cells still need a separate
issue/PR reconciliation; their stale labels must not be treated as fresh proof
of current vulnerabilities. See the [previous pentest](2026-10-22-claude-opus-5-5-pentest.md),
[security invariants](../rfc/security-invariants.md), and
[CVE regression mapping](../tests/security/CVE_REFERENCE.md).
