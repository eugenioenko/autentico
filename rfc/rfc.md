# RFC Compliance Review Plan

## Overview

Seven phases tackling one spec at a time, in dependency order. Each phase: read spec sections, review code paths, fix bugs, add unit + e2e tests (both positive and negative), annotate response/validation code with RFC comments, fill in the MUST/SHOULD/MAY table, review Security Considerations, and verify discovery document reflects the phase's features.

| Phase | Spec | Est. Time | Status |
|---|---|---|---|
| 1 | RFC 6749 — OAuth 2.0 Core | 2–3h | ✅ Done (2026-03-30) |
| 2 | RFC 6750 — Bearer Token Usage | 1.5h | ✅ Done (2026-03-30) |
| 3 | RFC 7636 — PKCE | 1.5h | ✅ Done (2026-03-30) |
| 4 | RFC 7009 — Token Revocation | 1.5h | pending |
| 5 | RFC 7662 — Token Introspection | 1.5h | pending |
| 6 | OIDC Core 1.0 | 3h | pending |
| 7 | OIDC Discovery 1.0 | 1h | pending |

**Recommended order:** 1 → 4 → 5 → 2 → 3 → 6 → 7

---

## Cross-Cutting Rules (apply to every phase)

### 0. Read the spec first
Before touching any code, read every section listed in the phase's "What to check" table in the actual RFC file (`rfc/` directory). Do not rely on the table alone — it was written before the code was fully reviewed and may be incomplete. If a section references other sections, read those too. The goal is to find requirements the table does not yet list, not just to confirm the ones it does. Add missing rows to the table before starting any code work.

### 1. Inline RFC Comments — responses
For every code path that returns an API value or error (success responses, error responses, redirects with error params), add an inline comment referencing the exact spec section that mandates the behavior:

```go
// RFC 7009 §2.2: server MUST return 200 for all revocation requests, including invalid tokens
// RFC 6749 §5.2: invalid_client MUST use 401, all other errors use 400
// OIDC Core §3.1.3.3: nonce MUST be included in ID token if present in auth request
```

Never remove or replace an existing RFC annotation. If the section reference needs correcting, keep the original and add the corrected one alongside it.

### 2. Inline RFC Comments — request validation
Same rule for input validation: wherever a parameter is validated or rejected, annotate with the spec clause that requires the check:

```go
// RFC 7636 §4.1: code_verifier MUST be 43–128 characters, unreserved charset only
// RFC 6749 §4.1.3: redirect_uri MUST match the value used in the authorization request
```

### 3. MUST / SHOULD / MAY compliance table
Each phase section includes a small table tracking keyword-level compliance:

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2.2 | Return 200 for all revocation requests | ✅ |
| SHOULD | §2.2 | Revoke associated access token on refresh revocation | ✅ |
| MAY | §2.1 | Accept `token_type_hint` | ✅ |

This makes the compliance posture explicit and helps prioritise what is a hard requirement vs best-effort.

Before marking any item ✅, read the relevant code and confirm the implementation actually exists. "pending" means not yet implemented — do not change status without verifying the code first.

### 4. Tests — positive and negative
For every bug fixed or behavior enforced, add both a positive test (the happy path works) and a negative test (the violation is rejected). This applies to unit tests and e2e tests. A fix with only one polarity is incomplete: a positive-only test doesn't prove the guard works; a negative-only test doesn't prove the feature works.

List both polarities explicitly in the phase's Tests section, even when the positive counterpart is a pre-existing test. Nothing should be left implicit.

### 5. Security Considerations checklist
Each RFC has a Security Considerations section. At the end of each phase, review it and add a checklist item for anything actionable. Mark items as implemented, skipped (with reason), or a new bug.

### 6. Discovery cross-check
At the end of each phase, verify that every endpoint or capability introduced by that spec is correctly advertised in `/.well-known/openid-configuration`. Do not defer discovery gaps to Phase 7 — fix them in the phase that owns the feature.

---

## Bug Inventory

| Severity | Location | Issue | Spec Reference | Status |
|---|---|---|---|---|
| High | `pkg/token/revoke.go:55` | Returns `401` for expired/invalid tokens instead of `200` | RFC 7009 §2.2 | ✅ Fixed (PR #108) |
| High | `pkg/introspect/handler.go:52` | Returns `401 invalid_token` for inactive tokens instead of `200 {"active":false}` | RFC 7662 §2.2 | ✅ Fixed (PR #108) |
| High | `pkg/introspect/handler.go:31` | Accepts only `application/json`; spec requires `application/x-www-form-urlencoded` | RFC 7662 §2.1 | ✅ Fixed (PR #108) |
| Medium | `pkg/authorize/handler.go:229` | `error_description` not URL-encoded in redirect URL | RFC 6749 §4.1.2.1 | ✅ Fixed (PR #108) |
| Medium | `pkg/token/handler.go` + `pkg/token/revoke.go` | No client authentication on revoke and introspect endpoints | RFC 7009 §2.1, RFC 7662 §2.1 | ⏭ Skipped (public endpoints by design) |
| Medium | `pkg/wellknown/handler.go` | Missing `introspection_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported` | RFC 7662 §4, RFC 7009 §4, RFC 7636 §6.2 | ✅ Fixed (PR #108) |
| Medium | `pkg/token/generate.go:26-44` | Access token always embeds profile/email claims regardless of scope | OIDC Core §5.4 | ✅ Fixed (PR #108) |
| Medium | all protected endpoints | Missing `WWW-Authenticate` header on 401 responses | RFC 6750 §3 | ✅ Fixed (PR #108) |
| Low | `pkg/token/authorization_code.go:84` | `code_verifier` length/charset not validated (43–128 chars, unreserved only) | RFC 7636 §4.1 | ✅ Fixed (PR #108) |
| Low | `pkg/wellknown/handler.go:33` | Advertises `token`, `id_token` response types that are not implemented | OIDC Discovery §3 | ✅ Fixed (PR #108) |
| Low | `pkg/token/generate.go:37` | `acr: "password"` in access token is non-standard | OIDC Core §2 | ✅ Fixed (PR #108) |
| Low | `pkg/token/handler.go` | `scope` absent from token response for `refresh_token` grant | RFC 6749 §5.1 | ✅ Fixed (PR #108) |

---

## Phase 1 — RFC 6749: OAuth 2.0 Core

**File:** `rfc/rfc6749.txt`

| Section | What to check | Code path |
|---|---|---|
| §3.1 | `response_type` validation, required params | `pkg/authorize/handler.go`, `pkg/authorize/model.go` |
| §4.1.2 | Auth response: `code`, `state`; `state` MUST echo client's value | `pkg/login/handler.go` redirect construction |
| §4.1.2.1 | `error_description` MUST be URL-encoded in redirect | `pkg/authorize/handler.go` `redirectWithError` |
| §4.1.3 | Token request: `grant_type`, `code`, `redirect_uri`, client auth | `pkg/token/handler.go`, `pkg/token/authorization_code.go` |
| §4.1.4 | Token response: `scope` must be omitted if identical to requested | `pkg/token/model.go` `TokenResponse` |
| §4.3 | ROPC: `invalid_grant` vs `invalid_client` error codes | `pkg/token/handler.go` password block |
| §4.6 | Refresh: `scope` MUST NOT exceed original; `scope` MUST appear in response | `pkg/token/refresh_token.go` |
| §5.2 | Error response: `error`, `error_description`, HTTP 400 (401 only for `invalid_client`) | `pkg/utils/responses.go` |
| §10.6 | Auth code replay: revoke all tokens for user/client | `pkg/token/revoke.go` |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §4.1.2 | Echo `state` unchanged in auth response | ✅ Fixed (2026-03-30) |
| MUST | §4.1.2.1 | URL-encode `error_description` in redirect | ✅ Fixed (PR #108) |
| MUST | §4.1.3 | Validate `redirect_uri` matches registered value | ✅ Verified + annotated (2026-03-30) |
| MUST | §5.2 | Use HTTP 400 for all errors except `invalid_client` (401) | ✅ Verified + annotated (2026-03-30) |
| MUST NOT | §4.6 | Refresh grant MUST NOT issue scope broader than original | ✅ Fixed (2026-03-30) |
| SHOULD | §4.1.4 | Omit `scope` from token response if identical to requested | ⏭ Skipped — always including scope is safe and aids client transparency |
| SHOULD | §10.6 | Revoke all tokens on auth code replay detection | ✅ Verified + annotated (2026-03-30) |

**Security Considerations (§10):**
- [x] §10.3: Auth codes MUST be single-use and short-lived — `auth_codes.used` flag enforced, expiry validated in `authorization_code.go`
- [x] §10.6: Auth code interception — PKCE mitigates; `RevokeTokensByUserAndClient` called on replay; note PKCE is not yet enforced for all public clients (covered in Phase 3)
- [x] §10.12: CSRF on redirect — `state` is now URL-encoded and echoed unchanged via `url.Values` in both `login/handler.go` and `authorize/handler.go` SSO path

**Discovery cross-check:** RFC 6749 does not define a discovery document — no action needed.

**Tests:**
- Unit: `error_description` URL-encoding — covered by `redirectWithError` using `url.Values` (no separate test needed; existing redirect tests exercise this path)
- Unit: `scope` present in token response for `refresh_token` grant — `TestHandleToken_RefreshTokenGrant_ScopeInResponse` (pre-existing)
- Unit: `TestHandleToken_RefreshTokenGrant_ScopeExpansion_Rejected` ✅ Added
- Unit: `TestHandleToken_RefreshTokenGrant_ScopeDownscope` ✅ Added
- Unit: `TestIsScopeSubset` ✅ Added
- E2e: `TestAuthorizationCodeFlow_StateWithSpecialChars` ✅ Added — verifies state with `=`, `&`, `+` is preserved exactly (exercises URL-encoding fix)
- E2e: `TestAuthorizationCodeFlow_ScopeExpansionOnRefresh_Rejected` ✅ Added — negative test
- E2e: `TestAuthorizationCodeFlow_ScopeDownscope` ✅ Added — positive test

---

## Phase 2 — RFC 6750: Bearer Token Usage

**File:** `rfc/rfc6750.txt`

| Section | What to check | Code path |
|---|---|---|
| §2.1 | `Bearer ` prefix parsing (capital B, single space) | `pkg/utils/extract_bearer_token.go` |
| §2.2 | Form-encoded `access_token`: only `application/x-www-form-urlencoded`, POST only, not alongside header | `pkg/userinfo/handler.go` |
| §3.1 | `WWW-Authenticate` header MUST be set on 401 responses | all protected endpoints |
| §3.1 | `WWW-Authenticate: Bearer realm="...", error="...", error_description="..."` format | all protected endpoints |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §3.1 | Set `WWW-Authenticate` header on 401 | ✅ Fixed (PR #108); extended to `admin_auth` and `auth_audience` middleware (2026-03-30) |
| MUST NOT | §2.2 | Reject requests with token in both header and body | ✅ Fixed (2026-03-30) |
| SHOULD | §2.1 | Accept `Bearer` prefix case-insensitively | ✅ Fixed (2026-03-30) |
| SHOULD | §2.2 | Support form-encoded `access_token` on POST endpoints | ✅ Verified — already implemented in `userinfo/handler.go` |

**Security Considerations (§5):**
- [x] §5.3: No endpoint accepts `access_token` as a URI query parameter — verified; `TestUserInfo_QueryParamToken_NotAccepted` confirms 401 for query-param attempts
- [x] §5.1: TLS enforced at infrastructure level; secure cookie flags gated on `AUTENTICO_CSRF_SECURE_COOKIE` / `AUTENTICO_REFRESH_TOKEN_SECURE`

**Discovery cross-check:** RFC 6750 does not add discovery fields — no action needed.

**Tests:**
- Unit: `TestExtractBearerToken_CaseInsensitive` ✅ Added — positive (lowercase, uppercase, mixed) and negative (wrong scheme)
- Unit: `TestHandleUserInfo_DualCredentials_Rejected` ✅ Added — negative
- Unit: `TestHandleUserInfo_CaseInsensitiveBearer` ✅ Added — positive
- Unit: `TestAdminAuthMiddleware_WWWAuthenticate_On401` ✅ Added — negative (missing, invalid format, invalid token)
- Unit: `TestAdminAuthMiddleware_CaseInsensitiveBearer` ✅ Added — positive
- Unit: `TestAuthAudienceMiddleware_WWWAuthenticate_On401` ✅ Added — negative
- Unit: `TestAuthAudienceMiddleware_CaseInsensitiveBearer` ✅ Added — positive
- E2e: `TestUserInfo_WWWAuthenticateHeader` ✅ Added — negative (no token, invalid token)
- E2e: `TestUserInfo_FormBodyToken` ✅ Added — positive
- E2e: `TestUserInfo_DualCredentials_Rejected` ✅ Added — negative
- E2e: `TestUserInfo_QueryParamToken_NotAccepted` ✅ Added — negative (§5.3 guard)

---

## Phase 3 — RFC 7636: PKCE

**File:** `rfc/rfc7636.txt`

| Section | What to check | Code path |
|---|---|---|
| §4.1 | `code_verifier`: 43–128 chars, unreserved chars only | `pkg/token/authorization_code.go` `validateCodeVerifier` |
| §4.2 | `code_challenge`: `BASE64URL(SHA256(ASCII(verifier)))`, no padding | `pkg/token/authorization_code.go` `verifyCodeChallenge` |
| §4.2 | `code_challenge_method` absent → default to S256 | `pkg/token/authorization_code.go` line 116 |
| §4.3 | If challenge was sent, verifier MUST be sent on exchange | `pkg/token/authorization_code.go` line 56 |
| §4.4.1 | Unsupported method → `invalid_request` error | `pkg/authorize/handler.go` (only S256 advertised) |
| §4.6 | Server verifies code_verifier before returning tokens | `pkg/token/authorization_code.go` line 70 |
| §6.2 | `code_challenge_methods_supported` in discovery | `pkg/wellknown/handler.go` |
| §7.2 | `plain` SHOULD NOT be used | `pkg/authorize/handler.go` — rejected when `AuthPKCEEnforceSHA256` is true (default) |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §4.1 | Validate verifier length (43–128) and charset | ✅ Fixed (PR #108) |
| MUST | §4.3 | Require verifier on exchange if challenge was present | ✅ Verified + annotated (2026-03-30) |
| MUST | §4.6 | Verify code_verifier against code_challenge; return `invalid_grant` on mismatch | ✅ Verified + annotated (2026-03-30) |
| MUST | §4.4.1 | Unsupported transformation → `invalid_request` | ✅ Verified + annotated (2026-03-30) |
| SHOULD | §4.2 | Default `code_challenge_method` to `S256` when absent | ✅ Verified + annotated (2026-03-30) — defaults to S256 (MTI) |
| SHOULD NOT | §7.2 | `plain` method SHOULD NOT be used | ✅ Rejected by default (`AuthPKCEEnforceSHA256=true`); configurable for backwards-compat |
| MAY | §5 | Accept clients that do not use PKCE (backwards compatibility) | ✅ Non-PKCE flows work — PKCE is optional |

**Security Considerations (§7):**
- [x] §7.1: Entropy of `code_verifier` — client-side concern; `validateCodeVerifier` enforces 43–128 chars (≥256 bits of entropy when base64url-encoded from 32 octets)
- [x] §7.2: `plain` rejected by default when `AuthPKCEEnforceSHA256` is true (the default); only `S256` is advertised in discovery; `plain` can be enabled via config for legacy compatibility
- [x] §7.3: Salting not needed — code_verifier contains sufficient entropy per spec
- [x] §7.5: TLS enforced at infrastructure level; secure cookie flags gated on bootstrap config

**Discovery cross-check:**
- [x] `code_challenge_methods_supported: ["S256"]` present in `/.well-known/openid-configuration` — verified by `TestHandleWellKnownConfig_RFC8414_Endpoints`

**Tests:**
- Unit: `TestValidateCodeVerifier_TooShort` — verifier shorter than 43 chars → rejected ✅ Pre-existing
- Unit: `TestValidateCodeVerifier_TooLong` — verifier longer than 128 chars → rejected ✅ Pre-existing
- Unit: `TestValidateCodeVerifier_MinLength` — boundary at 43 chars → accepted ✅ Pre-existing
- Unit: `TestValidateCodeVerifier_MaxLength` — boundary at 128 chars → accepted ✅ Pre-existing
- Unit: `TestValidateCodeVerifier_InvalidChars` — `+`, `/`, space → rejected ✅ Pre-existing
- Unit: `TestValidateCodeVerifier_AllUnreservedChars` — full unreserved charset → accepted ✅ Pre-existing
- Unit: `TestVerifyCodeChallenge_S256` — S256 valid + invalid (RFC 7636 Appendix B vector) ✅ Pre-existing, annotated
- Unit: `TestVerifyCodeChallenge_Plain` — plain valid + invalid ✅ Pre-existing, annotated
- Unit: `TestVerifyCodeChallenge_DefaultsToS256` — empty method defaults to S256 ✅ Pre-existing, annotated
- Unit: `TestVerifyCodeChallenge_UnsupportedMethod` — unknown method rejected ✅ Pre-existing, annotated
- Unit: `TestHandleWellKnownConfig_RFC8414_Endpoints` — asserts `code_challenge_methods_supported` includes `S256` ✅ Pre-existing
- Unit: `TestHandleAuthorize_PKCE_PlainRejected` — plain rejected at authorize endpoint (default config) ✅ Pre-existing
- Unit: `TestHandleAuthorize_PKCE_PlainAllowed_WhenFlagDisabled` — plain allowed when enforcement off ✅ Pre-existing
- Unit: `TestHandleAuthorize_PKCE_S256Accepted` — S256 accepted at authorize endpoint ✅ Pre-existing
- E2e: `TestAuthorizationCodeFlow_PKCE_S256` — full S256 flow end-to-end ✅ Pre-existing
- E2e: `TestAuthorizationCodeFlow_PKCE_WrongVerifier` — wrong verifier → `invalid_grant` ✅ Pre-existing
- E2e: `TestAuthorizationCodeFlow_PKCE_MissingVerifier` — missing verifier when challenge present → error ✅ Pre-existing
- E2e: `TestAuthorizationCodeFlow_PKCE_Plain` — full plain flow end-to-end (enforcement off) ✅ Added
- E2e: `TestAuthorizationCodeFlow_PKCE_PlainRejected` — plain rejected when enforcement on (default) ✅ Added

---

## Phase 4 — RFC 7009: Token Revocation

**File:** `rfc/rfc7009.txt`

| Section | What to check | Code path |
|---|---|---|
| §2.1 | `token` required, `token_type_hint` optional | `pkg/token/revoke.go` |
| §2.1 | Client auth required for confidential clients | `pkg/token/revoke.go` — missing |
| §2.2 | MUST return `200` for all requests incl. invalid/expired/unknown tokens | `pkg/token/revoke.go` — currently returns `401` (BUG) |
| §2.2 | Refresh token revocation SHOULD also revoke associated access token | `pkg/token/revoke.go` |
| §4 | `revocation_endpoint` in discovery | `pkg/wellknown/handler.go` — absent |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2.2 | Return 200 for all revocation requests, including invalid/unknown tokens | ✅ Fixed (PR #108) |
| MUST | §2.1 | `token` parameter required | pending |
| SHOULD | §2.2 | Revoking a refresh token SHOULD also revoke associated access token | pending |
| MAY | §2.1 | Accept and use `token_type_hint` to optimise lookup | pending |

**Security Considerations (§4 / RFC 6749 §10):**
- [ ] §4.1: Ensure revocation endpoint is only reachable over TLS in production
- [ ] Revocation of a token that was already revoked must still return 200 — no information leakage

**Discovery cross-check:**
- [ ] `revocation_endpoint` MUST appear in `/.well-known/openid-configuration` — fix in this phase, not Phase 7

**Tests to add:**
- E2e: `TestRevoke_ExpiredToken_Returns200`
- E2e: `TestRevoke_UnknownToken_Returns200`
- E2e: `TestRevoke_RefreshToken_RevokesAccessToo`
- Unit: `token_type_hint` present — accepted and ignored without error

---

## Phase 5 — RFC 7662: Token Introspection

**File:** `rfc/rfc7662.txt`

| Section | What to check | Code path |
|---|---|---|
| §2.1 | Request MUST be `application/x-www-form-urlencoded` | `pkg/introspect/handler.go` — JSON only (BUG) |
| §2.1 | Client authentication required | `pkg/introspect/handler.go` — missing |
| §2.2 | Active token: `active=true` + all registered claims (`scope`, `exp`, `iat`, `sub`, `client_id`, `username`, `aud`, `jti`) | `pkg/introspect/model.go` — missing `client_id`, `username`, `aud`, `nbf` |
| §2.2 | Inactive token: MUST return `200 {"active":false}` only | `pkg/introspect/handler.go` — returns `401` (BUG) |
| §4 | `introspection_endpoint` in discovery | `pkg/wellknown/handler.go` — absent |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2.1 | Accept `application/x-www-form-urlencoded` | ✅ Fixed (PR #108) |
| MUST | §2.2 | Return `200 {"active":false}` for invalid/expired/revoked tokens | ✅ Fixed (PR #108) |
| MUST | §2.2 | Include `active` field in all responses | pending |
| SHOULD | §2.2 | Include `scope`, `exp`, `iat`, `sub`, `client_id`, `username`, `aud`, `jti` for active tokens | pending |
| SHOULD NOT | §2.2 | Not return extra claims for inactive tokens (only `{"active":false}`) | pending |

**Security Considerations (§4):**
- [ ] §4: Introspection responses may contain sensitive data — ensure endpoint requires auth in future (currently public by design; document this decision)
- [ ] §4: Rate-limit introspection to prevent token enumeration

**Discovery cross-check:**
- [ ] `introspection_endpoint` MUST appear in `/.well-known/openid-configuration` — fix in this phase, not Phase 7

**Tests to add:**
- E2e: `TestIntrospect_ExpiredToken_ActiveFalse`
- E2e: `TestIntrospect_RevokedToken_ActiveFalse`
- E2e: `TestIntrospect_UnknownToken_ActiveFalse`
- E2e: `TestIntrospect_FormEncoded` (after fix)
- E2e: `TestIntrospect_ActiveToken_AllFields` — assert all required fields present
- Note: existing tests `TestRevokedToken_IntrospectRejects` and `TestExpiredAccessToken_IntrospectRejects` assert `401` — these must be updated to expect `200 {"active":false}`

---

## Phase 6 — OIDC Core 1.0

**File:** `rfc/openid-connect-core-1_0.html`

| Section | What to check | Code path |
|---|---|---|
| §3.1.2.1 | `scope` MUST include `openid` for OIDC requests | `pkg/authorize/model.go` |
| §3.1.3.3 | ID token required claims: `iss`, `sub`, `aud`, `exp`, `iat` | `pkg/token/generate.go` `GenerateIDToken` |
| §3.1.3.3 | `nonce` MUST be present in ID token if sent in auth request | `pkg/token/generate.go` |
| §3.1.3.3 | `acr: "password"` non-standard; ID token uses `"1"` — inconsistency | `pkg/token/generate.go` lines 37, 95 |
| §5.1 | UserInfo standard claims scope-filtered | `pkg/userinfo/handler.go` |
| §5.3 | UserInfo `sub` MUST match ID token `sub` | `pkg/userinfo/handler.go` |
| §5.4 | Claims in access token must respect scope | `pkg/token/generate.go` — always includes profile claims (BUG) |
| §11 | `offline_access` requires `prompt=consent` | `pkg/token/handler.go` — not enforced |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §3.1.2.1 | `scope` includes `openid` for OIDC requests | pending |
| MUST | §3.1.3.3 | ID token contains `iss`, `sub`, `aud`, `exp`, `iat` | pending |
| MUST | §3.1.3.3 | `nonce` echoed in ID token if sent in request | pending |
| MUST | §5.3 | UserInfo `sub` matches ID token `sub` | pending |
| MUST | §5.4 | Access token claims respect requested scope | ✅ Fixed (PR #108) |
| SHOULD | §11 | `offline_access` only issued with `prompt=consent` | pending |

**Security Considerations (§16):**
- [ ] §16.3: ID token audience — `aud` MUST be validated by clients; verify our tokens set `aud` to the correct client ID
- [ ] §16.6: `nonce` replay prevention — once an ID token with a given nonce is consumed, it should not be reusable; note this is client-side but worth documenting
- [ ] §16.14: `acr` value consistency — using `"password"` vs `"1"` inconsistently; standardise to a registered value

**Discovery cross-check:**
- [ ] `userinfo_endpoint` present in `/.well-known/openid-configuration`
- [ ] `scopes_supported` lists all supported scopes (`openid`, `profile`, `email`, `offline_access`, etc.)
- [ ] `claims_supported` lists all claims returned by UserInfo and ID token

**Tests to add:**
- E2e: `TestIDToken_Claims_Verification` — parse and validate all required claims
- E2e: `TestIDToken_Nonce_Preserved` — nonce in decoded token matches sent value
- E2e: `TestUserInfo_Sub_MatchesIDToken`
- E2e: `TestUserInfo_ScopeFiltering` — `openid` only; no `email`/`profile` claims
- Unit: `GenerateIDToken` — all required claims, correct absence of optional ones
- Unit: access token does not include profile claims when `profile` scope absent

---

## Phase 7 — OIDC Discovery 1.0

**File:** `rfc/openid-connect-discovery-1_0.html`

Note: `revocation_endpoint`, `introspection_endpoint`, and `code_challenge_methods_supported` should already be present by the time this phase runs (fixed in Phases 3–5). This phase focuses on completeness of all remaining fields and JWKS correctness.

| Section | What to check | Code path |
|---|---|---|
| §3 | Required: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | `pkg/wellknown/handler.go` — all present |
| §3 | `introspection_endpoint` — should be fixed in Phase 5 | `pkg/model/well_known_config.go` |
| §3 | `revocation_endpoint` — should be fixed in Phase 4 | `pkg/model/well_known_config.go` |
| §3 | `code_challenge_methods_supported` — should be fixed in Phase 3 | `pkg/model/well_known_config.go` |
| §3 | `response_types_supported` lists `token`, `id_token` — implicit flow not implemented | `pkg/wellknown/handler.go` |
| §3 | `issuer` MUST exactly match `iss` in tokens | `pkg/wellknown/handler.go` vs `pkg/token/generate.go` |
| §3 | JWKS keys: `kty`, `use`, `alg`, `kid`, `n`, `e` all present | `pkg/wellknown/handler.go` `HandleJWKS` |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §3 | `issuer` exactly matches `iss` claim in all issued tokens | pending |
| MUST | §3 | All required metadata fields present | pending |
| MUST | §4.3 | `/.well-known/openid-configuration` served at correct path relative to issuer | pending |
| SHOULD | §3 | `userinfo_endpoint`, `scopes_supported`, `claims_supported` present | pending |
| SHOULD | §3 | `response_types_supported` only lists implemented flows | pending |

**Security Considerations (§5):**
- [ ] §5: Discovery document integrity — served over TLS in production; no action needed in code but worth verifying `issuer` URL uses HTTPS in production config
- [ ] Ensure `issuer` in discovery exactly matches the `iss` in tokens to prevent token substitution attacks across issuers

**Tests to add:**
- E2e: `TestWellKnown_RequiredFields` — all required fields present with correct types
- E2e: `TestWellKnown_IssuerMatchesTokenIss` — compare `issuer` in discovery to `iss` in token
- E2e: `TestJWKS_Structure` — assert key fields present
- E2e: `TestJWKS_ValidatesIDToken` — use JWKS to verify ID token signature
- Unit: assert `introspection_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported` present (should pass after earlier phases)
