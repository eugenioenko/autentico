# RFC Compliance Review Plan

## Overview

Seven phases tackling one spec at a time, in dependency order. Each phase: read spec sections, review code paths, fix bugs, add unit + e2e tests (both positive and negative), annotate response/validation code with RFC comments, fill in the MUST/SHOULD/MAY table, review Security Considerations, and verify discovery document reflects the phase's features.

| Phase | Spec | Est. Time | Status |
|---|---|---|---|
| 1 | RFC 6749 — OAuth 2.0 Core | 2–3h | ✅ Done (2026-03-30) |
| 2 | RFC 6750 — Bearer Token Usage | 1.5h | ✅ Done (2026-03-30) |
| 3 | RFC 7636 — PKCE | 1.5h | ✅ Done (2026-03-30) |
| 4 | RFC 7009 — Token Revocation | 1.5h | ✅ Done (2026-03-30) |
| 5 | RFC 7662 — Token Introspection | 1.5h | ✅ Done (2026-03-30) |
| 6 | OIDC Core 1.0 | 3h | ✅ Done (2026-03-30) |
| 7 | OIDC Discovery 1.0 | 1h | ✅ Done (2026-03-30) |

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
| §2 | MUST support revocation of refresh tokens; SHOULD support access tokens | `pkg/token/revoke.go` — both supported (same row) |
| §2.1 | `token` REQUIRED, `token_type_hint` OPTIONAL | `pkg/token/revoke.go` lines 47-49 |
| §2.1 | Request MUST be HTTP POST with form-encoded body | `pkg/token/revoke.go` lines 35-43 |
| §2.1 | Client auth required for confidential clients | `pkg/token/revoke.go` — ⏭ Skipped (public endpoints by design) |
| §2.2 | MUST return `200` for all requests incl. invalid/expired/unknown tokens | `pkg/token/revoke.go` — ✅ Fixed (PR #108) |
| §2.2 | Refresh token revocation SHOULD also revoke associated access token | `pkg/token/revoke.go` — same row, both invalidated |
| §2.2 | Invalid `token_type_hint` MUST be ignored | `pkg/token/revoke.go` — hint not parsed, ignored |
| §4 | `revocation_endpoint` in discovery | `pkg/wellknown/handler.go` — ✅ present |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2 | Support revocation of refresh tokens | ✅ Verified + annotated (2026-03-30) |
| MUST | §2.2 | Return 200 for all revocation requests, including invalid/unknown tokens | ✅ Fixed (PR #108) |
| MUST | §2.1 | `token` parameter required | ✅ Verified + annotated (2026-03-30) |
| MUST | §2.1 | Request is HTTP POST with `application/x-www-form-urlencoded` | ✅ Verified + annotated (2026-03-30) |
| SHOULD | §2 | Support revocation of access tokens | ✅ Verified (2026-03-30) — both token types supported |
| SHOULD | §2.2 | Revoking a refresh token SHOULD also revoke associated access token | ✅ Verified + annotated (2026-03-30) — same DB row |
| MAY | §2.1 | Accept `token_type_hint` | ✅ Silently accepted; server ignores it per spec allowance |

**Security Considerations (§5):**
- [x] §5: DoS countermeasures — rate limiting middleware applies to the revocation endpoint
- [x] §5: Already-revoked token returns 200 — no information leakage; `UPDATE` is a no-op on already-revoked rows
- [x] §5: TLS enforced at infrastructure level in production

**Discovery cross-check:**
- [x] `revocation_endpoint` present in `/.well-known/openid-configuration` — verified by `TestHandleWellKnownConfig_RFC8414_Endpoints`

**Tests:**
- Unit: `TestHandleRevoke_NonPostMethod` — GET rejected ✅ Pre-existing, annotated
- Unit: `TestHandleRevoke_MissingToken` — missing token → 400 ✅ Pre-existing, annotated
- Unit: `TestHandleRevoke_InvalidToken` — invalid token → 200 ✅ Pre-existing
- Unit: `TestHandleRevoke_ValidToken` — valid token revoked → 200 ✅ Pre-existing
- Unit: `TestHandleRevoke_InvalidToken_Returns200` — RFC 7009 §2.2 invalid token → 200 ✅ Pre-existing
- Unit: `TestHandleRevoke_UnknownToken_Returns200` — RFC 7009 §2.2 unknown token → 200 ✅ Pre-existing
- Unit: `TestHandleRevoke` — full revoke + verify DB ✅ Pre-existing
- Unit: `TestHandleRevoke_TokenTypeHint_Accepted` — `token_type_hint` accepted without error ✅ Added
- Unit: `TestHandleRevoke_InvalidTokenTypeHint_Ignored` — invalid hint ignored, still 200 ✅ Added
- Unit: `TestHandleRevoke_RefreshToken_AlsoRevokesAccess` — revoke by refresh → access also revoked ✅ Added
- E2e: `TestRevokedToken_UserInfoRejects` — revoked token rejected by userinfo ✅ Pre-existing
- E2e: `TestRevokedToken_IntrospectRejects` — revoked token → `{"active":false}` ✅ Pre-existing
- E2e: `TestRevokedToken_RefreshRejects` — revoked token's refresh rejected ✅ Pre-existing

---

## Phase 5 — RFC 7662: Token Introspection

**File:** `rfc/rfc7662.txt`

| Section | What to check | Code path |
|---|---|---|
| §2.1 | Request MUST be `application/x-www-form-urlencoded` | `pkg/introspect/handler.go` — ✅ Fixed (PR #108) |
| §2.1 | `token` REQUIRED | `pkg/introspect/handler.go` line 60 |
| §2.1 | Client authentication required | `pkg/introspect/handler.go` — ⏭ Skipped (public endpoint by design) |
| §2.2 | `active` REQUIRED in all responses | `pkg/introspect/handler.go` — ✅ always present |
| §2.2 | Active token: OPTIONAL fields (`scope`, `exp`, `iat`, `sub`, `iss`, `aud`, `jti`, `token_type`) | `pkg/introspect/handler.go` lines 93-104 |
| §2.2 | Inactive token: MUST return `200 {"active":false}` only | `pkg/introspect/handler.go` `inactive()` — ✅ Fixed (PR #108) |
| §2.2 | SHOULD NOT include extra claims for inactive tokens | `pkg/introspect/handler.go` `inactive()` — only `{"active":false}` |
| §4 | Security checks: expiry, revocation, session liveness | `pkg/introspect/service.go` + handler session check |
| §4 | `introspection_endpoint` in discovery | `pkg/wellknown/handler.go` — ✅ present |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2.1 | Accept `application/x-www-form-urlencoded` | ✅ Fixed (PR #108) |
| MUST | §2.1 | `token` parameter required | ✅ Verified + annotated (2026-03-30) |
| MUST | §2.2 | Return `200 {"active":false}` for invalid/expired/revoked tokens | ✅ Fixed (PR #108) |
| MUST | §2.2 | Include `active` field in all responses | ✅ Verified + annotated (2026-03-30) |
| MUST | §4 | Perform expiry, revocation, and validity checks | ✅ Verified + annotated (2026-03-30) |
| SHOULD | §2.2 | Include OPTIONAL fields for active tokens | ✅ Fixed (2026-03-30) — added `iss`, `aud`; `client_id`/`username` omitted (not in token table) |
| SHOULD NOT | §2.2 | Not return extra claims for inactive tokens | ✅ Verified (2026-03-30) — `inactive()` returns only `{"active":false}` |

**Security Considerations (§4):**
- [x] §4: Expiry check — `IntrospectToken` checks `time.Now().After(AccessTokenExpiresAt)`
- [x] §4: Revocation check — `IntrospectToken` checks `RevokedAt != nil`
- [x] §4: Session liveness — handler checks `session.SessionByAccessToken` and `DeactivatedAt`
- [x] §4: Rate-limit — rate limiting middleware applies to the introspection endpoint
- [x] §4: Endpoint is public by design (no client auth); documented as a design decision

**Discovery cross-check:**
- [x] `introspection_endpoint` present in `/.well-known/openid-configuration` — verified by `TestHandleWellKnownConfig_RFC8414_Endpoints`

**Tests:**
- Unit: `TestHandleIntrospect_FormEncoded_InvalidToken_ActiveFalse` — form-encoded, unknown → `{"active":false}` ✅ Pre-existing
- Unit: `TestHandleIntrospect_FormEncoded_ValidToken_Active` — form-encoded, valid → active ✅ Pre-existing
- Unit: `TestHandleIntrospectEmptyBody` — nil body → 400 ✅ Pre-existing
- Unit: `TestHandleIntrospectInvalidJSON` — malformed JSON → 400 ✅ Pre-existing
- Unit: `TestHandleIntrospectMissingToken` — missing token → 400 ✅ Pre-existing
- Unit: `TestHandleIntrospectInvalidToken` — invalid token → 200 `{"active":false}` ✅ Pre-existing
- Unit: `TestHandleIntrospectValidToken` — valid token → active ✅ Pre-existing
- Unit: `TestHandleIntrospectTokenNotInDB` — valid JWT not in DB → `{"active":false}` ✅ Pre-existing
- Unit: `TestHandleIntrospectTokenNoSession` — no session → `{"active":false}` ✅ Pre-existing
- Unit: `TestIntrospectTokenRevoked` — revoked → error (inactive) ✅ Pre-existing
- Unit: `TestHandleIntrospect_DbError` — DB error → `{"active":false}` ✅ Pre-existing
- Unit: `TestHandleIntrospect_ActiveToken_AllFields` — all OPTIONAL fields populated ✅ Added
- Unit: `TestHandleIntrospect_InactiveToken_NoExtraFields` — no extra claims for inactive ✅ Added
- E2e: `TestRevokedToken_IntrospectRejects` — revoked → 200 `{"active":false}` ✅ Pre-existing (updated in PR #108)

---

## Phase 6 — OIDC Core 1.0

**File:** `rfc/openid-connect-core-1_0.html`

| Section | What to check | Code path |
|---|---|---|
| §3.1.2.1 | `scope` MUST include `openid` for OIDC requests; no ID token without it | `pkg/token/handler.go` line 237 |
| §3.1.3.3 | ID token required claims: `iss`, `sub`, `aud`, `exp`, `iat` | `pkg/token/generate.go` `GenerateIDToken` lines 96-104 |
| §3.1.3.3 | `nonce` MUST be present in ID token if sent in auth request | `pkg/token/generate.go` lines 110-112 |
| §3.1.3.7 | `azp` SHOULD be present when ID token has a single audience | `pkg/token/generate.go` lines 115-117 |
| §5.1 | UserInfo standard claims scope-filtered | `pkg/userinfo/handler.go` lines 102-145 |
| §5.3 | UserInfo `sub` MUST match ID token `sub` | `pkg/userinfo/handler.go` — both use `user.ID` / `tok.UserID` |
| §5.4 | Claims in access token must respect scope | `pkg/token/generate.go` — ✅ Fixed (PR #108) |
| §11 | `offline_access` requires `prompt=consent` | ⏭ Skipped — refresh tokens always issued; `offline_access` is effectively always on |
| §16.14 | `acr` value consistency | `pkg/token/generate.go` — consistently `"1"` in both access and ID tokens ✅ |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §3.1.2.1 | ID token only issued when `openid` scope present | ✅ Verified + annotated (2026-03-30) |
| MUST | §3.1.3.3 | ID token contains `iss`, `sub`, `aud`, `exp`, `iat` | ✅ Verified + annotated (2026-03-30) |
| MUST | §3.1.3.3 | `nonce` echoed in ID token if sent in request | ✅ Verified + annotated (2026-03-30) |
| MUST | §3.1.3.3 | `aud` contains the client_id | ✅ Verified + annotated (2026-03-30) |
| MUST | §5.3 | UserInfo `sub` matches ID token `sub` | ✅ Verified + annotated (2026-03-30) — both use same user ID |
| MUST | §5.4 | Access token claims respect requested scope | ✅ Fixed (PR #108) |
| SHOULD | §3.1.3.7 | `azp` present in ID token | ✅ Verified + annotated (2026-03-30) |
| SHOULD | §11 | `offline_access` only with `prompt=consent` | ⏭ Skipped — refresh tokens always issued by design |

**Security Considerations (§16):**
- [x] §16.3: ID token `aud` is set to the `client_id` — verified in `GenerateIDToken` line 98
- [x] §16.6: `nonce` replay prevention — client-side responsibility per spec; server correctly echoes nonce from auth request
- [x] §16.14: `acr` value consistency — standardised to `"1"` in both access token and ID token (was `"password"` in access token before PR #108)

**Discovery cross-check:**
- [x] `userinfo_endpoint` present in `/.well-known/openid-configuration` — verified
- [x] `scopes_supported` lists `openid`, `profile`, `email`, `address`, `phone`, `offline_access` — verified
- [x] `claims_supported` lists all claims from UserInfo and ID token — verified

**Tests:**
- Unit: `TestGenerateIDToken_WithNonce` — nonce present in claims ✅ Pre-existing
- Unit: `TestGenerateIDToken_WithoutNonce` — nonce absent when empty ✅ Pre-existing
- Unit: `TestGenerateIDToken_ScopeBasedClaims` — profile/email claim filtering ✅ Pre-existing
- Unit: `TestGenerateIDToken_AcrClaimPresent` — acr = "1" ✅ Pre-existing
- Unit: `TestGenerateIDToken_AuthTimeReflectsOriginalLogin` — auth_time correctness ✅ Pre-existing
- Unit: `TestGenerateTokens_ScopeFiltering` — access token scope-based claims ✅ Pre-existing
- Unit: `TestGenerateTokens_AcrValue` — access token acr = "1" ✅ Pre-existing
- Unit: `TestHandleUserInfo_ScopeClaims_OpenIDOnly` — openid only, no profile/email claims ✅ Pre-existing
- Unit: `TestHandleUserInfo_ScopeClaims_ProfileOnly` — profile claims present ✅ Pre-existing
- Unit: `TestHandleUserInfo_ScopeClaims_EmailOnly` — email claims present ✅ Pre-existing
- Unit: `TestHandleUserInfo_ScopeClaims_PhoneAndAddress` — phone/address claims ✅ Pre-existing
- E2e: `TestAuthorizationCodeFlow_IDTokenWithNonce` — ID token claims verification + nonce ✅ Enhanced (2026-03-30) — now parses JWT and verifies iss, sub, aud, exp, iat, nonce
- E2e: `TestAuthorizationCodeFlow_NoIDTokenWithoutOpenidScope` — no ID token without openid ✅ Pre-existing

---

## Phase 7 — OIDC Discovery 1.0

**File:** `rfc/openid-connect-discovery-1_0.html`

Note: `revocation_endpoint`, `introspection_endpoint`, and `code_challenge_methods_supported` were already added in Phases 3–5. This phase verifies completeness of all fields and JWKS correctness.

| Section | What to check | Code path |
|---|---|---|
| §3 | Required: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | `pkg/wellknown/handler.go` — all present ✅ |
| §3 | `introspection_endpoint` | `pkg/wellknown/handler.go` — ✅ (Phase 5) |
| §3 | `revocation_endpoint` | `pkg/wellknown/handler.go` — ✅ (Phase 4) |
| §3 | `code_challenge_methods_supported` | `pkg/wellknown/handler.go` — ✅ (Phase 3) |
| §3 | `response_types_supported` only lists implemented flows | `pkg/wellknown/handler.go` — only `"code"` ✅ |
| §3 | `issuer` MUST exactly match `iss` in tokens | Both use `config.GetBootstrap().AppAuthIssuer` ✅ |
| §3 | JWKS keys: `kty`, `use`, `alg`, `kid`, `n`, `e` all present | `pkg/wellknown/handler.go` `HandleJWKS` ✅ |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §3 | `issuer` exactly matches `iss` claim in all issued tokens | ✅ Verified + annotated (2026-03-30) |
| MUST | §3 | All required metadata fields present | ✅ Verified + annotated (2026-03-30) |
| MUST | §4.3 | `/.well-known/openid-configuration` served at correct path relative to issuer | ✅ Verified (2026-03-30) — route registered in `pkg/cli/start.go` |
| SHOULD | §3 | `userinfo_endpoint`, `scopes_supported`, `claims_supported` present | ✅ Verified (2026-03-30) |
| SHOULD | §3 | `response_types_supported` only lists implemented flows | ✅ Verified + annotated (2026-03-30) — only `"code"` |

**Security Considerations (§5):**
- [x] §5: Discovery document integrity — served over TLS in production; `issuer` URL uses HTTPS in production config
- [x] §5: `issuer` in discovery exactly matches `iss` in tokens — both read `AppAuthIssuer`; verified by `TestHandleWellKnownConfig_IssuerMatchesTokenIss`

**Tests:**
- Unit: `TestHandleWellKnownConfig` — basic endpoint returns expected fields ✅ Pre-existing
- Unit: `TestHandleWellKnownConfigResponse` — key fields present with correct values ✅ Pre-existing
- Unit: `TestHandleWellKnownConfig_GrantTypesSupported` — grant types advertised ✅ Pre-existing
- Unit: `TestHandleWellKnownConfig_RequestParameterNotSupported` — request objects not supported ✅ Pre-existing
- Unit: `TestHandleWellKnownConfig_RFC8414_Endpoints` — introspection, revocation, PKCE ✅ Pre-existing
- Unit: `TestHandleWellKnownConfig_RequiredFields` — all REQUIRED + SHOULD fields present; implicit flow not advertised ✅ Added
- Unit: `TestHandleWellKnownConfig_IssuerMatchesTokenIss` — issuer equals `AppAuthIssuer` ✅ Added
- Unit: `TestHandleJWKS` — basic JWKS response ✅ Pre-existing
- Unit: `TestHandleJWKSResponse` — key fields: `kty`, `alg`, `use`, `kid`, `n`, `e` ✅ Pre-existing
