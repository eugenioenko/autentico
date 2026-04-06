# RFC Compliance Review Plan

## Overview

Ten phases tackling one spec at a time, in dependency order. Each phase: read spec sections, review code paths, fix bugs, add unit + e2e tests (both positive and negative), annotate response/validation code with RFC comments, fill in the MUST/SHOULD/MAY table, review Security Considerations, and verify discovery document reflects the phase's features.

| Phase | Spec | Est. Time | Status |
|---|---|---|---|
| 1 | RFC 6749 — OAuth 2.0 Core | 2–3h | ✅ Done (2026-03-30) |
| 2 | RFC 6750 — Bearer Token Usage | 1.5h | ✅ Done (2026-03-30) |
| 3 | RFC 7636 — PKCE | 1.5h | ✅ Done (2026-03-30) |
| 4 | RFC 7009 — Token Revocation | 1.5h | ✅ Done (2026-03-30) |
| 5 | RFC 7662 — Token Introspection | 1.5h | ✅ Done (2026-03-30) |
| 6 | OIDC Core 1.0 | 3h | ✅ Done (2026-03-30) |
| 7 | OIDC Discovery 1.0 | 1h | ✅ Done (2026-03-30) |
| 8 | OIDC RP-Initiated Logout 1.0 | 1.5h | ✅ Done (2026-04-03) |
| 9 | RFC 7591 — Dynamic Client Registration | 1.5h | ✅ Done (2026-04-03) |
| 10 | RFC 8414 — OAuth 2.0 Authorization Server Metadata | 0.5h | ✅ Done (2026-04-03) |

**Recommended order:** 1 → 4 → 5 → 2 → 3 → 6 → 7 → 8 → 9 → 10

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

---

## Phase 8 — OIDC RP-Initiated Logout 1.0

**Spec:** https://openid.net/specs/openid-connect-rpinitiated-1_0.html (Final, September 2022)

**Context:** GitHub issue #131 — `POST /oauth2/logout` only accepted Bearer tokens, rejecting `client_secret_basic` and form-encoded params. The root cause was a spec gap: the POST handler was a custom Bearer-only endpoint and did not implement RP-Initiated Logout 1.0 §2, which requires POST to accept the same form-encoded params as GET.

| Section | What to check | Code path |
|---|---|---|
| §2 | OP MUST support GET and POST at the Logout Endpoint | `pkg/session/logout.go` `HandleLogout` (POST) + `HandleRpInitiatedLogout` (GET) |
| §2 | POST uses Form Serialization (same params as GET) | `pkg/session/logout.go` `HandleLogout` → `rpInitiatedLogout` |
| §2 | `id_token_hint` RECOMMENDED; expired tokens accepted | `pkg/session/logout.go` `parseIDTokenHint` — `Valid()` always returns nil |
| §2 | OP MUST validate it was the issuer of the ID Token | `pkg/session/logout.go` `parseIDTokenHint` — verifies JWT signature against our key |
| §2 | When both `client_id` and `id_token_hint` present, MUST verify they match | `pkg/session/logout.go` `rpInitiatedLogout` lines 192–207 |
| §3 | `post_logout_redirect_uri` MUST have been previously registered | `pkg/session/logout.go` `rpInitiatedLogout` — exact match against `GetPostLogoutRedirectURIs()` |
| §3 | MUST NOT redirect if URI doesn't exactly match | `pkg/session/logout.go` `rpInitiatedLogout` — falls through to `renderLogoutSuccess` |
| §4 | On validation failure, MUST NOT perform post-logout redirection | `pkg/session/logout.go` `rpInitiatedLogout` — `client_id` mismatch returns logout page |
| §2.1 | `end_session_endpoint` in discovery | `pkg/wellknown/handler.go` line 47 |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2 | Support HTTP GET and POST at Logout Endpoint | ✅ Fixed (2026-04-03) — POST now delegates to shared `rpInitiatedLogout` |
| MUST | §2 | POST uses Form Serialization for same params as GET | ✅ Fixed (2026-04-03) — `HandleLogout` parses form params |
| MUST | §2 | Validate OP was issuer of `id_token_hint` | ✅ Verified + annotated (2026-04-03) — JWT signature verification |
| MUST | §2 | When both `client_id` and `id_token_hint` present, verify `client_id` matches | ✅ Fixed (2026-04-03) — mismatch aborts redirect |
| MUST | §2 | If End-User says "yes" to logout, OP MUST log out | ✅ Verified (2026-04-03) — sessions deactivated unconditionally when hint has subject |
| MUST | §2.1 | `end_session_endpoint` in discovery when RP-Initiated Logout is supported | ✅ Pre-existing |
| MUST | §3 | `post_logout_redirect_uri` must be pre-registered | ✅ Verified + annotated (2026-04-03) — exact match against registered URIs |
| MUST NOT | §3 | Must NOT redirect if URI doesn't match a registered value | ✅ Verified + annotated (2026-04-03) — falls through to logout page |
| MUST NOT | §4 | Must NOT redirect when validation fails | ✅ Fixed (2026-04-03) — `client_id` mismatch renders logout page |
| RECOMMENDED | §2 | `id_token_hint` parameter | ✅ Supported but not required |
| RECOMMENDED | §3 | `id_token_hint` when `post_logout_redirect_uri` is included | ✅ Verified — redirect works with `client_id` alone as "other means" per §3 |
| SHOULD | §2 | Accept expired ID tokens when session is current/recent | ✅ Verified + annotated (2026-04-03) — `Valid()` always returns nil |
| SHOULD | §2 | Ask End-User whether to log out | ⏭ Skipped — logout is immediate per design (API-first IdP, not interactive confirmation flow) |
| SHOULD | §2 | Treat suspect `id_token_hint` (sid mismatch) as suspect | ⏭ Skipped — no `sid`-based session correlation in id_token_hint parsing |
| OPTIONAL | §2 | `client_id` parameter | ✅ Supported |
| OPTIONAL | §2 | `post_logout_redirect_uri` parameter | ✅ Supported |
| OPTIONAL | §2 | `state` parameter | ✅ Supported — passed through to redirect URI |
| OPTIONAL | §2 | `logout_hint` parameter | ⏭ Not implemented — spec leaves meaning up to OP |
| OPTIONAL | §2 | `ui_locales` parameter | ⏭ Not implemented — single-locale UI |

**Bug Inventory:**

| Severity | Location | Issue | Spec Reference | Status |
|---|---|---|---|---|
| High | `pkg/session/logout.go:32` | `POST /oauth2/logout` only accepts Bearer token; rejects form-encoded RP-Initiated Logout params | RP-Initiated Logout 1.0 §2 | ✅ Fixed (2026-04-03) |
| Medium | `pkg/session/logout.go` | No `client_id` vs `id_token_hint` mismatch validation | RP-Initiated Logout 1.0 §2 | ✅ Fixed (2026-04-03) |

**Security Considerations (§6):**
- [x] §6: Logout requests without a valid `id_token_hint` are a potential DoS vector — OPs should obtain explicit confirmation. Skipped: Autentico is API-first; logout without hint simply clears the IdP cookie and renders a logout page (no destructive side effects without a valid subject claim).
- [x] §6: End-User may expect complete logout including at the OP — both IdP sessions and OAuth sessions are deactivated when `id_token_hint` provides a subject.

**Discovery cross-check:**
- [x] `end_session_endpoint` present in `/.well-known/openid-configuration` — pre-existing, verified by `TestHandleWellKnownConfig_RequiredFields`

**Tests:**
- Unit: `TestHandleLogout` — Bearer logout (positive, backward compat) ✅ Pre-existing
- Unit: `TestHandleLogout_NoAuthNoParams_ShowsLogoutPage` — POST with no auth or params renders logout page ✅ Updated (was `TestHandleLogoutMissingAuth`)
- Unit: `TestHandleLogoutInvalidToken` — Bearer with invalid JWT → 401 ✅ Pre-existing
- Unit: `TestHandleLogout_BasicAuth_FallsThrough` — Basic Auth falls through to spec path ✅ Updated (was `TestHandleLogoutInvalidAuthFormat`)
- Unit: `TestHandleLogout_ClearsIdpSessionCookie` — Bearer logout clears IdP cookie ✅ Pre-existing
- Unit: `TestHandleLogout_RevokesIdpSessionWithoutCookie` — server-side Bearer logout revokes IdP sessions ✅ Pre-existing
- Unit: `TestHandleLogout_NoIdpSession` — Bearer logout without IdP session ✅ Pre-existing
- Unit: `TestHandleLogout_POST_WithIdTokenHint_DeactivatesSessions` — POST form id_token_hint deactivates sessions (positive) ✅ Added
- Unit: `TestHandleLogout_POST_WithPostLogoutRedirectURI` — POST form redirect with registered URI (positive) ✅ Added
- Unit: `TestHandleLogout_POST_WithPostLogoutRedirectURIAndState` — POST form redirect with state passthrough (positive) ✅ Added
- Unit: `TestHandleLogout_POST_UnregisteredRedirectURI_ShowsLogoutPage` — POST unregistered URI rejected (negative) ✅ Added
- Unit: `TestHandleLogout_POST_BasicAuthWithIdTokenHint` — Basic Auth + id_token_hint works (positive, GitHub #131) ✅ Added
- Unit: `TestHandleLogout_POST_ClearsIdpSessionCookie` — POST clears IdP cookie (positive) ✅ Added
- Unit: `TestRpInitiatedLogout_ClientIdMismatch_NoRedirect` — GET client_id/id_token_hint mismatch (negative) ✅ Added
- Unit: `TestRpInitiatedLogout_ClientIdMismatch_POST_NoRedirect` — POST client_id/id_token_hint mismatch (negative) ✅ Added
- Unit: `TestHandleRpInitiatedLogout_NoParams_ShowsLogoutPage` — GET no params (positive) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_ClearsIdpSessionCookie` — GET clears IdP cookie ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_WithIdTokenHint_DeactivatesSessions` — GET id_token_hint (positive) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_ValidPostLogoutRedirectURI` — GET registered redirect (positive) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_ValidPostLogoutRedirectURIWithState` — GET redirect with state (positive) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_UnregisteredPostLogoutRedirectURI_ShowsLogoutPage` — GET unregistered URI (negative) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_UnknownClientID_ShowsLogoutPage` — GET unknown client (negative) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_ClientIdFromIdTokenHint` — GET client_id resolved from token (positive) ✅ Pre-existing
- Unit: `TestHandleRpInitiatedLogout_InvalidIdTokenHint_StillLoggedOut` — GET invalid hint, graceful (positive) ✅ Pre-existing

---

## Phase 9 — RFC 7591: OAuth 2.0 Dynamic Client Registration

**File:** `rfc/rfc7591.txt`

**Context:** GitHub issue #132 — `POST /oauth2/register` implements dynamic client registration but had never been audited against RFC 7591. Error codes were generic (`invalid_request`) instead of spec-defined, and the `client_id_issued_at` field was missing from responses.

| Section | What to check | Code path |
|---|---|---|
| §2 | Client metadata fields, defaults, unknown field handling | `pkg/client/model.go`, `pkg/client/create.go` |
| §2 | redirect_uris MUST be registered for redirect-based flows | `pkg/client/handler.go` `HandleRegister` |
| §2 | Default grant_types, response_types, token_endpoint_auth_method | `pkg/client/create.go` `createClientInternal` |
| §3 | Registration endpoint MUST accept application/json POST | `pkg/client/handler.go` `HandleRegister` |
| §3.2.1 | Response MUST include client_id, all registered metadata | `pkg/client/create.go`, `pkg/client/model.go` `ClientResponse` |
| §3.2.1 | client_secret_expires_at REQUIRED when secret issued | `pkg/client/model.go` `ClientResponse` (hardcoded 0) |
| §3.2.2 | Error codes: invalid_client_metadata, invalid_redirect_uri | `pkg/client/handler.go` error paths |
| §3.2.2 | Error response: HTTP 400, application/json | `pkg/utils/responses.go` `WriteErrorResponse` |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2 | Ignore unrecognized client metadata fields | ✅ Pre-existing — Go json.Decoder silently ignores unknown fields |
| MUST | §2 | Clients using redirect-based flows MUST register redirect_uris | ✅ Pre-existing — redirect_uris required in validation |
| MUST | §3 | Accept HTTP POST with application/json | ✅ Pre-existing |
| MUST | §3.2.1 | Return client_id in registration response | ✅ Pre-existing |
| MUST | §3.2.1 | Return all registered metadata in response | ✅ Verified + annotated (2026-04-03) |
| MUST | §3.2.1 | client_secret_expires_at REQUIRED when secret issued | ✅ Pre-existing (hardcoded 0 — no expiration) |
| MUST | §3.2.2 | Return `invalid_client_metadata` for metadata validation errors | ✅ Fixed (2026-04-03) — was `invalid_request` |
| MUST | §3.2.2 | Return `invalid_redirect_uri` for redirect URI errors | ✅ Fixed (2026-04-03) — was `invalid_request` |
| MUST | §3.2.2 | Error response is HTTP 400 with application/json | ✅ Pre-existing |
| SHOULD | §2 | Default grant_types to ["authorization_code"] when omitted | ✅ Pre-existing + annotated (2026-04-03) |
| SHOULD | §2 | Default response_types to ["code"] when omitted | ✅ Pre-existing + annotated (2026-04-03) |
| SHOULD | §2.1 | Ensure grant_types and response_types are consistent | ✅ Pre-existing — both validated against known values |
| MAY | §2 | Default scope when omitted | ✅ Pre-existing — defaults to "openid profile email" |
| MAY | §3.1 | Provision default values for omitted metadata | ✅ Pre-existing — defaults for all major fields |
| OPTIONAL | §3.2.1 | client_id_issued_at in response | ✅ Added (2026-04-03) |
| OPTIONAL | §3.2.1 | client_secret in response (for confidential clients) | ✅ Pre-existing |

**RFC 7592 — Dynamic Client Registration Management (architectural decision):**

Autentico deliberately uses admin bearer tokens (via `AdminAuthMiddleware`) for client management (GET/PUT/DELETE) instead of RFC 7592's per-client `registration_access_token` model. This is a design choice: the client lifecycle is admin-controlled, not self-service.

Consequences:
- No `registration_access_token` in registration response (RFC 7592 §3 REQUIRED — not applicable)
- No `registration_client_uri` in registration response (RFC 7592 §3 REQUIRED — not applicable)
- PUT preserves omitted fields (RFC 7592 §2.2 says omitted = delete — not applicable; admin UI expects partial updates)
- DELETE soft-deletes (sets `is_active=false`) and returns 204 — matches RFC 7592 §2.3

This is analogous to the existing "public endpoints by design" decision for introspect/revoke (Phase 4/5).

**Bug Inventory:**

| Severity | Location | Issue | Spec Reference | Status |
|---|---|---|---|---|
| Medium | `pkg/client/handler.go:33` | Registration validation errors use `invalid_request` instead of `invalid_client_metadata` | RFC 7591 §3.2.2 | ✅ Fixed (2026-04-03) |
| Medium | `pkg/client/handler.go:38` | Redirect URI errors use `invalid_request` instead of `invalid_redirect_uri` | RFC 7591 §3.2.2 | ✅ Fixed (2026-04-03) |
| Low | `pkg/client/model.go` | Missing `client_id_issued_at` in registration response | RFC 7591 §3.2.1 | ✅ Fixed (2026-04-03) |

**Security Considerations (§5):**
- [x] §5: Registration endpoint is behind admin auth (`AdminAuthMiddleware`) — open registration is not supported, eliminating the open-registration attack surface
- [x] §5: Client secrets are bcrypt-hashed before storage; plaintext returned only once in registration response
- [x] §5: redirect_uris validated as proper URLs — prevents injection of malicious URIs
- [x] §5: All client metadata treated as admin-asserted (admin creates clients, not self-service)

**Discovery cross-check:**
- [x] `registration_endpoint` present in `/.well-known/openid-configuration` — pre-existing

**Tests:**
- Unit: `TestHandleRegister` — happy path registration ✅ Pre-existing
- Unit: `TestHandleRegisterInvalidJSON` — malformed JSON ✅ Pre-existing
- Unit: `TestHandleRegisterMissingFields` — missing required fields ✅ Pre-existing
- Unit: `TestHandleRegisterInvalidRedirectURI` — invalid redirect URI ✅ Pre-existing
- Unit: `TestHandleRegister_RFC7591_UnknownFieldsIgnored` — unknown metadata silently ignored (positive) ✅ Added
- Unit: `TestHandleRegister_RFC7591_InvalidMetadata_ErrorCode` — `invalid_client_metadata` error code (negative) ✅ Added
- Unit: `TestHandleRegister_RFC7591_InvalidRedirectURI_ErrorCode` — `invalid_redirect_uri` error code (negative) ✅ Added
- Unit: `TestHandleRegister_RFC7591_ResponseContainsAllFields` — all required response fields present (positive) ✅ Added
- Unit: `TestHandleRegister_RFC7591_PublicClient_NoSecret` — public client has no secret (positive) ✅ Added
- Unit: `TestHandleUpdateClient_RFC7591_InvalidMetadata_ErrorCode` — update `invalid_client_metadata` (negative) ✅ Added
- Unit: `TestHandleUpdateClient_RFC7591_InvalidRedirectURI_ErrorCode` — update `invalid_redirect_uri` (negative) ✅ Added

---

## Phase 10 — RFC 8414: OAuth 2.0 Authorization Server Metadata

**File:** `rfc/rfc8414.txt` (pre-existing)

**Context:** RFC 8414 defines the OAuth 2.0 authorization server metadata format. It heavily overlaps with OIDC Discovery 1.0 (Phase 7) since both specify the `.well-known` metadata document. This phase verifies that the existing implementation satisfies RFC 8414's requirements and adds RFC 8414 section annotations alongside the existing OIDC Discovery ones.

**Note:** No bugs found. The implementation was fully compliant — this phase is annotations and verification only.

| Section | What to check | Code path |
|---|---|---|
| §2 | REQUIRED: `issuer`, `authorization_endpoint`, `token_endpoint`, `response_types_supported` | `pkg/wellknown/handler.go`, `pkg/model/well_known_config.go` |
| §2 | RECOMMENDED: `scopes_supported` | `pkg/wellknown/handler.go` |
| §2 | OPTIONAL: `jwks_uri`, `registration_endpoint`, `grant_types_supported`, `token_endpoint_auth_methods_supported`, `introspection_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported` | `pkg/wellknown/handler.go` |
| §3 | Metadata available at well-known path; `issuer` must match; zero-element arrays omitted | `pkg/wellknown/handler.go`, `pkg/cli/start.go` route |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §2 | `issuer` REQUIRED (HTTPS, no query/fragment) | ✅ Pre-existing + annotated (2026-04-03) |
| MUST | §2 | `authorization_endpoint` REQUIRED | ✅ Pre-existing + annotated (2026-04-03) |
| MUST | §2 | `token_endpoint` REQUIRED | ✅ Pre-existing + annotated (2026-04-03) |
| MUST | §2 | `response_types_supported` REQUIRED | ✅ Pre-existing + annotated (2026-04-03) |
| MUST | §3 | Metadata served at well-known path | ✅ Pre-existing — `/.well-known/openid-configuration` (§5 permits this suffix) |
| MUST | §3 | `issuer` in response identical to server's issuer identifier | ✅ Pre-existing — verified by `TestHandleWellKnownConfig_RFC8414_IssuerIdentity` |
| MUST | §3 | Zero-element arrays omitted from response | ✅ Pre-existing — all arrays are populated; `omitempty` on optional fields |
| RECOMMENDED | §2 | `scopes_supported` | ✅ Pre-existing + annotated (2026-04-03) |
| OPTIONAL | §2 | `jwks_uri` | ✅ Pre-existing |
| OPTIONAL | §2 | `registration_endpoint` | ✅ Pre-existing |
| OPTIONAL | §2 | `grant_types_supported` (default: authorization_code + implicit) | ✅ Pre-existing — explicitly listed to override default |
| OPTIONAL | §2 | `token_endpoint_auth_methods_supported` (default: client_secret_basic) | ✅ Pre-existing |
| OPTIONAL | §2 | `revocation_endpoint` | ✅ Pre-existing (Phase 4) |
| OPTIONAL | §2 | `introspection_endpoint` | ✅ Pre-existing (Phase 5) |
| OPTIONAL | §2 | `code_challenge_methods_supported` | ✅ Pre-existing (Phase 3) |
| OPTIONAL | §2 | `service_documentation` | ⏭ Not implemented — no documentation URL configured |
| OPTIONAL | §2 | `revocation_endpoint_auth_methods_supported` | ⏭ Not implemented — revocation is public by design |
| OPTIONAL | §2 | `introspection_endpoint_auth_methods_supported` | ⏭ Not implemented — introspection is public by design |

**Security Considerations (§6):**
- [x] §6: TLS required for metadata endpoint — enforced at infrastructure level in production
- [x] §6: Issuer identifier in response must match requested — both use `AppAuthIssuer`; verified by tests
- [x] §6: Client MUST verify issuer identity — client-side responsibility per spec

**Tests:**
- Unit: `TestHandleWellKnownConfig_RFC8414_RequiredFields` — all REQUIRED/RECOMMENDED/OPTIONAL fields present, zero-element check ✅ Added
- Unit: `TestHandleWellKnownConfig_RFC8414_IssuerIdentity` — issuer matches server identifier (positive) ✅ Added
- Unit: `TestHandleWellKnownConfig_RFC8414_Endpoints` — introspection, revocation, PKCE endpoints ✅ Pre-existing
- Unit: `TestHandleWellKnownConfig_RequiredFields` — OIDC Discovery required fields ✅ Pre-existing (Phase 7)
- Unit: `TestHandleWellKnownConfig_IssuerMatchesTokenIss` — issuer matches token iss ✅ Pre-existing (Phase 7)

---

## Phase 11 — RFC 6749 §4.4: Client Credentials Grant

**File:** `rfc/rfc6749.txt`

| Section | What to check | Code path |
|---|---|---|
| §4.4 | Client credentials grant overview — M2M flow, no user context | `pkg/token/handler.go` client_credentials case |
| §4.4.2 | Token request: client MUST authenticate; only confidential clients | `pkg/token/handler.go` client auth + type check |
| §4.4.3 | Token response: access_token, token_type required; refresh token SHOULD NOT be included | `pkg/token/handler.go` response construction |
| §5.1 | Token response: Cache-Control no-store, Pragma no-cache | `pkg/token/handler.go` response headers |

**MUST / SHOULD / MAY compliance:**

| Keyword | Section | Requirement | Status |
|---------|---------|-------------|--------|
| MUST | §4.4.2 | Client MUST authenticate with the authorization server | ✅ Implemented (2026-04-06) |
| MUST | §4.4.2 | Only confidential clients may use client_credentials | ✅ Implemented (2026-04-06) |
| MUST | §5.1 | Token response includes `access_token`, `token_type` | ✅ Implemented (2026-04-06) |
| MUST | §5.1 | `Cache-Control: no-store` and `Pragma: no-cache` in token response | ✅ Implemented (2026-04-06) |
| SHOULD NOT | §4.4.3 | Refresh token SHOULD NOT be included in response | ✅ Implemented — no refresh token issued (2026-04-06) |

**Security Considerations:**
- [x] §10.1: Only confidential clients can use client_credentials — public clients are rejected
- [x] §10.3: No authorization codes involved — not applicable
- [x] Token has no associated user — `sub` claim set to `client_id`; no session created
- [x] Introspection skips session liveness check for client_credentials tokens

**Discovery cross-check:**
- [x] `grant_types_supported` includes `"client_credentials"` in `/.well-known/openid-configuration`

**Tests:**
- Unit: `TestHandleToken_ClientCredentials_Success` — confidential client → 200, access_token present, no refresh_token, no id_token, sub == client_id ✅ Added
- Unit: `TestHandleToken_ClientCredentials_NoClientAuth` — missing credentials → 401 invalid_client ✅ Added
- Unit: `TestHandleToken_ClientCredentials_PublicClient` — public client → unauthorized_client ✅ Added
- Unit: `TestHandleToken_ClientCredentials_GrantNotAllowed` — grant not in client's grant_types → unauthorized_client ✅ Added
- Unit: `TestHandleToken_ClientCredentials_InvalidScope` — scope not allowed → invalid_scope ✅ Added
- Unit: `TestHandleToken_ClientCredentials_OpenIDScopeStripped` — openid stripped from response scope ✅ Added
- Unit: `TestGenerateClientCredentialsToken` — generation function unit test ✅ Added
- Unit: `TestRemoveScope` — helper function unit test ✅ Added
- Unit: `TestHandleWellKnownConfig_ClientCredentialsGrantType` — discovery includes client_credentials ✅ Added
- E2e: `TestClientCredentials_FullFlow` — register client, get token, introspect → active ✅ Added
- E2e: `TestClientCredentials_TokenRevocation` — get token, revoke, introspect → inactive ✅ Added
- E2e: `TestClientCredentials_BasicAuth` — client_secret_basic authentication ✅ Added
- E2e: `TestClientCredentials_SecretPost` — client_secret_post authentication ✅ Added
- E2e: `TestClientCredentials_ScopeValidation` — invalid scope rejected ✅ Added
- E2e: `TestClientCredentials_NoRefreshToken` — response has no refresh_token ✅ Added
- E2e: `TestClientCredentials_PublicClientRejected` — public client cannot use this grant ✅ Added
