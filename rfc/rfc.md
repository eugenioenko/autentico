# RFC Compliance Review Plan

## Overview

Seven phases tackling one spec at a time, in dependency order. Each phase: read spec sections, review code paths, fix bugs, add unit + e2e tests.

| Phase | Spec | Est. Time | Status |
|---|---|---|---|
| 1 | RFC 6749 — OAuth 2.0 Core | 2–3h | pending |
| 2 | RFC 6750 — Bearer Token Usage | 1.5h | pending |
| 3 | RFC 7636 — PKCE | 1.5h | pending |
| 4 | RFC 7009 — Token Revocation | 1.5h | pending |
| 5 | RFC 7662 — Token Introspection | 1.5h | pending |
| 6 | OIDC Core 1.0 | 3h | pending |
| 7 | OIDC Discovery 1.0 | 1h | pending |

**Recommended order:** 1 → 4 → 5 → 2 → 3 → 6 → 7

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

**Tests to add:**
- Unit: `error_description` with spaces/special chars is URL-encoded in redirect
- Unit: `scope` present in token response for `refresh_token` grant
- Unit: `refresh_token` grant rejects scope expansion
- E2e: `TestAuthorizationCodeFlow_ScopeDownscope`

---

## Phase 2 — RFC 6750: Bearer Token Usage

**File:** `rfc/rfc6750.txt`

| Section | What to check | Code path |
|---|---|---|
| §2.1 | `Bearer ` prefix parsing (capital B, single space) | `pkg/utils/extract_bearer_token.go` |
| §2.2 | Form-encoded `access_token`: only `application/x-www-form-urlencoded`, POST only, not alongside header | `pkg/userinfo/handler.go` |
| §3.1 | `WWW-Authenticate` header MUST be set on 401 responses | all protected endpoints |
| §3.1 | `WWW-Authenticate: Bearer realm="...", error="...", error_description="..."` format | all protected endpoints |

**Tests to add:**
- E2e: `TestUserInfo_WWWAuthenticateHeader` — assert header on 401
- E2e: `TestUserInfo_FormBodyToken` — POST with `access_token` in form body
- E2e: `TestUserInfo_DualCredentials_Rejected` — header + body token simultaneously
- Unit: `ExtractBearerToken` with case variations

---

## Phase 3 — RFC 7636: PKCE

**File:** `rfc/rfc7636.txt`

| Section | What to check | Code path |
|---|---|---|
| §4.1 | `code_verifier`: 43–128 chars, unreserved chars only | `pkg/token/authorization_code.go` `verifyCodeChallenge` |
| §4.2 | `code_challenge`: `BASE64URL(SHA256(ASCII(verifier)))`, no padding | `pkg/token/authorization_code.go` |
| §4.2 | `code_challenge_method` absent → default to S256 | `pkg/token/authorization_code.go` line 86 |
| §4.3 | If challenge was sent, verifier MUST be sent on exchange | `pkg/token/authorization_code.go` line 54 |
| §6.1 | `code_challenge_methods_supported` in discovery | `pkg/wellknown/handler.go` — absent |

**Tests to add:**
- Unit: verifier shorter than 43 chars — rejected
- Unit: verifier with invalid chars (`+`, `/`) — rejected
- Unit: verifier at exactly 43 and 128 chars (boundary)
- E2e: `TestPKCE_PlainMethod_E2E`
- Unit: wellknown asserts `code_challenge_methods_supported` once added

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

| Section | What to check | Code path |
|---|---|---|
| §3 | Required: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | `pkg/wellknown/handler.go` — all present |
| §3 | `introspection_endpoint` — absent | `pkg/model/well_known_config.go` |
| §3 | `revocation_endpoint` — absent | `pkg/model/well_known_config.go` |
| §3 | `code_challenge_methods_supported` — absent | `pkg/model/well_known_config.go` |
| §3 | `response_types_supported` lists `token`, `id_token` — implicit flow not implemented | `pkg/wellknown/handler.go` |
| §3 | `issuer` MUST exactly match `iss` in tokens | `pkg/wellknown/handler.go` vs `pkg/token/generate.go` |
| §3 | JWKS keys: `kty`, `use`, `alg`, `kid`, `n`, `e` all present | `pkg/wellknown/handler.go` `HandleJWKS` |

**Tests to add:**
- E2e: `TestWellKnown_RequiredFields` — all required fields present with correct types
- E2e: `TestWellKnown_IssuerMatchesTokenIss` — compare `issuer` in discovery to `iss` in token
- E2e: `TestJWKS_Structure` — assert key fields present
- E2e: `TestJWKS_ValidatesIDToken` — use JWKS to verify ID token signature
- Unit: assert `introspection_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported` present once added
