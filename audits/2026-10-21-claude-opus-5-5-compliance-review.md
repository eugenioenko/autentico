# OIDC / OAuth 2.0 Spec Compliance Review: claude-opus-5-5

| Field | Value |
|---|---|
| Date | 2026-10-21 |
| Auditor | claude-opus-5-5 (Claude Code), manual code review against the specs in `rfc/`, with handler-level probe tests for confirmation. Run by eugenioenko. |
| Commit audited | 6132e44 |
| Scope | Protocol behavior against OIDC Core 1.0, OIDC Discovery 1.0, RP-Initiated Logout 1.0, RFC 6749, 6750, 7009, 7591, 7636, 7662, 8628 (and RFC 9068 where the code cites it): `/authorize`, login, consent, MFA finish, `/token` (all grants), userinfo, discovery and JWKS, logout, introspection, revocation, registration, device authorization |

Only MUST-level violations, or places where the server advertises or reports something untrue, are counted as findings. SHOULD/OPTIONAL items and documented deliberate deviations are listed separately. Confidence: **test** = reproduced with a throwaway handler test (deleted afterwards); **read** = confirmed by reading the code path end to end.

## Findings

| Severity | Finding | Location | Spec | Confidence | Status |
|---|---|---|---|---|---|
| HIGH | `prompt=none` with a valid SSO session and missing consent redirects to the consent page instead of returning `consent_required`. | `pkg/authorize/handler.go:149` | OIDC Core §3.1.2.1 | test | Fixed in [#525](https://github.com/eugenioenko/autentico/pull/525) ([#511](https://github.com/eugenioenko/autentico/issues/511)) |
| MEDIUM | Refreshed ID tokens use the previous token row's `issued_at` as `auth_time`; it drifts forward on every refresh. | `pkg/token/handler.go:319` | OIDC Core §12.2 | test | Fixed in [#525](https://github.com/eugenioenko/autentico/pull/525) ([#512](https://github.com/eugenioenko/autentico/issues/512)) |
| MEDIUM | Codes issued from the consent POST get `auth_time` = consent time, not the IdP session's authentication time. | `pkg/consent/handler.go:154`, `pkg/auth_code/create.go:10` | OIDC Core §2 (`auth_time`) | read | Fixed in [#525](https://github.com/eugenioenko/autentico/pull/525) ([#471](https://github.com/eugenioenko/autentico/issues/471)) |
| MEDIUM | `response_type=token` is accepted for clients registered with `token`, and a code is returned in the query. Registration accepts `token`/`id_token`. | `pkg/authorize/handler.go:128`, `pkg/client/model.go` | RFC 6749 §3.1.1, §4.1.2.1 | test | Fixed in [#526](https://github.com/eugenioenko/autentico/pull/526) ([#513](https://github.com/eugenioenko/autentico/issues/513)) |
| MEDIUM | Device authorization endpoint does not authenticate confidential clients. | `pkg/devicecode/handler.go:42` | RFC 8628 §3.1 | read | Fixed in [#528](https://github.com/eugenioenko/autentico/pull/528) ([#514](https://github.com/eugenioenko/autentico/issues/514)) |
| LOW | Unknown `grant_type` returns `invalid_request`; the `unsupported_grant_type` branch is unreachable. | `pkg/token/handler.go:80`, `pkg/token/model.go` | RFC 6749 §5.2 | test | Fixed ([#531](https://github.com/eugenioenko/autentico/pull/531)) |
| LOW | 401 `invalid_client` after Basic auth has no `WWW-Authenticate` at token and revoke; revoke's bearer 401 has none either. | `pkg/token/handler.go:92`, `pkg/revoke/handler.go:43,49,55` | RFC 6749 §5.2, RFC 6750 §3 | test | Fixed in [#528](https://github.com/eugenioenko/autentico/pull/528) ([#516](https://github.com/eugenioenko/autentico/issues/516)) |
| LOW | Unsupported `code_challenge_method` is not rejected at `/authorize`; SSO path issues a code, password path loops on an error. | `pkg/authorize/handler.go` | RFC 7636 §4.4.1 | test | Fixed ([#532](https://github.com/eugenioenko/autentico/pull/532)) |
| LOW | Missing `code_challenge_method` is treated as `S256` instead of `plain`. | `pkg/token/authorization_code.go:119` | RFC 7636 §4.3 | read | Fixed ([#533](https://github.com/eugenioenko/autentico/pull/533)) |
| LOW | `prompt=none login` renders the login page instead of returning an error. | `pkg/authorize/handler.go:164` | OIDC Core §3.1.2.1 | test | Fixed in [#525](https://github.com/eugenioenko/autentico/pull/525) ([#519](https://github.com/eugenioenko/autentico/issues/519)) |
| LOW | Discovery omits `request_uri_parameter_supported` (default `true`); `request_uri` is ignored and a code is issued. | `pkg/wellknown/handler.go:69`, `pkg/authorize/handler.go` | OIDC Discovery §3, Core §3.1.2.6 | test | Fixed ([#534](https://github.com/eugenioenko/autentico/pull/534)) |
| LOW | Discovery omits `response_modes_supported` (default `["query","fragment"]`); `response_mode` is ignored. | `pkg/wellknown/handler.go` | OIDC Discovery §3 | read | Fixed ([#521](https://github.com/eugenioenko/autentico/issues/521)) |
| LOW | Introspection `aud` is the global custom audiences space-joined; `jti` is the DB row id. Neither matches the token. | `pkg/introspect/handler.go:183,197` | RFC 7662 §2.2, RFC 7519 §4.1.3 | read | Fixed ([#522](https://github.com/eugenioenko/autentico/issues/522)): read the presented JWT after stored-hash/liveness checks; audience array and optional JWT ID; no schema change |
| LOW | Registration with `token_endpoint_auth_method: none` and no `client_type` creates a confidential client with a secret; RFC 7591 `scope` is named `scopes`. | `pkg/client/create.go:31`, `pkg/client/model.go` | RFC 7591 §2, §3.2.1 | read | Open ([#523](https://github.com/eugenioenko/autentico/issues/523)) |

### Minor (not filed)

| Item | Location | Spec |
|---|---|---|
| Basic-auth client credentials are not form-urldecoded; only affects secrets with reserved characters (tested with `a+b/c=`). Generated secrets are unaffected. | `pkg/client/authenticate.go`, `pkg/token/handler.go` | RFC 6749 §2.3.1 |
| Registration accepts redirect URIs with a fragment; login paths reject them later via `ValidateAuthorization`, the SSO path does not. | `pkg/client/model.go:300` | RFC 6749 §3.1.2 |
| Missing `refresh_token` parameter returns `invalid_grant` instead of `invalid_request`. | `pkg/token/refresh_token.go:17-21` | RFC 6749 §5.2 |
| If RFC 9068 compliance is claimed: access tokens use header `typ: JWT` (not `at+jwt`) and carry `azp` but no `client_id` claim. `rfc/rfc.md` does not claim full RFC 9068 compliance. | `pkg/token/generate.go` | RFC 9068 §2.1, §2.2 |

## What passed

- **Authorize:** redirect URI and client validated before any redirect (no redirect on invalid client/URI); error redirects preserve the registered callback query and encode `state`; `request` objects rejected with `request_not_supported`; PKCE required for public clients; `prompt=login` skips SSO; `max_age` forces re-authentication; SSO checks deactivated sessions, idle timeout, max age and current MFA evidence; POST authorize supported.
- **Token:** POST only; `redirect_uri` must match the code; code bound to `client_id`; PKCE verifier length/charset and S256 check; code reuse returns `invalid_grant` and revokes issued tokens; single-use grants consumed atomically with issuance; refresh requires client auth, binding to client and session, scope subset only, rotation with replay revocation; client_credentials confidential-only, no refresh token; `Cache-Control: no-store` and `Pragma: no-cache`.
- **ID token:** `iss`, `sub`, `aud`, `exp`, `iat` present; `nonce` echoed; `at_hash` correct for RS256; `azp` set; issued only with `openid`; SSO codes carry the IdP session's `auth_time`; refreshed ID tokens omit `nonce`.
- **UserInfo:** GET and POST; header or form-body token, never both; `WWW-Authenticate` on 401; claims gated by scope; `sub` matches the ID token.
- **Discovery / JWKS:** required metadata present; issuer matches `iss`; served at `{issuer}/.well-known/openid-configuration`; only `code` and `S256` advertised.
- **RP-Initiated Logout:** GET and POST; `id_token_hint` signature verified, expired hints accepted; `client_id` vs hint mismatch blocks redirect; `post_logout_redirect_uri` exact match only; `state` echoed.
- **Introspection:** authenticated confidential clients or admin bearer only; inactive tokens return `200 {"active":false}`; cross-client tokens reported inactive; session and user liveness checked; `exp` follows the presented credential.
- **Revocation:** client auth required; 200 for unknown/foreign tokens; revoking either token revokes the pair.
- **Device grant:** `authorization_pending`, `slow_down` (+5s), `expired_token`, `access_denied`; code bound to client; no-store headers.

## Deliberate deviations (not findings)

| Item | Why excluded |
|---|---|
| Wildcard redirect URIs break OIDC Core §3.1.2.1 exact matching | Documented compatibility extension, restricted to one plain path segment (`rfc/rfc.md`, "Redirect wildcard compatibility boundary"). |
| No logout confirmation without `id_token_hint` | SHOULD-level (RP-Initiated Logout §2 / §6). |
| `acr` in ID token always `"1"`; `prompt_values_supported` omits `consent`; `claims` parameter unsupported (#101); `form_post` unsupported (#166) | OPTIONAL / no MUST violated. |
| Duplicate request parameters not rejected | RFC 6749 §3.1 places the constraint on the client; server detection is implied, not required. |

## Annotations

As part of this review, inline spec annotations were added to compliant return paths that lacked them (comments only, no behavior change) in `pkg/authorize`, `pkg/login`, `pkg/consent`, `pkg/token`, `pkg/userinfo`, `pkg/introspect`, `pkg/revoke`, `pkg/devicecode` and `pkg/wellknown`. Non-compliant paths listed above were deliberately left unannotated.

## See also

- [`rfc/rfc.md`](../rfc/rfc.md): MUST/SHOULD/MAY tables
- [2026-05-09 compliance review](2026-05-09-rfc-compliance-review.md)
- [2026-10-20 security review](2026-10-20-claude-opus-5-5-security-review.md)

## Follow-up review

CodeRabbit’s source review of [#526](https://github.com/eugenioenko/autentico/pull/526) found that SSO code issuance also needed to enforce the registered authorization-code grant. The reproduced follow-up [#527](https://github.com/eugenioenko/autentico/issues/527) is fixed in that PR, with authenticated GET/POST regressions. This follow-up was outside the original audit.

CodeRabbit’s source review of [#528](https://github.com/eugenioenko/autentico/pull/528) identified shared client-credential transport, OAuth Basic decoding and ambiguous-credential handling defects. Reproduced helper/HTTP regressions track these in [#529](https://github.com/eugenioenko/autentico/issues/529), fixed by the shared parser changes in that PR.
